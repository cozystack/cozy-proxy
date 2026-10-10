package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

var log = ctrl.Log.WithName("nft-proxy-processor")

// NFTProxyProcessor implements a NATProcessor using nftables.
type NFTProxyProcessor struct {
	// mu serializes every queue-then-flush sequence below.
	//
	// nftables.Conn guards its own message list, but not the interval between
	// queueing messages and committing them. Two informer goroutines — plus
	// the startup reconciliation — share this connection, so without this
	// lock one flush carries the other caller's half-queued messages. A batch
	// is a single transaction: one stale deletion in it aborts the other
	// caller's addition, which is then never retried because the controller
	// only reacts to events. The service stays unprogrammed until the next
	// one, which is how a public IP can go dark for minutes after a restart.
	mu sync.Mutex

	conn *nftables.Conn

	// Table "cozy_proxy" will contain all objects.
	table *nftables.Table

	// IP-only NAT objects.
	podSvcMap *nftables.Set // Map "pod_svc": maps pod IP → svc IP.
	svcPodMap *nftables.Set // Map "svc_pod": maps svc IP → pod IP.

	// Port-filtering objects (post-DNAT, key on pod IP).
	filteredPods    *nftables.Set   // set of pod IPs subject to port filtering.
	allowedPorts    *nftables.Set   // concat set: (ipv4_addr . inet_proto . inet_service).
	icmpAllowedPods *nftables.Set   // set of pod IPs that should accept ICMP in port_filter.
	portFilterCh    *nftables.Chain // chain "port_filter" running post-conntrack and post-ingress_dnat.
}

// InitRules initializes the nftables configuration in a single table "cozy_proxy".
// It flushes the entire ruleset, then re-creates the table with the desired sets, maps, and chains.
func (p *NFTProxyProcessor) InitRules() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Initializing nftables NAT configuration")

	// Create a new connection if needed.
	if p.conn == nil {
		var err error
		p.conn, err = nftables.New()
		if err != nil {
			log.Error(err, "Could not create nftables connection")
			return fmt.Errorf("could not create nftables connection: %v", err)
		}
		log.Info("Created nftables connection")
	} else {
		log.Info("Using existing nftables connection")
	}

	// --- Create new table "cozy_proxy" ---
	p.table = p.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "cozy_proxy",
	})
	log.Info("Created new table", "table", p.table.Name)

	// --- Create Sets and Maps ---
	// Map "pod_svc": maps pod IP → svc IP.
	p.podSvcMap = &nftables.Set{
		Table:    p.table,
		Name:     "pod_svc",
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeIPAddr,
		IsMap:    true,
	}
	if err := p.conn.AddSet(p.podSvcMap, nil); err != nil {
		log.Error(err, "Could not add pod_svc map")
		return fmt.Errorf("could not add pod_svc map: %v", err)
	}
	log.Info("Created pod_svc map", "map", p.podSvcMap.Name)

	// Map "svc_pod": maps svc IP → pod IP.
	p.svcPodMap = &nftables.Set{
		Table:    p.table,
		Name:     "svc_pod",
		KeyType:  nftables.TypeIPAddr,
		DataType: nftables.TypeIPAddr,
		IsMap:    true,
	}
	if err := p.conn.AddSet(p.svcPodMap, nil); err != nil {
		log.Error(err, "Could not add svc_pod map")
		return fmt.Errorf("could not add svc_pod map: %v", err)
	}
	log.Info("Created svc_pod map", "map", p.svcPodMap.Name)

	// --- Port filter sets ---
	// Set "filtered_pods": pod IPs subject to ingress port filtering.
	// Keyed on pod IP because port_filter runs after ingress_dnat has rewritten
	// daddr from LB IP to pod IP.
	p.filteredPods = &nftables.Set{
		Table:   p.table,
		Name:    "filtered_pods",
		KeyType: nftables.TypeIPAddr,
	}
	if err := p.conn.AddSet(p.filteredPods, nil); err != nil {
		log.Error(err, "Could not add filtered_pods set")
		return fmt.Errorf("could not add filtered_pods set: %v", err)
	}
	log.Info("Created filtered_pods set", "set", p.filteredPods.Name)

	// Set "allowed_ports": concat key (ipv4_addr . inet_proto . inet_service).
	// Each component is padded to a 4-byte slot, total 12 bytes.
	allowedKeyType, err := nftables.ConcatSetType(
		nftables.TypeIPAddr,
		nftables.TypeInetProto,
		nftables.TypeInetService,
	)
	if err != nil {
		log.Error(err, "Could not build allowed_ports key type")
		return fmt.Errorf("could not build allowed_ports key type: %v", err)
	}
	p.allowedPorts = &nftables.Set{
		Table:         p.table,
		Name:          "allowed_ports",
		KeyType:       allowedKeyType,
		Concatenation: true,
	}
	if err := p.conn.AddSet(p.allowedPorts, nil); err != nil {
		log.Error(err, "Could not add allowed_ports set")
		return fmt.Errorf("could not add allowed_ports set: %v", err)
	}
	log.Info("Created allowed_ports concat set", "set", p.allowedPorts.Name)

	// Set "icmp_allowed_pods": pod IPs whose ICMP traffic should bypass the
	// port_filter drop rule. Opt-in via the allowICMP service annotation,
	// applies only to pods also present in filtered_pods.
	p.icmpAllowedPods = &nftables.Set{
		Table:   p.table,
		Name:    "icmp_allowed_pods",
		KeyType: nftables.TypeIPAddr,
	}
	if err := p.conn.AddSet(p.icmpAllowedPods, nil); err != nil {
		log.Error(err, "Could not add icmp_allowed_pods set")
		return fmt.Errorf("could not add icmp_allowed_pods set: %v", err)
	}
	log.Info("Created icmp_allowed_pods set", "set", p.icmpAllowedPods.Name)

	// --- Delete Chains ---
	chains, _ := p.conn.ListChains()
	for _, chain := range chains {
		if chain.Table.Name == p.table.Name {
			p.conn.DelChain(chain)
		}
	}

	// --- Create Chains ---
	// port_filter runs at priority filter (0), AFTER conntrack (-200) and
	// AFTER ingress_dnat (-150). At this priority, daddr has been rewritten
	// from LB IP to pod IP by ingress_dnat, so the filter matches on pod IP.
	// The "ct state established,related accept" rule below now works correctly
	// because conntrack has tagged the packet by the time we evaluate it.
	p.portFilterCh = p.conn.AddChain(&nftables.Chain{
		Name:     "port_filter",
		Table:    p.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityFilter,
	})
	log.Info("Created port_filter chain", "priority", "filter (0)")

	egressSNAT := p.conn.AddChain(&nftables.Chain{
		Name:     "egress_snat",
		Table:    p.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityRaw,
	})
	log.Info("Created egress_snat chain", "priority", "raw (-300)")

	// SNAT rule: rewrite saddr from pod IP to svc IP (egress IP preservation).
	// Runs BEFORE conntrack so the tracked tuple has saddr=LB_IP.
	p.conn.AddRule(&nftables.Rule{
		Table: p.table,
		Chain: egressSNAT,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       12,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				DestRegister:   1,
				SetName:        p.podSvcMap.Name,
				SetID:          p.podSvcMap.ID,
				IsDestRegSet:   true,
			},
			&expr.Payload{
				OperationType:  expr.PayloadWrite,
				SourceRegister: 1,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         12,
				Len:            4,
				CsumType:       expr.CsumTypeInet,
				CsumOffset:     10,
				CsumFlags:      unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR,
			},
		},
	})
	log.Info("Added egress_snat saddr rewrite rule")

	ingressDNAT := p.conn.AddChain(&nftables.Chain{
		Name:     "ingress_dnat",
		Table:    p.table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
	})
	log.Info("Created ingress_dnat chain", "priority", "mangle (-150)")

	// DNAT rule: rewrite daddr from svc IP to pod IP. Runs AFTER conntrack
	// so conntrack records the original daddr=LB_IP and can correctly match
	// reply packets of egress flows.
	p.conn.AddRule(&nftables.Rule{
		Table: p.table,
		Chain: ingressDNAT,
		Exprs: []expr.Any{
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				DestRegister:   1,
				SetName:        p.svcPodMap.Name,
				SetID:          p.svcPodMap.ID,
				IsDestRegSet:   true,
			},
			&expr.Payload{
				OperationType:  expr.PayloadWrite,
				SourceRegister: 1,
				Base:           expr.PayloadBaseNetworkHeader,
				Offset:         16,
				Len:            4,
				CsumType:       expr.CsumTypeInet,
				CsumOffset:     10,
				CsumFlags:      unix.NFT_PAYLOAD_L4CSUM_PSEUDOHDR,
			},
		},
	})
	log.Info("Added ingress_dnat daddr rewrite rule")

	// --- port_filter rule: bypass for established/related ---
	// Idiomatic stateful firewall: any packet that belongs to an existing
	// conntrack flow bypasses the per-port drop below. Without this, egress
	// traffic from VMs in PortList mode would be broken: their return packets
	// arrive with daddr=LB IP and dport=ephemeral source port, which would
	// otherwise match the drop rule below. Because port_filter runs at
	// priority filter (0), conntrack (priority -200) has already evaluated
	// the packet and ct state is correctly populated.
	p.conn.AddRule(&nftables.Rule{
		Table: p.table,
		Chain: p.portFilterCh,
		Exprs: []expr.Any{
			// Load ct state into reg 1 (uint32 bitmask).
			&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
			// Mask with (ESTABLISHED | RELATED). If any bit set, accept.
			&expr.Bitwise{
				SourceRegister: 1,
				DestRegister:   1,
				Len:            4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Op:       expr.CmpOpNeq,
				Register: 1,
				Data:     []byte{0, 0, 0, 0},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	log.Info("Added port_filter ct established,related accept rule")

	// --- port_filter rule: ICMP opt-in accept ---
	// Equivalent to:
	//   ip daddr @icmp_allowed_pods meta l4proto icmp accept
	//
	// Without this, ICMP to a filtered pod IP is dropped by the rule below
	// because it composes its lookup key from (daddr, l4proto, th_dport) and
	// the controller only populates allowed_ports with TCP/UDP entries —
	// breaking ping, PMTU discovery (ICMP Frag Needed), and ICMP unreachable
	// signalling. Services that opt in via the allowICMP annotation get their
	// pod IP added to icmp_allowed_pods, which gates this accept.
	p.conn.AddRule(&nftables.Rule{
		Table: p.table,
		Chain: p.portFilterCh,
		Exprs: []expr.Any{
			// Gate: ip daddr in icmp_allowed_pods (continue if matched).
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // IPv4 daddr (post-ingress_dnat: pod IP)
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        p.icmpAllowedPods.Name,
				SetID:          p.icmpAllowedPods.ID,
			},
			// meta l4proto == ICMP.
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{unix.IPPROTO_ICMP},
			},
			&expr.Verdict{Kind: expr.VerdictAccept},
		},
	})
	log.Info("Added port_filter ICMP accept rule")

	// --- port_filter rule ---
	// Equivalent to:
	//   ip daddr @filtered_pods ip daddr . meta l4proto . th dport != @allowed_ports drop
	//
	// At priority filter (0), daddr has been rewritten by ingress_dnat from
	// the LB IP to the pod IP. Both the gate set (filtered_pods) and the
	// allowed_ports composite key are therefore keyed on pod IP.
	//
	// Implementation: lay out the 12-byte concat key across NFT_REG32_00..02
	// (register IDs 8, 9, 10), then a single inverted lookup against
	// allowed_ports. Lookup reads s.KeyType.Bytes (12) bytes starting at the
	// source register, so the three 4-byte slots must be contiguous.
	p.conn.AddRule(&nftables.Rule{
		Table: p.table,
		Chain: p.portFilterCh,
		Exprs: []expr.Any{
			// 1. Gate: ip daddr in filtered_pods (continue if matched).
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16, // IPv4 daddr (post-ingress_dnat: pod IP)
				Len:          4,
			},
			&expr.Lookup{
				SourceRegister: 1,
				SetName:        p.filteredPods.Name,
				SetID:          p.filteredPods.ID,
			},
			// 2. Build composite key (daddr . l4proto . dport) into reg32_00..02.
			&expr.Payload{
				DestRegister: unix.NFT_REG32_00,
				Base:         expr.PayloadBaseNetworkHeader,
				Offset:       16,
				Len:          4,
			},
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: unix.NFT_REG32_01,
			},
			&expr.Payload{
				DestRegister: unix.NFT_REG32_02,
				Base:         expr.PayloadBaseTransportHeader,
				Offset:       2, // dport (TCP and UDP both at byte 2)
				Len:          2,
			},
			// 3. If (daddr, proto, dport) NOT in allowed_ports → drop.
			&expr.Lookup{
				SourceRegister: unix.NFT_REG32_00,
				SetName:        p.allowedPorts.Name,
				SetID:          p.allowedPorts.ID,
				Invert:         true,
			},
			&expr.Verdict{Kind: expr.VerdictDrop},
		},
	})
	log.Info("Added port_filter drop rule")

	// Commit all changes.
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit initial configuration")
		return fmt.Errorf("failed to commit initial configuration: %v", err)
	}
	log.Info("Initial configuration committed successfully")
	return nil
}

// EnsureEgressSNAT adds the pod_svc entry (podIP → svcIP) consulted by the
// egress_snat chain. If podIP is already mapped to another service, that stale
// entry is dropped first: a pod IP can only stand for one service IP.
//
// Programmed on every node, see ProxyProcessor.EnsureEgressSNAT.
func (p *NFTProxyProcessor) EnsureEgressSNAT(svcIP, podIP string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Ensuring egress SNAT", "svcIP", svcIP, "podIP", podIP)

	parsedSvcIP, parsedPodIP, err := parsePair(svcIP, podIP)
	if err != nil {
		return err
	}

	podSvcElems, err := p.conn.GetSetElements(p.podSvcMap)
	if err != nil {
		log.Error(err, "Failed to get pod_svc map elements")
		return fmt.Errorf("failed to get pod_svc map elements: %v", err)
	}
	for _, el := range podSvcElems {
		if !bytes.Equal(el.Key, parsedPodIP) {
			continue
		}
		if !bytes.Equal(el.Val, parsedSvcIP) {
			log.Info("Updating egress SNAT for pod", "podIP", podIP,
				"oldSvcIP", net.IP(el.Val).String(), "newSvcIP", svcIP)
			if err := p.conn.SetDeleteElements(p.podSvcMap, []nftables.SetElement{{Key: parsedPodIP, Val: el.Val}}); err != nil {
				log.Error(err, "Failed to delete stale pod_svc mapping", "podIP", podIP)
				return fmt.Errorf("failed to delete stale pod_svc mapping: %v", err)
			}
			// Commit the removal on its own. Sharing the batch with the
			// addition below would let an element that is already gone abort
			// the addition too, and nothing retries it.
			if err := p.flushTolerateENOENT("EnsureEgressSNAT conflict removal"); err != nil {
				log.Error(err, "Failed to commit stale pod_svc removal", "podIP", podIP)
				return fmt.Errorf("failed to commit stale pod_svc removal: %v", err)
			}
		}
		break
	}

	if err := p.conn.SetAddElements(p.podSvcMap, []nftables.SetElement{{Key: parsedPodIP, Val: parsedSvcIP}}); err != nil {
		log.Error(err, "Failed to add mapping to pod_svc", "podIP", podIP, "svcIP", svcIP)
		return fmt.Errorf("failed to add mapping to pod_svc: %v", err)
	}
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit egress SNAT changes")
		return fmt.Errorf("failed to commit egress SNAT changes: %v", err)
	}
	log.Info("Egress SNAT ensured successfully", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// DeleteEgressSNAT removes the pod_svc entry for the pair. An entry that is
// already gone is not an error.
func (p *NFTProxyProcessor) DeleteEgressSNAT(svcIP, podIP string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Deleting egress SNAT", "svcIP", svcIP, "podIP", podIP)

	parsedSvcIP, parsedPodIP, err := parsePair(svcIP, podIP)
	if err != nil {
		return err
	}

	if err := p.conn.SetDeleteElements(p.podSvcMap, []nftables.SetElement{
		{Key: parsedPodIP, Val: parsedSvcIP},
	}); err != nil {
		log.Error(err, "Failed to delete mapping from pod_svc", "podIP", podIP, "svcIP", svcIP)
		return fmt.Errorf("failed to delete mapping from pod_svc: %v", err)
	}
	if err := p.flushTolerateENOENT("DeleteEgressSNAT"); err != nil {
		log.Error(err, "Failed to commit egress SNAT deletion")
		return fmt.Errorf("failed to commit egress SNAT deletion: %v", err)
	}
	log.Info("Egress SNAT deleted successfully", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// EnsureIngressDNAT adds the svc_pod entry (svcIP → podIP) consulted by the
// ingress_dnat chain. If svcIP is already mapped to another pod — a migrated
// VM, a replaced backend — that stale entry is dropped first.
//
// Programmed only by the node hosting the backend, see
// ProxyProcessor.EnsureIngressDNAT.
func (p *NFTProxyProcessor) EnsureIngressDNAT(svcIP, podIP string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Ensuring ingress DNAT", "svcIP", svcIP, "podIP", podIP)

	parsedSvcIP, parsedPodIP, err := parsePair(svcIP, podIP)
	if err != nil {
		return err
	}

	svcPodElems, err := p.conn.GetSetElements(p.svcPodMap)
	if err != nil {
		log.Error(err, "Failed to get svc_pod map elements")
		return fmt.Errorf("failed to get svc_pod map elements: %v", err)
	}
	for _, el := range svcPodElems {
		if !bytes.Equal(el.Key, parsedSvcIP) {
			continue
		}
		if !bytes.Equal(el.Val, parsedPodIP) {
			log.Info("Updating ingress DNAT for svc", "svcIP", svcIP,
				"oldPodIP", net.IP(el.Val).String(), "newPodIP", podIP)
			if err := p.conn.SetDeleteElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: el.Val}}); err != nil {
				log.Error(err, "Failed to delete stale svc_pod mapping", "svcIP", svcIP)
				return fmt.Errorf("failed to delete stale svc_pod mapping: %v", err)
			}
			// Commit the removal on its own, see EnsureEgressSNAT.
			if err := p.flushTolerateENOENT("EnsureIngressDNAT conflict removal"); err != nil {
				log.Error(err, "Failed to commit stale svc_pod removal", "svcIP", svcIP)
				return fmt.Errorf("failed to commit stale svc_pod removal: %v", err)
			}
		}
		break
	}

	if err := p.conn.SetAddElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: parsedPodIP}}); err != nil {
		log.Error(err, "Failed to add mapping to svc_pod", "svcIP", svcIP, "podIP", podIP)
		return fmt.Errorf("failed to add mapping to svc_pod: %v", err)
	}
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit ingress DNAT changes")
		return fmt.Errorf("failed to commit ingress DNAT changes: %v", err)
	}
	log.Info("Ingress DNAT ensured successfully", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// DeleteIngressDNAT removes the svc_pod entry for the pair. An entry that is
// already gone is not an error.
func (p *NFTProxyProcessor) DeleteIngressDNAT(svcIP, podIP string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Deleting ingress DNAT", "svcIP", svcIP, "podIP", podIP)

	parsedSvcIP, parsedPodIP, err := parsePair(svcIP, podIP)
	if err != nil {
		return err
	}

	if err := p.conn.SetDeleteElements(p.svcPodMap, []nftables.SetElement{
		{Key: parsedSvcIP, Val: parsedPodIP},
	}); err != nil {
		log.Error(err, "Failed to delete mapping from svc_pod", "svcIP", svcIP, "podIP", podIP)
		return fmt.Errorf("failed to delete mapping from svc_pod: %v", err)
	}
	if err := p.flushTolerateENOENT("DeleteIngressDNAT"); err != nil {
		log.Error(err, "Failed to commit ingress DNAT deletion")
		return fmt.Errorf("failed to commit ingress DNAT deletion: %v", err)
	}
	log.Info("Ingress DNAT deleted successfully", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// parsePair validates a (svcIP, podIP) pair and returns both as IPv4 bytes.
func parsePair(svcIP, podIP string) (net.IP, net.IP, error) {
	parsedSvcIP := net.ParseIP(svcIP).To4()
	if parsedSvcIP == nil {
		return nil, nil, fmt.Errorf("invalid svcIP: %s", svcIP)
	}
	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return nil, nil, fmt.Errorf("invalid podIP: %s", podIP)
	}
	return parsedSvcIP, parsedPodIP, nil
}

// flushTolerateENOENT commits the pending batch and treats ENOENT as success.
//
// Deleting a set element that is already gone reports ENOENT, which fails the
// whole flush. Deletions must therefore be committed on their own, so a stale
// element cannot mask a genuine failure among the additions that would
// otherwise share the batch.
// Note on detection: the errno travels as an *netlink.OpError wrapping a
// syscall.Errno, which errors.Is unwraps, and that is the path taken when the
// kernel refuses a batch. github.com/google/nftables v0.3.0 has one branch in
// receiveAckAware that formats a trailing error ack with %v instead of wrapping
// it, and an ENOENT arriving that way reads as an ordinary failure. v0.3.0 is
// the latest release, so the caller is returned an error in that case rather
// than silently continuing — which is the safe direction.
func (p *NFTProxyProcessor) flushTolerateENOENT(op string) error {
	err := p.conn.Flush()
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ENOENT) {
		log.Info("Ignoring ENOENT on flush — element already gone", "op", op)
		return nil
	}
	return err
}

// deleteElementsTolerant removes elements from a set, falling back to one
// commit per element when a batched commit reports that one of them is gone.
//
// A flush is a single nftables transaction: one missing element aborts every
// other deletion queued with it. Tolerating that ENOENT on the batch would
// report success while removing nothing, leaving exactly the stale state the
// purge exists to clear — which is how a node can keep entries belonging to a
// scope it no longer programs. Retrying per element skips only the ones that
// really are gone.
func (p *NFTProxyProcessor) deleteElementsTolerant(m *nftables.Set, elems []nftables.SetElement, op string) error {
	if len(elems) == 0 {
		return nil
	}

	if err := p.conn.SetDeleteElements(m, elems); err != nil {
		return fmt.Errorf("failed to queue deletions for %s: %v", m.Name, err)
	}
	err := p.conn.Flush()
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("failed to commit deletions for %s: %v", m.Name, err)
	}

	log.Info("Batched deletion hit ENOENT, retrying element by element",
		"op", op, "set", m.Name, "elements", len(elems))
	removed := 0
	for _, el := range elems {
		if err := p.conn.SetDeleteElements(m, []nftables.SetElement{el}); err != nil {
			return fmt.Errorf("failed to queue deletion for %s: %v", m.Name, err)
		}
		if err := p.conn.Flush(); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue // already gone, nothing to do
			}
			return fmt.Errorf("failed to commit deletion for %s: %v", m.Name, err)
		}
		removed++
	}
	log.Info("Element-by-element deletion completed",
		"op", op, "set", m.Name, "removed", removed, "alreadyGone", len(elems)-removed)
	return nil
}

// CleanupRules reconciles both NAT maps against the desired state.
//
// keepEgress and keepIngress both map service IP → pod IP. They differ in
// scope, which is the whole point: pod_svc must carry every managed service so
// a reply reaching this node over the overlay still gets its source rewritten,
// while svc_pod must carry only the backends hosted here so no other node
// translates a destination before the packet has left.
//
// Anything present in a map but absent from its keep set is removed, which is
// what purges state inherited from a build that scoped the two maps alike.
func (p *NFTProxyProcessor) CleanupRules(keepEgress, keepIngress map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Starting CleanupRules", "keepEgress", keepEgress, "keepIngress", keepIngress)

	// --- Step 1: collect what has to change in both maps ---

	// pod_svc is keyed by pod IP, so the desired state is keepEgress inverted.
	desiredPodSvc := make(map[string]string, len(keepEgress)) // pod → svc
	for svc, pod := range keepEgress {
		desiredPodSvc[pod] = svc
	}

	podSvcDel, podSvcAdd, err := p.diffMap(p.podSvcMap, desiredPodSvc)
	if err != nil {
		return fmt.Errorf("failed to diff pod_svc: %v", err)
	}
	svcPodDel, svcPodAdd, err := p.diffMap(p.svcPodMap, keepIngress)
	if err != nil {
		return fmt.Errorf("failed to diff svc_pod: %v", err)
	}

	// --- Step 2: commit the deletions on their own ---
	//
	// An element that is already gone fails the flush, and a shared batch
	// would report that as a cleanup failure, aborting the controller at
	// startup.
	if len(podSvcDel) > 0 || len(svcPodDel) > 0 {
		if err := p.deleteElementsTolerant(p.podSvcMap, podSvcDel, "CleanupRules"); err != nil {
			log.Error(err, "Failed to delete stale mappings from pod_svc")
			return err
		}
		if err := p.deleteElementsTolerant(p.svcPodMap, svcPodDel, "CleanupRules"); err != nil {
			log.Error(err, "Failed to delete stale mappings from svc_pod")
			return err
		}
		log.Info("Stale mappings removed", "podSvc", len(podSvcDel), "svcPod", len(svcPodDel))
	} else {
		log.Info("No stale mappings found in maps")
	}

	// --- Step 3: add whatever is missing ---
	if len(podSvcAdd) > 0 {
		if err := p.conn.SetAddElements(p.podSvcMap, podSvcAdd); err != nil {
			log.Error(err, "Failed to add missing mappings to pod_svc")
			return fmt.Errorf("failed to add missing mappings to pod_svc: %v", err)
		}
	}
	if len(svcPodAdd) > 0 {
		if err := p.conn.SetAddElements(p.svcPodMap, svcPodAdd); err != nil {
			log.Error(err, "Failed to add missing mappings to svc_pod")
			return fmt.Errorf("failed to add missing mappings to svc_pod: %v", err)
		}
	}

	// Startup cleanup must not be fatal: aborting here takes the whole
	// DaemonSet pod down and leaves the node's datapath half-programmed, while
	// the reconcile loop would have converged on the next event anyway.
	// Additions are committed strictly: an ENOENT on an addition-only batch
	// means the table or the set is gone, so tolerating it would report a
	// successful reconciliation with nothing installed.
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit cleanup changes")
		return fmt.Errorf("failed to commit cleanup changes: %v", err)
	}
	log.Info("CleanupRules completed successfully",
		"podSvcAdded", len(podSvcAdd), "svcPodAdded", len(svcPodAdd))
	return nil
}

// diffMap compares one nft map against its desired state and returns the
// elements to delete and to add. Both the map and desired are read in the
// map's own key → value direction.
func (p *NFTProxyProcessor) diffMap(m *nftables.Set, desired map[string]string) (del, add []nftables.SetElement, err error) {
	elems, err := p.conn.GetSetElements(m)
	if err != nil {
		log.Error(err, "Failed to get map elements", "map", m.Name)
		return nil, nil, fmt.Errorf("failed to get %s elements: %v", m.Name, err)
	}

	current := make(map[string]string, len(elems))
	for _, el := range elems {
		key := net.IP(el.Key).String()
		val := net.IP(el.Val).String()
		current[key] = val
		if want, ok := desired[key]; !ok || want != val {
			log.Info("Marking stale mapping for deletion", "map", m.Name, "key", key, "value", val)
			del = append(del, nftables.SetElement{Key: el.Key, Val: el.Val})
		}
	}

	for key, val := range desired {
		if cur, ok := current[key]; ok && cur == val {
			continue
		}
		parsedKey := net.ParseIP(key).To4()
		parsedVal := net.ParseIP(val).To4()
		if parsedKey == nil || parsedVal == nil {
			log.Error(nil, "Invalid IP in desired state", "map", m.Name, "key", key, "value", val)
			continue
		}
		log.Info("Adding missing mapping", "map", m.Name, "key", key, "value", val)
		add = append(add, nftables.SetElement{Key: parsedKey, Val: parsedVal})
	}
	return del, add, nil
}

// EnsurePortFilter installs ingress port filtering rules for the given
// (svcIP, podIP) pair. The actual nft set keys are pod IPs, because the
// port_filter chain runs at priority filter (0), after ingress_dnat has
// rewritten daddr from svcIP to podIP. The given ports are the only ones
// permitted on the post-DNAT pod IP; all other traffic destined to that
// pod IP is dropped. Idempotent.
func (p *NFTProxyProcessor) EnsurePortFilter(svcIP, podIP string, ports []corev1.ServicePort) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Empty ports list is documented as equivalent to DeletePortFilter:
	// the caller wants to disable filtering for this pod entirely. Without
	// this short-circuit we would add the pod to filtered_pods with no
	// matching allowed_ports entries, which would drop every ingress packet
	// to the pod IP — the opposite of "no filter".
	if len(ports) == 0 {
		return p.deletePortFilterLocked(svcIP, podIP)
	}
	log.Info("Ensuring port filter", "svcIP", svcIP, "podIP", podIP, "portCount", len(ports))

	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return fmt.Errorf("invalid podIP: %s", podIP)
	}

	// 1. Remove any pre-existing entries in allowed_ports for podIP so we can
	// rebuild the tuple set cleanly (idempotent). Committed on its own: an
	// element that is already gone would otherwise abort the additions below
	// in the same transaction, leaving the pod in filtered_pods with no
	// allowed port — every packet to it dropped.
	if err := p.removeAllowedPortsForPod(parsedPodIP); err != nil {
		return err
	}
	if err := p.flushTolerateENOENT("EnsurePortFilter port rebuild"); err != nil {
		return fmt.Errorf("failed to commit allowed_ports rebuild for pod %s: %v", podIP, err)
	}

	// 2. Add podIP to filtered_pods (idempotent — Add ignores duplicates).
	if err := p.conn.SetAddElements(p.filteredPods, []nftables.SetElement{{Key: parsedPodIP}}); err != nil {
		return fmt.Errorf("failed to add %s to filtered_pods: %v", podIP, err)
	}

	// 3. Accumulate allowed (podIP, proto, port) tuples and add them in a single batch.
	var elements []nftables.SetElement
	for _, sp := range ports {
		var protoByte byte
		switch sp.Protocol {
		case corev1.ProtocolTCP, "":
			protoByte = unix.IPPROTO_TCP
		case corev1.ProtocolUDP:
			protoByte = unix.IPPROTO_UDP
		default:
			log.Info("Skipping unsupported protocol for port filter",
				"podIP", podIP, "protocol", sp.Protocol)
			continue
		}
		elements = append(elements, nftables.SetElement{Key: concatPortKey(parsedPodIP, protoByte, uint16(sp.Port))})
	}
	if len(elements) > 0 {
		if err := p.conn.SetAddElements(p.allowedPorts, elements); err != nil {
			return fmt.Errorf("failed to add port tuples to allowed_ports for pod %s: %v", podIP, err)
		}
	}

	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush EnsurePortFilter: %v", err)
	}
	log.Info("Port filter ensured", "svcIP", svcIP, "podIP", podIP, "ports", ports)
	return nil
}

// DeletePortFilter removes podIP from filtered_pods and clears any allowed
// port entries for it. svcIP is used only for logging context. Tolerates
// ENOENT for clean idempotency.
func (p *NFTProxyProcessor) DeletePortFilter(svcIP, podIP string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.deletePortFilterLocked(svcIP, podIP)
}

// deletePortFilterLocked is DeletePortFilter without the lock, for callers
// that already hold it. sync.Mutex is not reentrant, so EnsurePortFilter must
// come through here rather than calling the exported method.
func (p *NFTProxyProcessor) deletePortFilterLocked(svcIP, podIP string) error {
	log.Info("Deleting port filter", "svcIP", svcIP, "podIP", podIP)
	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return fmt.Errorf("invalid podIP: %s", podIP)
	}
	if err := p.removeAllowedPortsForPod(parsedPodIP); err != nil {
		return err
	}
	if err := p.conn.SetDeleteElements(p.filteredPods, []nftables.SetElement{{Key: parsedPodIP}}); err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("failed to delete %s from filtered_pods: %v", podIP, err)
		}
	}
	if err := p.conn.Flush(); err != nil {
		if errors.Is(err, unix.ENOENT) {
			log.Info("DeletePortFilter ENOENT on flush — already gone", "podIP", podIP)
			return nil
		}
		return fmt.Errorf("failed to flush DeletePortFilter: %v", err)
	}
	log.Info("Port filter deleted", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// CleanupPortFilters reconciles port_filter state with the desired snapshot.
// The keep map is keyed by svcIP (for caller convenience) but the on-disk
// nft set keys are pod IPs. The implementation is a single-pass diff: it
// fetches current state once, computes additions and removals in memory,
// batches SetAddElements / SetDeleteElements per set, and Flushes exactly
// once.
func (p *NFTProxyProcessor) CleanupPortFilters(keep map[string]PortFilterEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Starting CleanupPortFilters", "keepCount", len(keep))

	// 1. Build desired state in memory.
	desiredPods := make(map[string]bool, len(keep))
	desiredPortKeys := make(map[string][]byte) // hex(key) → key (byte slice)
	for _, entry := range keep {
		parsedPodIP := net.ParseIP(entry.PodIP).To4()
		if parsedPodIP == nil {
			log.Info("Skipping invalid podIP in cleanup keep map", "podIP", entry.PodIP)
			continue
		}
		desiredPods[entry.PodIP] = true
		for _, sp := range entry.Ports {
			var protoByte byte
			switch sp.Protocol {
			case corev1.ProtocolTCP, "":
				protoByte = unix.IPPROTO_TCP
			case corev1.ProtocolUDP:
				protoByte = unix.IPPROTO_UDP
			default:
				continue
			}
			key := concatPortKey(parsedPodIP, protoByte, uint16(sp.Port))
			desiredPortKeys[fmt.Sprintf("%x", key)] = key
		}
	}

	// 2. Fetch current state.
	currentPods, err := p.conn.GetSetElements(p.filteredPods)
	if err != nil {
		return fmt.Errorf("failed to list filtered_pods: %v", err)
	}
	currentPorts, err := p.conn.GetSetElements(p.allowedPorts)
	if err != nil {
		return fmt.Errorf("failed to list allowed_ports: %v", err)
	}

	// 3. Compute additions / removals.
	var addPods, delPods []nftables.SetElement
	var addPorts, delPorts []nftables.SetElement
	seenPods := make(map[string]bool, len(currentPods))
	for _, el := range currentPods {
		ipStr := net.IP(el.Key).String()
		seenPods[ipStr] = true
		if !desiredPods[ipStr] {
			delPods = append(delPods, nftables.SetElement{Key: el.Key})
		}
	}
	for podIPStr := range desiredPods {
		if !seenPods[podIPStr] {
			parsed := net.ParseIP(podIPStr).To4()
			if parsed == nil {
				continue
			}
			addPods = append(addPods, nftables.SetElement{Key: parsed})
		}
	}
	seenPorts := make(map[string]bool, len(currentPorts))
	for _, el := range currentPorts {
		keyHex := fmt.Sprintf("%x", el.Key)
		seenPorts[keyHex] = true
		if _, want := desiredPortKeys[keyHex]; !want {
			delPorts = append(delPorts, nftables.SetElement{Key: el.Key})
		}
	}
	for keyHex, key := range desiredPortKeys {
		if !seenPorts[keyHex] {
			addPorts = append(addPorts, nftables.SetElement{Key: key})
		}
	}

	// 4. Batch ops. Deletions are committed first and on their own, so an
	// element that is already gone cannot fail the batch carrying the
	// additions below.
	if err := p.deleteElementsTolerant(p.filteredPods, delPods, "CleanupPortFilters"); err != nil {
		return err
	}
	if err := p.deleteElementsTolerant(p.allowedPorts, delPorts, "CleanupPortFilters"); err != nil {
		return err
	}
	if len(addPods) > 0 {
		if err := p.conn.SetAddElements(p.filteredPods, addPods); err != nil {
			return fmt.Errorf("failed to add filtered_pods: %v", err)
		}
	}
	if len(addPorts) > 0 {
		if err := p.conn.SetAddElements(p.allowedPorts, addPorts); err != nil {
			return fmt.Errorf("failed to add allowed_ports: %v", err)
		}
	}

	// 5. Commit the additions strictly: an ENOENT here means the table or the
	// set is missing, not that an element was already gone. The caller keeps
	// startup non-fatal.
	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush CleanupPortFilters: %v", err)
	}
	log.Info("CleanupPortFilters completed",
		"addedPods", len(addPods), "removedPods", len(delPods),
		"addedPorts", len(addPorts), "removedPorts", len(delPorts))
	return nil
}

// concatPortKey returns the bytes for a (ipv4 . proto . port) concat set key.
// nftables packs each component to 4-byte-aligned slots: 4 + 4 + 4 = 12 bytes.
// proto goes in the low byte of slot 1, port goes in the first 2 bytes
// (big-endian) of slot 2.
func concatPortKey(ipv4 net.IP, proto byte, port uint16) []byte {
	key := make([]byte, 12)
	copy(key[0:4], ipv4.To4())
	key[4] = proto
	// bytes 5,6,7 stay zero (padding)
	key[8] = byte(port >> 8)
	key[9] = byte(port & 0xff)
	// bytes 10,11 stay zero (padding)
	return key
}

// removeAllowedPortsForPod deletes all allowed_ports entries whose key prefix
// matches parsedPodIP. Used to make EnsurePortFilter idempotent.
func (p *NFTProxyProcessor) removeAllowedPortsForPod(parsedPodIP net.IP) error {
	elems, err := p.conn.GetSetElements(p.allowedPorts)
	if err != nil {
		return fmt.Errorf("failed to list allowed_ports: %v", err)
	}
	var toDel []nftables.SetElement
	for _, el := range elems {
		if len(el.Key) >= 4 && bytes.Equal(el.Key[:4], parsedPodIP.To4()) {
			toDel = append(toDel, nftables.SetElement{Key: el.Key})
		}
	}
	if len(toDel) > 0 {
		if err := p.conn.SetDeleteElements(p.allowedPorts, toDel); err != nil {
			return fmt.Errorf("failed to delete stale allowed_ports for pod: %v", err)
		}
	}
	return nil
}

// EnsureICMPAllow adds podIP to the icmp_allowed_pods set so that ICMP
// traffic to that pod IP bypasses the port_filter drop rule. svcIP is used
// only for logging context. Idempotent.
func (p *NFTProxyProcessor) EnsureICMPAllow(svcIP, podIP string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Ensuring ICMP allow", "svcIP", svcIP, "podIP", podIP)
	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return fmt.Errorf("invalid podIP: %s", podIP)
	}
	if err := p.conn.SetAddElements(p.icmpAllowedPods, []nftables.SetElement{{Key: parsedPodIP}}); err != nil {
		return fmt.Errorf("failed to add %s to icmp_allowed_pods: %v", podIP, err)
	}
	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush EnsureICMPAllow: %v", err)
	}
	log.Info("ICMP allow ensured", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// DeleteICMPAllow removes podIP from icmp_allowed_pods. Tolerates ENOENT for
// clean idempotency. svcIP is used only for logging context.
func (p *NFTProxyProcessor) DeleteICMPAllow(svcIP, podIP string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Deleting ICMP allow", "svcIP", svcIP, "podIP", podIP)
	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return fmt.Errorf("invalid podIP: %s", podIP)
	}
	if err := p.conn.SetDeleteElements(p.icmpAllowedPods, []nftables.SetElement{{Key: parsedPodIP}}); err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("failed to delete %s from icmp_allowed_pods: %v", podIP, err)
		}
	}
	if err := p.conn.Flush(); err != nil {
		if errors.Is(err, unix.ENOENT) {
			log.Info("DeleteICMPAllow ENOENT on flush — already gone", "podIP", podIP)
			return nil
		}
		return fmt.Errorf("failed to flush DeleteICMPAllow: %v", err)
	}
	log.Info("ICMP allow deleted", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// CleanupICMPAllow reconciles icmp_allowed_pods with the desired snapshot.
// keep is keyed by svcIP (caller convenience); the value is the podIP that
// must remain in the set. Single-pass diff with one Flush, mirroring
// CleanupPortFilters.
func (p *NFTProxyProcessor) CleanupICMPAllow(keep map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Info("Starting CleanupICMPAllow", "keepCount", len(keep))

	desired := make(map[string]bool, len(keep))
	for _, podIP := range keep {
		if net.ParseIP(podIP).To4() == nil {
			log.Info("Skipping invalid podIP in ICMP cleanup keep map", "podIP", podIP)
			continue
		}
		desired[podIP] = true
	}

	current, err := p.conn.GetSetElements(p.icmpAllowedPods)
	if err != nil {
		return fmt.Errorf("failed to list icmp_allowed_pods: %v", err)
	}

	var addPods, delPods []nftables.SetElement
	seen := make(map[string]bool, len(current))
	for _, el := range current {
		ipStr := net.IP(el.Key).String()
		seen[ipStr] = true
		if !desired[ipStr] {
			delPods = append(delPods, nftables.SetElement{Key: el.Key})
		}
	}
	for podIPStr := range desired {
		if !seen[podIPStr] {
			parsed := net.ParseIP(podIPStr).To4()
			if parsed == nil {
				continue
			}
			addPods = append(addPods, nftables.SetElement{Key: parsed})
		}
	}

	if err := p.deleteElementsTolerant(p.icmpAllowedPods, delPods, "CleanupICMPAllow"); err != nil {
		return err
	}
	if len(addPods) > 0 {
		if err := p.conn.SetAddElements(p.icmpAllowedPods, addPods); err != nil {
			return fmt.Errorf("failed to add icmp_allowed_pods: %v", err)
		}
	}

	// Additions committed strictly, see CleanupPortFilters.
	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("failed to flush CleanupICMPAllow: %v", err)
	}
	log.Info("CleanupICMPAllow completed",
		"addedPods", len(addPods), "removedPods", len(delPods))
	return nil
}

// Compile-time assertion that NFTProxyProcessor satisfies ProxyProcessor.
var _ ProxyProcessor = (*NFTProxyProcessor)(nil)
