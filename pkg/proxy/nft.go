package proxy

import (
	"bytes"
	"errors"
	"fmt"
	"net"

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
	conn *nftables.Conn

	// Table "cozy_proxy" will contain all objects.
	table *nftables.Table

	// IP-only NAT objects.
	podSvcMap *nftables.Set // Map "pod_svc": maps pod IP → svc IP.
	svcPodMap *nftables.Set // Map "svc_pod": maps svc IP → pod IP.

	// Port-filtering objects (post-DNAT, key on pod IP).
	filteredPods *nftables.Set   // set of pod IPs subject to port filtering.
	allowedPorts *nftables.Set   // concat set: (ipv4_addr . inet_proto . inet_service).
	portFilterCh *nftables.Chain // chain "port_filter" running post-conntrack and post-early_snat.
}

// InitRules initializes the nftables configuration in a single table "cozy_proxy".
// It flushes the entire ruleset, then re-creates the table with the desired sets, maps, and chains.
func (p *NFTProxyProcessor) InitRules() error {
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
	// Keyed on pod IP because port_filter runs after early_snat has rewritten
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

	// --- Delete Chains ---
	chains, _ := p.conn.ListChains()
	for _, chain := range chains {
		if chain.Table.Name == p.table.Name {
			p.conn.DelChain(chain)
		}
	}

	// --- Create Chains ---
	// port_filter runs at priority filter (0), AFTER early_snat (-300) and
	// AFTER conntrack (-200). At this priority, daddr has been rewritten from
	// LB IP to pod IP by early_snat, so the filter matches on pod IP. The
	// "ct state established,related accept" rule below now works correctly
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

	// --- port_filter rule ---
	// Equivalent to:
	//   ip daddr @filtered_pods ip daddr . meta l4proto . th dport != @allowed_ports drop
	//
	// At priority filter (0), daddr has been rewritten by early_snat from the
	// LB IP to the pod IP. Both the gate set (filtered_pods) and the
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
				Offset:       16, // IPv4 daddr (post-early_snat: pod IP)
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

// EnsureRules ensures that a one-to-one mapping exists between svcIP and podIP.
// If a mapping already exists for svcIP with a different podIP,
// the old mapping is removed (from svc_pod, pod_svc, and from the raw pod set)
// before the new mapping is added.
func (p *NFTProxyProcessor) EnsureRules(svcIP, podIP string) error {
	log.Info("Ensuring NAT mapping", "svcIP", svcIP, "podIP", podIP)

	parsedSvcIP := net.ParseIP(svcIP).To4()
	if parsedSvcIP == nil {
		return fmt.Errorf("invalid svcIP: %s", svcIP)
	}
	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return fmt.Errorf("invalid podIP: %s", podIP)
	}

	// --- Remove conflicting mapping for svcIP in svc_pod map ---
	// If svcIP already maps to a different pod, remove that mapping and
	// delete the old pod from the raw pod set.
	svcPodElems, err := p.conn.GetSetElements(p.svcPodMap)
	if err != nil {
		log.Error(err, "Failed to get svc_pod map elements")
		return fmt.Errorf("failed to get svc_pod map elements: %v", err)
	}
	for _, el := range svcPodElems {
		if bytes.Equal(el.Key, parsedSvcIP) {
			// Found an existing mapping for svcIP.
			if !bytes.Equal(el.Val, parsedPodIP) {
				oldPodIP := el.Val
				log.Info("Updating mapping for svc", "svcIP", svcIP, "oldPodIP", net.IP(oldPodIP).String(), "newPodIP", podIP)
				// Remove the old mapping from svc_pod.
				if err := p.conn.SetDeleteElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: oldPodIP}}); err != nil {
					log.Error(err, "Failed to delete old svc_pod mapping", "svcIP", svcIP, "oldPodIP", net.IP(oldPodIP).String())
					return fmt.Errorf("failed to delete old svc_pod mapping: %v", err)
				}
				// Remove the corresponding mapping from pod_svc.
				if err := p.conn.SetDeleteElements(p.podSvcMap, []nftables.SetElement{{Key: oldPodIP, Val: parsedSvcIP}}); err != nil {
					log.Error(err, "Failed to delete corresponding pod_svc mapping", "oldPodIP", net.IP(oldPodIP).String(), "svcIP", svcIP)
					return fmt.Errorf("failed to delete corresponding pod_svc mapping: %v", err)
				}
			}
			break // svcIP mapping handled; exit loop.
		}
	}

	// --- Remove conflicting mapping for podIP in pod_svc map ---
	// If podIP already maps to a different svc, remove that mapping and delete the podIP
	// from the raw pod set (since the old mapping is no longer desired).
	podSvcElems, err := p.conn.GetSetElements(p.podSvcMap)
	if err != nil {
		log.Error(err, "Failed to get pod_svc map elements")
		return fmt.Errorf("failed to get pod_svc map elements: %v", err)
	}
	for _, el := range podSvcElems {
		if bytes.Equal(el.Key, parsedPodIP) {
			// Found an existing mapping for podIP.
			if !bytes.Equal(el.Val, parsedSvcIP) {
				log.Info("Updating mapping for pod", "podIP", podIP, "oldSvcIP", net.IP(el.Val).String(), "newSvcIP", svcIP)
				// Remove the old mapping from pod_svc.
				if err := p.conn.SetDeleteElements(p.podSvcMap, []nftables.SetElement{{Key: parsedPodIP, Val: el.Val}}); err != nil {
					log.Error(err, "Failed to delete old pod_svc mapping", "podIP", podIP, "oldSvcIP", net.IP(el.Val).String())
					return fmt.Errorf("failed to delete old pod_svc mapping: %v", err)
				}
				// Remove the corresponding mapping from svc_pod.
				if err := p.conn.SetDeleteElements(p.svcPodMap, []nftables.SetElement{{Key: el.Val, Val: parsedPodIP}}); err != nil {
					log.Error(err, "Failed to delete corresponding svc_pod mapping", "oldSvcIP", net.IP(el.Val).String(), "podIP", podIP)
					return fmt.Errorf("failed to delete corresponding svc_pod mapping: %v", err)
				}
			}
			break // podIP mapping handled; exit loop.
		}
	}

	// --- Add the new mapping to both maps ---
	if err := p.conn.SetAddElements(p.podSvcMap, []nftables.SetElement{{Key: parsedPodIP, Val: parsedSvcIP}}); err != nil {
		log.Error(err, "Failed to add mapping to pod_svc", "podIP", podIP, "svcIP", svcIP)
		return fmt.Errorf("failed to add mapping to pod_svc: %v", err)
	}
	if err := p.conn.SetAddElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: parsedPodIP}}); err != nil {
		log.Error(err, "Failed to add mapping to svc_pod", "svcIP", svcIP, "podIP", podIP)
		return fmt.Errorf("failed to add mapping to svc_pod: %v", err)
	}
	log.Info("Added mapping", "svcIP", svcIP, "podIP", podIP)

	// Commit all changes.
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit EnsureNAT changes")
		return fmt.Errorf("failed to commit EnsureNAT changes: %v", err)
	}
	log.Info("NAT mapping ensured successfully", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// DeleteRules removes the mapping for the given svcIP and podIP from both maps
// and commits the removal from NAT translation maps.
func (p *NFTProxyProcessor) DeleteRules(svcIP, podIP string) error {
	log.Info("Deleting NAT mapping", "svcIP", svcIP, "podIP", podIP)

	// Parse svcIP and podIP into IPv4 byte slices.
	parsedSvcIP := net.ParseIP(svcIP).To4()
	if parsedSvcIP == nil {
		return fmt.Errorf("invalid svcIP: %s", svcIP)
	}
	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return fmt.Errorf("invalid podIP: %s", podIP)
	}

	// Delete mapping from the "pod_svc" map.
	if err := p.conn.SetDeleteElements(p.podSvcMap, []nftables.SetElement{
		{Key: parsedPodIP, Val: parsedSvcIP},
	}); err != nil {
		log.Error(err, "Failed to delete mapping from pod_svc", "podIP", podIP, "svcIP", svcIP)
		return fmt.Errorf("failed to delete mapping from pod_svc: %v", err)
	}

	// Delete mapping from the "svc_pod" map.
	if err := p.conn.SetDeleteElements(p.svcPodMap, []nftables.SetElement{
		{Key: parsedSvcIP, Val: parsedPodIP},
	}); err != nil {
		log.Error(err, "Failed to delete mapping from svc_pod", "svcIP", svcIP, "podIP", podIP)
		return fmt.Errorf("failed to delete mapping from svc_pod: %v", err)
	}

	// Commit all changes.
	if err := p.conn.Flush(); err != nil {
		// Check if the error is ENOENT (no such file or directory) and ignore it.
		// This may happen if the elements or even the table were already removed.
		if errors.Is(err, unix.ENOENT) {
			log.Info("Ignoring ENOENT error during flush in DeleteRules", "error", err)
		} else {
			log.Error(err, "Failed to commit DeleteNAT changes")
			return fmt.Errorf("failed to commit DeleteNAT changes: %v", err)
		}
	}

	log.Info("NAT mapping and raw set elements deleted successfully", "svcIP", svcIP, "podIP", podIP)
	return nil
}

// CleanupRules receives a keepMap (keys: svcIP, values: podIP) representing the desired state.
// It recovers from an inconsistent state by:
// 1. Removing any mappings in the pod_svc and svc_pod maps that do not match keepMap.
// 2. Adding any missing mappings from keepMap into both maps.
// 3. Cleaning up the raw sets (pod and svc) so that only the desired IPs remain.
func (p *NFTProxyProcessor) CleanupRules(keepMap map[string]string) error {
	log.Info("Starting CleanupRules", "keepMap", keepMap)

	// --- Step 1: Clean up mapping sets ---

	// Retrieve current mappings from the pod_svc map.
	// Note: pod_svc maps pod IP → svc IP.
	podSvcElems, err := p.conn.GetSetElements(p.podSvcMap)
	if err != nil {
		log.Error(err, "Failed to get pod_svc elements")
		return fmt.Errorf("failed to get pod_svc elements: %v", err)
	}

	// Build a current mapping in svc->pod direction (for easy comparison with keepMap)
	currentMapping := make(map[string]string) // key: svc, value: pod
	for _, el := range podSvcElems {
		pod := net.IP(el.Key).String()
		svc := net.IP(el.Val).String()
		currentMapping[svc] = pod
	}

	// Prepare slices for elements to delete from both maps.
	var toDeletePodSvc []nftables.SetElement
	var toDeleteSvcPod []nftables.SetElement

	// For each mapping found in the current configuration, if it does not match the desired state, mark it for deletion.
	for svc, pod := range currentMapping {
		if expectedPod, ok := keepMap[svc]; !ok || expectedPod != pod {
			log.Info("Marking inconsistent mapping for deletion", "svcIP", svc, "podIP", pod)
			// Prepare deletion elements.
			// pod_svc: key = pod, val = svc.
			toDeletePodSvc = append(toDeletePodSvc, nftables.SetElement{
				Key: net.ParseIP(pod).To4(),
				Val: net.ParseIP(svc).To4(),
			})
			// svc_pod: key = svc, val = pod.
			toDeleteSvcPod = append(toDeleteSvcPod, nftables.SetElement{
				Key: net.ParseIP(svc).To4(),
				Val: net.ParseIP(pod).To4(),
			})
		}
	}

	// Delete any inconsistent mappings.
	if len(toDeletePodSvc) > 0 {
		if err := p.conn.SetDeleteElements(p.podSvcMap, toDeletePodSvc); err != nil {
			log.Error(err, "Failed to delete inconsistent mappings from pod_svc")
			return fmt.Errorf("failed to delete inconsistent mappings from pod_svc: %v", err)
		}
		if err := p.conn.SetDeleteElements(p.svcPodMap, toDeleteSvcPod); err != nil {
			log.Error(err, "Failed to delete inconsistent mappings from svc_pod")
			return fmt.Errorf("failed to delete inconsistent mappings from svc_pod: %v", err)
		}
		log.Info("Inconsistent mappings removed from both maps")
	} else {
		log.Info("No inconsistent mappings found in maps")
	}

	// --- Step 2: Add missing mappings from keepMap ---

	// For every desired mapping in keepMap, ensure it exists in both maps.
	for svc, pod := range keepMap {
		// Check if the current mapping for svc exists and matches.
		if existingPod, ok := currentMapping[svc]; !ok || existingPod != pod {
			parsedSvcIP := net.ParseIP(svc).To4()
			parsedPodIP := net.ParseIP(pod).To4()
			if parsedSvcIP == nil || parsedPodIP == nil {
				log.Error(nil, "Invalid IP in keepMap", "svcIP", svc, "podIP", pod)
				continue
			}
			// Add mapping to pod_svc (pod → svc)
			if err := p.conn.SetAddElements(p.podSvcMap, []nftables.SetElement{{Key: parsedPodIP, Val: parsedSvcIP}}); err != nil {
				log.Error(err, "Failed to add missing mapping to pod_svc", "podIP", pod, "svcIP", svc)
				return fmt.Errorf("failed to add missing mapping to pod_svc: %v", err)
			}
			// Add mapping to svc_pod (svc → pod)
			if err := p.conn.SetAddElements(p.svcPodMap, []nftables.SetElement{{Key: parsedSvcIP, Val: parsedPodIP}}); err != nil {
				log.Error(err, "Failed to add missing mapping to svc_pod", "svcIP", svc, "podIP", pod)
				return fmt.Errorf("failed to add missing mapping to svc_pod: %v", err)
			}
			log.Info("Added missing mapping", "svcIP", svc, "podIP", pod)
		}
	}

	// --- Final commit ---
	if err := p.conn.Flush(); err != nil {
		log.Error(err, "Failed to commit cleanup changes")
		return fmt.Errorf("failed to commit cleanup changes: %v", err)
	}
	log.Info("CleanupRules completed successfully")
	return nil
}

// EnsurePortFilter installs ingress port filtering rules for the given
// (svcIP, podIP) pair. The actual nft set keys are pod IPs, because the
// port_filter chain runs at priority filter (0), after early_snat has
// rewritten daddr from svcIP to podIP. The given ports are the only ones
// permitted on the post-DNAT pod IP; all other traffic destined to that
// pod IP is dropped. Idempotent.
func (p *NFTProxyProcessor) EnsurePortFilter(svcIP, podIP string, ports []corev1.ServicePort) error {
	log.Info("Ensuring port filter", "svcIP", svcIP, "podIP", podIP, "portCount", len(ports))

	parsedPodIP := net.ParseIP(podIP).To4()
	if parsedPodIP == nil {
		return fmt.Errorf("invalid podIP: %s", podIP)
	}

	// 1. Remove any pre-existing entries in allowed_ports for podIP so we can
	// rebuild the tuple set cleanly (idempotent).
	if err := p.removeAllowedPortsForPod(parsedPodIP); err != nil {
		return err
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

	// 4. Batch ops.
	if len(delPods) > 0 {
		if err := p.conn.SetDeleteElements(p.filteredPods, delPods); err != nil {
			return fmt.Errorf("failed to delete stale filtered_pods: %v", err)
		}
	}
	if len(delPorts) > 0 {
		if err := p.conn.SetDeleteElements(p.allowedPorts, delPorts); err != nil {
			return fmt.Errorf("failed to delete stale allowed_ports: %v", err)
		}
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

	// 5. Single flush.
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

// Compile-time assertion that NFTProxyProcessor satisfies ProxyProcessor.
var _ ProxyProcessor = (*NFTProxyProcessor)(nil)
