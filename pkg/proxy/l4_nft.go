package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"

	"github.com/cozystack/cozy-proxy/pkg/l4"
)

// L4TableName is the table of the L4 LoadBalancer mode. It is separate from
// the VM mode's "cozy_proxy" table, which it never touches, so deleting it
// removes the L4 mode entirely.
const L4TableName = "cozy_proxy_l4"

// Chain priorities of the L4 mode. See docs/rfc/l4-loadbalancer-mode.md for how
// they interleave with the VM mode's chains.
var (
	// After conntrack (-200) and the VM mode's ingress_dnat (-150), before
	// the DNAT below.
	l4GuardPriority = nftables.ChainPriorityRef(*nftables.ChainPriorityMangle + 10)
	// Just before the iptables / kube-ovn nat hooks (-100), which then see the
	// translated packet.
	l4DNATPriority = nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest - 5)
	l4MasqPriority = nftables.ChainPriorityRef(*nftables.ChainPriorityNATSource - 5)
)

// ipsDstNAT is IPS_DST_NAT from linux/netfilter/nf_conntrack_common.h: the
// conntrack status bit set once a flow has been destination-NATed.
const ipsDstNAT = 1 << 5

// NFTL4Datapath programs the L4 mode's table with nftables.
//
// Every Sync rebuilds the table as a whole in a single transaction: the table
// is small, nftables applies a batch atomically — a packet sees the old or the
// new ruleset, never a mix — and conntrack entries are not tied to rules. There
// is no incremental diff to get wrong and no stale element to collect, and a
// retry is just the next Sync.
type NFTL4Datapath struct {
	mu sync.Mutex

	// ConnOptions are passed to every netlink connection. Tests use them to
	// work in a scratch network namespace.
	ConnOptions []nftables.ConnOption
}

// Sync replaces the L4 table with the given state.
func (d *NFTL4Datapath) Sync(st l4.State) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	conn, err := nftables.New(d.ConnOptions...)
	if err != nil {
		return fmt.Errorf("could not create nftables connection: %w", err)
	}

	t := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: L4TableName}
	// Adding the table first makes the deletion valid when it does not exist
	// yet, all within the one transaction.
	conn.AddTable(t)
	conn.DelTable(t)
	t = conn.AddTable(t)

	if err := buildL4Table(conn, t, st); err != nil {
		return err
	}
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to commit table %s: %w", L4TableName, err)
	}
	return nil
}

// Teardown removes the L4 table, if any. It is how the mode is switched off.
func (d *NFTL4Datapath) Teardown() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	conn, err := nftables.New(d.ConnOptions...)
	if err != nil {
		return fmt.Errorf("could not create nftables connection: %w", err)
	}

	t := &nftables.Table{Family: nftables.TableFamilyIPv4, Name: L4TableName}
	conn.AddTable(t)
	conn.DelTable(t)
	if err := conn.Flush(); err != nil {
		return fmt.Errorf("failed to delete table %s: %w", L4TableName, err)
	}
	return nil
}

// buildL4Table queues the sets, maps, chains and rules for st into t.
//
//	set vips      { type ipv4_addr }                                  all VIPs, every node
//	set vip_ports { type ipv4_addr . inet_proto . inet_service }      declared ports, every node
//	set node_ips  { type ipv4_addr }                                  masqueraded sources
//	set backends  { type ipv4_addr . inet_proto . inet_service }      local targets, announcer
//	map backends-<vip>-<proto>-<port> { type integer : ipv4_addr . inet_service }
//
//	chain guard  filter prerouting mangle+10
//	  ct state established,related accept
//	  ip daddr @vips ip daddr . meta l4proto . th dport != @vip_ports drop
//	chain translate  nat prerouting dstnat-5  (rules on the announcer only)
//	  ip daddr V tcp dport P dnat ip addr . port to numgen inc mod N map @backends-...
//	  ip daddr V tcp dport P drop             (announced port with no local backend)
//	chain masq   nat postrouting srcnat-5
//	  ct status dnat ip saddr @node_ips ip daddr . meta l4proto . th dport @backends masquerade fully-random
func buildL4Table(conn *nftables.Conn, t *nftables.Table, st l4.State) error {
	var ids setIDs
	vips := &nftables.Set{Table: t, ID: ids.next(), Name: "vips", KeyType: nftables.TypeIPAddr}
	if err := conn.AddSet(vips, addrElements(st.VIPs)); err != nil {
		return fmt.Errorf("could not add set %s: %w", vips.Name, err)
	}

	portKeyType, err := nftables.ConcatSetType(nftables.TypeIPAddr, nftables.TypeInetProto, nftables.TypeInetService)
	if err != nil {
		return fmt.Errorf("could not build vip_ports key type: %w", err)
	}
	vipPorts := &nftables.Set{Table: t, ID: ids.next(), Name: "vip_ports", KeyType: portKeyType, Concatenation: true}
	var portElems []nftables.SetElement
	for _, pk := range st.Ports {
		portElems = append(portElems, nftables.SetElement{
			Key: concatPortKey(net.IP(pk.VIP.AsSlice()), protoByte(pk.Protocol), pk.Port),
		})
	}
	if err := conn.AddSet(vipPorts, portElems); err != nil {
		return fmt.Errorf("could not add set %s: %w", vipPorts.Name, err)
	}

	nodeIPs := &nftables.Set{Table: t, ID: ids.next(), Name: "node_ips", KeyType: nftables.TypeIPAddr}
	if err := conn.AddSet(nodeIPs, addrElements(st.NodeIPs)); err != nil {
		return fmt.Errorf("could not add set %s: %w", nodeIPs.Name, err)
	}

	// The translation targets, for the masquerade below to recognize the
	// flows this table translated. Matching the flow's original destination
	// instead ("ct original ip daddr @vips") is what nft itself would write,
	// but github.com/google/nftables v0.3.0 can only emit it with the generic
	// conntrack key, which nft then fails to decode: "nft list" aborts on the
	// whole ruleset, which is too high a price for every operator on the node.
	backends := &nftables.Set{Table: t, ID: ids.next(), Name: "backends", KeyType: portKeyType, Concatenation: true}
	var backendElems []nftables.SetElement
	seen := map[l4.Backend]bool{}
	for _, r := range st.Rules {
		for _, b := range r.Backends {
			if seen[b] {
				continue
			}
			seen[b] = true
			backendElems = append(backendElems, nftables.SetElement{
				Key: concatPortKey(net.IP(b.IP.AsSlice()), protoByte(r.Protocol), b.Port),
			})
		}
	}
	if err := conn.AddSet(backends, backendElems); err != nil {
		return fmt.Errorf("could not add set %s: %w", backends.Name, err)
	}

	guard := conn.AddChain(&nftables.Chain{
		Name:     "guard",
		Table:    t,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: l4GuardPriority,
	})
	// ICMP errors about a translated flow (PMTU) are "related": they must reach
	// the NAT below, which translates them along with their flow.
	conn.AddRule(&nftables.Rule{Table: t, Chain: guard, Exprs: ctStateEstablishedRelatedAccept()})
	// Anything else addressed to a VIP and not declared — another port, ICMP
	// echo — is dropped. Left alone it would not be translated, and since the
	// VIP is not a local address the node would route it back to its gateway,
	// which sends it straight back: a loop until the TTL expires.
	conn.AddRule(&nftables.Rule{Table: t, Chain: guard, Exprs: []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: vips.Name, SetID: vips.ID},
		&expr.Payload{DestRegister: unix.NFT_REG32_00, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: unix.NFT_REG32_01},
		&expr.Payload{DestRegister: unix.NFT_REG32_02, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Lookup{SourceRegister: unix.NFT_REG32_00, SetName: vipPorts.Name, SetID: vipPorts.ID, Invert: true},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}})

	// Not "dnat": nft takes that for its keyword, and an operator could not
	// name the chain on the command line without quoting it.
	translate := conn.AddChain(&nftables.Chain{
		Name:     "translate",
		Table:    t,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: l4DNATPriority,
	})
	for _, r := range st.Rules {
		exprs := matchFrontend(r.PortKey)
		if len(r.Backends) == 0 {
			// Announced here with no local ready backend: drop rather than let
			// the packet loop through the gateway.
			exprs = append(exprs, &expr.Verdict{Kind: expr.VerdictDrop})
		} else {
			m, err := addBackendMap(conn, t, r, ids.next())
			if err != nil {
				return err
			}
			exprs = append(exprs,
				// Round-robin slot, then slot -> (address . port) into
				// NFT_REG32_00 and NFT_REG32_01, which the NAT reads.
				&expr.Numgen{Register: 1, Modulus: uint32(len(r.Backends)), Type: unix.NFT_NG_INCREMENTAL},
				&expr.Lookup{SourceRegister: 1, DestRegister: 1, IsDestRegSet: true, SetName: m.Name, SetID: m.ID},
				&expr.NAT{
					Type:        expr.NATTypeDestNAT,
					Family:      unix.NFPROTO_IPV4,
					RegAddrMin:  1,
					RegProtoMin: unix.NFT_REG32_01,
					Specified:   true,
				},
			)
		}
		conn.AddRule(&nftables.Rule{
			Table:    t,
			Chain:    translate,
			Exprs:    exprs,
			UserData: userdata.AppendString(nil, userdata.TypeComment, r.Service),
		})
	}

	masq := conn.AddChain(&nftables.Chain{
		Name:     "masq",
		Table:    t,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: l4MasqPriority,
	})
	// A pod on another node reaches the VIP masqueraded by its own node. Left
	// as is, the backend would answer that node IP directly and the overlay
	// would carry the reply to the client's node, bypassing this node's
	// conntrack: the client then resets the connection. Masquerading the node
	// sources pins the reply here. Every other source — the Internet, a VM's
	// public IP — is kept.
	//
	// "ct status dnat" restricts it to translated flows, so a node process
	// talking to a backend pod directly (a kubelet probe) keeps its source.
	//
	// The source port is drawn fully at random. By default the kernel keeps
	// the client's port whenever its own conntrack has the tuple free, but it
	// cannot see OVS's: every client of a node collapses onto one masqueraded
	// address, and under load the announcer reused a tuple OVS still tracked,
	// 29 to 50 s after the previous connection. OVN dropped the backend's
	// SYN-ACK and the client retransmitted a second later.
	conn.AddRule(&nftables.Rule{Table: t, Chain: masq, Exprs: []expr.Any{
		&expr.Ct{Register: 1, Key: expr.CtKeySTATUS},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(ipsDstNAT),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Lookup{SourceRegister: 1, SetName: nodeIPs.Name, SetID: nodeIPs.ID},
		&expr.Payload{DestRegister: unix.NFT_REG32_00, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: unix.NFT_REG32_01},
		&expr.Payload{DestRegister: unix.NFT_REG32_02, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Lookup{SourceRegister: unix.NFT_REG32_00, SetName: backends.Name, SetID: backends.ID},
		&expr.Masq{FullyRandom: true},
	}})
	return nil
}

// setIDs hands out the set IDs of one transaction, which the rules use to
// reference sets created in the same batch. github.com/google/nftables would
// draw them from a package-level counter guarded only by each connection's own
// lock, so the VM mode queueing its sets on its connection at the same moment
// could give two of ours the same ID, and a rule would then point at the wrong
// set. The kernel only needs them unique within a batch.
type setIDs uint32

func (n *setIDs) next() uint32 {
	*n++
	return uint32(*n)
}

// addBackendMap adds the map from round-robin slot to backend for one frontend.
// It is named after the frontend, which is unique, and commented with the
// service it belongs to.
func addBackendMap(conn *nftables.Conn, t *nftables.Table, r l4.Rule, id uint32) (*nftables.Set, error) {
	dataType, err := nftables.ConcatSetType(nftables.TypeIPAddr, nftables.TypeInetService)
	if err != nil {
		return nil, fmt.Errorf("could not build backend map data type: %w", err)
	}
	m := &nftables.Set{
		Table:    t,
		ID:       id,
		Name:     fmt.Sprintf("backends-%s-%s-%d", r.VIP, protoName(r.Protocol), r.Port),
		Comment:  r.Service,
		IsMap:    true,
		KeyType:  nftables.TypeInteger,
		DataType: dataType,
		// numgen writes the slot in host byte order. nft lists the key type as
		// "type 0": it only names an integer key through a "typeof" annotation,
		// which github.com/google/nftables cannot write. The elements are listed
		// correctly, and the kernel does not look at either.
		KeyByteOrder: binaryutil.NativeEndian,
	}
	elems := make([]nftables.SetElement, 0, len(r.Backends))
	for i, b := range r.Backends {
		val := make([]byte, 8) // address, then the port padded to 4 bytes
		ip := b.IP.As4()
		copy(val[0:4], ip[:])
		val[4] = byte(b.Port >> 8)
		val[5] = byte(b.Port)
		elems = append(elems, nftables.SetElement{Key: binaryutil.NativeEndian.PutUint32(uint32(i)), Val: val})
	}
	if err := conn.AddSet(m, elems); err != nil {
		return nil, fmt.Errorf("could not add map %s: %w", m.Name, err)
	}
	return m, nil
}

// matchFrontend matches "ip daddr VIP <proto> dport PORT".
func matchFrontend(pk l4.PortKey) []expr.Any {
	vip := pk.VIP.As4()
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: vip[:]},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{protoByte(pk.Protocol)}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(pk.Port)},
	}
}

// ctStateEstablishedRelatedAccept is "ct state established,related accept".
func ctStateEstablishedRelatedAccept() []expr.Any {
	return []expr.Any{
		&expr.Ct{Register: 1, SourceRegister: false, Key: expr.CtKeySTATE},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}
}

func addrElements(addrs []netip.Addr) []nftables.SetElement {
	elems := make([]nftables.SetElement, 0, len(addrs))
	for _, a := range addrs {
		ip := a.As4()
		elems = append(elems, nftables.SetElement{Key: ip[:]})
	}
	return elems
}

func protoByte(p v1.Protocol) byte {
	switch p {
	case v1.ProtocolUDP:
		return unix.IPPROTO_UDP
	case v1.ProtocolSCTP:
		return unix.IPPROTO_SCTP
	default:
		return unix.IPPROTO_TCP
	}
}

func protoName(p v1.Protocol) string {
	switch p {
	case v1.ProtocolUDP:
		return "udp"
	case v1.ProtocolSCTP:
		return "sctp"
	default:
		return "tcp"
	}
}

// Compile-time assertion that NFTL4Datapath satisfies L4Datapath.
var _ L4Datapath = (*NFTL4Datapath)(nil)
