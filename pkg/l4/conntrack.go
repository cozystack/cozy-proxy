package l4

import (
	"net/netip"

	v1 "k8s.io/api/core/v1"
)

// Flow is the part of a conntrack entry the purge decision needs.
type Flow struct {
	// Protocol is the IANA protocol number.
	Protocol uint8
	// OrigDst is the destination the client used.
	OrigDst netip.AddrPort
	// ReplySrc is the source of the replies: the backend when this node
	// translated the flow, OrigDst otherwise.
	ReplySrc netip.AddrPort
}

// target is one translation the datapath performs.
type target struct {
	vip      netip.Addr
	protocol uint8
	port     uint16
	backend  netip.AddrPort
}

// targets returns the translations whose flows must be kept: the ones the
// datapath performs, and the ones towards draining backends, which finish
// their connections.
func targets(st State) map[target]struct{} {
	out := map[target]struct{}{}
	for _, r := range st.Rules {
		for _, bs := range [][]Backend{r.Backends, r.Draining} {
			for _, b := range bs {
				out[target{r.VIP, protocolNumber(r.Protocol), r.Port, netip.AddrPortFrom(b.IP, b.Port)}] = struct{}{}
			}
		}
	}
	return out
}

// frontend is a (VIP, protocol, port) this node translates.
type frontend struct {
	vip      netip.Addr
	protocol uint8
	port     uint16
}

func frontends(st State) map[frontend]struct{} {
	out := map[frontend]struct{}{}
	for _, r := range st.Rules {
		out[frontend{r.VIP, protocolNumber(r.Protocol), r.Port}] = struct{}{}
	}
	return out
}

// StaleFlows returns the predicate selecting the conntrack entries to delete
// once cur has been committed, coming from prev (nil after a restart).
//
// A conntrack entry outlives the rule that created it. It is stale when this
// node translated it (its replies do not come from the address the client
// used), towards a VIP the L4 mode knows, and:
//
//   - for TCP, when its frontend — the service, the port, or this node's
//     announcement — is gone. A TCP connection to a backend withdrawn from a
//     frontend that still exists is left to end on its own, or with its pod,
//     as kube-proxy does. Purging it helps nobody: on the lab an idle client
//     then hung until its own timeout, the backend's reply matching no entry
//     and no RST reaching the client.
//   - for UDP and the rest, when its backend is no longer programmed nor
//     draining: without the purge an active UDP flow would keep being sent to
//     a backend that left, forever.
//
// Untranslated flows to a VIP — a pod on a node that does not announce it,
// passing through — are left alone, and so is everything addressed elsewhere,
// which keeps the VM mode out of reach.
func StaleFlows(prev *State, cur State) func(Flow) bool {
	vips := map[netip.Addr]struct{}{}
	for _, st := range []*State{prev, &cur} {
		if st == nil {
			continue
		}
		for _, v := range st.VIPs {
			vips[v] = struct{}{}
		}
		for _, r := range st.Rules {
			vips[r.VIP] = struct{}{}
		}
	}
	keep := targets(cur)
	served := frontends(cur)

	return func(f Flow) bool {
		if _, ours := vips[f.OrigDst.Addr()]; !ours {
			return false
		}
		if f.ReplySrc == f.OrigDst {
			return false
		}
		if f.Protocol == protocolNumber(v1.ProtocolTCP) {
			_, stillServed := served[frontend{f.OrigDst.Addr(), f.Protocol, f.OrigDst.Port()}]
			return !stillServed
		}
		_, programmed := keep[target{f.OrigDst.Addr(), f.Protocol, f.OrigDst.Port(), f.ReplySrc}]
		return !programmed
	}
}

// PurgeNeeded reports whether moving from prev to cur withdrew something whose
// flows StaleFlows would select: a frontend, or a non-TCP backend. After a
// restart (prev nil) the answer is always yes: changes may have happened while
// no instance was watching.
func PurgeNeeded(prev *State, cur State) bool {
	if prev == nil {
		return true
	}
	served := frontends(cur)
	for fe := range frontends(*prev) {
		if _, ok := served[fe]; !ok {
			return true
		}
	}
	now := targets(cur)
	for t := range targets(*prev) {
		if t.protocol == protocolNumber(v1.ProtocolTCP) {
			continue
		}
		if _, ok := now[t]; !ok {
			return true
		}
	}
	return false
}

func protocolNumber(p v1.Protocol) uint8 {
	switch p {
	case v1.ProtocolUDP:
		return 17
	case v1.ProtocolSCTP:
		return 132
	default:
		return 6
	}
}
