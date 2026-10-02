package l4

import (
	"net/netip"
	"testing"

	v1 "k8s.io/api/core/v1"
)

const (
	tcp = 6
	udp = 17
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// translated is a flow this node DNATed from vip to backend.
func translated(proto uint8, vip, backend string) Flow {
	return Flow{Protocol: proto, OrigDst: ap(vip), ReplySrc: ap(backend)}
}

func stateWith(rules ...Rule) State {
	st := State{}
	for _, r := range rules {
		st.VIPs = append(st.VIPs, r.VIP)
		st.Ports = append(st.Ports, r.PortKey)
	}
	st.VIPs = sortedUnique(st.VIPs, netip.Addr.Compare)
	st.Rules = rules
	return st
}

func rule(vip string, port uint16, backends ...Backend) Rule {
	return Rule{PortKey: key(vip, port), Service: "ns/svc", Backends: backends}
}

func TestStaleFlows(t *testing.T) {
	prev := stateWith(
		rule("192.0.2.10", 80, be("10.0.0.1", 8080), be("10.0.0.2", 8080)),
		rule("192.0.2.10", 443, be("10.0.0.1", 8443)),
		rule("192.0.2.20", 5432, be("10.0.0.3", 5432)),
	)
	// 10.0.0.2 went away, port 443 was removed from the service, and the
	// 192.0.2.20 service is gone altogether.
	cur := stateWith(rule("192.0.2.10", 80, be("10.0.0.1", 8080)))

	stale := StaleFlows(&prev, cur)

	cases := []struct {
		name string
		flow Flow
		want bool
	}{
		{"backend still programmed", translated(tcp, "192.0.2.10:80", "10.0.0.1:8080"), false},
		{"backend gone", translated(tcp, "192.0.2.10:80", "10.0.0.2:8080"), true},
		{"port removed", translated(tcp, "192.0.2.10:443", "10.0.0.1:8443"), true},
		{"service removed", translated(tcp, "192.0.2.20:5432", "10.0.0.3:5432"), true},
		{"same backend IP, other port", translated(tcp, "192.0.2.10:80", "10.0.0.1:9090"), true},
		{"protocol not programmed", translated(udp, "192.0.2.10:80", "10.0.0.1:8080"), true},
		// A pod on a node that does not announce the VIP goes through
		// untranslated; its flow is not ours to cut.
		{"untranslated flow to a VIP", translated(tcp, "192.0.2.10:80", "192.0.2.10:80"), false},
		{"flow to another address", translated(tcp, "198.51.100.1:80", "10.0.0.2:8080"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := stale(c.flow); got != c.want {
				t.Errorf("stale(%+v) = %v, want %v", c.flow, got, c.want)
			}
		})
	}
}

// After a restart there is no previous state: whatever this node translated
// towards a VIP it knows and no longer programs must go — for instance after
// the announcement moved to another node while the pod was down.
func TestStaleFlowsWithoutPreviousState(t *testing.T) {
	cur := State{
		VIPs:  []netip.Addr{addr("192.0.2.10")},
		Ports: []PortKey{key("192.0.2.10", 80)},
	}
	stale := StaleFlows(nil, cur)
	if !stale(translated(tcp, "192.0.2.10:80", "10.0.0.1:8080")) {
		t.Error("a translation this node no longer programs must be purged")
	}
	if stale(translated(tcp, "192.0.2.10:80", "192.0.2.10:80")) {
		t.Error("an untranslated flow must be kept")
	}
}

func TestPurgeNeeded(t *testing.T) {
	base := stateWith(rule("192.0.2.10", 80, be("10.0.0.1", 8080)))
	cases := []struct {
		name string
		prev *State
		cur  State
		want bool
	}{
		{"first sync", nil, base, true},
		{"unchanged", &base, base, false},
		{"backend added", &base, stateWith(rule("192.0.2.10", 80, be("10.0.0.1", 8080), be("10.0.0.2", 8080))), false},
		{"service added", &base, stateWith(rule("192.0.2.10", 80, be("10.0.0.1", 8080)), rule("192.0.2.11", 80)), false},
		{"backend replaced", &base, stateWith(rule("192.0.2.10", 80, be("10.0.0.2", 8080))), true},
		{"no longer announced", &base, State{VIPs: base.VIPs, Ports: base.Ports}, true},
		{"node IPs only", &base, State{VIPs: base.VIPs, Ports: base.Ports, Rules: base.Rules, NodeIPs: []netip.Addr{addr("10.200.24.11")}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PurgeNeeded(c.prev, c.cur); got != c.want {
				t.Errorf("PurgeNeeded = %v, want %v", got, c.want)
			}
		})
	}
}

func TestProtocolNumber(t *testing.T) {
	if protocolNumber(v1.ProtocolTCP) != tcp || protocolNumber(v1.ProtocolUDP) != udp {
		t.Error("IANA numbers expected for TCP and UDP")
	}
}

// A backend that stops being ready keeps its live connections until it leaves
// the EndpointSlice; only then are they purged.
func TestDrainingBackendKeepsItsFlows(t *testing.T) {
	ready := stateWith(rule("192.0.2.10", 80, be("10.0.0.1", 8080), be("10.0.0.2", 8080)))
	draining := stateWith(rule("192.0.2.10", 80, be("10.0.0.1", 8080)))
	draining.Rules[0].Draining = []Backend{be("10.0.0.2", 8080)}
	gone := stateWith(rule("192.0.2.10", 80, be("10.0.0.1", 8080)))

	if PurgeNeeded(&ready, draining) {
		t.Error("a backend that starts draining must not trigger a purge")
	}
	if StaleFlows(&ready, draining)(translated(tcp, "192.0.2.10:80", "10.0.0.2:8080")) {
		t.Error("a draining backend's flows must be kept")
	}
	if !PurgeNeeded(&draining, gone) {
		t.Error("a draining backend that leaves the slice must trigger a purge")
	}
	if !StaleFlows(&draining, gone)(translated(tcp, "192.0.2.10:80", "10.0.0.2:8080")) {
		t.Error("the flows of a backend gone from the slice must be purged")
	}
}
