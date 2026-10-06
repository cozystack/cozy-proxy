package l4

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const thisNode = "node-a"

func ptr[T any](v T) *T { return &v }

// endpoint is a ready endpoint on the given node.
func endpoint(ip, node string) discoveryv1.Endpoint {
	return discoveryv1.Endpoint{
		Addresses:  []string{ip},
		Conditions: discoveryv1.EndpointConditions{Ready: ptr(true)},
		NodeName:   ptr(node),
	}
}

// slice builds an IPv4 EndpointSlice for the service ns/svc.
func slice(ns, svc, name string, ports []discoveryv1.EndpointPort, eps ...discoveryv1.Endpoint) *discoveryv1.EndpointSlice {
	return &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: ns,
			Name:      name,
			Labels:    map[string]string{discoveryv1.LabelServiceName: svc},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       ports,
		Endpoints:   eps,
	}
}

func epPort(name string, port int32) discoveryv1.EndpointPort {
	return discoveryv1.EndpointPort{Name: ptr(name), Port: ptr(port), Protocol: ptr(v1.ProtocolTCP)}
}

func svcPort(name string, port int32) v1.ServicePort {
	return v1.ServicePort{Name: name, Port: port, Protocol: v1.ProtocolTCP}
}

func node(name string, addrs ...v1.NodeAddress) *v1.Node {
	return &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     v1.NodeStatus{Addresses: addrs},
	}
}

func internalIP(ip string) v1.NodeAddress {
	return v1.NodeAddress{Type: v1.NodeInternalIP, Address: ip}
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func be(ip string, port uint16) Backend { return Backend{IP: addr(ip), Port: port} }

func key(vip string, port uint16) PortKey {
	return PortKey{VIP: addr(vip), Protocol: v1.ProtocolTCP, Port: port}
}

// The phase 1 shape: one announced service, several ports, only the ready
// backends hosted here.
func TestBuildAnnouncedServiceUsesLocalReadyBackends(t *testing.T) {
	svc := l4Service("ns", "pg", "192.0.2.10")
	svc.Spec.Ports = []v1.ServicePort{svcPort("http", 80), svcPort("https", 443)}

	notReady := endpoint("10.0.0.4", thisNode)
	notReady.Conditions.Ready = ptr(false)
	terminating := endpoint("10.0.0.5", thisNode)
	terminating.Conditions.Terminating = ptr(true)
	terminating.Conditions.Ready = ptr(false)
	unknown := endpoint("10.0.0.6", thisNode)
	unknown.Conditions.Ready = nil // nil means ready, per the API

	in := Input{
		NodeName: thisNode,
		Services: []*v1.Service{svc},
		EndpointSlices: []*discoveryv1.EndpointSlice{slice("ns", "pg", "pg-1",
			// Target ports are already resolved in the slice, named targets
			// included; they need not match the service port.
			[]discoveryv1.EndpointPort{epPort("http", 8080), epPort("https", 8443)},
			endpoint("10.0.0.2", thisNode),
			endpoint("10.0.0.1", thisNode),
			endpoint("10.0.0.3", "node-b"), // remote: eTP Local only uses local backends
			notReady,
			terminating,
			unknown,
		)},
		Announced: map[string]bool{"ns/pg": true},
	}

	got, notices := Build(in)

	want := State{
		VIPs:  []netip.Addr{addr("192.0.2.10")},
		Ports: []PortKey{key("192.0.2.10", 80), key("192.0.2.10", 443)},
		Rules: []Rule{
			{PortKey: key("192.0.2.10", 80), Service: "ns/pg",
				Backends: []Backend{be("10.0.0.1", 8080), be("10.0.0.2", 8080), be("10.0.0.6", 8080)},
				Draining: []Backend{be("10.0.0.5", 8080)}},
			{PortKey: key("192.0.2.10", 443), Service: "ns/pg",
				Backends: []Backend{be("10.0.0.1", 8443), be("10.0.0.2", 8443), be("10.0.0.6", 8443)},
				Draining: []Backend{be("10.0.0.5", 8443)}},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Build =\n%+v\nwant\n%+v", got, want)
	}
	if len(notices) != 0 {
		t.Errorf("no notice expected, got %v", notices)
	}
}

// Only the announcer translates. Every other node still guards the VIP, and
// lets declared ports through so that its pods' packets reach the announcer.
func TestBuildNotAnnouncedServiceIsGuardedOnly(t *testing.T) {
	svc := l4Service("ns", "pg", "192.0.2.10")
	svc.Spec.Ports = []v1.ServicePort{svcPort("pg", 5432)}

	got, _ := Build(Input{
		NodeName: thisNode,
		Services: []*v1.Service{svc},
		EndpointSlices: []*discoveryv1.EndpointSlice{slice("ns", "pg", "pg-1",
			[]discoveryv1.EndpointPort{epPort("pg", 5432)}, endpoint("10.0.0.1", thisNode))},
	})

	if len(got.Rules) != 0 {
		t.Errorf("a node that does not announce the VIP must not translate it, got %+v", got.Rules)
	}
	if !reflect.DeepEqual(got.VIPs, []netip.Addr{addr("192.0.2.10")}) {
		t.Errorf("VIPs = %v, want the service VIP", got.VIPs)
	}
	if !reflect.DeepEqual(got.Ports, []PortKey{key("192.0.2.10", 5432)}) {
		t.Errorf("Ports = %v, want the declared port", got.Ports)
	}
}

// An announced port without any local ready backend must be dropped, not left
// untranslated: an untranslated packet would be routed back to the gateway.
func TestBuildPortWithoutBackendIsAnEmptyRule(t *testing.T) {
	svc := l4Service("ns", "pg", "192.0.2.10")
	svc.Spec.Ports = []v1.ServicePort{svcPort("pg", 5432), svcPort("metrics", 9187)}

	got, _ := Build(Input{
		NodeName: thisNode,
		Services: []*v1.Service{svc},
		EndpointSlices: []*discoveryv1.EndpointSlice{slice("ns", "pg", "pg-1",
			[]discoveryv1.EndpointPort{epPort("pg", 5432)}, // no "metrics" port in the slice
			endpoint("10.0.0.1", "node-b"))},               // and no local backend at all
		Announced: map[string]bool{"ns/pg": true},
	})

	want := []Rule{
		{PortKey: key("192.0.2.10", 5432), Service: "ns/pg"},
		{PortKey: key("192.0.2.10", 9187), Service: "ns/pg"},
	}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Errorf("Rules = %+v, want empty rules for both ports %+v", got.Rules, want)
	}
}

// The kubevirt CCM creates selector-less services whose single port has no
// name, and writes their slices itself.
func TestBuildSelectorlessCCMService(t *testing.T) {
	svc := l4Service("tenant-k8s", "a6ed08", "192.0.2.20")
	svc.Spec.Ports = []v1.ServicePort{{Port: 80, Protocol: v1.ProtocolTCP}}

	s := slice("tenant-k8s", "a6ed08", "a6ed08-x", []discoveryv1.EndpointPort{
		{Name: ptr(""), Port: ptr(int32(31790)), Protocol: ptr(v1.ProtocolTCP)},
	}, endpoint("10.0.80.67", thisNode))
	s.Labels[discoveryv1.LabelManagedBy] = "kubevirt-eps-controller"

	got, _ := Build(Input{
		NodeName:       thisNode,
		Services:       []*v1.Service{svc},
		EndpointSlices: []*discoveryv1.EndpointSlice{s},
		Announced:      map[string]bool{"tenant-k8s/a6ed08": true},
	})

	want := []Rule{{PortKey: key("192.0.2.20", 80), Service: "tenant-k8s/a6ed08",
		Backends: []Backend{be("10.0.80.67", 31790)}}}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Errorf("Rules = %+v, want %+v", got.Rules, want)
	}
}

// Endpoints of one service can transiently appear in two slices.
func TestBuildDeduplicatesBackendsAcrossSlices(t *testing.T) {
	svc := l4Service("ns", "web", "192.0.2.10")
	svc.Spec.Ports = []v1.ServicePort{svcPort("http", 80)}
	ports := []discoveryv1.EndpointPort{epPort("http", 8080)}

	got, _ := Build(Input{
		NodeName: thisNode,
		Services: []*v1.Service{svc},
		EndpointSlices: []*discoveryv1.EndpointSlice{
			slice("ns", "web", "web-1", ports, endpoint("10.0.0.1", thisNode)),
			slice("ns", "web", "web-2", ports, endpoint("10.0.0.1", thisNode), endpoint("10.0.0.2", thisNode)),
			// Same name, other namespace: not this service's slice.
			slice("other", "web", "web-3", ports, endpoint("10.0.0.9", thisNode)),
		},
		Announced: map[string]bool{"ns/web": true},
	})

	want := []Backend{be("10.0.0.1", 8080), be("10.0.0.2", 8080)}
	if len(got.Rules) != 1 || !reflect.DeepEqual(got.Rules[0].Backends, want) {
		t.Errorf("Rules = %+v, want one rule with %v", got.Rules, want)
	}
}

func TestBuildIgnoresNonIPv4AndUnscheduledEndpoints(t *testing.T) {
	svc := l4Service("ns", "web", "192.0.2.10", "2001:db8::10")
	svc.Spec.Ports = []v1.ServicePort{svcPort("http", 80)}
	ports := []discoveryv1.EndpointPort{epPort("http", 8080)}

	v6 := slice("ns", "web", "web-v6", ports, endpoint("2001:db8::1", thisNode))
	v6.AddressType = discoveryv1.AddressTypeIPv6
	noNode := endpoint("10.0.0.2", thisNode)
	noNode.NodeName = nil

	got, _ := Build(Input{
		NodeName:       thisNode,
		Services:       []*v1.Service{svc},
		EndpointSlices: []*discoveryv1.EndpointSlice{v6, slice("ns", "web", "web-v4", ports, endpoint("10.0.0.1", thisNode), noNode)},
		Announced:      map[string]bool{"ns/web": true},
	})

	if !reflect.DeepEqual(got.VIPs, []netip.Addr{addr("192.0.2.10")}) {
		t.Errorf("VIPs = %v, want only the IPv4 one", got.VIPs)
	}
	want := []Rule{{PortKey: key("192.0.2.10", 80), Service: "ns/web", Backends: []Backend{be("10.0.0.1", 8080)}}}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Errorf("Rules = %+v, want %+v", got.Rules, want)
	}
}

// Phase 1 is TCP only. A UDP port is left out of the declared ports, so the
// guard drops it rather than letting it loop.
func TestBuildLeavesUDPPortsOut(t *testing.T) {
	svc := l4Service("ns", "dns", "192.0.2.10")
	svc.Spec.Ports = []v1.ServicePort{svcPort("tcp", 53), {Name: "udp", Port: 53, Protocol: v1.ProtocolUDP}}

	got, notices := Build(Input{
		NodeName: thisNode,
		Services: []*v1.Service{svc},
		EndpointSlices: []*discoveryv1.EndpointSlice{slice("ns", "dns", "dns-1", []discoveryv1.EndpointPort{
			epPort("tcp", 53),
			{Name: ptr("udp"), Port: ptr(int32(53)), Protocol: ptr(v1.ProtocolUDP)},
		}, endpoint("10.0.0.1", thisNode))},
		Announced: map[string]bool{"ns/dns": true},
	})

	if !reflect.DeepEqual(got.Ports, []PortKey{key("192.0.2.10", 53)}) {
		t.Errorf("Ports = %v, want only TCP/53", got.Ports)
	}
	if len(got.Rules) != 1 || got.Rules[0].Protocol != v1.ProtocolTCP {
		t.Errorf("Rules = %+v, want only the TCP rule", got.Rules)
	}
	if !hasNotice(notices, "ns/dns", "UDP") {
		t.Errorf("a skipped port must be reported, got %v", notices)
	}
}

// A service Cilium released but phase 1 cannot program is guarded: its VIP
// drops everything.
func TestBuildUnsupportedServiceIsGuardedWithNoPort(t *testing.T) {
	svc := l4Service("ns", "maria", "192.0.2.10")
	svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyCluster
	svc.Spec.Ports = []v1.ServicePort{svcPort("mysql", 3306)}

	got, notices := Build(Input{
		NodeName:  thisNode,
		Services:  []*v1.Service{svc},
		Announced: map[string]bool{"ns/maria": true},
	})

	if !reflect.DeepEqual(got.VIPs, []netip.Addr{addr("192.0.2.10")}) {
		t.Errorf("VIPs = %v, want the VIP guarded", got.VIPs)
	}
	if len(got.Ports) != 0 || len(got.Rules) != 0 {
		t.Errorf("an unsupported service must not be opened, got ports %v rules %v", got.Ports, got.Rules)
	}
	if !hasNotice(notices, "ns/maria", "externalTrafficPolicy") {
		t.Errorf("an unsupported service must be reported, got %v", notices)
	}
}

// Services some other component owns are left entirely alone, guard included.
func TestBuildIgnoredAndUnselectedServicesAreUntouched(t *testing.T) {
	noAnnotation := l4Service("ns", "half", "192.0.2.10")
	delete(noAnnotation.Annotations, CiliumTypeAnnotation)
	plain := l4Service("ns", "plain", "192.0.2.11")
	delete(plain.Labels, ProxyLabel)

	got, notices := Build(Input{NodeName: thisNode, Services: []*v1.Service{noAnnotation, plain}})

	if len(got.VIPs) != 0 || len(got.Ports) != 0 || len(got.Rules) != 0 {
		t.Errorf("nothing must be programmed, got %+v", got)
	}
	if !hasNotice(notices, "ns/half", CiliumTypeAnnotation) {
		t.Errorf("an ignored labelled service must be reported, got %v", notices)
	}
	if hasNotice(notices, "ns/plain", "") {
		t.Errorf("an unselected service is none of our business, got %v", notices)
	}
}

// A service waiting for its VIP contributes nothing yet.
func TestBuildServiceWithoutVIP(t *testing.T) {
	svc := l4Service("ns", "pending")
	svc.Spec.Ports = []v1.ServicePort{svcPort("pg", 5432)}
	got, _ := Build(Input{NodeName: thisNode, Services: []*v1.Service{svc}, Announced: map[string]bool{"ns/pending": true}})
	if len(got.VIPs) != 0 || len(got.Ports) != 0 || len(got.Rules) != 0 {
		t.Errorf("nothing must be programmed before the VIP is allocated, got %+v", got)
	}
}

// Masquerading is restricted to the nodes' own addresses, read from the Node
// objects rather than guessed as a CIDR: the LoadBalancer pool can sit in the
// node subnet, and a VM client's public IP must not be masqueraded.
func TestBuildNodeIPs(t *testing.T) {
	got, _ := Build(Input{
		NodeName: thisNode,
		Nodes: []*v1.Node{
			node("node-b", internalIP("10.200.24.12"), v1.NodeAddress{Type: v1.NodeHostName, Address: "node-b"}),
			node("node-a", internalIP("10.200.24.11"), internalIP("fd00::11"),
				v1.NodeAddress{Type: v1.NodeExternalIP, Address: "198.51.100.1"}),
			node("node-c", internalIP("10.200.24.12")), // duplicate address
		},
	})
	want := []netip.Addr{addr("10.200.24.11"), addr("10.200.24.12")}
	if !reflect.DeepEqual(got.NodeIPs, want) {
		t.Errorf("NodeIPs = %v, want %v", got.NodeIPs, want)
	}
}

// A VM-mode pod rewrites its replies' source at priority raw, before
// conntrack, so an L4 translation towards it could never be reversed.
func TestBuildExcludesBackendsOwnedByTheVMMode(t *testing.T) {
	vm := l4Service("tenant", "vm", "192.0.2.50")
	delete(vm.Annotations, CiliumTypeAnnotation)
	delete(vm.Labels, ProxyLabel)
	vm.Labels[vmProxyNameLabel] = vmProxyName

	web := l4Service("tenant", "web", "192.0.2.10")
	web.Spec.Ports = []v1.ServicePort{svcPort("http", 80), svcPort("https", 443)}
	ports := []discoveryv1.EndpointPort{epPort("http", 8080), epPort("https", 8443)}

	got, notices := Build(Input{
		NodeName: thisNode,
		Services: []*v1.Service{vm, web},
		EndpointSlices: []*discoveryv1.EndpointSlice{
			slice("tenant", "vm", "vm-1", nil, endpoint("10.0.0.7", thisNode)),
			slice("tenant", "web", "web-1", ports, endpoint("10.0.0.7", thisNode), endpoint("10.0.0.8", thisNode)),
		},
		Announced: map[string]bool{"tenant/web": true},
	})

	want := []Backend{be("10.0.0.8", 8080)}
	if len(got.Rules) != 2 || !reflect.DeepEqual(got.Rules[0].Backends, want) {
		t.Errorf("Rules = %+v, want only %v on port 80", got.Rules, want)
	}
	if !hasNotice(notices, "tenant/web", "10.0.0.7") {
		t.Errorf("an excluded backend must be reported, got %v", notices)
	}
	// Once, although both ports raise it.
	if len(notices) != 1 {
		t.Errorf("notices = %v, want a single one", notices)
	}
}

// MetalLB can share a VIP between services on distinct ports. Two services
// declaring the same port cannot both be served; the first one in key order
// keeps it.
func TestBuildSharedVIP(t *testing.T) {
	a := l4Service("ns", "a", "192.0.2.10")
	a.Spec.Ports = []v1.ServicePort{svcPort("http", 80)}
	b := l4Service("ns", "b", "192.0.2.10")
	b.Spec.Ports = []v1.ServicePort{svcPort("http", 80), svcPort("ssh", 22)}
	ports := []discoveryv1.EndpointPort{epPort("http", 8080), epPort("ssh", 22)}

	got, notices := Build(Input{
		NodeName: thisNode,
		// Deliberately out of order: the result must not depend on it.
		Services: []*v1.Service{b, a},
		EndpointSlices: []*discoveryv1.EndpointSlice{
			slice("ns", "a", "a-1", ports, endpoint("10.0.0.1", thisNode)),
			slice("ns", "b", "b-1", ports, endpoint("10.0.0.2", thisNode)),
		},
		Announced: map[string]bool{"ns/a": true, "ns/b": true},
	})

	if !reflect.DeepEqual(got.VIPs, []netip.Addr{addr("192.0.2.10")}) {
		t.Errorf("VIPs = %v, want the shared VIP once", got.VIPs)
	}
	want := []Rule{
		{PortKey: key("192.0.2.10", 22), Service: "ns/b", Backends: []Backend{be("10.0.0.2", 22)}},
		{PortKey: key("192.0.2.10", 80), Service: "ns/a", Backends: []Backend{be("10.0.0.1", 8080)}},
	}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Errorf("Rules = %+v, want %+v", got.Rules, want)
	}
	if !hasNotice(notices, "ns/b", "ns/a") {
		t.Errorf("the conflict must be reported on the losing service, got %v", notices)
	}
}

func hasNotice(notices []Notice, service, substr string) bool {
	for _, n := range notices {
		if n.Service == service && strings.Contains(n.Message, substr) {
			return true
		}
	}
	return false
}

// A terminating local endpoint gets no new connection, but is kept as
// draining, so its live connections are not purged: a rolling update of an
// Ingress must not reset every client. A merely not-ready one is not: its
// probe says it cannot serve, so its flows are purged like a removed one's.
func TestBuildKeepsTerminatingLocalEndpointsAsDraining(t *testing.T) {
	svc := l4Service("ns", "web", "192.0.2.10")
	svc.Spec.Ports = []v1.ServicePort{svcPort("http", 80)}

	notReady := endpoint("10.0.0.2", thisNode)
	notReady.Conditions.Ready = ptr(false)
	// publishNotReadyAddresses keeps Ready true on a terminating endpoint.
	terminating := endpoint("10.0.0.3", thisNode)
	terminating.Conditions.Terminating = ptr(true)
	remote := endpoint("10.0.0.4", "node-b")
	remote.Conditions.Ready = ptr(false)

	got, _ := Build(Input{
		NodeName: thisNode,
		Services: []*v1.Service{svc},
		EndpointSlices: []*discoveryv1.EndpointSlice{slice("ns", "web", "web-1",
			[]discoveryv1.EndpointPort{epPort("http", 8080)},
			endpoint("10.0.0.1", thisNode), notReady, terminating, remote)},
		Announced: map[string]bool{"ns/web": true},
	})

	want := []Rule{{
		PortKey:  key("192.0.2.10", 80),
		Service:  "ns/web",
		Backends: []Backend{be("10.0.0.1", 8080)},
		Draining: []Backend{be("10.0.0.3", 8080)},
	}}
	if !reflect.DeepEqual(got.Rules, want) {
		t.Errorf("Rules = %+v, want %+v", got.Rules, want)
	}
}
