package l4

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
)

// Backend is one translation target: a ready endpoint hosted on this node, at
// the port the EndpointSlice resolved for the service port.
type Backend struct {
	IP   netip.Addr
	Port uint16
}

func (b Backend) String() string { return netip.AddrPortFrom(b.IP, b.Port).String() }

// PortKey is a declared (VIP, protocol, port) frontend.
type PortKey struct {
	VIP      netip.Addr
	Protocol v1.Protocol
	Port     uint16
}

// Rule is a frontend this node translates. An empty Backends means the port is
// announced here but has no local ready backend: its traffic is dropped, since
// leaving it untranslated would route it back to the gateway.
type Rule struct {
	PortKey
	// Service is the namespace/name of the Service the frontend belongs to.
	Service  string
	Backends []Backend
	// Draining are the local endpoints that are terminating. They get no new
	// connection, but their live ones are not purged: a backend shutting down
	// gracefully must be able to finish them, as it would behind kube-proxy or
	// Cilium. A merely not-ready endpoint is not draining: its probe says it
	// cannot serve, so its flows are purged like a removed one's. The datapath
	// ignores this field.
	Draining []Backend
}

// State is everything one node programs for the L4 mode. Every slice is sorted,
// so two states can be compared with reflect.DeepEqual.
type State struct {
	// VIPs are guarded on every node: new traffic to them that is not on a
	// declared port is dropped.
	VIPs []netip.Addr
	// Ports are the declared frontends of every supported service, on every
	// node, including the ones this node does not announce: a pod here must be
	// able to reach them through the announcer.
	Ports []PortKey
	// NodeIPs are the sources masqueraded after translation.
	NodeIPs []netip.Addr
	// Rules are the frontends this node announces and therefore translates.
	Rules []Rule
}

// Notice explains why a service, or part of it, is not programmed.
type Notice struct {
	Service string
	Message string
}

// Input is the cluster state Build reads.
type Input struct {
	// NodeName is the node this instance programs.
	NodeName string
	// Services and EndpointSlices hold every object in the cluster, not only
	// the L4 ones: the VM mode's slices are needed to exclude its pods.
	Services       []*v1.Service
	EndpointSlices []*discoveryv1.EndpointSlice
	Nodes          []*v1.Node
	// Announced holds the namespace/name of the services whose VIP this node
	// announces.
	Announced map[string]bool
}

// Build computes the state this node must program, and the notices worth
// logging. It is a pure function of its input.
func Build(in Input) (State, []Notice) {
	b := builder{in: in, slices: groupSlices(in.EndpointSlices), owner: map[PortKey]string{}}
	b.vmPods = b.vmModePods()

	services := slices.Clone(in.Services)
	slices.SortFunc(services, func(x, y *v1.Service) int { return cmp.Compare(serviceKey(x), serviceKey(y)) })
	for _, svc := range services {
		b.addService(svc)
	}

	b.st.NodeIPs = nodeIPs(in.Nodes)
	b.st.VIPs = sortedUnique(b.st.VIPs, netip.Addr.Compare)
	slices.SortFunc(b.st.Ports, comparePortKey)
	slices.SortFunc(b.st.Rules, func(x, y Rule) int { return comparePortKey(x.PortKey, y.PortKey) })
	return b.st, b.notices
}

type builder struct {
	in      Input
	slices  map[string][]*discoveryv1.EndpointSlice
	vmPods  map[netip.Addr]string
	owner   map[PortKey]string
	st      State
	notices []Notice
}

// notice records a message once, however many ports or slices raise it.
func (b *builder) notice(service, format string, args ...any) {
	n := Notice{Service: service, Message: fmt.Sprintf(format, args...)}
	if slices.Contains(b.notices, n) {
		return
	}
	b.notices = append(b.notices, n)
}

func (b *builder) addService(svc *v1.Service) {
	key := serviceKey(svc)
	sel, reason := Classify(svc)
	switch sel {
	case NotSelected:
		return
	case Ignored:
		b.notice(key, "ignored: %s", reason)
		return
	}

	vips := serviceVIPs(svc)
	b.st.VIPs = append(b.st.VIPs, vips...)
	if sel == Unsupported {
		b.notice(key, "not programmed, its VIP drops all traffic: %s", reason)
		return
	}

	announced := b.in.Announced[key]
	for _, sp := range svc.Spec.Ports {
		proto := sp.Protocol
		if proto == "" {
			proto = v1.ProtocolTCP
		}
		if proto != v1.ProtocolTCP {
			b.notice(key, "port %s/%d not programmed: only TCP is supported", proto, sp.Port)
			continue
		}
		var backends, draining []Backend
		if announced {
			backends, draining = b.localBackends(key, svc.Namespace, svc.Name, sp.Name, proto)
		}
		for _, vip := range vips {
			pk := PortKey{VIP: vip, Protocol: proto, Port: uint16(sp.Port)}
			if prev, taken := b.owner[pk]; taken {
				b.notice(key, "port %s %s/%d not programmed: already served by %s", vip, proto, sp.Port, prev)
				continue
			}
			b.owner[pk] = key
			b.st.Ports = append(b.st.Ports, pk)
			if announced {
				b.st.Rules = append(b.st.Rules, Rule{PortKey: pk, Service: key, Backends: backends, Draining: draining})
			}
		}
	}
}

// localBackends returns the endpoints of the service port hosted on this node,
// sorted and deduplicated: the ones serving, and the terminating ones. The port
// is matched by name and protocol, the way kube-proxy does, which also
// resolves named target ports.
func (b *builder) localBackends(key, ns, name, portName string, proto v1.Protocol) (ready, draining []Backend) {
	for _, s := range b.slices[ns+"/"+name] {
		if s.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}
		port, ok := slicePort(s, portName, proto)
		if !ok {
			continue
		}
		for _, ep := range s.Endpoints {
			if ep.NodeName == nil || *ep.NodeName != b.in.NodeName || len(ep.Addresses) == 0 {
				continue
			}
			ip, err := netip.ParseAddr(ep.Addresses[0])
			if err != nil || !ip.Is4() {
				continue
			}
			if owner, vm := b.vmPods[ip]; vm {
				b.notice(key, "backend %s excluded: it is the pod of VM-mode service %s", ip, owner)
				continue
			}
			switch {
			case serves(ep):
				ready = append(ready, Backend{IP: ip, Port: port})
			case terminating(ep):
				draining = append(draining, Backend{IP: ip, Port: port})
			}
		}
	}
	ready = sortedUnique(ready, compareBackend)
	// An endpoint listed both ways during a transition counts as serving.
	draining = slices.DeleteFunc(sortedUnique(draining, compareBackend), func(d Backend) bool {
		_, found := slices.BinarySearchFunc(ready, d, compareBackend)
		return found
	})
	if len(draining) == 0 {
		draining = nil
	}
	return ready, draining
}

func compareBackend(x, y Backend) int {
	return cmp.Or(x.IP.Compare(y.IP), cmp.Compare(x.Port, y.Port))
}

// vmModePods returns the pod IPs backing a VM-mode service. The VM mode
// rewrites their replies' source at priority raw, before conntrack, so an L4
// translation towards them could never be reversed.
func (b *builder) vmModePods() map[netip.Addr]string {
	out := map[netip.Addr]string{}
	for _, svc := range b.in.Services {
		if svc == nil || svc.Labels[vmProxyNameLabel] != vmProxyName {
			continue
		}
		for _, s := range b.slices[serviceKey(svc)] {
			for _, ep := range s.Endpoints {
				for _, a := range ep.Addresses {
					if ip, err := netip.ParseAddr(a); err == nil {
						out[ip] = serviceKey(svc)
					}
				}
			}
		}
	}
	return out
}

// serves reports whether an endpoint may take new connections. A nil Ready is
// to be read as ready, per the EndpointSlice API. A terminating endpoint does
// not serve even when Ready says true, which publishNotReadyAddresses makes it
// do.
func serves(ep discoveryv1.Endpoint) bool {
	if terminating(ep) {
		return false
	}
	return ep.Conditions.Ready == nil || *ep.Conditions.Ready
}

func terminating(ep discoveryv1.Endpoint) bool {
	return ep.Conditions.Terminating != nil && *ep.Conditions.Terminating
}

func slicePort(s *discoveryv1.EndpointSlice, name string, proto v1.Protocol) (uint16, bool) {
	for _, p := range s.Ports {
		pName := ""
		if p.Name != nil {
			pName = *p.Name
		}
		pProto := v1.ProtocolTCP
		if p.Protocol != nil {
			pProto = *p.Protocol
		}
		if pName == name && pProto == proto && p.Port != nil && *p.Port > 0 && *p.Port <= 65535 {
			return uint16(*p.Port), true
		}
	}
	return 0, false
}

func serviceVIPs(svc *v1.Service) []netip.Addr {
	var out []netip.Addr
	for _, ing := range svc.Status.LoadBalancer.Ingress {
		if ip, err := netip.ParseAddr(ing.IP); err == nil && ip.Is4() {
			out = append(out, ip)
		}
	}
	return out
}

func nodeIPs(nodes []*v1.Node) []netip.Addr {
	var out []netip.Addr
	for _, n := range nodes {
		if n == nil {
			continue
		}
		for _, a := range n.Status.Addresses {
			if a.Type != v1.NodeInternalIP {
				continue
			}
			if ip, err := netip.ParseAddr(a.Address); err == nil && ip.Is4() {
				out = append(out, ip)
			}
		}
	}
	return sortedUnique(out, netip.Addr.Compare)
}

func groupSlices(all []*discoveryv1.EndpointSlice) map[string][]*discoveryv1.EndpointSlice {
	out := map[string][]*discoveryv1.EndpointSlice{}
	for _, s := range all {
		if s == nil {
			continue
		}
		svc := s.Labels[discoveryv1.LabelServiceName]
		if svc == "" {
			continue
		}
		k := s.Namespace + "/" + svc
		out[k] = append(out[k], s)
	}
	return out
}

func serviceKey(svc *v1.Service) string { return svc.Namespace + "/" + svc.Name }

func comparePortKey(x, y PortKey) int {
	return cmp.Or(
		x.VIP.Compare(y.VIP),
		strings.Compare(string(x.Protocol), string(y.Protocol)),
		cmp.Compare(x.Port, y.Port),
	)
}

func sortedUnique[T comparable](s []T, compare func(T, T) int) []T {
	if len(s) == 0 {
		return nil
	}
	slices.SortFunc(s, compare)
	return slices.Compact(s)
}
