package proxy

import corev1 "k8s.io/api/core/v1"

type ProxyProcessor interface {
	InitRules() error

	// EnsureEgressSNAT programs the pod_svc entry (pod IP → service IP) read
	// by the egress_snat chain, so traffic leaving the backend is seen with
	// the service IP as its source.
	//
	// Every node programs it, for every managed service, whether or not it
	// hosts the backend. A reply from the backend to an intra-cluster client
	// is handed straight to the client's node over the overlay: it never
	// traverses the backend node's netfilter hooks, and the client's node is
	// then the only place left where the source can still be rewritten.
	EnsureEgressSNAT(SvcIP, PodIP string) error

	// DeleteEgressSNAT removes the pod_svc entry for the pair. No-op if absent.
	DeleteEgressSNAT(SvcIP, PodIP string) error

	// EnsureIngressDNAT programs the svc_pod entry (service IP → pod IP) read
	// by the ingress_dnat chain, so traffic addressed to the service IP is
	// delivered to the backend.
	//
	// Only the node hosting the backend may program it. On any other node the
	// rewrite would happen before the packet even leaves, and the hosting node
	// would then record a conntrack tuple the reply can no longer match.
	EnsureIngressDNAT(SvcIP, PodIP string) error

	// DeleteIngressDNAT removes the svc_pod entry for the pair. No-op if absent.
	DeleteIngressDNAT(SvcIP, PodIP string) error

	// CleanupRules reconciles both maps against the desired state. Both
	// arguments map service IP → pod IP: keepEgress covers every managed
	// service, keepIngress only the backends hosted on this node. Anything
	// else is removed, so state inherited from a build with different scoping
	// is purged at startup.
	CleanupRules(keepEgress, keepIngress map[string]string) error

	// EnsurePortFilter installs (or replaces) ingress port-filtering rules
	// for the given pod IP. Only TCP/UDP traffic destined to one of the
	// listed ports (in the post-DNAT pod IP) will be accepted; any other
	// port is dropped after the ingress_dnat rewrite. Pass an empty ports
	// slice to disable filtering for the (svcIP, podIP) pair (equivalent
	// to DeletePortFilter).
	EnsurePortFilter(SvcIP, PodIP string, Ports []corev1.ServicePort) error

	// DeletePortFilter removes any port-filtering rules previously installed
	// for the (svcIP, podIP) pair. No-op if none exist.
	DeletePortFilter(SvcIP, PodIP string) error

	// CleanupPortFilters keeps only the port-filter entries listed in
	// keepFilters. Any stale entries are removed. The PortFilterEntry struct
	// carries both the pod IP (used as the actual nft key) and the ports.
	CleanupPortFilters(keepFilters map[string]PortFilterEntry) error

	// EnsureICMPAllow adds the pod IP to the ICMP allowlist consulted by the
	// port_filter chain. With this in place, ICMP traffic to a pod that is
	// otherwise port-filtered is accepted instead of dropped (preserves ping,
	// PMTU discovery, ICMP unreachable signalling). Idempotent.
	EnsureICMPAllow(SvcIP, PodIP string) error

	// DeleteICMPAllow removes the pod IP from the ICMP allowlist. No-op if
	// not present.
	DeleteICMPAllow(SvcIP, PodIP string) error

	// CleanupICMPAllow keeps only the entries listed in keepICMP (svcIP →
	// podIP) in the ICMP allowlist; everything else is removed.
	CleanupICMPAllow(keepICMP map[string]string) error
}

// PortFilterEntry describes a port-filter desired state in the controller's
// reconciliation snapshot. Keyed by service IP in the caller map.
type PortFilterEntry struct {
	PodIP string
	Ports []corev1.ServicePort
}
