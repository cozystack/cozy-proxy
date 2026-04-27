package proxy

import corev1 "k8s.io/api/core/v1"

type ProxyProcessor interface {
	InitRules() error
	EnsureRules(SvcIP, PodIP string) error
	DeleteRules(SvcIP, PodIP string) error
	CleanupRules(KeepMap map[string]string) error

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
}

// PortFilterEntry describes a port-filter desired state in the controller's
// reconciliation snapshot. Keyed by service IP in the caller map.
type PortFilterEntry struct {
	PodIP string
	Ports []corev1.ServicePort
}
