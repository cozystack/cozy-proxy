package proxy

import corev1 "k8s.io/api/core/v1"

type ProxyProcessor interface {
	InitRules() error
	EnsureRules(SvcIP, PodIP string) error
	DeleteRules(SvcIP, PodIP string) error
	CleanupRules(KeepMap map[string]string) error

	// EnsurePortFilter installs (or replaces) ingress port-filtering rules
	// for the given service IP. Only TCP/UDP traffic destined to one of the
	// listed ports will be accepted; any other port is dropped before the
	// SNAT/DNAT rewrite. Pass an empty ports slice to disable filtering for
	// SvcIP (equivalent to DeletePortFilter).
	EnsurePortFilter(SvcIP string, Ports []corev1.ServicePort) error

	// DeletePortFilter removes any port-filtering rules previously installed
	// for SvcIP. No-op if none exist.
	DeletePortFilter(SvcIP string) error

	// CleanupPortFilters keeps only the port-filter entries listed in
	// keepFilters (svcIP → ports). Any stale entries are removed. Used at
	// controller startup to reconcile against the live cluster snapshot.
	CleanupPortFilters(keepFilters map[string][]corev1.ServicePort) error
}
