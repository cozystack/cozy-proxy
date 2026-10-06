// Package l4 computes the desired state of cozy-proxy's L4 LoadBalancer mode:
// which services it takes over from Cilium, and what this node must program for
// them. It holds no datapath code, so it can be tested anywhere; the nftables
// side lives in pkg/proxy.
//
// See docs/rfc/l4-loadbalancer-mode.md for the model.
package l4

import (
	v1 "k8s.io/api/core/v1"
)

const (
	// ProxyLabel selects a Service for the L4 mode. It is deliberately not the
	// VM mode's service.kubernetes.io/service-proxy-name: that label also makes
	// Cilium drop the ClusterIP and the NodePort, while the L4 mode only takes
	// over the public IP.
	ProxyLabel      = "networking.cozystack.io/lb-proxy"
	ProxyLabelValue = "cozy-proxy"

	// CiliumTypeAnnotation set to CiliumTypeClusterIP makes Cilium install only
	// the ClusterIP frontend, releasing the VIP. The L4 mode requires it: without
	// it Cilium keeps translating the VIP and the two would race.
	CiliumTypeAnnotation = "service.cilium.io/type"
	CiliumTypeClusterIP  = "ClusterIP"

	vmProxyNameLabel = "service.kubernetes.io/service-proxy-name"
	vmProxyName      = "cozy-proxy"
)

// Selection says how the L4 mode treats a Service.
type Selection int

const (
	// NotSelected services do not carry the label and are none of our business.
	NotSelected Selection = iota
	// Ignored services carry the label but must not be touched, because some
	// other component still owns the VIP.
	Ignored
	// Unsupported services are ours — Cilium has released the VIP — but this
	// version cannot program them. Their VIP is still guarded, so that its
	// traffic is dropped instead of being routed back to the gateway.
	Unsupported
	// Managed services are programmed.
	Managed
)

func (s Selection) String() string {
	switch s {
	case NotSelected:
		return "NotSelected"
	case Ignored:
		return "Ignored"
	case Unsupported:
		return "Unsupported"
	case Managed:
		return "Managed"
	}
	return "Selection(?)"
}

// Classify decides how the L4 mode treats svc. The reason explains anything
// other than Managed or NotSelected, and is meant for the log.
//
// The label is the trust anchor, not the annotation: the kubevirt CCM copies a
// tenant Service's annotations onto the infra Service, so a tenant can set the
// annotation on an infra object, but not the label.
func Classify(svc *v1.Service) (Selection, string) {
	if svc == nil || svc.Labels[ProxyLabel] != ProxyLabelValue {
		return NotSelected, ""
	}
	if svc.Labels[vmProxyNameLabel] == vmProxyName {
		return Ignored, "also selected by the VM mode, which owns it"
	}
	if svc.Spec.Type != v1.ServiceTypeLoadBalancer {
		return Ignored, "not a LoadBalancer service"
	}
	if svc.Annotations[CiliumTypeAnnotation] != CiliumTypeClusterIP {
		return Ignored, "missing " + CiliumTypeAnnotation + ": " + CiliumTypeClusterIP + ", Cilium still owns the VIP"
	}
	if svc.Spec.ExternalTrafficPolicy != v1.ServiceExternalTrafficPolicyLocal {
		return Unsupported, "externalTrafficPolicy must be Local"
	}
	return Managed, ""
}
