package proxy

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"
)

type DummyProxyProcessor struct{}

func (d *DummyProxyProcessor) InitRules() error {
	fmt.Println("InitRules called")
	return nil
}

func (d *DummyProxyProcessor) EnsureEgressSNAT(SvcIP, PodIP string) error {
	fmt.Printf("EnsureEgressSNAT called with SvcIP: %s, PodIP: %s\n", SvcIP, PodIP)
	return nil
}

func (d *DummyProxyProcessor) DeleteEgressSNAT(SvcIP, PodIP string) error {
	fmt.Printf("DeleteEgressSNAT called with SvcIP: %s, PodIP: %s\n", SvcIP, PodIP)
	return nil
}

func (d *DummyProxyProcessor) EnsureIngressDNAT(SvcIP, PodIP string) error {
	fmt.Printf("EnsureIngressDNAT called with SvcIP: %s, PodIP: %s\n", SvcIP, PodIP)
	return nil
}

func (d *DummyProxyProcessor) DeleteIngressDNAT(SvcIP, PodIP string) error {
	fmt.Printf("DeleteIngressDNAT called with SvcIP: %s, PodIP: %s\n", SvcIP, PodIP)
	return nil
}

func (d *DummyProxyProcessor) CleanupRules(keepEgress, keepIngress map[string]string) error {
	fmt.Printf("CleanupRules called with keepEgress: %v, keepIngress: %v\n", keepEgress, keepIngress)
	return nil
}

func (d *DummyProxyProcessor) EnsurePortFilter(SvcIP, PodIP string, Ports []corev1.ServicePort) error {
	fmt.Printf("EnsurePortFilter called with SvcIP: %s, PodIP: %s, Ports: %+v\n", SvcIP, PodIP, Ports)
	return nil
}

func (d *DummyProxyProcessor) DeletePortFilter(SvcIP, PodIP string) error {
	fmt.Printf("DeletePortFilter called with SvcIP: %s, PodIP: %s\n", SvcIP, PodIP)
	return nil
}

func (d *DummyProxyProcessor) CleanupPortFilters(keep map[string]PortFilterEntry) error {
	fmt.Printf("CleanupPortFilters called with %d entries\n", len(keep))
	return nil
}

func (d *DummyProxyProcessor) EnsureICMPAllow(SvcIP, PodIP string) error {
	fmt.Printf("EnsureICMPAllow called with SvcIP: %s, PodIP: %s\n", SvcIP, PodIP)
	return nil
}

func (d *DummyProxyProcessor) DeleteICMPAllow(SvcIP, PodIP string) error {
	fmt.Printf("DeleteICMPAllow called with SvcIP: %s, PodIP: %s\n", SvcIP, PodIP)
	return nil
}

func (d *DummyProxyProcessor) CleanupICMPAllow(keep map[string]string) error {
	fmt.Printf("CleanupICMPAllow called with %d entries\n", len(keep))
	return nil
}

// Compile-time assertion that DummyProxyProcessor satisfies ProxyProcessor.
var _ ProxyProcessor = (*DummyProxyProcessor)(nil)
