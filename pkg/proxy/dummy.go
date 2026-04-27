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

func (d *DummyProxyProcessor) EnsureRules(SvcIP, PodIP string) error {
	fmt.Printf("EnsureRules called with SvcIP: %s, PodIP: %s\n", SvcIP, PodIP)
	return nil
}

func (d *DummyProxyProcessor) DeleteRules(SvcIP, PodIP string) error {
	fmt.Printf("DeleteRules called with SvcIP: %s, PodIP: %s\n", SvcIP, PodIP)
	return nil
}

func (d *DummyProxyProcessor) CleanupRules(KeepMap map[string]string) error {
	fmt.Println("CleanupRules called with KeepMap:", KeepMap)
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

// Compile-time assertion that DummyProxyProcessor satisfies ProxyProcessor.
var _ ProxyProcessor = (*DummyProxyProcessor)(nil)
