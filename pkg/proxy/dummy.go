package proxy

import "fmt"

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
