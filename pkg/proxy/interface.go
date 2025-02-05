package proxy

type ProxyProcessor interface {
	InitRules() error
	EnsureRules(SvcIP, PodIP string) error
	DeleteRules(SvcIP, PodIP string) error
	CleanupRules(KeepMap map[string]string) error
}
