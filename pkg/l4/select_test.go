package l4

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// l4Service builds a LoadBalancer service carrying the L4 label and the Cilium
// annotation, with externalTrafficPolicy Local: the shape the L4 mode manages.
func l4Service(ns, name string, vips ...string) *v1.Service {
	svc := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   ns,
			Name:        name,
			Labels:      map[string]string{ProxyLabel: ProxyLabelValue},
			Annotations: map[string]string{CiliumTypeAnnotation: CiliumTypeClusterIP},
		},
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyLocal,
		},
	}
	for _, ip := range vips {
		svc.Status.LoadBalancer.Ingress = append(svc.Status.LoadBalancer.Ingress, v1.LoadBalancerIngress{IP: ip})
	}
	return svc
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*v1.Service)
		want   Selection
	}{
		{"label, annotation, eTP Local", func(*v1.Service) {}, Managed},
		{"no label", func(s *v1.Service) { delete(s.Labels, ProxyLabel) }, NotSelected},
		{"label with another value", func(s *v1.Service) { s.Labels[ProxyLabel] = "kube-router" }, NotSelected},
		// Cilium still translates the VIP: programming it too would give the
		// address two owners.
		{"annotation missing", func(s *v1.Service) { delete(s.Annotations, CiliumTypeAnnotation) }, Ignored},
		{"annotation with another value", func(s *v1.Service) { s.Annotations[CiliumTypeAnnotation] = "LoadBalancer" }, Ignored},
		// The VM mode owns the service; it must keep its behavior untouched.
		{"also selected by the VM mode", func(s *v1.Service) {
			s.Labels["service.kubernetes.io/service-proxy-name"] = "cozy-proxy"
		}, Ignored},
		{"not a LoadBalancer", func(s *v1.Service) { s.Spec.Type = v1.ServiceTypeClusterIP }, Ignored},
		// Cilium has let go of the VIP, so it must at least be guarded, but
		// phase 1 cannot program it.
		{"eTP Cluster", func(s *v1.Service) {
			s.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyCluster
		}, Unsupported},
		{"eTP unset defaults to Cluster", func(s *v1.Service) { s.Spec.ExternalTrafficPolicy = "" }, Unsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			svc := l4Service("ns", "svc", "192.0.2.10")
			c.mutate(svc)
			got, reason := Classify(svc)
			if got != c.want {
				t.Errorf("Classify = %v (%s), want %v", got, reason, c.want)
			}
			if got != Managed && got != NotSelected && reason == "" {
				t.Errorf("a %v service must come with a reason", got)
			}
		})
	}
}

func TestClassifyNil(t *testing.T) {
	if got, _ := Classify(nil); got != NotSelected {
		t.Errorf("Classify(nil) = %v, want NotSelected", got)
	}
}
