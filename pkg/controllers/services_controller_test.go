package controllers

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func svcWith(annot map[string]string) *v1.Service {
	return &v1.Service{ObjectMeta: metav1.ObjectMeta{Annotations: annot}}
}

func svcWithLabels(labels map[string]string) *v1.Service {
	return &v1.Service{ObjectMeta: metav1.ObjectMeta{Labels: labels}}
}

func TestIsCozyProxyService(t *testing.T) {
	cases := []struct {
		name   string
		svc    *v1.Service
		expect bool
	}{
		{"label with correct value", svcWithLabels(map[string]string{"service.kubernetes.io/service-proxy-name": "cozy-proxy"}), true},
		{"label with other value", svcWithLabels(map[string]string{"service.kubernetes.io/service-proxy-name": "kube-router"}), false},
		{"label absent", svcWithLabels(map[string]string{}), false},
		{"nil service", nil, false},
		{"only wholeIP annotation no label", svcWith(map[string]string{"networking.cozystack.io/wholeIP": "true"}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isCozyProxyService(c.svc); got != c.expect {
				t.Errorf("isCozyProxyService = %v, want %v", got, c.expect)
			}
		})
	}
}

func TestWholeIPPassthrough(t *testing.T) {
	cases := []struct {
		name   string
		svc    *v1.Service
		expect bool
	}{
		{"explicit true", svcWith(map[string]string{"networking.cozystack.io/wholeIP": "true"}), true},
		{"explicit false", svcWith(map[string]string{"networking.cozystack.io/wholeIP": "false"}), false},
		{"empty value", svcWith(map[string]string{"networking.cozystack.io/wholeIP": ""}), false},
		{"absent annotation defaults to port-filter", svcWith(map[string]string{}), false},
		{"nil annotations defaults to port-filter", &v1.Service{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := wholeIPPassthrough(c.svc); got != c.expect {
				t.Errorf("wholeIPPassthrough = %v, want %v", got, c.expect)
			}
		})
	}
}

func TestAllowICMP(t *testing.T) {
	cases := []struct {
		name   string
		svc    *v1.Service
		expect bool
	}{
		{"explicit true", svcWith(map[string]string{"networking.cozystack.io/allowICMP": "true"}), true},
		{"explicit false", svcWith(map[string]string{"networking.cozystack.io/allowICMP": "false"}), false},
		{"empty value", svcWith(map[string]string{"networking.cozystack.io/allowICMP": ""}), false},
		{"absent annotation defaults to false", svcWith(map[string]string{}), false},
		{"nil annotations defaults to false", &v1.Service{}, false},
		{"unrelated annotation", svcWith(map[string]string{"networking.cozystack.io/wholeIP": "false"}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := allowICMP(c.svc); got != c.expect {
				t.Errorf("allowICMP = %v, want %v", got, c.expect)
			}
		})
	}
}
