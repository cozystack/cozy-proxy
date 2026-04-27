package controllers

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func svcWith(annot map[string]string) *v1.Service {
	return &v1.Service{ObjectMeta: metav1.ObjectMeta{Annotations: annot}}
}

func TestHasWholeIPAnnotation(t *testing.T) {
	cases := []struct {
		name   string
		svc    *v1.Service
		expect bool
	}{
		{"true value", svcWith(map[string]string{"networking.cozystack.io/wholeIP": "true"}), true},
		{"false value", svcWith(map[string]string{"networking.cozystack.io/wholeIP": "false"}), true},
		{"absent annotation", svcWith(map[string]string{}), false},
		{"nil annotations", &v1.Service{}, false},
		{"unrelated annotation", svcWith(map[string]string{"foo": "bar"}), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := hasWholeIPAnnotation(c.svc); got != c.expect {
				t.Errorf("hasWholeIPAnnotation = %v, want %v", got, c.expect)
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
		{"true value", svcWith(map[string]string{"networking.cozystack.io/wholeIP": "true"}), true},
		{"false value", svcWith(map[string]string{"networking.cozystack.io/wholeIP": "false"}), false},
		{"absent annotation defaults to passthrough", svcWith(map[string]string{}), true},
		{"nil annotations defaults to passthrough", &v1.Service{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := wholeIPPassthrough(c.svc); got != c.expect {
				t.Errorf("wholeIPPassthrough = %v, want %v", got, c.expect)
			}
		})
	}
}
