package controllers

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cozystack/cozy-proxy/pkg/l4"
)

// fakeL4Datapath records the states it is asked to program.
type fakeL4Datapath struct {
	mu      sync.Mutex
	synced  []l4.State
	failing bool
}

func (f *fakeL4Datapath) setFailing(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failing = v
}

func (f *fakeL4Datapath) Sync(st l4.State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failing {
		return errors.New("commit refused")
	}
	f.synced = append(f.synced, st)
	return nil
}

func (f *fakeL4Datapath) Teardown() error { return nil }

func (f *fakeL4Datapath) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.synced)
}

func (f *fakeL4Datapath) last() (l4.State, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.synced) == 0 {
		return l4.State{}, false
	}
	return f.synced[len(f.synced)-1], true
}

// fakePurger runs the predicate over a fixed set of flows, as the conntrack
// table would hold them.
type fakePurger struct {
	flows   []l4.Flow
	calls   int
	purged  []l4.Flow
	failing bool
}

func (f *fakePurger) Purge(stale func(l4.Flow) bool) (uint, error) {
	f.calls++
	if f.failing {
		return 0, errors.New("dump interrupted")
	}
	var n uint
	var left []l4.Flow
	for _, fl := range f.flows {
		if stale(fl) {
			f.purged = append(f.purged, fl)
			n++
			continue
		}
		left = append(left, fl)
	}
	f.flows = left
	return n, nil
}

const l4Node = "node-a"

func l4Svc(name, vip string) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "ns",
			Name:        name,
			Labels:      map[string]string{l4.ProxyLabel: l4.ProxyLabelValue},
			Annotations: map[string]string{l4.CiliumTypeAnnotation: l4.CiliumTypeClusterIP},
		},
		Spec: v1.ServiceSpec{
			Type:                  v1.ServiceTypeLoadBalancer,
			ExternalTrafficPolicy: v1.ServiceExternalTrafficPolicyLocal,
			Ports:                 []v1.ServicePort{{Name: "pg", Port: 5432, Protocol: v1.ProtocolTCP}},
		},
		Status: v1.ServiceStatus{LoadBalancer: v1.LoadBalancerStatus{
			Ingress: []v1.LoadBalancerIngress{{IP: vip}},
		}},
	}
}

func l4Slice(svc string, ips ...string) *discoveryv1.EndpointSlice {
	name, port, proto, ready, node := "pg", int32(5432), v1.ProtocolTCP, true, l4Node
	s := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns",
			Name:      svc + "-1",
			Labels:    map[string]string{discoveryv1.LabelServiceName: svc},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
		Ports:       []discoveryv1.EndpointPort{{Name: &name, Port: &port, Protocol: &proto}},
	}
	for _, ip := range ips {
		s.Endpoints = append(s.Endpoints, discoveryv1.Endpoint{
			Addresses:  []string{ip},
			Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			NodeName:   &node,
		})
	}
	return s
}

func l4Input(slices ...*discoveryv1.EndpointSlice) l4.Input {
	return l4.Input{
		NodeName:       l4Node,
		Services:       []*v1.Service{l4Svc("pg", "192.0.2.10")},
		EndpointSlices: slices,
		Announced:      map[string]bool{"ns/pg": true},
	}
}

func flowTo(backend string) l4.Flow {
	return l4.Flow{
		Protocol: 6,
		OrigDst:  netip.MustParseAddrPort("192.0.2.10:5432"),
		ReplySrc: netip.MustParseAddrPort(backend),
	}
}

// The first sync programs the state Build computes and purges once, since the
// previous instance may have left translations this one no longer programs.
func TestL4SyncProgramsAndPurgesOnFirstSync(t *testing.T) {
	// A flow the previous instance translated through a port the service no
	// longer has.
	oldPort := l4.Flow{
		Protocol: 6,
		OrigDst:  netip.MustParseAddrPort("192.0.2.10:5433"),
		ReplySrc: netip.MustParseAddrPort("10.0.0.1:5433"),
	}
	dp, ct := &fakeL4Datapath{}, &fakePurger{flows: []l4.Flow{flowTo("10.0.0.1:5432"), flowTo("10.0.0.9:5432"), oldPort}}
	c := &L4Controller{NodeName: l4Node, Datapath: dp, Conntrack: ct}

	in := l4Input(l4Slice("pg", "10.0.0.1"))
	if err := c.syncWith(in, false); err != nil {
		t.Fatalf("sync: %v", err)
	}

	want, _ := l4.Build(in)
	if got, ok := dp.last(); !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("programmed %+v, want %+v", got, want)
	}
	if ct.calls != 1 {
		t.Fatalf("the first sync must purge once, got %d", ct.calls)
	}
	// A TCP flow to a frontend still served is kept whatever its backend, as
	// kube-proxy would.
	if len(ct.purged) != 1 || ct.purged[0] != oldPort {
		t.Errorf("purged %+v, want only the flow through the port that is gone", ct.purged)
	}
}

// An unchanged state is neither reprogrammed nor purged again.
func TestL4SyncSkipsUnchangedState(t *testing.T) {
	dp, ct := &fakeL4Datapath{}, &fakePurger{}
	c := &L4Controller{NodeName: l4Node, Datapath: dp, Conntrack: ct}
	in := l4Input(l4Slice("pg", "10.0.0.1"))

	for i := 0; i < 3; i++ {
		if err := c.syncWith(in, false); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
	}
	if dp.count() != 1 || ct.calls != 1 {
		t.Errorf("an unchanged state must be programmed once, got %d syncs and %d purges", dp.count(), ct.calls)
	}

	// The periodic resync re-applies it anyway, so a table removed by hand
	// comes back, but has nothing to purge.
	if err := c.syncWith(in, true); err != nil {
		t.Fatalf("forced sync: %v", err)
	}
	if dp.count() != 2 || ct.calls != 1 {
		t.Errorf("a forced sync must reprogram without purging, got %d syncs and %d purges", dp.count(), ct.calls)
	}
}

// A TCP backend withdrawn from a frontend that remains keeps its connections
// until they end; its flows only go with the frontend.
func TestL4SyncPurgesTCPFlowsWithTheirFrontendOnly(t *testing.T) {
	dp, ct := &fakeL4Datapath{}, &fakePurger{}
	c := &L4Controller{NodeName: l4Node, Datapath: dp, Conntrack: ct}

	if err := c.syncWith(l4Input(l4Slice("pg", "10.0.0.1", "10.0.0.2")), false); err != nil {
		t.Fatalf("sync: %v", err)
	}
	ct.flows = []l4.Flow{flowTo("10.0.0.1:5432"), flowTo("10.0.0.2:5432")}

	// A backend added: nothing to purge.
	if err := c.syncWith(l4Input(l4Slice("pg", "10.0.0.1", "10.0.0.2", "10.0.0.3")), false); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if ct.calls != 1 {
		t.Errorf("adding a backend must not purge, got %d purges", ct.calls)
	}

	// A backend withdrawn: its connections are left alone.
	if err := c.syncWith(l4Input(l4Slice("pg", "10.0.0.1", "10.0.0.3")), false); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if ct.calls != 1 || len(ct.purged) != 0 {
		t.Errorf("withdrawing a TCP backend must not purge, got %d purges, purged %+v", ct.calls, ct.purged)
	}

	// The node stops announcing the service: every flow through it goes.
	gone := l4Input(l4Slice("pg", "10.0.0.1", "10.0.0.3"))
	gone.Announced = nil
	if err := c.syncWith(gone, false); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if ct.calls != 2 || len(ct.purged) != 2 {
		t.Errorf("losing the announcement must purge every flow, got %d purges, purged %+v", ct.calls, ct.purged)
	}
}

// A refused commit leaves the applied state as it was, and the next attempt
// commits even though the desired state did not change in between.
func TestL4SyncRetriesAFailedCommit(t *testing.T) {
	dp, ct := &fakeL4Datapath{failing: true}, &fakePurger{}
	c := &L4Controller{NodeName: l4Node, Datapath: dp, Conntrack: ct}
	in := l4Input(l4Slice("pg", "10.0.0.1"))

	if err := c.syncWith(in, false); err == nil {
		t.Fatal("a refused commit must be reported")
	}
	if ct.calls != 0 {
		t.Error("nothing may be purged before the commit succeeded")
	}

	dp.failing = false
	if err := c.syncWith(in, false); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if dp.count() != 1 || ct.calls != 1 {
		t.Errorf("the retry must commit and purge, got %d syncs and %d purges", dp.count(), ct.calls)
	}
}

// A failed purge is retried on the next sync, and still covers the VIP of a
// service that was removed in the meantime.
func TestL4SyncRetriesAFailedPurge(t *testing.T) {
	dp, ct := &fakeL4Datapath{}, &fakePurger{}
	c := &L4Controller{NodeName: l4Node, Datapath: dp, Conntrack: ct}

	if err := c.syncWith(l4Input(l4Slice("pg", "10.0.0.1")), false); err != nil {
		t.Fatalf("sync: %v", err)
	}

	// The service goes away, and the purge that follows fails.
	ct.flows = []l4.Flow{flowTo("10.0.0.1:5432")}
	ct.failing = true
	gone := l4.Input{NodeName: l4Node}
	if err := c.syncWith(gone, false); err == nil {
		t.Fatal("a failed purge must be reported")
	}

	ct.failing = false
	if err := c.syncWith(gone, false); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(ct.purged) != 1 {
		t.Errorf("the retried purge must still reach the removed service's flows, purged %+v", ct.purged)
	}
	if err := c.syncWith(gone, false); err != nil {
		t.Fatalf("sync: %v", err)
	}
	// The first sync, the failed one and its retry; the last sync has
	// nothing left to do.
	if ct.calls != 3 {
		t.Errorf("purges = %d, want 3", ct.calls)
	}
}

var l2StatusGVR = schema.GroupVersionResource{Group: "metallb.io", Version: "v1beta1", Resource: "servicel2statuses"}

func l2Status(name, node, svcNS, svcName string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion("metallb.io/v1beta1")
	u.SetKind("ServiceL2Status")
	u.SetNamespace("metallb-system")
	u.SetName(name)
	u.SetLabels(map[string]string{"metallb.io/node": node})
	_ = unstructured.SetNestedField(u.Object, node, "status", "node")
	_ = unstructured.SetNestedField(u.Object, svcName, "status", "serviceName")
	_ = unstructured.SetNestedField(u.Object, svcNS, "status", "serviceNamespace")
	return u
}

// Wiring: the controller reads Services, EndpointSlices, Nodes and MetalLB's
// ServiceL2Status from the API, and programs what Build makes of them.
func TestL4ControllerProgramsFromTheAPI(t *testing.T) {
	node := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{Name: l4Node},
		Status:     v1.NodeStatus{Addresses: []v1.NodeAddress{{Type: v1.NodeInternalIP, Address: "10.200.24.11"}}},
	}
	cs := fake.NewSimpleClientset(l4Svc("pg", "192.0.2.10"), l4Slice("pg", "10.0.0.1"), node)
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{l2StatusGVR: "ServiceL2StatusList"},
		// Another node's status must not make this node an announcer.
		l2Status("l2-other", "node-b", "ns", "pg"),
	)

	dp := &fakeL4Datapath{}
	c := &L4Controller{
		Clientset:       cs,
		Dynamic:         dyn,
		NodeName:        l4Node,
		Datapath:        dp,
		Conntrack:       &fakePurger{},
		MinSyncInterval: time.Millisecond,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.Start(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Start returned %v", err)
		}
	}()

	notAnnounced := func(st l4.State) bool {
		return len(st.VIPs) == 1 && len(st.Ports) == 1 && len(st.Rules) == 0 && len(st.NodeIPs) == 1
	}
	waitFor(t, dp, "the VIP guarded but not translated", notAnnounced)

	// MetalLB elects this node.
	if _, err := dyn.Resource(l2StatusGVR).Namespace("metallb-system").Create(ctx,
		l2Status("l2-here", l4Node, "ns", "pg"), metav1.CreateOptions{}); err != nil {
		t.Fatalf("creating the ServiceL2Status: %v", err)
	}
	waitFor(t, dp, "the VIP translated to the local backend", func(st l4.State) bool {
		return len(st.Rules) == 1 && len(st.Rules[0].Backends) == 1 &&
			st.Rules[0].Backends[0].IP == netip.MustParseAddr("10.0.0.1")
	})

	// The backend goes away.
	if _, err := cs.DiscoveryV1().EndpointSlices("ns").Update(ctx, l4Slice("pg"), metav1.UpdateOptions{}); err != nil {
		t.Fatalf("updating the EndpointSlice: %v", err)
	}
	waitFor(t, dp, "the port dropped for lack of backend", func(st l4.State) bool {
		return len(st.Rules) == 1 && len(st.Rules[0].Backends) == 0
	})
}

func waitFor(t *testing.T, dp *fakeL4Datapath, what string, ok func(l4.State) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, synced := dp.last(); synced && ok(st) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	st, _ := dp.last()
	t.Fatalf("timed out waiting for %s; last programmed state: %+v", what, st)
}

// Without a node name the mode cannot tell what is local: it must refuse to
// program anything, and must not take the process down with it — the VM mode
// runs in the same manager.
func TestL4ControllerWithoutNodeNameProgramsNothing(t *testing.T) {
	dp := &fakeL4Datapath{}
	c := &L4Controller{Datapath: dp, Conntrack: &fakePurger{}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := c.Start(ctx); err != nil {
		t.Errorf("Start must not fail the manager, got %v", err)
	}
	if dp.count() != 0 {
		t.Errorf("nothing may be programmed without a node name, got %d syncs", dp.count())
	}
}

// A forced pass — the first one, or the periodic resync that restores a table
// altered by hand — must stay forced until it succeeds. Retried as an ordinary
// pass, it would find the desired state unchanged and skip the commit.
func TestL4RunKeepsForcingUntilAForcedPassSucceeds(t *testing.T) {
	in := l4Input(l4Slice("pg", "10.0.0.1"))
	st, _ := l4.Build(in)
	dp := &fakeL4Datapath{failing: true}
	c := &L4Controller{
		NodeName:        l4Node,
		Datapath:        dp,
		Conntrack:       &fakePurger{},
		MinSyncInterval: time.Millisecond,
		RetryInterval:   5 * time.Millisecond,
		ResyncInterval:  time.Hour,
		applied:         &st, // what the datapath last committed, as far as we know
		dirty:           make(chan struct{}, 1),
		input:           func() l4.Input { return in },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.run(ctx); close(done) }()
	defer func() { cancel(); <-done }()

	time.Sleep(30 * time.Millisecond)
	dp.setFailing(false)
	waitFor(t, dp, "the forced pass committed on retry", func(got l4.State) bool {
		return reflect.DeepEqual(got, st)
	})
}
