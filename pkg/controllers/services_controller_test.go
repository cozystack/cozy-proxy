package controllers

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/client-go/tools/cache"

	nat "github.com/cozystack/cozy-proxy/pkg/proxy"
)

// epOnNode builds an Endpoints with a single address, optionally pinned to a
// node. Pass an empty node to omit NodeName, as an endpoint with no scheduling
// information would have.
func epOnNode(podIP, node string) *v1.Endpoints {
	addr := v1.EndpointAddress{IP: podIP}
	if node != "" {
		addr.NodeName = &node
	}
	return &v1.Endpoints{
		Subsets: []v1.EndpointSubset{{Addresses: []v1.EndpointAddress{addr}}},
	}
}

// lbService builds a LoadBalancer service already assigned the given IP.
func lbService(svcIP string, annot map[string]string) *v1.Service {
	return &v1.Service{
		ObjectMeta: metav1.ObjectMeta{Annotations: annot},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{{IP: svcIP}},
			},
		},
	}
}

// recordingProxy captures which datapath calls a controller makes.
type recordingProxy struct {
	nat.DummyProxyProcessor
	mu          sync.Mutex
	calls       []string
	keepEgress  map[string]string
	keepIngress map[string]string

	// failEgress makes EnsureEgressSNAT fail, standing in for a refused
	// nftables commit.
	failEgress bool
	// failPortFilter makes EnsurePortFilter fail.
	failPortFilter bool
	// failCleanup makes CleanupRules fail.
	failCleanup bool
	// failDeleteEgress makes DeleteEgressSNAT fail.
	failDeleteEgress bool
	// failDeleteIngress makes DeleteIngressDNAT fail.
	failDeleteIngress bool
}

func (r *recordingProxy) EnsureEgressSNAT(svcIP, podIP string) error {
	r.record("EnsureEgressSNAT")
	if r.failEgress {
		return errors.New("commit refused")
	}
	return nil
}

func (r *recordingProxy) DeleteEgressSNAT(svcIP, podIP string) error {
	r.record("DeleteEgressSNAT")
	if r.failDeleteEgress {
		return errors.New("commit refused")
	}
	return nil
}

func (r *recordingProxy) EnsureIngressDNAT(svcIP, podIP string) error {
	r.record("EnsureIngressDNAT")
	return nil
}

func (r *recordingProxy) DeleteIngressDNAT(svcIP, podIP string) error {
	r.record("DeleteIngressDNAT")
	if r.failDeleteIngress {
		return errors.New("commit refused")
	}
	return nil
}

func (r *recordingProxy) CleanupRules(keepEgress, keepIngress map[string]string) error {
	r.record("CleanupRules")
	r.keepEgress = keepEgress
	r.keepIngress = keepIngress
	if r.failCleanup {
		return errors.New("commit refused")
	}
	return nil
}

func (r *recordingProxy) EnsurePortFilter(svcIP, podIP string, ports []v1.ServicePort) error {
	r.record("EnsurePortFilter")
	if r.failPortFilter {
		return errors.New("commit refused")
	}
	return nil
}

func (r *recordingProxy) DeletePortFilter(svcIP, podIP string) error {
	r.record("DeletePortFilter")
	return nil
}

// record appends under the lock: the retry loop and the informer callbacks
// both drive the proxy in the concurrency test.
func (r *recordingProxy) record(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *recordingProxy) has(call string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if c == call {
			return true
		}
	}
	return false
}

func TestServesEndpoint(t *testing.T) {
	cases := []struct {
		name     string
		nodeName string
		ep       *v1.Endpoints
		expect   bool
	}{
		{"backend on this node", "node-a", epOnNode("10.0.0.1", "node-a"), true},
		{"backend on another node", "node-a", epOnNode("10.0.0.1", "node-b"), false},
		{"endpoint without NodeName is programmed", "node-a", epOnNode("10.0.0.1", ""), true},
		{"NODE_NAME unset programs everything", "", epOnNode("10.0.0.1", "node-b"), true},
		{"invalid endpoint is programmed", "node-a", &v1.Endpoints{}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctrl := &ServicesController{NodeName: c.nodeName}
			if got := ctrl.servesEndpoint(c.ep); got != c.expect {
				t.Errorf("servesEndpoint = %v, want %v", got, c.expect)
			}
		})
	}
}

// The owning node programs both halves of the datapath.
func TestApplyRulesProgramsBothHalvesOnOwningNode(t *testing.T) {
	svc := lbService("192.0.2.10", map[string]string{"networking.cozystack.io/wholeIP": "false"})

	local := &recordingProxy{}
	localCtrl := &ServicesController{Proxy: local, NodeName: "node-a"}
	localCtrl.applyRules(svc, epOnNode("10.0.0.1", "node-a"), "test")

	for _, want := range []string{"EnsureEgressSNAT", "EnsureIngressDNAT", "EnsurePortFilter"} {
		if !local.has(want) {
			t.Errorf("owning node must call %s, got %v", want, local.calls)
		}
	}
}

// A non-owning node must not translate the destination — doing so
// desynchronises conntrack on the owning node and gets the reply dropped by
// port_filter — but it must still program the source rewrite.
//
// That rewrite is the only thing that repairs a reply reaching this node
// straight over the overlay, which is what happens whenever the client is
// inside the cluster and kube-ovn SNATs it to this node's own address.
func TestApplyRulesKeepsEgressSNATOnRemoteBackend(t *testing.T) {
	svc := lbService("192.0.2.10", map[string]string{"networking.cozystack.io/wholeIP": "false"})

	remote := &recordingProxy{}
	remoteCtrl := &ServicesController{Proxy: remote, NodeName: "node-a"}
	remoteCtrl.applyRules(svc, epOnNode("10.0.0.1", "node-b"), "test")

	if !remote.has("EnsureEgressSNAT") {
		t.Errorf("non-owning node must still program the source rewrite, got %v", remote.calls)
	}
	if remote.has("DeleteEgressSNAT") {
		t.Errorf("non-owning node must not withdraw the source rewrite, got %v", remote.calls)
	}
	if remote.has("EnsureIngressDNAT") || remote.has("EnsurePortFilter") {
		t.Errorf("non-owning node must not program the ingress half, got %v", remote.calls)
	}
	if !remote.has("DeleteIngressDNAT") {
		t.Errorf("non-owning node must withdraw an inherited destination rewrite, got %v", remote.calls)
	}
}

// A migrated VM leaves its old mapping behind on the node it came from.
func TestWithdrawStaleEndpoint(t *testing.T) {
	svc := lbService("192.0.2.10", map[string]string{"networking.cozystack.io/wholeIP": "false"})

	moved := &recordingProxy{}
	movedCtrl := &ServicesController{Proxy: moved, NodeName: "node-a"}
	movedCtrl.withdrawStaleEndpoint(svc, epOnNode("10.0.0.1", "node-a"), "10.0.0.2", "test")
	// A pod IP that is gone must leave nothing behind, in either half: every
	// node carries its source rewrite, so every node has to drop it.
	for _, want := range []string{"DeleteIngressDNAT", "DeleteEgressSNAT"} {
		if !moved.has(want) {
			t.Errorf("changed pod IP must call %s, got %v", want, moved.calls)
		}
	}

	same := &recordingProxy{}
	sameCtrl := &ServicesController{Proxy: same, NodeName: "node-a"}
	sameCtrl.withdrawStaleEndpoint(svc, epOnNode("10.0.0.1", "node-a"), "10.0.0.1", "test")
	if len(same.calls) != 0 {
		t.Errorf("unchanged pod IP must not touch the datapath, got %v", same.calls)
	}
}

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

// The startup snapshot must keep every managed pair in the egress map and only
// the locally hosted ones in the ingress map. Handing the same set to both is
// exactly what leaves an intra-cluster client without a usable reply.
func TestCleanupRemovedServicesScopesKeepMaps(t *testing.T) {
	annot := map[string]string{"networking.cozystack.io/wholeIP": "false"}

	ctrl := &ServicesController{Proxy: &recordingProxy{}, NodeName: "node-a"}
	ctrl.Services = NewServiceMap()
	ctrl.Services.Set("ns", "local", &ServiceEndpoints{
		Service:  lbService("192.0.2.10", annot),
		Endpoint: epOnNode("10.0.0.1", "node-a"),
	})
	ctrl.Services.Set("ns", "remote", &ServiceEndpoints{
		Service:  lbService("192.0.2.11", annot),
		Endpoint: epOnNode("10.0.0.2", "node-b"),
	})
	// A service still waiting for its endpoint contributes to neither map.
	ctrl.Services.Set("ns", "pending", &ServiceEndpoints{
		Service:  lbService("192.0.2.12", annot),
		Endpoint: nil,
	})

	if err := ctrl.cleanupRemovedServices(); err != nil {
		t.Fatalf("cleanupRemovedServices: %v", err)
	}
	rec := ctrl.Proxy.(*recordingProxy)

	wantEgress := map[string]string{"192.0.2.10": "10.0.0.1", "192.0.2.11": "10.0.0.2"}
	if len(rec.keepEgress) != len(wantEgress) {
		t.Fatalf("keepEgress = %v, want %v", rec.keepEgress, wantEgress)
	}
	for svc, pod := range wantEgress {
		if rec.keepEgress[svc] != pod {
			t.Errorf("keepEgress[%s] = %q, want %q", svc, rec.keepEgress[svc], pod)
		}
	}

	wantIngress := map[string]string{"192.0.2.10": "10.0.0.1"}
	if len(rec.keepIngress) != len(wantIngress) {
		t.Fatalf("keepIngress = %v, want %v", rec.keepIngress, wantIngress)
	}
	if rec.keepIngress["192.0.2.10"] != "10.0.0.1" {
		t.Errorf("keepIngress = %v, want %v", rec.keepIngress, wantIngress)
	}
}

// A refused commit must not be forgotten: the informers only deliver events, so
// a service left unprogrammed would stay that way until the next one.
func TestFailedProgrammingIsQueuedForRetry(t *testing.T) {
	svc := lbService("192.0.2.10", map[string]string{"networking.cozystack.io/wholeIP": "false"})
	svc.Namespace, svc.Name = "ns", "svc1"
	ep := epOnNode("10.0.0.1", "node-a")

	px := &recordingProxy{failEgress: true}
	ctrl := &ServicesController{Proxy: px, NodeName: "node-a"}
	ctrl.applyRules(svc, ep, "test")

	keys, _, _ := ctrl.takePending()
	if len(keys) != 1 || keys[0] != "ns/svc1" {
		t.Fatalf("failed write must be queued, got %v", keys)
	}

	// A clean pass clears it again.
	px.failEgress = false
	ctrl.applyRules(svc, ep, "test")
	keys, _, _ = ctrl.takePending()
	if len(keys) != 0 {
		t.Errorf("clean pass must clear the queue, got %v", keys)
	}
}

// A port filter that could not be applied is an outage — the pod is filtered
// with no open port — so it must be queued too.
func TestFailedPortFilterIsQueuedForRetry(t *testing.T) {
	svc := lbService("192.0.2.10", map[string]string{"networking.cozystack.io/wholeIP": "false"})
	svc.Namespace, svc.Name = "ns", "svc2"

	px := &recordingProxy{failPortFilter: true}
	ctrl := &ServicesController{Proxy: px, NodeName: "node-a"}
	ctrl.applyRules(svc, epOnNode("10.0.0.1", "node-a"), "test")

	keys, _, _ := ctrl.takePending()
	if len(keys) != 1 || keys[0] != "ns/svc2" {
		t.Fatalf("failed port filter must be queued, got %v", keys)
	}
}

// The retry pass must re-apply from the stored state.
func TestRetryPendingReappliesDatapath(t *testing.T) {
	svc := lbService("192.0.2.10", map[string]string{"networking.cozystack.io/wholeIP": "false"})
	svc.Namespace, svc.Name = "ns", "svc3"
	ep := epOnNode("10.0.0.1", "node-a")

	px := &recordingProxy{failEgress: true}
	ctrl := &ServicesController{Proxy: px, NodeName: "node-a"}
	ctrl.Services = NewServiceMap()
	ctrl.Services.Set("ns", "svc3", &ServiceEndpoints{Service: svc, Endpoint: ep})
	ctrl.applyRules(svc, ep, "test")

	px.failEgress = false
	px.calls = nil
	ctrl.retryPending()

	for _, want := range []string{"EnsureEgressSNAT", "EnsureIngressDNAT", "EnsurePortFilter"} {
		if !px.has(want) {
			t.Errorf("retry must call %s, got %v", want, px.calls)
		}
	}
	if keys, _, _ := ctrl.takePending(); len(keys) != 0 {
		t.Errorf("successful retry must clear the queue, got %v", keys)
	}
}

// A service that disappeared between the failure and the retry must not be
// re-applied; its delete path has already withdrawn the rules.
func TestRetryPendingSkipsVanishedService(t *testing.T) {
	px := &recordingProxy{}
	ctrl := &ServicesController{Proxy: px, NodeName: "node-a"}
	ctrl.Services = NewServiceMap()
	ctrl.markPending("ns", "gone")

	ctrl.retryPending()
	if len(px.calls) != 0 {
		t.Errorf("vanished service must not be re-applied, got %v", px.calls)
	}
}

// A failed startup cleanup must be re-attempted rather than wait for the next
// event or the 12-hour informer resync.
func TestFailedCleanupIsQueuedAndRetried(t *testing.T) {
	px := &recordingProxy{failCleanup: true}
	ctrl := &ServicesController{Proxy: px, NodeName: "node-a"}
	ctrl.Services = NewServiceMap()

	if err := ctrl.cleanupRemovedServices(); err == nil {
		t.Fatal("cleanupRemovedServices must surface the failure")
	}
	ctrl.markCleanupPending()

	px.failCleanup = false
	px.calls = nil
	ctrl.retryPending()
	if !px.has("CleanupRules") {
		t.Errorf("cleanup must be retried, got %v", px.calls)
	}
	if _, _, pending := ctrl.takePending(); pending {
		t.Error("successful cleanup retry must clear the flag")
	}
}

func TestSplitKey(t *testing.T) {
	cases := []struct {
		key, ns, name string
		ok            bool
	}{
		{"ns/name", "ns", "name", true},
		{"ns/sub/name", "ns", "sub/name", true},
		{"noslash", "", "", false},
		{"/name", "", "", false},
		{"ns/", "", "", false},
		{"", "", "", false},
	}
	for _, c := range cases {
		ns, name, ok := splitKey(c.key)
		if ok != c.ok || ns != c.ns || name != c.name {
			t.Errorf("splitKey(%q) = (%q,%q,%v), want (%q,%q,%v)", c.key, ns, name, ok, c.ns, c.name, c.ok)
		}
	}
}

// The retry goroutine and the informer callbacks reconcile the same stored
// pair. The retry must read it under the map lock and hold the reconciliation
// lock while it programs, or it applies an endpoint the update has already
// withdrawn — pointing the service IP at a pod that is gone.
//
// Run with -race: an unsynchronized read of the shared Endpoint field shows up
// here, which is what reading it through ServiceMap.Get used to do.
func TestRetryIsSerializedAgainstEndpointUpdates(t *testing.T) {
	svc := lbService("192.0.2.10", map[string]string{"networking.cozystack.io/wholeIP": "false"})
	svc.Namespace, svc.Name = "ns", "svc"

	ctrl := &ServicesController{Proxy: &recordingProxy{}, NodeName: "node-a"}
	ctrl.Services = NewServiceMap()
	ctrl.Services.Set("ns", "svc", &ServiceEndpoints{
		Service:  svc,
		Endpoint: epOnNode("10.0.0.1", "node-a"),
	})

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Informer side: keep replacing the endpoint, as a migrating VM does.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			ctrl.Services.SetEndpoint("ns", "svc", epOnNode(fmt.Sprintf("10.0.0.%d", i%250+1), "node-a"))
		}
	}()

	// Retry side.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			ctrl.markPending("ns", "svc")
			ctrl.retryPending()
		}
	}()

	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// A withdrawal that failed cannot go through the service queue: by then the
// service is gone from the map. Left behind, a stale pod_svc entry rewrites the
// source of whatever pod next receives that IP.
func TestFailedWithdrawalIsQueuedAndRetried(t *testing.T) {
	px := &recordingProxy{failDeleteEgress: true}
	ctrl := &ServicesController{Proxy: px, NodeName: "node-a"}
	ctrl.Services = NewServiceMap()

	if err := ctrl.withdrawRules("192.0.2.10", "10.0.0.1", "test"); err == nil {
		t.Fatal("withdrawRules must surface the failure")
	}
	_, pending, _ := ctrl.takePending()
	if len(pending) != 1 || pending[0].svcIP != "192.0.2.10" || !pending[0].egress {
		t.Fatalf("failed withdrawal must be queued as a full one, got %+v", pending)
	}

	// Re-queue it and let the retry succeed.
	ctrl.markWithdrawal("192.0.2.10", "10.0.0.1", true)
	px.failDeleteEgress = false
	px.calls = nil
	ctrl.retryPending()

	for _, want := range []string{"DeleteIngressDNAT", "DeleteEgressSNAT"} {
		if !px.has(want) {
			t.Errorf("retry must call %s, got %v", want, px.calls)
		}
	}
	if _, pending, _ := ctrl.takePending(); len(pending) != 0 {
		t.Errorf("successful retry must clear the queue, got %+v", pending)
	}
}

// An endpoint that flaps back to the pod IP whose withdrawal failed must not
// have its freshly installed rules deleted by the queued removal.
func TestReprogrammingClearsQueuedWithdrawal(t *testing.T) {
	svc := lbService("192.0.2.10", map[string]string{"networking.cozystack.io/wholeIP": "false"})
	svc.Namespace, svc.Name = "ns", "svc"
	ep := epOnNode("10.0.0.1", "node-a")

	px := &recordingProxy{}
	ctrl := &ServicesController{Proxy: px, NodeName: "node-a"}
	ctrl.Services = NewServiceMap()
	ctrl.markWithdrawal("192.0.2.10", "10.0.0.1", true)

	ctrl.applyRules(svc, ep, "test")

	if _, pending, _ := ctrl.takePending(); len(pending) != 0 {
		t.Errorf("programming the pair again must drop its queued removal, got %+v", pending)
	}
}

// A node that stops hosting the backend withdraws only the ingress half, and
// must keep the cluster-wide source rewrite.
func TestIngressOnlyWithdrawalIsQueuedWithoutEgress(t *testing.T) {
	px := &recordingProxy{failDeleteIngress: true}
	ctrl := &ServicesController{Proxy: px, NodeName: "node-a"}

	if err := ctrl.withdrawIngressRules("192.0.2.10", "10.0.0.1", "test"); err == nil {
		t.Fatal("withdrawIngressRules must surface the failure")
	}
	_, pending, _ := ctrl.takePending()
	if len(pending) != 1 || pending[0].egress {
		t.Fatalf("ingress-only failure must not queue an egress withdrawal, got %+v", pending)
	}
}

// A full withdrawal supersedes an ingress-only one already queued for the pair.
func TestFullWithdrawalSupersedesIngressOnly(t *testing.T) {
	ctrl := &ServicesController{Proxy: &recordingProxy{}}
	ctrl.markWithdrawal("192.0.2.10", "10.0.0.1", true)
	ctrl.markWithdrawal("192.0.2.10", "10.0.0.1", false)

	_, pending, _ := ctrl.takePending()
	if len(pending) != 1 || !pending[0].egress {
		t.Fatalf("full withdrawal must win, got %+v", pending)
	}
}

// The startup snapshot must come from the informer stores, not from the map the
// callbacks fill. WaitForCacheSync returns once the store is populated, not
// once every initial callback has run, and reading the half-filled map made the
// purge delete a live mapping it then had to wait for an event to restore.
func TestSnapshotSourcePrefersInformerStores(t *testing.T) {
	managed := lbService("192.0.2.10", nil)
	managed.Namespace, managed.Name = "ns", "managed"
	managed.Labels = map[string]string{"service.kubernetes.io/service-proxy-name": "cozy-proxy"}

	unmanaged := lbService("192.0.2.11", nil)
	unmanaged.Namespace, unmanaged.Name = "ns", "unmanaged"

	noIP := &v1.Service{ObjectMeta: metav1.ObjectMeta{
		Namespace: "ns", Name: "noip",
		Labels: map[string]string{"service.kubernetes.io/service-proxy-name": "cozy-proxy"},
	}}

	noEndpoint := lbService("192.0.2.12", nil)
	noEndpoint.Namespace, noEndpoint.Name = "ns", "noep"
	noEndpoint.Labels = map[string]string{"service.kubernetes.io/service-proxy-name": "cozy-proxy"}

	svcStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	for _, s := range []*v1.Service{managed, unmanaged, noIP, noEndpoint} {
		if err := svcStore.Add(s); err != nil {
			t.Fatalf("seeding service store: %v", err)
		}
	}

	ep := epOnNode("10.0.0.1", "node-a")
	ep.Namespace, ep.Name = "ns", "managed"
	epStore := cache.NewStore(cache.MetaNamespaceKeyFunc)
	if err := epStore.Add(ep); err != nil {
		t.Fatalf("seeding endpoint store: %v", err)
	}

	ctrl := &ServicesController{Proxy: &recordingProxy{}, svcStore: svcStore, epStore: epStore}
	// Deliberately empty: this is the map the callbacks had not filled yet.
	ctrl.Services = NewServiceMap()

	got := ctrl.snapshotSource()
	if len(got) != 1 {
		t.Fatalf("snapshot must hold only the managed service with a valid IP and endpoint, got %d: %v", len(got), got)
	}
	se, ok := got["ns/managed"]
	if !ok || se.Service.Name != "managed" || se.Endpoint.Subsets[0].Addresses[0].IP != "10.0.0.1" {
		t.Errorf("unexpected snapshot entry: %+v", got)
	}
}

// Without informers the controller still has to work, which is how the unit
// tests drive it.
func TestSnapshotSourceFallsBackToServiceMap(t *testing.T) {
	svc := lbService("192.0.2.10", nil)
	svc.Namespace, svc.Name = "ns", "svc"

	ctrl := &ServicesController{Proxy: &recordingProxy{}}
	ctrl.Services = NewServiceMap()
	ctrl.Services.Set("ns", "svc", &ServiceEndpoints{Service: svc, Endpoint: epOnNode("10.0.0.1", "node-a")})

	if got := ctrl.snapshotSource(); len(got) != 1 {
		t.Errorf("fallback must read the service map, got %v", got)
	}
}

// takePending clears the cleanup flag, so a retry that fails again has to put
// it back — otherwise the reconciliation is attempted exactly once and the
// stale state it exists to remove stays for good.
func TestFailedCleanupRetryIsQueuedAgain(t *testing.T) {
	px := &recordingProxy{failCleanup: true}
	ctrl := &ServicesController{Proxy: px, NodeName: "node-a"}
	ctrl.Services = NewServiceMap()
	ctrl.markCleanupPending()

	ctrl.retryPending()
	if _, _, pending := ctrl.takePending(); !pending {
		t.Fatal("a cleanup retry that failed must be queued again")
	}

	// And it stops being queued once it succeeds.
	ctrl.markCleanupPending()
	px.failCleanup = false
	ctrl.retryPending()
	if _, _, pending := ctrl.takePending(); pending {
		t.Error("a successful cleanup retry must clear the flag")
	}
}
