package controllers

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/cozystack/cozy-proxy/pkg/l4"
	nat "github.com/cozystack/cozy-proxy/pkg/proxy"
)

// l4log is not derived from the VM controller's logger: named
// "services-controller.l4", its lines read as if the VM mode were doing the
// work, which is confusing when both modes run in one process.
var l4log = ctrl.Log.WithName("l4-controller")

// serviceL2StatusGVR is MetalLB's record of which node announces a service in
// L2 mode. Each speaker writes one per service it announces, labelled with its
// node.
var serviceL2StatusGVR = schema.GroupVersionResource{
	Group:    "metallb.io",
	Version:  "v1beta1",
	Resource: "servicel2statuses",
}

const metallbNodeLabel = "metallb.io/node"

const (
	defaultL4MinSyncInterval = 250 * time.Millisecond
	defaultL4ResyncInterval  = time.Minute
	defaultL4RetryInterval   = 5 * time.Second
)

// L4Controller runs the L4 LoadBalancer mode: it keeps this node's L4 table
// in line with the cluster. It shares nothing with ServicesController, which
// runs the VM mode, but the process.
//
// Reconciliation is level-triggered. Events only mark the state dirty; a
// single loop recomputes the whole desired state from the informer caches and
// hands it to the datapath, which replaces its table atomically. A failure is
// simply retried by a later pass.
type L4Controller struct {
	Clientset kubernetes.Interface
	Dynamic   dynamic.Interface
	// NodeName is the node this instance programs. Required: without it the
	// mode cannot tell which backends are local, and programs nothing.
	NodeName  string
	Datapath  nat.L4Datapath
	Conntrack nat.ConntrackPurger

	// MinSyncInterval coalesces bursts of events into one pass.
	MinSyncInterval time.Duration
	// ResyncInterval re-applies the state even without events, so that a
	// table removed or altered by hand comes back.
	ResyncInterval time.Duration
	// RetryInterval is how soon a failed pass is retried.
	RetryInterval time.Duration

	dirty chan struct{}
	input func() l4.Input

	// applied is the last state the datapath committed; nil until the first
	// commit of this process.
	applied *l4.State
	// purgePending is set when a commit withdrew translations whose
	// conntrack entries have not been purged yet, and purgeVIPs collects the
	// VIPs those entries may target, removed services included.
	purgePending bool
	purgeVIPs    map[netip.Addr]struct{}
	// notices holds what was last logged per service, so a notice is logged
	// when it changes rather than on every pass.
	notices map[string]string
}

// Start runs the controller until ctx ends.
//
// It never returns an error: the VM mode runs in the same manager, and a
// failure of the L4 mode must not take it down. Problems are logged and
// retried instead.
func (c *L4Controller) Start(ctx context.Context) error {
	if c.NodeName == "" {
		l4log.Error(nil, "NODE_NAME is not set; the L4 mode cannot tell which backends are local and stays idle")
		<-ctx.Done()
		return nil
	}
	l4log.Info("starting the L4 LoadBalancer mode", "node", c.NodeName)

	factory := informers.NewSharedInformerFactory(c.Clientset, 0)
	svcInformer := factory.Core().V1().Services()
	sliceInformer := factory.Discovery().V1().EndpointSlices()
	nodeInformer := factory.Core().V1().Nodes()

	// Only this node's statuses: that is all the mode needs to know.
	dynFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(c.Dynamic, 0, metav1.NamespaceAll,
		func(o *metav1.ListOptions) { o.LabelSelector = metallbNodeLabel + "=" + c.NodeName })
	l2Informer := dynFactory.ForResource(serviceL2StatusGVR)

	c.dirty = make(chan struct{}, 1)
	handler := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(interface{}) { c.markDirty() },
		UpdateFunc: func(interface{}, interface{}) { c.markDirty() },
		DeleteFunc: func(interface{}) { c.markDirty() },
	}
	for _, inf := range []cache.SharedIndexInformer{
		svcInformer.Informer(), sliceInformer.Informer(), nodeInformer.Informer(), l2Informer.Informer(),
	} {
		if _, err := inf.AddEventHandler(handler); err != nil {
			l4log.Error(err, "could not register an event handler; the L4 mode stays idle")
			<-ctx.Done()
			return nil
		}
	}

	factory.Start(ctx.Done())
	dynFactory.Start(ctx.Done())

	// The table the previous instance left keeps forwarding until the first
	// pass, which needs complete caches: programming from a partial view would
	// withdraw live services.
	synced := []cache.InformerSynced{
		svcInformer.Informer().HasSynced,
		sliceInformer.Informer().HasSynced,
		nodeInformer.Informer().HasSynced,
		l2Informer.Informer().HasSynced,
	}
	for !cache.WaitForNamedCacheSync("l4", waitOrTimeout(ctx, time.Minute), synced...) {
		if ctx.Err() != nil {
			return nil
		}
		l4log.Info("still waiting for the L4 caches to sync; is the MetalLB ServiceL2Status CRD installed?")
	}

	svcLister := svcInformer.Lister()
	sliceLister := sliceInformer.Lister()
	nodeLister := nodeInformer.Lister()
	l2Lister := l2Informer.Lister()
	c.input = func() l4.Input {
		in := l4.Input{NodeName: c.NodeName, Announced: map[string]bool{}}
		in.Services, _ = svcLister.List(labels.Everything())
		in.EndpointSlices, _ = sliceLister.List(labels.Everything())
		in.Nodes, _ = nodeLister.List(labels.Everything())
		objs, _ := l2Lister.List(labels.Everything())
		for _, o := range objs {
			if key, ok := announcedService(o, c.NodeName); ok {
				in.Announced[key] = true
			}
		}
		return in
	}

	c.run(ctx)
	l4log.Info("stopping the L4 LoadBalancer mode; its table stays in place")
	return nil
}

// run is the sync loop.
func (c *L4Controller) run(ctx context.Context) {
	resync := time.NewTicker(orDefault(c.ResyncInterval, defaultL4ResyncInterval))
	defer resync.Stop()
	var retry <-chan time.Time

	// The first pass replaces whatever the previous instance left. A forced
	// pass stays forced until it succeeds: retried as an ordinary one, it would
	// find the desired state unchanged and skip the commit it exists for.
	force := true
	for {
		if err := c.syncWith(c.input(), force); err != nil {
			l4log.Error(err, "L4 sync failed, retrying")
			retry = time.After(orDefault(c.RetryInterval, defaultL4RetryInterval))
		} else {
			retry = nil
			force = false
		}

		select {
		case <-ctx.Done():
			return
		case <-c.dirty:
		case <-retry:
		case <-resync.C:
			force = true
		}
		// Let a burst of events settle into one pass.
		select {
		case <-ctx.Done():
			return
		case <-time.After(orDefault(c.MinSyncInterval, defaultL4MinSyncInterval)):
		}
	}
}

func (c *L4Controller) markDirty() {
	select {
	case c.dirty <- struct{}{}:
	default:
	}
}

// syncWith programs the state computed from in, then purges the conntrack
// entries it left stale. An unchanged state is not reprogrammed unless force
// is set.
func (c *L4Controller) syncWith(in l4.Input, force bool) error {
	st, notices := l4.Build(in)
	c.logNotices(notices)

	unchanged := c.applied != nil && reflect.DeepEqual(*c.applied, st)
	if !unchanged || force {
		if err := c.Datapath.Sync(st); err != nil {
			return fmt.Errorf("programming the L4 table: %w", err)
		}
		if !unchanged {
			l4log.Info("L4 table programmed", "vips", len(st.VIPs), "ports", len(st.Ports), "translated", len(st.Rules))
		}
		prev := c.applied
		if c.purgePending || l4.PurgeNeeded(prev, st) {
			c.purgePending = true
			if prev != nil {
				if c.purgeVIPs == nil {
					c.purgeVIPs = map[netip.Addr]struct{}{}
				}
				for _, v := range prev.VIPs {
					c.purgeVIPs[v] = struct{}{}
				}
			}
		}
		c.applied = &st
	}

	if !c.purgePending {
		return nil
	}
	// The previous VIPs keep the flows of a service removed since the last
	// successful purge within reach.
	before := &l4.State{}
	for v := range c.purgeVIPs {
		before.VIPs = append(before.VIPs, v)
	}
	n, err := c.Conntrack.Purge(l4.StaleFlows(before, st))
	if err != nil {
		return fmt.Errorf("purging stale L4 conntrack entries: %w", err)
	}
	if n > 0 {
		l4log.Info("purged stale L4 conntrack entries", "count", n)
	}
	c.purgePending = false
	c.purgeVIPs = nil
	return nil
}

func (c *L4Controller) logNotices(notices []l4.Notice) {
	current := map[string]string{}
	for _, n := range notices {
		if prev, ok := current[n.Service]; ok {
			current[n.Service] = prev + "; " + n.Message
		} else {
			current[n.Service] = n.Message
		}
	}
	for svc, msg := range current {
		if c.notices[svc] != msg {
			l4log.Info("service not fully programmed", "service", svc, "reason", msg)
		}
	}
	c.notices = current
}

// announcedService returns the service a ServiceL2Status says node announces.
func announcedService(obj interface{}, node string) (string, bool) {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return "", false
	}
	// The informer already filters on the node label; the status is the
	// authoritative field.
	if n, _, _ := unstructured.NestedString(u.Object, "status", "node"); n != node {
		return "", false
	}
	ns, _, _ := unstructured.NestedString(u.Object, "status", "serviceNamespace")
	name, _, _ := unstructured.NestedString(u.Object, "status", "serviceName")
	if ns == "" || name == "" {
		return "", false
	}
	return ns + "/" + name, true
}

// waitOrTimeout returns a channel closed when ctx ends or after d, whichever
// comes first, so a cache sync that never completes is reported periodically.
func waitOrTimeout(ctx context.Context, d time.Duration) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}
	}()
	return ch
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}
