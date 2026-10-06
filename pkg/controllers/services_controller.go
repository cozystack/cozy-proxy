package controllers

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"

	nat "github.com/cozystack/cozy-proxy/pkg/proxy"
)

var (
	log = ctrl.Log.WithName("services-controller")
)

// ServiceEndpoints holds the service and its endpoints.
type ServiceEndpoints struct {
	Service  *v1.Service
	Endpoint *v1.Endpoints
}

// ServiceMap encapsulates a map with a mutex to protect concurrent access.
type ServiceMap struct {
	mu             sync.Mutex
	serviceMapping map[string]*ServiceEndpoints
}

// NewServiceMap creates and returns a new ServiceMap.
func NewServiceMap() *ServiceMap {
	return &ServiceMap{
		serviceMapping: make(map[string]*ServiceEndpoints),
	}
}

// makeKey generates a map key from the namespace and name.
func makeKey(namespace, name string) string {
	return namespace + "/" + name
}

// Get returns the ServiceEndpoints stored under the given namespace and name.
func (sm *ServiceMap) Get(namespace, name string) (*ServiceEndpoints, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	key := makeKey(namespace, name)
	se, ok := sm.serviceMapping[key]
	return se, ok
}

// Snapshot returns the stored Service and Endpoints under the lock.
//
// Get hands back the pointer to the shared ServiceEndpoints, whose Endpoint
// field SetEndpoint rewrites under the lock. Reading that field after Get has
// returned is an unsynchronized read, so any caller outside the informer
// callbacks has to come through here.
func (sm *ServiceMap) Snapshot(namespace, name string) (*v1.Service, *v1.Endpoints, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	se, ok := sm.serviceMapping[makeKey(namespace, name)]
	if !ok || se == nil {
		return nil, nil, false
	}
	return se.Service, se.Endpoint, true
}

// Set stores the ServiceEndpoints under the given namespace and name.
func (sm *ServiceMap) Set(namespace, name string, se *ServiceEndpoints) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	key := makeKey(namespace, name)
	sm.serviceMapping[key] = se
}

// Delete removes the ServiceEndpoints stored under the given namespace and name.
func (sm *ServiceMap) Delete(namespace, name string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	key := makeKey(namespace, name)
	delete(sm.serviceMapping, key)
}

// SetEndpoint updates the Endpoint for the ServiceEndpoints stored under the given namespace and name.
func (sm *ServiceMap) SetEndpoint(namespace, name string, ep *v1.Endpoints) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	key := makeKey(namespace, name)
	if se, ok := sm.serviceMapping[key]; ok {
		se.Endpoint = ep
	}
}

// GetAll returns a copy of the service mapping.
func (sm *ServiceMap) GetAll() map[string]*ServiceEndpoints {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	copyMap := make(map[string]*ServiceEndpoints, len(sm.serviceMapping))
	for k, v := range sm.serviceMapping {
		copyMap[k] = v
	}
	return copyMap
}

type ServicesController struct {
	Clientset *kubernetes.Clientset
	Services  *ServiceMap
	Proxy     nat.ProxyProcessor

	// NodeName is the node this instance runs on. It scopes the ingress
	// half of the datapath — the destination rewrite and the port filter —
	// to backend pods hosted here. Empty disables the check and programs
	// everything everywhere.
	NodeName string

	// svcStore and epStore are the informer stores. The startup snapshot is
	// built from them rather than from Services, because WaitForCacheSync
	// returns once the store is populated, not once every initial callback
	// has run. Reading the half-filled map made the purge treat a live
	// mapping as stale and delete it, leaving the node without it until an
	// event happened to re-apply that service — or until the 12-hour resync.
	svcStore cache.Store
	epStore  cache.Store

	// RetryInterval is how often failed datapath writes are re-attempted.
	// Zero selects defaultRetryInterval.
	RetryInterval time.Duration

	// reconcileMu serializes whole reconciliations, not just the individual
	// datapath calls the proxy already serializes.
	//
	// An informer callback withdraws the rules of a replaced endpoint and then
	// applies the new one. Without this lock the retry goroutine can slip
	// between the two with the endpoint it snapshotted a moment earlier, and
	// its writes land after the update — restoring the mapping of a pod that
	// is gone, which points the service IP at a dead backend.
	reconcileMu sync.Mutex

	// retryMu guards pendingServices and pendingCleanup.
	retryMu sync.Mutex

	// pendingServices holds the keys of services whose datapath programming
	// failed. The informers only deliver events, so without a re-attempt a
	// transient nftables failure leaves the service unprogrammed until the
	// next event — long enough for a public IP to stay dark for minutes.
	pendingServices map[string]struct{}

	// pendingWithdrawals holds datapath state that could not be removed.
	//
	// A failed withdrawal cannot go through pendingServices: by then the
	// service is usually gone from Services, so there is nothing to re-derive
	// the pair from. It is carried explicitly instead. Leaving it behind is
	// not merely untidy — a stale pod_svc entry rewrites the source of
	// whatever pod next receives that IP, which on a shared /16 means one
	// tenant's egress leaving under another tenant's service IP.
	pendingWithdrawals map[string]withdrawal

	// pendingCleanup records that the startup reconciliation failed and has
	// to run again. It stays non-fatal, but it no longer waits for the next
	// event or the 12-hour informer resync.
	pendingCleanup bool
}

// withdrawal is datapath state waiting to be removed.
type withdrawal struct {
	svcIP, podIP string
	// egress also withdraws the source rewrite. False when only the ingress
	// half has to go, which is the case on a node that stopped hosting the
	// backend but still carries the cluster-wide source rewrite.
	egress bool
}

// withdrawalKey identifies a pair independently of which half is pending.
func withdrawalKey(svcIP, podIP string) string { return svcIP + "/" + podIP }

// markWithdrawal queues datapath state for another removal attempt.
func (c *ServicesController) markWithdrawal(svcIP, podIP string, egress bool) {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	if c.pendingWithdrawals == nil {
		c.pendingWithdrawals = make(map[string]withdrawal)
	}
	k := withdrawalKey(svcIP, podIP)
	// A full withdrawal supersedes an ingress-only one for the same pair.
	if prev, ok := c.pendingWithdrawals[k]; ok && prev.egress {
		egress = true
	}
	c.pendingWithdrawals[k] = withdrawal{svcIP: svcIP, podIP: podIP, egress: egress}
}

// clearWithdrawal drops a queued removal.
//
// Called when the same pair is programmed again — an endpoint that flapped back
// to the pod IP whose withdrawal failed. Without this the retry would delete
// the rules that were just reinstalled.
func (c *ServicesController) clearWithdrawal(svcIP, podIP string) {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	delete(c.pendingWithdrawals, withdrawalKey(svcIP, podIP))
}

// defaultRetryInterval is short enough that a failed write is repaired well
// within a human noticing, and long enough that a permanent failure does not
// flood the log.
const defaultRetryInterval = 30 * time.Second

// markPending queues a service for another programming attempt.
func (c *ServicesController) markPending(namespace, name string) {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	if c.pendingServices == nil {
		c.pendingServices = make(map[string]struct{})
	}
	c.pendingServices[makeKey(namespace, name)] = struct{}{}
}

// clearPending drops a service from the retry set after a clean pass.
func (c *ServicesController) clearPending(namespace, name string) {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	delete(c.pendingServices, makeKey(namespace, name))
}

// markCleanupPending queues the startup reconciliation for another attempt.
func (c *ServicesController) markCleanupPending() {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	c.pendingCleanup = true
}

// takePending returns the queued work and clears it. Anything that fails again
// is re-queued by the attempt itself.
func (c *ServicesController) takePending() (services []string, withdrawals []withdrawal, cleanup bool) {
	c.retryMu.Lock()
	defer c.retryMu.Unlock()
	for k := range c.pendingServices {
		services = append(services, k)
	}
	c.pendingServices = nil
	for _, w := range c.pendingWithdrawals {
		withdrawals = append(withdrawals, w)
	}
	c.pendingWithdrawals = nil
	cleanup = c.pendingCleanup
	c.pendingCleanup = false
	return services, withdrawals, cleanup
}

// retryPending re-attempts everything that failed since the last pass. Every
// datapath call is idempotent, so a re-attempt on something already correct is
// a no-op.
func (c *ServicesController) retryPending() {
	services, withdrawals, cleanup := c.takePending()

	// Withdrawals first: an apply for the same pair clears its queued removal
	// at the moment it succeeds, so it wins either way.
	for _, w := range withdrawals {
		c.retryWithdrawal(w)
	}

	for _, key := range services {
		ns, name, ok := splitKey(key)
		if !ok {
			continue
		}
		c.retryOne(ns, name, key)
	}

	if cleanup {
		log.Info("retrying startup cleanup")
		if err := c.cleanupRemovedServices(); err != nil {
			// takePending cleared the flag, and unlike the per-service and
			// withdrawal paths — which re-queue themselves from inside the
			// call that failed — nothing here would put it back. Without this
			// the reconciliation is retried exactly once.
			c.markCleanupPending()
			log.Error(err, "cleanup retry failed, queued again")
		}
	}
}

// retryWithdrawal re-attempts a removal that failed. The pair is carried
// explicitly because the service it belonged to is usually gone by now.
func (c *ServicesController) retryWithdrawal(w withdrawal) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	log.Info("retrying datapath withdrawal", "svcIP", w.svcIP, "podIP", w.podIP, "egress", w.egress)
	if w.egress {
		// Re-queues itself on failure.
		_ = c.withdrawRules(w.svcIP, w.podIP, "on retry")
		return
	}
	_ = c.withdrawIngressRules(w.svcIP, w.podIP, "on retry")
}

// retryOne re-applies a single service, reading its state and programming the
// datapath under the reconciliation lock so an informer callback cannot
// interleave and have this attempt restore what it just withdrew.
func (c *ServicesController) retryOne(namespace, name, key string) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	svc, ep, exists := c.Services.Snapshot(namespace, name)
	if !exists || !hasValidServiceIP(svc) || !hasValidEndpointIP(ep) {
		// The service went away or lost its endpoint; the delete paths have
		// already withdrawn its rules. Drop it from the queue.
		c.clearPending(namespace, name)
		return
	}
	log.Info("retrying datapath programming", "service", key)
	c.applyRules(svc, ep, "on retry")
}

// runRetryLoop re-attempts failed datapath writes until the context ends.
func (c *ServicesController) runRetryLoop(ctx context.Context) {
	interval := c.RetryInterval
	if interval <= 0 {
		interval = defaultRetryInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.retryPending()
		}
	}
}

// splitKey reverses makeKey.
func splitKey(key string) (namespace, name string, ok bool) {
	i := strings.Index(key, "/")
	if i <= 0 || i == len(key)-1 {
		return "", "", false
	}
	return key[:i], key[i+1:], true
}

// endpointNode returns the node hosting the endpoint's first address.
func endpointNode(ep *v1.Endpoints) (string, bool) {
	if !hasValidEndpointIP(ep) {
		return "", false
	}
	node := ep.Subsets[0].Addresses[0].NodeName
	if node == nil || *node == "" {
		return "", false
	}
	return *node, true
}

// servesEndpoint reports whether this node hosts ep's backend, and may
// therefore program the ingress half of the datapath.
//
// Only the hosting node may rewrite the destination. Doing it cluster-wide
// makes a non-owning node translate the destination before the packet even
// leaves it, so the owning node records a conntrack tuple the SNATed reply can
// no longer match, and port_filter drops that reply.
//
// This says nothing about the egress half: the source rewrite is programmed on
// every node regardless, see applyRules.
//
// When the node name is unknown (NODE_NAME not injected, or an endpoint
// carrying no NodeName) the ingress rules are programmed anyway, so an older
// chart keeps the previous behavior instead of silently losing the datapath.
func (c *ServicesController) servesEndpoint(ep *v1.Endpoints) bool {
	if c.NodeName == "" {
		return true
	}
	node, ok := endpointNode(ep)
	if !ok {
		return true
	}
	return node == c.NodeName
}

// applyRules programs the datapath for a (service, endpoint) pair. The two
// halves have different scopes. Both objects must already have been checked
// with hasValidServiceIP/hasValidEndpointIP.
func (c *ServicesController) applyRules(svc *v1.Service, ep *v1.Endpoints, ctx string) {
	svcIP := svc.Status.LoadBalancer.Ingress[0].IP
	podIP := ep.Subsets[0].Addresses[0].IP

	// The source rewrite goes on every node, including the ones that do not
	// host the backend. When the client is inside the cluster, kube-ovn SNATs
	// it to its own node address, which OVN knows how to reach: the backend's
	// reply is then handed straight to that node over the Geneve tunnel and
	// never traverses the backend node's netfilter hooks. The client's node is
	// the last place where the pod IP can still be turned back into the
	// service IP the client's conntrack is waiting for. Without it the reply
	// arrives with the wrong source and the client answers it with a RST.
	// This pair is wanted again; drop any removal still queued for it.
	c.clearWithdrawalFor(svc, ep)

	failed := false
	if err := c.Proxy.EnsureEgressSNAT(svcIP, podIP); err != nil {
		log.Error(err, "failed to ensure egress SNAT "+ctx, "svcIP", svcIP, "podIP", podIP)
		failed = true
	}

	// The destination rewrite and the port filter stay on the hosting node.
	if !c.servesEndpoint(ep) {
		if err := c.withdrawIngressRules(svcIP, podIP, ctx+" (backend not on this node)"); err != nil {
			failed = true
		}
		c.recordOutcome(svc, failed)
		return
	}

	if err := c.Proxy.EnsureIngressDNAT(svcIP, podIP); err != nil {
		log.Error(err, "failed to ensure ingress DNAT "+ctx, "svcIP", svcIP, "podIP", podIP)
		failed = true
	}
	if err := c.reconcilePortFilter(svc, svcIP, podIP, ctx); err != nil {
		failed = true
	}
	c.recordOutcome(svc, failed)
}

// recordOutcome queues the service for another attempt when any part of its
// datapath failed, and clears a previous failure once a pass is clean.
func (c *ServicesController) recordOutcome(svc *v1.Service, failed bool) {
	if failed {
		c.markPending(svc.Namespace, svc.Name)
		return
	}
	c.clearPending(svc.Namespace, svc.Name)
}

// clearWithdrawalFor drops a queued removal for a pair that has just been
// programmed again, so the retry does not delete what was reinstalled.
func (c *ServicesController) clearWithdrawalFor(svc *v1.Service, ep *v1.Endpoints) {
	c.clearWithdrawal(svc.Status.LoadBalancer.Ingress[0].IP, ep.Subsets[0].Addresses[0].IP)
}

// withdrawIngressRules removes the ingress half only — destination rewrite and
// port filter — and leaves the source rewrite in place. This is what a node
// that does not host the backend must end up with.
// It returns an error when any part could not be removed, so the caller can
// queue the pair for another attempt.
func (c *ServicesController) withdrawIngressRules(svcIP, podIP, ctx string) error {
	failed := c.clearPortFilter(svcIP, podIP, ctx)
	if err := c.Proxy.DeleteIngressDNAT(svcIP, podIP); err != nil {
		log.Error(err, "failed to delete ingress DNAT "+ctx, "svcIP", svcIP, "podIP", podIP)
		failed = err
	}
	if failed != nil {
		c.markWithdrawal(svcIP, podIP, false)
	}
	return failed
}

// withdrawRules removes every datapath entry for the pair, both halves. Used
// when the pair itself is going away: service deleted, endpoint gone, or a pod
// IP that has been replaced. Absent entries are not an error.
func (c *ServicesController) withdrawRules(svcIP, podIP, ctx string) error {
	failed := c.withdrawIngressRules(svcIP, podIP, ctx)
	if err := c.Proxy.DeleteEgressSNAT(svcIP, podIP); err != nil {
		log.Error(err, "failed to delete egress SNAT "+ctx, "svcIP", svcIP, "podIP", podIP)
		failed = err
	}
	if failed != nil {
		c.markWithdrawal(svcIP, podIP, true)
	}
	return failed
}

// withdrawStaleEndpoint drops the rules of a previous endpoint whose pod IP no
// longer matches the current one, which is what happens when a VM is migrated
// to another node. Without this the old node keeps a mapping for a pod it no
// longer hosts.
func (c *ServicesController) withdrawStaleEndpoint(svc *v1.Service, prev *v1.Endpoints, podIP, ctx string) {
	if !hasValidServiceIP(svc) || !hasValidEndpointIP(prev) {
		return
	}
	prevPodIP := prev.Subsets[0].Addresses[0].IP
	if prevPodIP == podIP {
		return
	}
	c.withdrawRules(svc.Status.LoadBalancer.Ingress[0].IP, prevPodIP, ctx+" (stale endpoint)")
}

// Start initializes the NAT, runs the service and endpoint informers, and cleans up removed services.
func (c *ServicesController) Start(ctx context.Context) error {
	log.Info("starting services-controller")

	// Initialize the Services map.
	c.Services = NewServiceMap()

	// Initialize proxy rules.
	if err := c.Proxy.InitRules(); err != nil {
		return fmt.Errorf("failed to initialize Proxy processor: %w", err)
	}

	// Create informer for services.
	serviceLW := cache.NewListWatchFromClient(
		c.Clientset.CoreV1().RESTClient(),
		"services",
		v1.NamespaceAll,
		fields.Everything(),
	)
	serviceInformer := cache.NewSharedIndexInformer(
		serviceLW,
		&v1.Service{},
		12*time.Hour,
		cache.Indexers{
			"namespace_name": func(obj interface{}) ([]string, error) {
				svc, ok := obj.(*v1.Service)
				if !ok {
					return nil, fmt.Errorf("object is not *v1.Service")
				}
				return []string{svc.Namespace + "/" + svc.Name}, nil
			},
		},
	)

	c.svcStore = serviceInformer.GetStore()

	serviceInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addServiceFunc,
		DeleteFunc: c.deleteServiceFunc,
		UpdateFunc: c.updateServiceFunc,
	})

	stopper := make(chan struct{})
	defer close(stopper)
	defer utilruntime.HandleCrash()

	// Run the service informer.
	go serviceInformer.Run(stopper)
	log.Info("synchronizing services")
	if !cache.WaitForCacheSync(stopper, serviceInformer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for services cache to sync"))
		log.Info("synchronization of services failed")
		return fmt.Errorf("synchronization of services failed")
	}
	log.Info("services synchronization completed")

	// Create informer for endpoints.
	endpointsLW := cache.NewListWatchFromClient(
		c.Clientset.CoreV1().RESTClient(),
		"endpoints",
		v1.NamespaceAll,
		fields.Everything(),
	)
	endpointsInformer := cache.NewSharedIndexInformer(
		endpointsLW,
		&v1.Endpoints{},
		12*time.Hour,
		cache.Indexers{
			"namespace_name": func(obj interface{}) ([]string, error) {
				ep, ok := obj.(*v1.Endpoints)
				if !ok {
					return nil, fmt.Errorf("object is not *v1.Endpoints")
				}
				return []string{ep.Namespace + "/" + ep.Name}, nil
			},
		},
	)

	c.epStore = endpointsInformer.GetStore()

	endpointsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.addEndpointFunc,
		DeleteFunc: c.deleteEndpointFunc,
		UpdateFunc: c.updateEndpointFunc,
	})

	// Run the endpoints informer.
	go endpointsInformer.Run(stopper)
	log.Info("synchronizing endpoints")
	if !cache.WaitForCacheSync(stopper, endpointsInformer.HasSynced) {
		utilruntime.HandleError(fmt.Errorf("Timed out waiting for endpoints cache to sync"))
		log.Info("synchronization of endpoints failed")
		return fmt.Errorf("synchronization of endpoints failed")
	}
	log.Info("endpoints synchronization completed")

	// Run cleanup for removed services. A failure here is logged but does not
	// abort: exiting takes the pod down and leaves the node's datapath
	// half-programmed, whereas the informers below converge on the next event.
	log.Info("running cleanup for removed services")
	if err := c.cleanupRemovedServices(); err != nil {
		log.Error(err, "cleanup of removed services failed, queued for retry")
		c.markCleanupPending()
	} else {
		log.Info("cleanup of removed services completed")
	}

	// Re-attempt whatever failed. The informers only deliver events, so
	// without this a transient nftables failure leaves a service
	// unprogrammed until the next one.
	go c.runRetryLoop(ctx)

	<-ctx.Done()
	log.Info("shutting down services-controller")

	return nil
}

// addServiceFunc handles the addition of a service.
func (c *ServicesController) addServiceFunc(obj interface{}) {
	// Reconciliations are serialized end to end, see reconcileMu.
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	svc, ok := obj.(*v1.Service)
	if !ok {
		// Object is not a Service.
		return
	}
	if !isCozyProxyService(svc) {
		return
	}

	// Always add the service to the mapping, even if the endpoint is nil.
	se := &ServiceEndpoints{
		Service:  svc,
		Endpoint: nil,
	}
	c.Services.Set(svc.Namespace, svc.Name, se)

	// Try to retrieve the corresponding endpoint from the API server.
	ep, err := c.Clientset.CoreV1().Endpoints(svc.Namespace).Get(context.TODO(), svc.Name, metav1.GetOptions{})
	if err != nil && !errors.IsNotFound(err) {
		log.Error(err, "failed to get endpoints for service")
		return
	}
	// If the endpoint exists and both Service and Endpoint have valid IPs, update the mapping.
	if err == nil && ep != nil && hasValidEndpointIP(ep) && hasValidServiceIP(svc) {
		se.Endpoint = ep
		c.Services.Set(svc.Namespace, svc.Name, se)
		c.applyRules(svc, ep, "on svc add")
	}
}

// deleteServiceFunc handles the deletion of a service.
func (c *ServicesController) deleteServiceFunc(obj interface{}) {
	// Reconciliations are serialized end to end, see reconcileMu.
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	svc, ok := obj.(*v1.Service)
	if !ok {
		// object is not Service
		return
	}

	se, exists := c.Services.Get(svc.Namespace, svc.Name)
	if !exists {
		// Service is not managed by us
		return
	}
	if !hasValidServiceIP(se.Service) || !hasValidEndpointIP(se.Endpoint) {
		return
	}

	svcIP := se.Service.Status.LoadBalancer.Ingress[0].IP
	podIP := se.Endpoint.Subsets[0].Addresses[0].IP
	c.withdrawRules(svcIP, podIP, "on svc deletion")
	c.Services.Delete(svc.Namespace, svc.Name)
}

// updateServiceFunc handles service updates.
func (c *ServicesController) updateServiceFunc(oldObj, newObj interface{}) {
	// Reconciliations are serialized end to end, see reconcileMu.
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	// Cast the object to a Service type.
	svc, ok := newObj.(*v1.Service)
	if !ok {
		// Object is not a Service.
		return
	}

	// If the service no longer matches our selection criteria, remove the service mapping and delete NAT rules if applicable.
	if !isCozyProxyService(svc) {
		if se, exists := c.Services.Get(svc.Namespace, svc.Name); exists {
			if hasValidServiceIP(se.Service) && hasValidEndpointIP(se.Endpoint) {
				svcIP := se.Service.Status.LoadBalancer.Ingress[0].IP
				podIP := se.Endpoint.Subsets[0].Addresses[0].IP
				c.withdrawRules(svcIP, podIP, "on annotation removal")
			}
			c.Services.Delete(svc.Namespace, svc.Name)
		}
		return
	}

	// If the service does not have a valid IP, remove the service mapping.
	if !hasValidServiceIP(svc) {
		if se, exists := c.Services.Get(svc.Namespace, svc.Name); exists {
			if hasValidServiceIP(se.Service) && hasValidEndpointIP(se.Endpoint) {
				svcIP := se.Service.Status.LoadBalancer.Ingress[0].IP
				podIP := se.Endpoint.Subsets[0].Addresses[0].IP
				c.withdrawRules(svcIP, podIP, "on svc IP loss")
			}
			c.Services.Delete(svc.Namespace, svc.Name)
		}
		return
	}

	// Attempt to retrieve the corresponding endpoints.
	ep, err := c.Clientset.CoreV1().Endpoints(svc.Namespace).Get(context.TODO(), svc.Name, metav1.GetOptions{})
	if err != nil {
		// If the error is NotFound, treat the endpoint as nil.
		if errors.IsNotFound(err) {
			ep = nil
		} else {
			log.Error(err, "failed to get endpoints for service")
			// Update the mapping with a nil endpoint so it can be updated later.
			c.Services.Set(svc.Namespace, svc.Name, &ServiceEndpoints{Service: svc, Endpoint: nil})
			return
		}
	}

	// If the endpoint is nil or does not have a valid IP,
	// update the mapping with a nil endpoint and remove any existing NAT rules.
	if ep == nil || !hasValidEndpointIP(ep) {
		if se, exists := c.Services.Get(svc.Namespace, svc.Name); exists &&
			hasValidServiceIP(se.Service) && hasValidEndpointIP(se.Endpoint) {
			c.withdrawRules(
				se.Service.Status.LoadBalancer.Ingress[0].IP,
				se.Endpoint.Subsets[0].Addresses[0].IP,
				"on endpoint loss",
			)
		}
		c.Services.Set(svc.Namespace, svc.Name, &ServiceEndpoints{Service: svc, Endpoint: nil})
		return
	}

	// At this point, both the Service and Endpoint have valid IPs.
	// Ensure NAT mapping is up-to-date.
	if se, exists := c.Services.Get(svc.Namespace, svc.Name); exists {
		c.withdrawStaleEndpoint(svc, se.Endpoint, ep.Subsets[0].Addresses[0].IP, "on svc update")
	}
	c.applyRules(svc, ep, "on svc update")

	// Update or add the service mapping with the new endpoint.
	c.Services.Set(svc.Namespace, svc.Name, &ServiceEndpoints{Service: svc, Endpoint: ep})
}

// addEndpointFunc handles the addition of endpoints.
func (c *ServicesController) addEndpointFunc(obj interface{}) {
	// Reconciliations are serialized end to end, see reconcileMu.
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	// Cast the object to an Endpoints type.
	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		// Object is not an Endpoints.
		return
	}

	// Retrieve the ServiceEndpoints mapping for the service.
	se, exists := c.Services.Get(ep.Namespace, ep.Name)
	if !exists {
		// If the service is not managed by us, do nothing.
		return
	}

	// Update the endpoint in the mapping.
	c.Services.SetEndpoint(ep.Namespace, ep.Name, ep)

	// If both the Service and the Endpoint have valid IPs, ensure NAT mapping rules.
	if hasValidServiceIP(se.Service) && hasValidEndpointIP(ep) {
		c.withdrawStaleEndpoint(se.Service, se.Endpoint, ep.Subsets[0].Addresses[0].IP, "on endpoint add")
		c.applyRules(se.Service, ep, "on endpoint add")
	}
}

// deleteEndpointFunc handles endpoint deletions.
func (c *ServicesController) deleteEndpointFunc(obj interface{}) {
	// Reconciliations are serialized end to end, see reconcileMu.
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	ep, ok := obj.(*v1.Endpoints)
	if !ok {
		// object is not Endpoints
		return
	}

	se, exists := c.Services.Get(ep.Namespace, ep.Name)
	if !exists {
		// Service is not managed by us
		return
	}
	if !hasValidServiceIP(se.Service) || !hasValidEndpointIP(se.Endpoint) {
		return
	}
	svcIP := se.Service.Status.LoadBalancer.Ingress[0].IP
	podIP := se.Endpoint.Subsets[0].Addresses[0].IP
	c.withdrawRules(svcIP, podIP, "on endpoint delete")
	// Set the endpoint to nil.
	c.Services.SetEndpoint(ep.Namespace, ep.Name, nil)
}

// updateEndpointFunc handles updates to endpoints.
func (c *ServicesController) updateEndpointFunc(oldObj, newObj interface{}) {
	// Reconciliations are serialized end to end, see reconcileMu.
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	ep, ok := newObj.(*v1.Endpoints)
	if !ok {
		// object is not Endpoints
		return
	}

	se, exists := c.Services.Get(ep.Namespace, ep.Name)
	if !exists {
		// Service is not managed by us
		return
	}
	if !hasValidEndpointIP(ep) {
		if hasValidServiceIP(se.Service) && hasValidEndpointIP(se.Endpoint) {
			svcIP := se.Service.Status.LoadBalancer.Ingress[0].IP
			oldPodIP := se.Endpoint.Subsets[0].Addresses[0].IP
			c.withdrawRules(svcIP, oldPodIP, "on endpoint invalidation")
		}
		c.Services.SetEndpoint(ep.Namespace, ep.Name, ep)
		return
	}
	if !hasValidServiceIP(se.Service) {
		return
	}
	if !hasValidEndpointIP(ep) {
		return
	}
	c.withdrawStaleEndpoint(se.Service, se.Endpoint, ep.Subsets[0].Addresses[0].IP, "on endpoint update")
	c.applyRules(se.Service, ep, "on endpoint update")
	c.Services.SetEndpoint(ep.Namespace, ep.Name, ep)
}

// hasValidServiceIP checks whether the service has a valid IP.
// It returns false if the service is nil, if the LoadBalancer Ingress slice is empty,
// or if the first Ingress entry does not have a valid (non-empty) IP.
func hasValidServiceIP(svc *v1.Service) bool {
	// Return false if svc is nil.
	if svc == nil {
		return false
	}
	// Ensure that there is at least one LoadBalancer Ingress.
	if len(svc.Status.LoadBalancer.Ingress) == 0 {
		return false
	}
	// Check if the first Ingress has a non-empty IP.
	return svc.Status.LoadBalancer.Ingress[0].IP != ""
}

// hasValidEndpointIP checks whether the endpoints have a valid IP.
// It returns false if the endpoints object is nil or does not contain a valid IP.
func hasValidEndpointIP(ep *v1.Endpoints) bool {
	// Return false if ep is nil.
	if ep == nil {
		return false
	}
	// Ensure that there is at least one subset.
	if len(ep.Subsets) == 0 {
		return false
	}
	// Ensure that the first subset contains at least one address.
	if len(ep.Subsets[0].Addresses) == 0 {
		return false
	}
	// Check if the first address has a non-empty IP.
	return ep.Subsets[0].Addresses[0].IP != ""
}

const (
	wholeIPAnnotation   = "networking.cozystack.io/wholeIP"
	allowICMPAnnotation = "networking.cozystack.io/allowICMP"

	// serviceProxyNameLabel is the standard Kubernetes label used to delegate
	// a service to a non-default proxy implementation; kube-proxy skips
	// services carrying it.
	serviceProxyNameLabel = "service.kubernetes.io/service-proxy-name"

	// serviceProxyName is the value cozy-proxy matches in serviceProxyNameLabel.
	serviceProxyName = "cozy-proxy"
)

// isCozyProxyService reports whether the service should be managed by
// cozy-proxy. The sole selector is the standard Kubernetes
// service.kubernetes.io/service-proxy-name=cozy-proxy label, which also
// tells kube-proxy to ignore the service. Services without the label are
// not managed regardless of any cozy-proxy annotations they may carry.
func isCozyProxyService(svc *v1.Service) bool {
	if svc == nil {
		return false
	}
	return svc.Labels[serviceProxyNameLabel] == serviceProxyName
}

// wholeIPPassthrough reports whether ingress traffic should bypass port
// filtering. Opt-in: requires an explicit networking.cozystack.io/wholeIP=true
// annotation. Any other value, or no annotation at all, keeps the service in
// the default port-filter mode.
func wholeIPPassthrough(svc *v1.Service) bool {
	if svc == nil || svc.Annotations == nil {
		return false
	}
	return svc.Annotations[wholeIPAnnotation] == "true"
}

// allowICMP reports whether ICMP traffic should bypass the port_filter drop
// rule for this service. Only meaningful in port-filter mode (wholeIP=false);
// in passthrough mode the port_filter drop rule does not apply at all.
func allowICMP(svc *v1.Service) bool {
	if svc == nil || svc.Annotations == nil {
		return false
	}
	return svc.Annotations[allowICMPAnnotation] == "true"
}

// reconcilePortFilter applies the port-filter and ICMP-allow state implied by
// the service's annotations. Call sites pass the resolved svcIP/podIP and a
// short context string that ends up in error logs.
// It returns an error when any part of the port-filter state could not be
// applied, so the caller can queue the service for another attempt. A filtered
// pod with missing allowed_ports drops every packet, so a silent failure here
// is an outage.
func (c *ServicesController) reconcilePortFilter(svc *v1.Service, svcIP, podIP, ctx string) error {
	var failed error
	if wholeIPPassthrough(svc) {
		if err := c.Proxy.DeletePortFilter(svcIP, podIP); err != nil {
			log.Error(err, "failed to delete port filter "+ctx, "svcIP", svcIP, "podIP", podIP)
			failed = err
		}
		if err := c.Proxy.DeleteICMPAllow(svcIP, podIP); err != nil {
			log.Error(err, "failed to delete ICMP allow "+ctx, "svcIP", svcIP, "podIP", podIP)
			failed = err
		}
		return failed
	}
	if err := c.Proxy.EnsurePortFilter(svcIP, podIP, svc.Spec.Ports); err != nil {
		log.Error(err, "failed to ensure port filter "+ctx, "svcIP", svcIP, "podIP", podIP)
		failed = err
	}
	if allowICMP(svc) {
		if err := c.Proxy.EnsureICMPAllow(svcIP, podIP); err != nil {
			log.Error(err, "failed to ensure ICMP allow "+ctx, "svcIP", svcIP, "podIP", podIP)
			failed = err
		}
	} else {
		if err := c.Proxy.DeleteICMPAllow(svcIP, podIP); err != nil {
			log.Error(err, "failed to delete ICMP allow "+ctx, "svcIP", svcIP, "podIP", podIP)
			failed = err
		}
	}
	return failed
}

// clearPortFilter unconditionally removes both port-filter and ICMP-allow
// state for (svcIP, podIP). Used by delete paths.
func (c *ServicesController) clearPortFilter(svcIP, podIP, ctx string) error {
	var failed error
	if err := c.Proxy.DeletePortFilter(svcIP, podIP); err != nil {
		log.Error(err, "failed to delete port filter "+ctx, "svcIP", svcIP, "podIP", podIP)
		failed = err
	}
	if err := c.Proxy.DeleteICMPAllow(svcIP, podIP); err != nil {
		log.Error(err, "failed to delete ICMP allow "+ctx, "svcIP", svcIP, "podIP", podIP)
		failed = err
	}
	return failed
}

// snapshotSource returns the pairs the datapath should hold.
//
// It reads the informer stores when they are available, because they are
// authoritative as soon as WaitForCacheSync returns, whereas Services is
// filled by callbacks that may not have run yet. Falling back to Services
// keeps the controller usable without informers, which is how the unit tests
// drive it.
func (c *ServicesController) snapshotSource() map[string]*ServiceEndpoints {
	if c.svcStore == nil || c.epStore == nil {
		return c.Services.GetAll()
	}
	out := make(map[string]*ServiceEndpoints)
	for _, obj := range c.svcStore.List() {
		svc, ok := obj.(*v1.Service)
		if !ok || !isCozyProxyService(svc) || !hasValidServiceIP(svc) {
			continue
		}
		epObj, exists, err := c.epStore.GetByKey(makeKey(svc.Namespace, svc.Name))
		if err != nil || !exists {
			continue
		}
		ep, ok := epObj.(*v1.Endpoints)
		if !ok || !hasValidEndpointIP(ep) {
			continue
		}
		out[makeKey(svc.Namespace, svc.Name)] = &ServiceEndpoints{Service: svc, Endpoint: ep}
	}
	return out
}

// cleanupRemovedServices performs an initial cleanup for removed services.
func (c *ServicesController) cleanupRemovedServices() error {
	// Reconciliations are serialized end to end, see reconcileMu.
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	// keepEgress holds every managed pair, because the source rewrite is
	// programmed cluster-wide. keepIngress holds only the pairs whose backend
	// runs here, because the destination rewrite is node-local. The difference
	// between the two is what purges entries inherited from a build that
	// scoped both maps alike.
	keepEgress := make(map[string]string)
	keepIngress := make(map[string]string)
	allServices := c.snapshotSource()
	for _, serviceEndpoints := range allServices {
		if serviceEndpoints.Service == nil || serviceEndpoints.Endpoint == nil {
			continue
		}
		if !hasValidServiceIP(serviceEndpoints.Service) || !hasValidEndpointIP(serviceEndpoints.Endpoint) {
			continue
		}

		serviceIP := serviceEndpoints.Service.Status.LoadBalancer.Ingress[0].IP
		endpointIP := serviceEndpoints.Endpoint.Subsets[0].Addresses[0].IP

		keepEgress[serviceIP] = endpointIP
		if c.servesEndpoint(serviceEndpoints.Endpoint) {
			keepIngress[serviceIP] = endpointIP
		}
	}
	// Call InitialCleanup with the snapshot.
	if err := c.Proxy.CleanupRules(keepEgress, keepIngress); err != nil {
		return fmt.Errorf("failed to perform initial cleanup: %w", err)
	}
	// Build per-svc port filter snapshot for services in non-passthrough mode.
	// Keyed by svcIP (caller convenience); the entry carries podIP and ports
	// because the actual nft set keys are pod IPs (post-DNAT match).
	keepFilters := make(map[string]nat.PortFilterEntry)
	for _, se := range allServices {
		if se.Service == nil || se.Endpoint == nil {
			continue
		}
		if !hasValidServiceIP(se.Service) || !hasValidEndpointIP(se.Endpoint) {
			continue
		}
		if wholeIPPassthrough(se.Service) || !c.servesEndpoint(se.Endpoint) {
			continue
		}
		keepFilters[se.Service.Status.LoadBalancer.Ingress[0].IP] = nat.PortFilterEntry{
			PodIP: se.Endpoint.Subsets[0].Addresses[0].IP,
			Ports: se.Service.Spec.Ports,
		}
	}
	if err := c.Proxy.CleanupPortFilters(keepFilters); err != nil {
		return fmt.Errorf("failed to perform port-filter cleanup: %w", err)
	}
	// Build ICMP-allow snapshot: services in port-filter mode that opt into
	// ICMP via the allowICMP annotation.
	keepICMP := make(map[string]string)
	for _, se := range allServices {
		if se.Service == nil || se.Endpoint == nil {
			continue
		}
		if !hasValidServiceIP(se.Service) || !hasValidEndpointIP(se.Endpoint) {
			continue
		}
		if wholeIPPassthrough(se.Service) || !allowICMP(se.Service) || !c.servesEndpoint(se.Endpoint) {
			continue
		}
		keepICMP[se.Service.Status.LoadBalancer.Ingress[0].IP] = se.Endpoint.Subsets[0].Addresses[0].IP
	}
	if err := c.Proxy.CleanupICMPAllow(keepICMP); err != nil {
		return fmt.Errorf("failed to perform ICMP-allow cleanup: %w", err)
	}
	return nil
}
