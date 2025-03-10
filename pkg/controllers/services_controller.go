package controllers

import (
	"context"
	"fmt"
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

	// Run cleanup for removed services.
	log.Info("running cleanup for removed services")
	if err := c.cleanupRemovedServices(); err != nil {
		return fmt.Errorf("failed to cleanup removed services: %w", err)
	}
	log.Info("cleanup of removed services completed")

	<-ctx.Done()
	log.Info("shutting down services-controller")

	return nil
}

// addServiceFunc handles the addition of a service.
func (c *ServicesController) addServiceFunc(obj interface{}) {
	svc, ok := obj.(*v1.Service)
	if !ok {
		// Object is not a Service.
		return
	}
	if !hasWholeIPAnnotation(svc) {
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
		// Ensure NAT mapping rules are set.
		c.Proxy.EnsureRules(svc.Status.LoadBalancer.Ingress[0].IP, ep.Subsets[0].Addresses[0].IP)
	}
}

// deleteServiceFunc handles the deletion of a service.
func (c *ServicesController) deleteServiceFunc(obj interface{}) {
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

	c.Proxy.DeleteRules(se.Service.Status.LoadBalancer.Ingress[0].IP, se.Endpoint.Subsets[0].Addresses[0].IP)
	c.Services.Delete(svc.Namespace, svc.Name)
}

// updateServiceFunc handles service updates.
func (c *ServicesController) updateServiceFunc(oldObj, newObj interface{}) {
	// Cast the object to a Service type.
	svc, ok := newObj.(*v1.Service)
	if !ok {
		// Object is not a Service.
		return
	}

	// If the required annotation is missing, remove the service mapping and delete NAT rules if applicable.
	if !hasWholeIPAnnotation(svc) {
		if se, exists := c.Services.Get(svc.Namespace, svc.Name); exists {
			if hasValidServiceIP(se.Service) && hasValidEndpointIP(se.Endpoint) {
				c.Proxy.DeleteRules(
					se.Service.Status.LoadBalancer.Ingress[0].IP,
					se.Endpoint.Subsets[0].Addresses[0].IP,
				)
			}
			c.Services.Delete(svc.Namespace, svc.Name)
		}
		return
	}

	// If the service does not have a valid IP, remove the service mapping.
	if !hasValidServiceIP(svc) {
		if se, exists := c.Services.Get(svc.Namespace, svc.Name); exists {
			if hasValidServiceIP(se.Service) && hasValidEndpointIP(se.Endpoint) {
				c.Proxy.DeleteRules(
					se.Service.Status.LoadBalancer.Ingress[0].IP,
					se.Endpoint.Subsets[0].Addresses[0].IP,
				)
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
			c.Proxy.DeleteRules(
				se.Service.Status.LoadBalancer.Ingress[0].IP,
				se.Endpoint.Subsets[0].Addresses[0].IP,
			)
		}
		c.Services.Set(svc.Namespace, svc.Name, &ServiceEndpoints{Service: svc, Endpoint: nil})
		return
	}

	// At this point, both the Service and Endpoint have valid IPs.
	// Ensure NAT mapping is up-to-date.
	c.Proxy.EnsureRules(
		svc.Status.LoadBalancer.Ingress[0].IP,
		ep.Subsets[0].Addresses[0].IP,
	)

	// Update or add the service mapping with the new endpoint.
	c.Services.Set(svc.Namespace, svc.Name, &ServiceEndpoints{Service: svc, Endpoint: ep})
}

// addEndpointFunc handles the addition of endpoints.
func (c *ServicesController) addEndpointFunc(obj interface{}) {
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
		c.Proxy.EnsureRules(
			se.Service.Status.LoadBalancer.Ingress[0].IP,
			ep.Subsets[0].Addresses[0].IP,
		)
	}
}

// deleteEndpointFunc handles endpoint deletions.
func (c *ServicesController) deleteEndpointFunc(obj interface{}) {
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
	c.Proxy.DeleteRules(se.Service.Status.LoadBalancer.Ingress[0].IP, se.Endpoint.Subsets[0].Addresses[0].IP)
	// Set the endpoint to nil.
	c.Services.SetEndpoint(ep.Namespace, ep.Name, nil)
}

// updateEndpointFunc handles updates to endpoints.
func (c *ServicesController) updateEndpointFunc(oldObj, newObj interface{}) {
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
			c.Proxy.DeleteRules(se.Service.Status.LoadBalancer.Ingress[0].IP, se.Endpoint.Subsets[0].Addresses[0].IP)
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
	c.Proxy.EnsureRules(se.Service.Status.LoadBalancer.Ingress[0].IP, ep.Subsets[0].Addresses[0].IP)
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

// hasWholeIPAnnotation checks if the service has the wholeIP annotation set to true.
func hasWholeIPAnnotation(svc *v1.Service) bool {
	val, ok := svc.Annotations["networking.cozystack.io/wholeIP"]
	return ok && val == "true"
}

// cleanupRemovedServices performs an initial cleanup for removed services.
func (c *ServicesController) cleanupRemovedServices() error {
	keepMap := make(map[string]string)
	// Get a snapshot of all managed services.
	allServices := c.Services.GetAll()
	for _, serviceEndpoints := range allServices {
		if serviceEndpoints.Service != nil && serviceEndpoints.Endpoint != nil {
			var serviceIP, endpointIP string

			if len(serviceEndpoints.Service.Status.LoadBalancer.Ingress) > 0 {
				serviceIP = serviceEndpoints.Service.Status.LoadBalancer.Ingress[0].IP
			}
			if len(serviceEndpoints.Endpoint.Subsets) > 0 && len(serviceEndpoints.Endpoint.Subsets[0].Addresses) > 0 {
				endpointIP = serviceEndpoints.Endpoint.Subsets[0].Addresses[0].IP
			}

			if serviceIP != "" && endpointIP != "" {
				keepMap[serviceIP] = endpointIP
			}
		}
	}
	// Call InitialCleanup with the snapshot.
	if err := c.Proxy.CleanupRules(keepMap); err != nil {
		return fmt.Errorf("failed to perform initial cleanup: %w", err)
	}
	return nil
}
