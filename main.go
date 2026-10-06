package main

import (
	"flag"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/cozystack/cozy-proxy/pkg/controllers"
	"github.com/cozystack/cozy-proxy/pkg/l4"
	"github.com/cozystack/cozy-proxy/pkg/proxy"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	scheme = runtime.NewScheme()
	log    = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
}

func main() {
	var probeAddr string
	var metricsAddr string
	var enableL4 bool
	var enableVM bool
	var removeL4Table bool
	flag.StringVar(&probeAddr, "health-probe-bind-address", "0", "The address the probe endpoint binds to. Set to \"0\" to disable.")
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metric endpoint binds to. Set to \"0\" to disable.")
	flag.BoolVar(&enableL4, "enable-l4-loadbalancer", false,
		"Run the L4 LoadBalancer mode for services labelled "+l4.ProxyLabel+"="+l4.ProxyLabelValue+
			" (see docs/rfc/l4-loadbalancer-mode.md).")
	flag.BoolVar(&removeL4Table, "remove-l4-table-when-disabled", true,
		"With the L4 mode disabled, remove the table left by an earlier run, which is how the mode is rolled back. "+
			"Turn it off on an instance that runs next to another cozy-proxy running the L4 mode: "+
			"each of its starts would delete that instance's table.")
	flag.BoolVar(&enableVM, "enable-vm-mode", true,
		"Run the VM mode for services labelled service.kubernetes.io/service-proxy-name=cozy-proxy. "+
			"Turn it off only for an instance running the L4 mode next to another cozy-proxy that keeps the VM mode.")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsserver.Options{BindAddress: metricsAddr},
		HealthProbeBindAddress: probeAddr,
	})
	if err != nil {
		log.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// The L4 mode builds its own clients from an untouched copy: the VM mode
	// pins the shared config to the core group below.
	l4Cfg := rest.CopyConfig(mgr.GetConfig())

	cfg := mgr.GetConfig()
	cfg.GroupVersion = &corev1.SchemeGroupVersion
	cfg.APIPath = "/api"

	cfg.NegotiatedSerializer = serializer.WithoutConversionCodecFactory{
		CodecFactory: serializer.NewCodecFactory(scheme),
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "failed to create clientset")
		os.Exit(1)
	}

	// Datapath rules are programmed only for backend pods hosted on this node.
	// When NODE_NAME is absent the check is disabled and every service is
	// programmed, which is the pre-node-local behavior: degraded, but it keeps
	// a new binary working under a chart that does not inject the variable yet.
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Info("NODE_NAME is not set, falling back to programming rules for every node's backends; " +
			"set it from spec.nodeName to scope rules to this node")
	}

	if enableVM {
		controller := &controllers.ServicesController{
			Clientset: clientset,
			Proxy:     &proxy.NFTProxyProcessor{},
			NodeName:  nodeName,
		}

		if err := mgr.Add(controller); err != nil {
			log.Error(err, "unable to add endpoints controller to manager")
			os.Exit(1)
		}
	} else {
		// Another instance owns the cozy_proxy table: leave it alone, the VM
		// mode's startup would rebuild its chains and purge its maps.
		log.Info("VM mode disabled, the cozy_proxy table is left untouched")
	}

	setupL4(mgr, l4Cfg, enableL4, removeL4Table, nodeName)

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	log.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// setupL4 adds the L4 LoadBalancer mode to the manager. When it is disabled,
// it removes what an earlier run left if removeTable is set, and otherwise
// leaves the table to the instance that owns it. Nothing here may stop the
// process: the VM mode runs in the same manager.
func setupL4(mgr ctrl.Manager, cfg *rest.Config, enabled, removeTable bool, nodeName string) {
	datapath := &proxy.NFTL4Datapath{}
	if !enabled {
		if !removeTable {
			log.Info("L4 mode disabled, the " + proxy.L4TableName + " table is left untouched")
			return
		}
		if err := datapath.Teardown(); err != nil {
			log.Error(err, "could not remove the L4 table left by an earlier run")
		}
		return
	}
	if nodeName == "" {
		log.Error(nil, "the L4 LoadBalancer mode needs NODE_NAME to tell which backends are local; not starting it")
		return
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "failed to create the L4 clientset; not starting the L4 mode")
		return
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Error(err, "failed to create the L4 dynamic client; not starting the L4 mode")
		return
	}
	if err := mgr.Add(&controllers.L4Controller{
		Clientset: clientset,
		Dynamic:   dyn,
		NodeName:  nodeName,
		Datapath:  datapath,
		Conntrack: &proxy.NetlinkConntrack{},
	}); err != nil {
		log.Error(err, "unable to add the L4 controller to the manager")
		return
	}
	log.Info("L4 LoadBalancer mode enabled")
}
