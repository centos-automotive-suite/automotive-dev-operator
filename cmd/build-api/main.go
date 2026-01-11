package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
)

func main() {
	// Parse command line flags
	var (
		kubeconfigPath = flag.String("kubeconfig-path", "", "Path to kubeconfig file")
		port           = flag.String("port", "", "Port to listen on (default: 8080)")
		namespace      = flag.String("namespace", "automotive-dev-operator-system", "Kubernetes namespace to use")
	)
	flag.Parse()

	// Set kubeconfig from flag if provided
	if *kubeconfigPath != "" {
		os.Setenv("KUBECONFIG", *kubeconfigPath)
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))
	logger := logr.FromSlogHandler(handler)
	ctrl.SetLogger(logger)

	// Configure server address
	addr := ":8080"
	if *port != "" {
		addr = ":" + *port
	} else if p := os.Getenv("PORT"); p != "" {
		addr = ":" + p
	}

	if *namespace != "" {
		os.Setenv("BUILD_API_NAMESPACE", *namespace)
	}

	// Set Gin mode for development/testing
	if os.Getenv("GIN_MODE") == "" {
		os.Setenv("GIN_MODE", "debug")
	}

	// Load API limits from OperatorConfig
	limits := loadLimitsFromOperatorConfig(*namespace, logger)

	slog.Info("starting build-api server",
		"addr", addr,
		"gin_mode", os.Getenv("GIN_MODE"),
		"kubeconfig", os.Getenv("KUBECONFIG"),
		"namespace", os.Getenv("BUILD_API_NAMESPACE"),
		"maxManifestSize", limits.MaxManifestSize,
		"maxUploadFileSize", limits.MaxUploadFileSize,
		"maxTotalUploadSize", limits.MaxTotalUploadSize,
		"maxLogStreamDurationMinutes", limits.MaxLogStreamDurationMinutes)

	apiServer := buildapi.NewAPIServerWithLimits(addr, logger, limits)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		slog.Info("received shutdown signal")
		cancel()
	}()

	if err := apiServer.Start(ctx); err != nil {
		slog.Error("server error", "error", err)
	}
}

func loadLimitsFromOperatorConfig(namespace string, logger logr.Logger) buildapi.APILimits {
	k8sClient, err := createK8sClient()
	if err != nil {
		logger.Info("could not create Kubernetes client, using default limits", "error", err)
		return buildapi.DefaultAPILimits()
	}

	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := k8sClient.Get(context.Background(), types.NamespacedName{Name: "config", Namespace: namespace}, operatorConfig); err != nil {
		logger.Info("could not get OperatorConfig, using default limits", "error", err)
		return buildapi.DefaultAPILimits()
	}

	return buildapi.LoadLimitsFromConfig(operatorConfig.Spec.BuildAPI)
}

func createK8sClient() (client.Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		cfg, err = clientcmd.BuildConfigFromFlags("", os.Getenv("KUBECONFIG"))
		if err != nil {
			return nil, err
		}
	}

	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	return client.New(cfg, client.Options{Scheme: scheme})
}
