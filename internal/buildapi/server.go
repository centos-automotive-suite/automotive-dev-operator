package buildapi

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/catalog"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/bundleverify"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/manifestschema"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var apiTracer = otel.Tracer("build-api")

func spanError(span trace.Span, err error) {
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

type traceIDContextKey struct{}

func extractTraceID(ctx context.Context) string {
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		return sc.TraceID().String()
	}
	if id, ok := ctx.Value(traceIDContextKey{}).(string); ok && id != "" {
		return id
	}
	return ""
}

const (
	// Build phase constants — aliases for readability; canonical values in api/v1alpha1
	phaseCancelled = automotivev1alpha1.ImageBuildPhaseCancelled
	phaseCompleted = automotivev1alpha1.ImageBuildPhaseCompleted
	phaseFailed    = automotivev1alpha1.ImageBuildPhaseFailed
	phasePending   = automotivev1alpha1.ImageBuildPhasePending
	phaseUploading = automotivev1alpha1.ImageBuildPhaseUploading
	phaseBuilding  = automotivev1alpha1.ImageBuildPhaseBuilding
	phasePushing   = automotivev1alpha1.ImageBuildPhasePushing
	phaseFlashing  = automotivev1alpha1.ImageBuildPhaseFlashing
	phaseRunning   = "Running"

	// Image format constants
	formatImage    = "image"
	formatQcow2    = "qcow2"
	extensionRaw   = ".raw"
	extensionQcow2 = ".qcow2"
	statusUnknown  = "unknown"
	statusMissing  = "MISSING"
	buildAPIName   = "ado-build-api"

	// maxManifestSize is the maximum allowed manifest size in bytes.
	// Manifests are stored in ConfigMaps, which are limited by etcd's ~1MB object size.
	maxManifestSize = 900 * 1024
)

// buildProducedArtifacts reports whether artifact URLs point to real objects.
// For Failed builds, only true when flash was attempted (proving push succeeded).
func buildProducedArtifacts(build *automotivev1alpha1.ImageBuild) bool {
	switch build.Status.Phase {
	case phaseCompleted, phaseFlashing:
		return true
	case phaseFailed:
		return build.Status.FlashTaskRunName != ""
	default:
		return false
	}
}

var getClientFromRequestFn = getClientFromRequest
var getRESTConfigFromRequestFn = getRESTConfigFromRequest
var createInternalRegistrySecretFn = createInternalRegistrySecret
var newPodExecExecutorFn = func(
	config *rest.Config,
	namespace, podName, containerName string,
	cmd []string,
) (remotecommand.Executor, error) {
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	req := clientset.CoreV1().RESTClient().Post().Resource("pods").Name(podName).Namespace(namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   cmd,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, kscheme.ParameterCodec)
	return remotecommand.NewSPDYExecutor(config, http.MethodPost, req.URL())
}
var loadOperatorConfigFn = func(
	ctx context.Context,
	k8sClient client.Client,
	namespace string,
) (*automotivev1alpha1.OperatorConfig, error) {
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      "config",
	}, operatorConfig); err != nil {
		return nil, err
	}
	return operatorConfig, nil
}

var loadTargetDefaultsFn = func(
	ctx context.Context,
	k8sClient client.Client,
	namespace string,
) (map[string]TargetDefaults, error) {
	cm := &corev1.ConfigMap{}
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Namespace: namespace,
		Name:      "aib-target-defaults",
	}, cm); err != nil {
		return nil, err
	}

	data, ok := cm.Data["target-defaults.yaml"]
	if !ok {
		return nil, nil
	}

	var parsed struct {
		Targets map[string]struct {
			Architecture          string   `yaml:"architecture"`
			ExtraArgs             []string `yaml:"extraArgs"`
			DefaultFormat         string   `yaml:"defaultFormat"`
			AcceptedFormats       []string `yaml:"acceptedFormats"`
			AcceptedArchitectures []string `yaml:"acceptedArchitectures"`
		} `yaml:"targets"`
	}
	if err := yaml.Unmarshal([]byte(data), &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse target-defaults.yaml: %w", err)
	}

	result := make(map[string]TargetDefaults, len(parsed.Targets))
	for name, t := range parsed.Targets {
		result[name] = TargetDefaults{
			Architecture:          t.Architecture,
			ExtraArgs:             t.ExtraArgs,
			DefaultFormat:         t.DefaultFormat,
			AcceptedFormats:       t.AcceptedFormats,
			AcceptedArchitectures: t.AcceptedArchitectures,
		}
	}

	if err := validateTargetDefaults(result); err != nil {
		return nil, fmt.Errorf("invalid target-defaults.yaml: %w", err)
	}

	return result, nil
}

// APILimits holds configurable limits for the API server
type APILimits struct {
	MaxUploadFileSize           int64
	MaxTotalUploadSize          int64
	MaxLogStreamDurationMinutes int32
	ClientTokenExpiryDays       int32
}

// DefaultAPILimits returns the default limits
func DefaultAPILimits() APILimits {
	return APILimits{
		MaxUploadFileSize:           1 * 1024 * 1024 * 1024, // 1GB
		MaxTotalUploadSize:          2 * 1024 * 1024 * 1024, // 2GB
		MaxLogStreamDurationMinutes: 120,                    // 2 hours
		ClientTokenExpiryDays:       automotivev1alpha1.DefaultClientTokenExpiryDays,
	}
}

// APIServer provides the REST API for build operations.
type APIServer struct {
	server              *http.Server
	router              *gin.Engine
	addr                string
	log                 logr.Logger
	limits              APILimits
	internalJWT         *internalJWTConfig
	externalJWT         authenticator.Token
	internalPrefix      string
	authConfig          *AuthenticationConfiguration // Store raw config for API exposure
	oidcClientID        string
	authConfigMu        sync.RWMutex // Protects externalJWT, authConfig, internalPrefix, oidcClientID
	lastAuthConfigCheck time.Time    // Last time we checked OperatorConfig
	progressCache       map[string]progressCacheEntry
	progressCacheMu     sync.RWMutex
}

//go:embed openapi.yaml
var embeddedOpenAPI []byte

// NewAPIServer creates a new API server
func NewAPIServer(addr string, logger logr.Logger) *APIServer {
	return NewAPIServerWithLimits(addr, logger, DefaultAPILimits())
}

// NewAPIServerWithLimits creates a new API server with custom limits
func NewAPIServerWithLimits(addr string, logger logr.Logger, limits APILimits) *APIServer {
	// Gin mode should be controlled by environment, not by which constructor is used
	if os.Getenv("GIN_MODE") == "" {
		// Default to release mode for production safety
		gin.SetMode(gin.ReleaseMode)
	}

	a := &APIServer{addr: addr, log: logger, limits: limits}
	if clientID := strings.TrimSpace(os.Getenv("BUILD_API_OIDC_CLIENT_ID")); clientID != "" {
		a.oidcClientID = clientID
	}
	if cfg, err := loadInternalJWTConfig(); err != nil {
		logger.Error(err, "internal JWT configuration is invalid; internal JWT auth disabled")
	} else if cfg != nil {
		a.internalJWT = cfg
		logger.Info("internal JWT auth enabled", "issuer", cfg.issuer, "audience", cfg.audience)
	}

	// Try to load authentication configuration directly from OperatorConfig CRD
	namespace := resolveNamespace()
	logger.Info("attempting to load authentication config from OperatorConfig", "namespace", namespace)
	k8sClient, err := a.getCatalogClient()
	if err == nil {
		// IMPORTANT: Use context.Background() without cancel - the OIDC authenticator does lazy
		// initialization in the background and needs the context to remain valid after this function returns.
		// Using a cancellable context would kill the background JWKS fetch.
		cfg, authn, prefix, err := loadAuthenticationConfigurationFromOperatorConfig(context.Background(), k8sClient, namespace)
		if err != nil {
			// If OperatorConfig doesn't exist or can't be read, log and continue without OIDC
			// This allows kubeconfig fallback to work
			logger.Info("failed to load authentication config from OperatorConfig, will use kubeconfig fallback", "namespace", namespace, "error", err)
		} else if cfg != nil {
			a.authConfig = cfg
			a.externalJWT = authn
			a.internalPrefix = prefix
			if cfg.ClientID != "" {
				a.oidcClientID = cfg.ClientID
			}
			if len(cfg.JWT) > 0 {
				if authn != nil {
					logger.Info("loaded authentication config from OperatorConfig", "jwt_count", len(cfg.JWT), "namespace", namespace, "client_id", cfg.ClientID)
				} else {
					logger.Info("OIDC configured in OperatorConfig but initialization failed, externalJWT set to nil to enable kubeconfig fallback", "jwt_count", len(cfg.JWT), "namespace", namespace)
					// Ensure externalJWT is nil so clients don't try to use OIDC tokens
					a.externalJWT = nil
				}
			} else {
				logger.Info("authentication config loaded from OperatorConfig but no JWT issuers configured", "namespace", namespace)
			}
		} else {
			logger.Info("no authentication config in OperatorConfig, will use kubeconfig fallback", "namespace", namespace)
		}
	} else {
		logger.Info("failed to create k8s client for OperatorConfig, will use kubeconfig fallback", "error", err)
	}
	a.router = a.createRouter()
	a.server = &http.Server{Addr: addr, Handler: otelhttp.NewHandler(a.router, "build-api")}
	return a
}

// LoadLimitsFromConfig loads API limits from OperatorConfig, using defaults for unset values
func LoadLimitsFromConfig(cfg *automotivev1alpha1.BuildAPIConfig) APILimits {
	limits := DefaultAPILimits()
	if cfg == nil {
		return limits
	}
	if cfg.MaxUploadFileSize > 0 {
		limits.MaxUploadFileSize = cfg.MaxUploadFileSize
	}
	if cfg.MaxTotalUploadSize > 0 {
		limits.MaxTotalUploadSize = cfg.MaxTotalUploadSize
	}
	if cfg.MaxLogStreamDurationMinutes > 0 {
		limits.MaxLogStreamDurationMinutes = cfg.MaxLogStreamDurationMinutes
	}
	if cfg.ClientTokenExpiryDays > 0 {
		limits.ClientTokenExpiryDays = cfg.ClientTokenExpiryDays
	}
	return limits
}

// Start implements manager.Runnable
func (a *APIServer) Start(ctx context.Context) error {

	go func() {
		a.log.Info("build-api listening", "addr", a.addr)
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.log.Error(err, "build-api server error")
		}
	}()

	go a.startResourceWatcher(ctx)

	<-ctx.Done()
	a.log.Info("shutting down build-api server...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := a.server.Shutdown(shutdownCtx); err != nil {
		a.log.Error(err, "build-api server forced to shutdown")
		return err
	}
	a.log.Info("build-api server exited")
	return nil
}

func (a *APIServer) createRouter() *gin.Engine {
	router := gin.New()
	router.Use(gin.Recovery())

	router.Use(func(c *gin.Context) {
		reqID := uuid.New().String()
		c.Set("reqID", reqID)

		ctx := c.Request.Context()
		if sc := trace.SpanContextFromContext(ctx); !sc.IsValid() {
			var tid trace.TraceID
			_, _ = rand.Read(tid[:])
			ctx = context.WithValue(ctx, traceIDContextKey{}, tid.String())
			c.Request = c.Request.WithContext(ctx)
		}

		a.log.Info("http request", "method", c.Request.Method, "path", c.Request.URL.Path, "reqID", reqID, "traceID", extractTraceID(ctx))
		c.Next()
	})

	router.GET("/metrics", metricsHandler())

	v1 := router.Group("/v1")
	{
		v1.GET("/healthz", func(c *gin.Context) {
			c.String(http.StatusOK, "ok")
		})

		v1.GET("/openapi.yaml", func(c *gin.Context) {
			c.Data(http.StatusOK, "application/yaml", embeddedOpenAPI)
		})

		// Auth config endpoint (no auth required - needed for OIDC discovery)
		v1.GET("/auth/config", a.handleGetAuthConfig)

		buildsGroup := v1.Group("/builds")
		buildsGroup.Use(a.authMiddleware())
		{
			buildsGroup.POST("", a.wrapHandler("create build", a.createBuild))
			buildsGroup.GET("", a.wrapHandler("list builds", listBuilds))
			buildsGroup.GET("/:name", a.wrapNamedHandler("get build", a.getBuild))
			buildsGroup.GET("/:name/logs", a.wrapNamedHandler("logs requested", a.streamLogs))
			buildsGroup.GET("/:name/progress", a.handleGetProgress)
			buildsGroup.GET("/:name/template", a.wrapNamedHandler("template requested", getBuildTemplate))
			buildsGroup.POST("/:name/uploads", a.wrapNamedHandler("uploads", a.uploadFiles))
			buildsGroup.POST("/:name/token", a.handleCreateBuildToken)
			buildsGroup.POST("/:name/cancel", a.wrapNamedHandler("cancel build", a.cancelBuild))
			buildsGroup.DELETE("/:name", a.wrapNamedHandler("delete build", a.deleteBuild))
		}

		flashGroup := v1.Group("/flash")
		flashGroup.Use(flashMetricsMiddleware(), a.authMiddleware())
		{
			flashGroup.POST("", a.wrapHandler("create flash", a.createFlash))
			flashGroup.GET("", a.wrapHandler("list flash jobs", a.listFlash))
			flashGroup.GET("/:name", a.wrapNamedHandler("get flash", a.getFlash))
			flashGroup.GET("/:name/logs", a.wrapNamedHandler("flash logs requested", a.streamFlashLogs))
		}

		configGroup := v1.Group("/config")
		configGroup.Use(a.authMiddleware())
		{
			configGroup.GET("", a.handleGetOperatorConfig)
		}

		containerBuildsGroup := v1.Group("/container-builds")
		containerBuildsGroup.Use(a.authMiddleware())
		{
			containerBuildsGroup.POST("", a.wrapHandler("create container build", a.createContainerBuild))
			containerBuildsGroup.GET("", a.wrapHandler("list container builds", listContainerBuilds))
			containerBuildsGroup.GET("/:name", a.wrapNamedHandler("get container build", a.getContainerBuild))
			containerBuildsGroup.POST("/:name/upload", a.wrapNamedHandler("container build upload", a.uploadContainerBuildContext))
			containerBuildsGroup.GET("/:name/logs", a.wrapNamedHandler("container build logs", a.streamContainerBuildLogs))
		}

		a.registerSealedRoutes(v1)

		a.registerWorkspaceRoutes(v1)

		// Register catalog routes with authentication
		catalogClient, err := a.getCatalogClient()
		if err != nil {
			a.log.Error(err, "failed to create catalog client, catalog routes will not be available")
		} else if catalogClient != nil {
			a.log.Info("registering catalog routes")
			catalog.RegisterRoutes(v1, catalogClient, a.log)
		}
	}

	return router
}

// StartServer starts the REST API server on the given address in a goroutine and returns the server
func StartServer(addr string, logger logr.Logger) (*http.Server, error) {
	api := NewAPIServer(addr, logger)
	server := api.server
	go func() {
		if err := api.Start(context.Background()); err != nil {
			logger.Error(err, "failed to start build-api server")
		}
	}()
	return server, nil
}

// getCatalogClient returns a Kubernetes client for catalog operations
func (a *APIServer) getCatalogClient() (client.Client, error) {
	var cfg *rest.Config
	var err error
	cfg, err = rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build kube config: %w", err)
		}
	}

	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add automotive scheme: %w", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add core scheme: %w", err)
	}

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}
	return k8sClient, nil
}

// authError represents an authentication failure with a reason
type authError struct {
	Reason  string `json:"reason"`
	Details string `json:"details,omitempty"`
}

func (a *APIServer) handleCreateBuildToken(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("token requested", "build", name, "reqID", c.GetString("reqID"))

	namespace := resolveNamespace()
	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}

	ctx := c.Request.Context()
	build := &automotivev1alpha1.ImageBuild{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, build, "build"); err != nil {
		return
	}

	// Verify the requesting user owns this build
	requester := a.resolveRequester(c)
	owner := build.Annotations[labels.RequestedBy]
	if owner != requester {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only request tokens for your own builds"})
		return
	}

	if !build.Spec.GetUseServiceAccountAuth() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "build does not use the internal registry"})
		return
	}

	if build.Status.Phase != phaseCompleted {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("build is not completed (current: %s)", build.Status.Phase)})
		return
	}

	// Determine the image ref first — only mint tokens if there's an internal image
	imageRef := build.Spec.GetExportOCI()
	if imageRef == "" {
		imageRef = build.Spec.GetContainerPush()
	}
	if imageRef == "" || !strings.HasPrefix(imageRef, defaultInternalRegistryURL+"/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "build has no image in the internal registry"})
		return
	}

	tokenLifetime := resolveTokenLifetime(ctx, k8sClient, namespace)
	token, expiresAt, err := a.mintRegistryToken(ctx, c, namespace, tokenLifetime)
	if err != nil {
		a.log.Error(err, "failed to mint registry token", "build", name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to mint registry token: %v", err)})
		return
	}

	registryHost := ""
	externalRoute, routeErr := getExternalRegistryRoute(ctx, k8sClient, namespace)
	if routeErr == nil && externalRoute != "" {
		imageRef = translateToExternalURL(imageRef, externalRoute)
		registryHost = externalRoute
	} else {
		registryHost = strings.SplitN(imageRef, "/", 2)[0]
	}

	writeJSON(c, http.StatusOK, TokenResponse{
		Registry:  registryHost,
		Username:  "serviceaccount",
		Token:     token,
		ExpiresAt: expiresAt.UTC().Format(time.RFC3339),
		Image:     imageRef,
	})
}

func (a *APIServer) deleteBuild(c *gin.Context, name string) {
	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}

	namespace := resolveNamespace()
	ctx := c.Request.Context()

	build := &automotivev1alpha1.ImageBuild{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, build, "build"); err != nil {
		return
	}

	requester := a.resolveRequester(c)
	owner := build.Annotations[labels.RequestedBy]
	if owner != requester {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only delete your own builds"})
		return
	}

	// Clean up ImageStream tags created by this build before deleting
	// Only delete the specific tags this build created; if the stream becomes
	// empty afterwards, delete the whole ImageStream.
	if build.Spec.GetUseServiceAccountAuth() {
		streamName, tags := resolveImageStreamRefs(build)
		if streamName != "" {
			for _, tag := range tags {
				if delErr := deleteImageStreamTag(ctx, k8sClient, namespace, streamName, tag); delErr != nil {
					if !k8serrors.IsNotFound(delErr) {
						a.log.Error(delErr, "failed to delete ImageStreamTag", "imageStreamTag", streamName+":"+tag)
					}
				}
			}
			// If no tags remain, clean up the empty ImageStream
			hasTags, err := imageStreamHasTags(ctx, k8sClient, namespace, streamName)
			if err != nil {
				if !k8serrors.IsNotFound(err) {
					a.log.Error(err, "failed to check ImageStream tags", "imageStream", streamName)
				}
			} else if !hasTags {
				if delErr := deleteImageStream(ctx, k8sClient, namespace, streamName); delErr != nil {
					if !k8serrors.IsNotFound(delErr) {
						a.log.Error(delErr, "failed to delete empty ImageStream", "imageStream", streamName)
					}
				}
			}
		}
	}

	// Delete the ImageBuild CR — Kubernetes cascading delete handles owned resources
	// (PipelineRuns, TaskRuns, PVCs, Secrets, Pods, Services, ConfigMaps)
	if err := k8sClient.Delete(ctx, build); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to delete build: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("build %q deleted", name)})
}

func (a *APIServer) cancelBuild(c *gin.Context, name string) {
	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}

	namespace := resolveNamespace()
	ctx := c.Request.Context()

	build := &automotivev1alpha1.ImageBuild{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, build, "build"); err != nil {
		return
	}

	requester := a.resolveRequester(c)
	owner := build.Annotations[labels.RequestedBy]
	if owner != requester {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only cancel your own builds"})
		return
	}

	switch build.Status.Phase {
	case "", phasePending, phaseUploading, phaseBuilding, phasePushing, phaseFlashing:
		// cancellable
	default:
		c.JSON(http.StatusConflict, gin.H{
			"error": fmt.Sprintf("build is in %q phase and cannot be cancelled", build.Status.Phase),
		})
		return
	}

	if build.Status.PipelineRunName != "" {
		pipelineRun := &tektonv1.PipelineRun{}
		prKey := types.NamespacedName{Name: build.Status.PipelineRunName, Namespace: namespace}
		if err := k8sClient.Get(ctx, prKey, pipelineRun); err != nil {
			if !k8serrors.IsNotFound(err) {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching PipelineRun: %v", err)})
				return
			}
		} else if pipelineRun.Status.CompletionTime != nil {
			c.JSON(http.StatusConflict, gin.H{
				"error": "build has already completed; refresh and retry",
			})
			return
		} else {
			pipelineRun.Spec.Status = tektonv1.PipelineRunSpecStatusCancelled
			if err := k8sClient.Update(ctx, pipelineRun); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to cancel PipelineRun: %v", err)})
				return
			}
		}
	}

	build.Status.Phase = phaseCancelled
	build.Status.Message = "Build cancelled by user"
	now := metav1.Now()
	if build.Status.CompletionTime == nil {
		build.Status.CompletionTime = &now
	}
	if err := k8sClient.Status().Update(ctx, build); err != nil {
		// Controller may have already set phase to Cancelled after seeing the PipelineRun cancel
		if k8serrors.IsConflict(err) {
			c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("build %q cancelled", name)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update build status: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("build %q cancelled", name)})
}

// resolveRegistryForBuild handles registry setup for both internal and external registry builds.
// It returns envSecretRef, pushSecretName, and an error (non-nil means the response was already written).
func (a *APIServer) resolveRegistryForBuild(
	ctx context.Context, c *gin.Context, k8sClient client.Client,
	namespace string, req *BuildRequest,
) (string, string, error) {
	if req.UseInternalRegistry {
		_, pushSecretName, err := a.setupInternalRegistryBuild(ctx, c, k8sClient, namespace, req)
		if err != nil {
			return "", "", err
		}

		// Hybrid: container pushed to external registry, disk to internal.
		// Create external registry secret for the container push workspace.
		if req.ContainerPush != "" && req.RegistryCredentials != nil && req.RegistryCredentials.Enabled {
			envSecretRef, err := createRegistrySecret(ctx, k8sClient, namespace, req.Name, req.RegistryCredentials)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return "", "", err
			}
			return envSecretRef, pushSecretName, nil
		}

		return pushSecretName, pushSecretName, nil
	}

	envSecretRef, pushSecretName, err := setupBuildSecrets(ctx, k8sClient, namespace, req)
	if err != nil {
		if errors.Is(err, errRegistryCredentialsRequiredForPush) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		} else if k8serrors.IsAlreadyExists(err) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}
		return "", "", err
	}
	return envSecretRef, pushSecretName, nil
}

// setupInternalRegistryBuild validates and configures internal registry push,
// returning ("", pushSecretName, nil) on success.
func (a *APIServer) setupInternalRegistryBuild(
	ctx context.Context, c *gin.Context, k8sClient client.Client,
	namespace string, req *BuildRequest,
) (string, string, error) {
	// Validate: internal registry handles the disk push, so exportOci must not be set.
	// containerPush (and registryCredentials) MAY be set for hybrid builds where
	// the bootc container is pushed to an external registry.
	if req.ExportOCI != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "useInternalRegistry cannot be used with exportOci"})
		return "", "", fmt.Errorf("validation error")
	}
	if req.Reproducible {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reproducible builds cannot use internal registry (OCI referrers not supported)"})
		return "", "", fmt.Errorf("validation error")
	}
	// Resolve external route (validates registry is reachable)
	if _, err := getExternalRegistryRoute(ctx, k8sClient, namespace); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return "", "", err
	}

	// Generate image name and tag
	imageName := req.InternalRegistryImageName
	if imageName == "" {
		imageName = req.Name
	}
	tag := req.InternalRegistryTag

	// Set concrete URLs based on build mode.
	// When ContainerPush is already set (hybrid: external container push),
	// keep it and only generate internal URLs for what's missing.
	externalContainerPush := req.ContainerPush != ""
	if req.Mode.IsBootc() {
		if !externalContainerPush {
			bootcTag := tag
			if bootcTag == "" {
				bootcTag = "bootc"
			}
			req.ContainerPush = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, bootcTag)
		}
		// Flash requires a disk image
		if req.FlashEnabled && !req.BuildDiskImage {
			req.BuildDiskImage = true
		}
		if req.BuildDiskImage {
			diskTag := tag
			if diskTag == "" {
				diskTag = "disk"
			}
			req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, diskTag)
		}
	} else {
		// Traditional/disk modes: push disk image as OCI artifact
		diskTag := tag
		if diskTag == "" {
			diskTag = "disk"
		}
		req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, diskTag)
	}

	// Pre-create ImageStream for internal registry pushes.
	// All images (bootc container and disk) share the same ImageStream,
	// distinguished by tag (:bootc, :disk).
	needsImageStream := !externalContainerPush || req.BuildDiskImage || !req.Mode.IsBootc()
	if needsImageStream {
		if _, err := ensureImageStream(ctx, k8sClient, namespace, imageName); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error creating ImageStream: %v", err)})
			return "", "", err
		}
	}

	// Create auth secret from SA token
	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error getting REST config: %v", err)})
		return "", "", err
	}
	tokenLifetime := resolveTokenLifetime(ctx, k8sClient, namespace)
	secretName, err := createInternalRegistrySecret(ctx, restCfg, namespace, req.Name, tokenLifetime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return "", "", err
	}
	// Return as both envSecretRef (for pipeline registry-auth workspace + WhenExpression)
	// and pushSecretName (for push credential binding)
	return secretName, secretName, nil
}

// buildExportSpec creates ExportSpec configuration from build request
// resolveExtraRepos processes --extra-repo flags (workspace:path pairs), starts HTTP
// servers in the workspace pods, and injects extra_repos into the build's CustomDefs.
func (a *APIServer) resolveExtraRepos(ctx context.Context, k8sClient client.Client, restCfg *rest.Config, req *BuildRequest) error {
	if len(req.ExtraRepos) == 0 {
		return nil
	}

	namespace := resolveNamespace()
	basePort := 8080

	type repoEntry struct {
		ID      string `json:"id"`
		BaseURL string `json:"baseurl"`
	}
	repos := make([]repoEntry, 0, len(req.ExtraRepos))

	for i, entry := range req.ExtraRepos {
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid --extra-repo %q: must be workspace-name:/path", entry)
		}
		wsName, repoPath := parts[0], parts[1]
		port := basePort + i

		// Look up the workspace pod
		ws := &automotivev1alpha1.Workspace{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: wsName}, ws); err != nil {
			return fmt.Errorf("workspace %q not found: %w", wsName, err)
		}
		if ws.Status.Phase != phaseRunning {
			return fmt.Errorf("workspace %q is not running (phase: %s)", wsName, ws.Status.Phase)
		}

		pod := &corev1.Pod{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ws.Status.PodName}, pod); err != nil {
			return fmt.Errorf("workspace pod %q not found: %w", ws.Status.PodName, err)
		}
		podIP := pod.Status.PodIP
		if podIP == "" {
			return fmt.Errorf("workspace pod %q has no IP", ws.Status.PodName)
		}

		// Start HTTP server in the workspace (background, fire-and-forget).
		// Redirect shell's own FDs first so runc exec doesn't block waiting for SPDY pipes.
		cmd := []string{"/bin/sh", "-c",
			fmt.Sprintf("exec 0</dev/null 1>/dev/null 2>/dev/null; cd %s && python3 -m http.server %d &", shellQuote(repoPath), port)}
		if err := podExec(ctx, restCfg, namespace, ws.Status.PodName, workspaceContainerName, cmd, io.Discard); err != nil {
			return fmt.Errorf("starting HTTP server in workspace %q: %w", wsName, err)
		}

		repoURL := fmt.Sprintf("http://%s:%d", podIP, port)
		repos = append(repos, repoEntry{
			ID:      fmt.Sprintf("workspace-%s", wsName),
			BaseURL: repoURL,
		})
		a.log.Info("Extra repo configured", "workspace", wsName, "url", repoURL)
	}

	reposJSON, err := json.Marshal(repos)
	if err != nil {
		return fmt.Errorf("marshaling extra_repos: %w", err)
	}
	req.CustomDefs = append(req.CustomDefs, fmt.Sprintf("extra_repos=%s", string(reposJSON)))
	return nil
}

// resolveOCIRepoImages validates the OCI repo image ref and injects a file:// extra_repos
// entry into CustomDefs. If workspace extra_repos already exist in CustomDefs, the
// OCI entry is merged into the same JSON array.
func resolveOCIRepoImages(req *BuildRequest) error {
	if len(req.OCIRepoImages) == 0 {
		return nil
	}
	if len(req.OCIRepoImages) > 1 {
		return fmt.Errorf("too many OCI repo images: %d exceeds maximum of 1", len(req.OCIRepoImages))
	}

	type repoEntry struct {
		ID       string `json:"id"`
		BaseURL  string `json:"baseurl"`
		Priority *int   `json:"priority,omitempty"`
	}

	ref := strings.TrimSpace(req.OCIRepoImages[0])
	if ref == "" {
		return fmt.Errorf("OCI repo image ref is empty")
	}
	entry := repoEntry{
		ID:      tasks.OCIRepoVolumeName,
		BaseURL: "file://" + tasks.OCIRepoMountPath,
	}
	if req.LocalRepo {
		p := 1
		entry.Priority = &p
	}
	ociRepos := []repoEntry{entry}

	// Check if extra_repos already exists in CustomDefs (from workspace repos).
	// If so, merge OCI entries into the existing array.
	const prefix = "extra_repos="
	mergedIdx := -1
	for i, def := range req.CustomDefs {
		if strings.HasPrefix(def, prefix) {
			mergedIdx = i
			break
		}
	}

	if mergedIdx >= 0 {
		// Parse existing extra_repos JSON and append OCI entries
		existingJSON := req.CustomDefs[mergedIdx][len(prefix):]
		var existing []repoEntry
		if err := json.Unmarshal([]byte(existingJSON), &existing); err != nil {
			return fmt.Errorf("parsing existing extra_repos: %w", err)
		}
		merged := append(existing, ociRepos...)
		mergedJSON, err := json.Marshal(merged)
		if err != nil {
			return fmt.Errorf("marshaling merged extra_repos: %w", err)
		}
		req.CustomDefs[mergedIdx] = prefix + string(mergedJSON)
	} else {
		// No existing extra_repos — create a new entry
		reposJSON, err := json.Marshal(ociRepos)
		if err != nil {
			return fmt.Errorf("marshaling OCI extra_repos: %w", err)
		}
		req.CustomDefs = append(req.CustomDefs, prefix+string(reposJSON))
	}

	return nil
}

// resolveWorkspaceForBuild resolves a workspace reference for a build:
// - Finds the workspace or auto-creates it if it doesn't exist
// - Creates/finds a build-cache PVC for osbuild checkpoint persistence
// - Forwards the workspace's lease if the build has flash enabled but no explicit lease
// - Starts an HTTP file server in the workspace pod and injects workspace_url as a custom define
// Returns the build-cache PVC name.
func (a *APIServer) resolveWorkspaceForBuild(ctx context.Context, k8sClient client.Client, restCfg *rest.Config, namespace, wsName, requester string, req *BuildRequest) (string, error) {
	operatorConfig, _ := loadOperatorConfigFn(ctx, k8sClient, namespace)
	var wsConfig *automotivev1alpha1.WorkspacesConfig
	if operatorConfig != nil {
		wsConfig = operatorConfig.Spec.Workspaces
	}

	ws := &automotivev1alpha1.Workspace{}
	err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: wsName}, ws)
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			return "", fmt.Errorf("checking workspace %q: %w", wsName, err)
		}
		// Auto-create workspace with defaults from OperatorConfig
		ws = &automotivev1alpha1.Workspace{
			ObjectMeta: metav1.ObjectMeta{
				Name:      wsName,
				Namespace: namespace,
			},
			Spec: automotivev1alpha1.WorkspaceSpec{
				Owner:        requester,
				PVCSize:      wsConfig.GetPVCSize(),
				StorageClass: wsConfig.GetStorageClass(),
				NodeSelector: wsConfig.GetNodeSelector(),
			},
		}
		if err := k8sClient.Create(ctx, ws); err != nil {
			return "", fmt.Errorf("creating workspace %q: %w", wsName, err)
		}
		a.log.Info("Auto-created workspace for build", "workspace", wsName, "requester", requester)
	} else {
		if ws.Spec.Owner != requester {
			return "", fmt.Errorf("workspace %q not found", wsName)
		}
	}

	// Forward workspace lease if flash is enabled and no explicit lease was provided
	if req.FlashEnabled && req.FlashLeaseName == "" && ws.Spec.LeaseID != "" {
		req.FlashLeaseName = ws.Spec.LeaseID
	}

	// Start file server in workspace pod and inject workspace_url for manifest use
	// (e.g. add_files: [{path: /usr/bin/foo, url: $workspace_url/my-binary}])
	if ws.Status.Phase == phaseRunning && ws.Status.PodName != "" && restCfg != nil {
		pod := &corev1.Pod{}
		if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: ws.Status.PodName}, pod); err == nil && pod.Status.PodIP != "" {
			const wsFileServerPort = 9090
			// Redirect shell's own FDs first so runc exec doesn't block waiting for SPDY pipes.
			cmd := []string{"/bin/sh", "-c",
				fmt.Sprintf("exec 0</dev/null 1>/dev/null 2>/dev/null; python3 -m http.server %d -d /workspace &", wsFileServerPort)}
			if err := podExec(ctx, restCfg, namespace, ws.Status.PodName, workspaceContainerName, cmd, io.Discard); err != nil {
				a.log.Error(err, "Failed to start workspace file server", "workspace", wsName)
			} else {
				wsURL := fmt.Sprintf("http://%s:%d", pod.Status.PodIP, wsFileServerPort)
				req.CustomDefs = append(req.CustomDefs, fmt.Sprintf("workspace_url=%s", wsURL))
				a.log.Info("Workspace file server started", "workspace", wsName, "url", wsURL)
			}
		}
	}

	// Find existing build-cache PVC via labels, or create a new one
	buildCacheLabels := map[string]string{
		labels.Workspace: wsName,
		labels.Component: "build-cache",
	}
	pvcList := &corev1.PersistentVolumeClaimList{}
	if err := k8sClient.List(ctx, pvcList,
		client.InNamespace(namespace),
		client.MatchingLabels(buildCacheLabels),
	); err != nil {
		return "", fmt.Errorf("listing build-cache PVCs: %w", err)
	}
	for i := range pvcList.Items {
		if pvcList.Items[i].DeletionTimestamp == nil {
			return pvcList.Items[i].Name, nil
		}
	}

	// Determine cache PVC size and storage class from OperatorConfig
	cacheSize := "20Gi"
	var storageClassName *string
	if wsConfig != nil {
		if wsConfig.BuildCacheSize != "" {
			cacheSize = wsConfig.BuildCacheSize
		}
		if sc := wsConfig.GetStorageClass(); sc != "" {
			storageClassName = &sc
		}
	}
	cacheSizeQty, err := resource.ParseQuantity(cacheSize)
	if err != nil {
		return "", fmt.Errorf("invalid buildCacheSize %q: %w", cacheSize, err)
	}

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: wsName + "-build-cache-",
			Namespace:    namespace,
			Labels:       buildCacheLabels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: automotivev1alpha1.GroupVersion.String(),
					Kind:       "Workspace",
					Name:       ws.Name,
					UID:        ws.UID,
				},
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
			StorageClassName: storageClassName,
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: cacheSizeQty,
				},
			},
		},
	}
	if err := k8sClient.Create(ctx, pvc); err != nil {
		return "", fmt.Errorf("creating build-cache PVC: %w", err)
	}

	a.log.Info("Created build-cache PVC", "workspace", wsName, "pvc", pvc.Name, "size", cacheSize)
	return pvc.Name, nil
}

// buildAIBSpec creates AIBSpec configuration from build request
// resolveTaskBundleRef resolves and optionally verifies the Tekton Bundle reference.
// Returns the validated ref, an HTTP status code, and error.
func resolveTaskBundleRef(ctx context.Context, k8sClient client.Client, namespace string, req *BuildRequest) (string, int, error) {
	if !req.SecureBuild {
		return "", 0, nil
	}

	operatorConfig, err := loadOperatorConfigFn(ctx, k8sClient, namespace)
	if err != nil {
		return "", http.StatusInternalServerError, fmt.Errorf("secureBuild requested but OperatorConfig could not be read: %w", err)
	}
	if operatorConfig == nil {
		return "", http.StatusInternalServerError, fmt.Errorf("secureBuild requested but OperatorConfig is nil")
	}

	var ref string
	if req.TaskBundleRef != "" {
		ref = strings.TrimSpace(req.TaskBundleRef)
		if !digestPinnedRef.MatchString(ref) {
			return "", http.StatusBadRequest, fmt.Errorf("taskBundleRef must be digest-pinned (image@sha256:<64 hex>), got %q", ref)
		}
	} else {
		if operatorConfig.Spec.OSBuilds == nil || operatorConfig.Spec.OSBuilds.TaskBundleRef == "" {
			return "", http.StatusBadRequest, fmt.Errorf("secureBuild requested but OperatorConfig.spec.osBuilds.taskBundleRef is not set")
		}
		ref = strings.TrimSpace(operatorConfig.Spec.OSBuilds.TaskBundleRef)
		if !digestPinnedRef.MatchString(ref) {
			return "", http.StatusBadRequest, fmt.Errorf("secureBuild requires a digest-pinned taskBundleRef (must match image@sha256:<64 hex>), got %q", ref)
		}
	}

	if status, err := verifyTaskBundle(ctx, k8sClient, namespace, operatorConfig, ref); err != nil {
		return "", status, err
	}

	return ref, 0, nil
}

func verifyTaskBundle(ctx context.Context, k8sClient client.Client, namespace string, operatorConfig *automotivev1alpha1.OperatorConfig, bundleRef string) (int, error) {
	if operatorConfig.Spec.OSBuilds == nil || !operatorConfig.Spec.OSBuilds.TaskBundleVerify {
		return 0, nil
	}

	pubKeyPEM, err := bundleverify.FetchCosignPublicKey(ctx, k8sClient, operatorConfig.Spec.OSBuilds.TaskBundleCosignKeyRef, namespace)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("taskBundleVerify is enabled but cosign key is unavailable: %w", err)
	}

	registryOpts := ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err := bundleverify.VerifyBundle(ctx, bundleRef, pubKeyPEM, registryOpts); err != nil {
		return http.StatusForbidden, fmt.Errorf("task bundle signature verification failed: %w", err)
	}

	return 0, nil
}

func verifyWorkspaceImage(ctx context.Context, k8sClient client.Client, namespace string, wsConfig *automotivev1alpha1.WorkspacesConfig, imageRef string, imagePullSecrets []corev1.LocalObjectReference) (int, error) {
	if wsConfig == nil || !wsConfig.ImageVerify {
		return 0, nil
	}

	pubKeyPEM, err := bundleverify.FetchCosignPublicKey(ctx, k8sClient, wsConfig.ImageCosignKeyRef, namespace)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("imageVerify is enabled but cosign key is unavailable: %w", err)
	}

	keychain, err := bundleverify.KeychainFromPullSecrets(ctx, k8sClient, namespace, imagePullSecrets)
	if err != nil {
		return http.StatusInternalServerError, fmt.Errorf("building registry keychain: %w", err)
	}
	registryOpts := ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(keychain))
	if err := bundleverify.VerifyBundle(ctx, imageRef, pubKeyPEM, registryOpts); err != nil {
		return http.StatusForbidden, fmt.Errorf("workspace image signature verification failed: %w", err)
	}

	return 0, nil
}

func (a *APIServer) validateManifestSchema(c *gin.Context, span trace.Span, req *BuildRequest) bool {
	result, err := manifestschema.ValidateFromImage(req.AutomotiveImageBuilder, []byte(req.Manifest))
	if err != nil {
		a.log.Info("Skipping manifest schema validation", "error", err, "reqID", c.GetString("reqID"))
		return true
	}
	if !result.Valid {
		spanError(span, fmt.Errorf("%s", result.Error()))
		c.JSON(http.StatusBadRequest, gin.H{"error": result.Error()})
		return false
	}
	return true
}

func (a *APIServer) applyExtraRepos(ctx context.Context, c *gin.Context, span trace.Span, k8sClient client.Client, req *BuildRequest) bool {
	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		spanError(span, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes config"})
		return false
	}
	if err := a.resolveExtraRepos(ctx, k8sClient, restCfg, req); err != nil {
		spanError(span, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}
	return true
}

// applyAllExtraRepos resolves workspace extra repos and OCI RPM repo images,
// merging both into a single extra_repos CustomDef entry.
func (a *APIServer) applyAllExtraRepos(ctx context.Context, c *gin.Context, span trace.Span, k8sClient client.Client, req *BuildRequest) bool {
	if len(req.ExtraRepos) > 0 {
		if !a.applyExtraRepos(ctx, c, span, k8sClient, req) {
			return false
		}
	}
	if err := resolveOCIRepoImages(req); err != nil {
		spanError(span, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}
	return true
}

func (a *APIServer) createBuild(c *gin.Context) {
	ctx, span := apiTracer.Start(c.Request.Context(), "createBuild")
	defer span.End()
	c.Request = c.Request.WithContext(ctx)

	var req BuildRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		spanError(span, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}

	needsUpload := req.HasLocalFiles || manifestNeedsUpload(req.Manifest)

	if err := validateBuildRequest(&req); err != nil {
		spanError(span, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := applyBuildDefaults(&req); err != nil {
		spanError(span, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !a.validateManifestSchema(c, span, &req) {
		return
	}

	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		spanError(span, err)
		return
	}

	namespace := resolveNamespace()

	effectiveTTL, ttlErr := resolveAndClampTTL(ctx, k8sClient, namespace, req.TTL)
	if ttlErr != nil {
		spanError(span, ttlErr)
		c.JSON(http.StatusBadRequest, gin.H{"error": ttlErr.Error()})
		return
	}

	// Resolve workspace extra repos and OCI RPM repo images.
	// OCI resolution runs second so it can merge into the same extra_repos array.
	if !a.applyAllExtraRepos(ctx, c, span, k8sClient, &req) {
		return
	}

	// Append a short random suffix to ensure unique names for parallel builds
	req.Name = fmt.Sprintf("%s-%s", req.Name, uuid.New().String()[:5])
	span.SetAttributes(attribute.String("build.name", req.Name))

	requestedBy := a.resolveRequester(c)

	taskBundleRef, bundleStatus, bundleErr := resolveTaskBundleRef(ctx, k8sClient, namespace, &req)
	if bundleErr != nil {
		spanError(span, bundleErr)
		c.JSON(bundleStatus, gin.H{"error": bundleErr.Error()})
		return
	}

	if err := validateRestoreSourcesRef(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Resolve --workspace: create/find build-cache PVC, forward lease, start file server
	var buildCachePVCName string
	if req.Workspace != "" {
		restCfg, restErr := getRESTConfigFromRequest(c)
		if restErr != nil {
			spanError(span, restErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes config"})
			return
		}
		pvcName, wsErr := a.resolveWorkspaceForBuild(ctx, k8sClient, restCfg, namespace, req.Workspace, requestedBy, &req)
		if wsErr != nil {
			spanError(span, wsErr)
			c.JSON(http.StatusBadRequest, gin.H{"error": wsErr.Error()})
			return
		}
		buildCachePVCName = pvcName
	}

	existing := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: req.Name, Namespace: namespace}, existing); err == nil {
		conflictErr := fmt.Errorf("ImageBuild %s already exists", req.Name)
		spanError(span, conflictErr)
		c.JSON(http.StatusConflict, gin.H{"error": conflictErr.Error()})
		return
	} else if !k8serrors.IsNotFound(err) {
		spanError(span, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error checking existing build: %v", err)})
		return
	}

	buildLabels := map[string]string{
		labels.ManagedBy:    labels.ValueBuildAPI,
		labels.PartOf:       labels.ValueAutomotiveDev,
		labels.CreatedBy:    labels.ValueBuildAPICreator,
		labels.Distro:       string(req.Distro),
		labels.Target:       string(req.Target),
		labels.Architecture: string(req.Architecture),
	}

	envSecretRef, pushSecretName, apiErr := a.resolveRegistryForBuild(ctx, c, k8sClient, namespace, &req)
	if apiErr != nil {
		spanError(span, apiErr)
		return
	}

	var flashSpec *automotivev1alpha1.FlashSpec
	var flashSecretName string
	if req.FlashEnabled {
		if req.FlashClientConfig == "" {
			flashErr := fmt.Errorf("flash enabled but client config is required")
			spanError(span, flashErr)
			c.JSON(http.StatusBadRequest, gin.H{"error": flashErr.Error()})
			return
		}
		flashSecretName = req.Name + "-jumpstarter-client"
		if err := createFlashClientSecret(ctx, k8sClient, namespace, flashSecretName, req.FlashClientConfig); err != nil {
			spanError(span, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error creating flash client secret: %v", err)})
			return
		}
		flashSpec = &automotivev1alpha1.FlashSpec{
			ClientConfigSecretRef: flashSecretName,
			LeaseDuration:         req.FlashLeaseDuration,
			LeaseName:             req.FlashLeaseName,
			FlashCmd:              req.FlashCmd,
			ExporterSelector:      req.FlashExporterSelector,
			LeaseTags:             req.FlashLeaseTags,
		}
	}

	if status, err := resolveS3Credentials(ctx, k8sClient, &req, namespace); err != nil {
		spanError(span, err)
		c.JSON(status, gin.H{"error": err.Error()})
		return
	}

	traceID := extractTraceID(ctx)
	annotations := map[string]string{
		automotivev1alpha1.AnnotationRequestedBy: requestedBy,
		automotivev1alpha1.AnnotationTraceID:     traceID,
	}
	if req.Reproducible && taskBundleRef != "" {
		annotations[automotivev1alpha1.AnnotationTaskBundleRef] = taskBundleRef
	}

	imageBuild := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:        req.Name,
			Namespace:   namespace,
			Labels:      buildLabels,
			Annotations: annotations,
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			Architecture:      string(req.Architecture),
			StorageClass:      req.StorageClass,
			SecretRef:         envSecretRef,
			PushSecretRef:     pushSecretName,
			AIB:               buildAIBSpec(&req, req.Manifest, req.ManifestFileName, needsUpload),
			Export:            buildExportSpec(&req),
			Flash:             flashSpec,
			BuildCachePVC:     buildCachePVCName,
			Workspace:         req.Workspace,
			SecureBuild:       req.SecureBuild,
			Reproducible:      req.Reproducible,
			TaskBundleRef:     taskBundleRef,
			RestoreSourcesRef: req.RestoreSourcesRef,
			TTL:               effectiveTTL,
		},
	}
	if err := k8sClient.Create(ctx, imageBuild); err != nil {
		spanError(span, err)
		cleanupInlineS3Secret(ctx, k8sClient, &req, namespace)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error creating ImageBuild: %v", err)})
		return
	}

	setBuildSecretOwnerRefs(ctx, k8sClient, namespace, imageBuild, envSecretRef, pushSecretName, flashSecretName, &req)

	writeJSON(c, http.StatusAccepted, BuildResponse{
		Name:        req.Name,
		Phase:       phaseBuilding,
		Message:     "Build triggered",
		RequestedBy: requestedBy,
		TraceID:     traceID,
	})
}

func listBuilds(c *gin.Context) {
	namespace := resolveNamespace()
	limit, offset := parsePagination(c)

	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}

	ctx := c.Request.Context()
	list := &automotivev1alpha1.ImageBuildList{}
	if err := k8sClient.List(ctx, list, client.InNamespace(namespace)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error listing builds: %v", err)})
		return
	}

	// Sort by creation time, newest first
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[j].CreationTimestamp.Before(&list.Items[i].CreationTimestamp)
	})

	// Paginate before doing per-item work (external route lookup, etc.)
	page := applyPagination(list.Items, limit, offset)

	// Resolve external route once for translating internal registry URLs
	externalRoute, _ := getExternalRegistryRoute(ctx, k8sClient, namespace)

	resp := make([]BuildListItem, 0, len(page))
	for _, b := range page {
		var startStr, compStr string
		if b.Status.StartTime != nil {
			startStr = b.Status.StartTime.Format(time.RFC3339)
		}
		if b.Status.CompletionTime != nil {
			compStr = b.Status.CompletionTime.Format(time.RFC3339)
		}

		var containerImage, diskImage string
		if buildProducedArtifacts(&b) {
			containerImage = b.Spec.GetContainerPush()
			diskImage = b.Spec.GetExportOCI()
		}
		if b.Spec.GetUseServiceAccountAuth() && externalRoute != "" {
			if containerImage != "" {
				containerImage = translateToExternalURL(containerImage, externalRoute)
			}
			if diskImage != "" {
				diskImage = translateToExternalURL(diskImage, externalRoute)
			}
		}

		resp = append(resp, BuildListItem{
			Name:           b.Name,
			Phase:          b.Status.Phase,
			Message:        b.Status.Message,
			RequestedBy:    b.Annotations[labels.RequestedBy],
			CreatedAt:      b.CreationTimestamp.Format(time.RFC3339),
			StartTime:      startStr,
			CompletionTime: compStr,
			ContainerImage: containerImage,
			DiskImage:      diskImage,
		})
	}
	writeJSON(c, http.StatusOK, resp)
}

func (a *APIServer) getBuild(c *gin.Context, name string) {
	namespace := resolveNamespace()
	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}

	ctx := c.Request.Context()
	build := &automotivev1alpha1.ImageBuild{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, build, "build"); err != nil {
		return
	}

	// Only report artifact URLs when the build progressed past the Building
	// phase — otherwise no image was produced and the URLs are misleading.
	var containerImage, diskImage string
	if buildProducedArtifacts(build) {
		containerImage = build.Spec.GetContainerPush()
		diskImage = build.Spec.GetExportOCI()
	}
	var warning string

	if build.Spec.GetUseServiceAccountAuth() {
		externalRoute, err := getExternalRegistryRoute(ctx, k8sClient, namespace)
		if err != nil {
			a.log.Error(err, "failed to resolve external registry route, returning internal URLs", "build", name)
			warning = fmt.Sprintf("external registry route lookup failed: %v; returning internal URLs", err)
		} else if externalRoute != "" {
			if containerImage != "" {
				containerImage = translateToExternalURL(containerImage, externalRoute)
			}
			if diskImage != "" {
				diskImage = translateToExternalURL(diskImage, externalRoute)
			}
		}
	}

	// For terminal builds, include Jumpstarter mapping so the CLI can show
	// manual flash guidance after successful or failed flash attempts.
	var jumpstarterInfo *JumpstarterInfo
	if isTerminalPhase(build.Status.Phase) {
		operatorConfig := &automotivev1alpha1.OperatorConfig{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: "config", Namespace: namespace}, operatorConfig); err == nil {
			if operatorConfig.Status.JumpstarterAvailable {
				jumpstarterInfo = &JumpstarterInfo{Available: true}
				// Include lease ID if flash was executed
				if build.Status.LeaseID != "" {
					jumpstarterInfo.LeaseID = build.Status.LeaseID
				}
				if operatorConfig.Spec.Jumpstarter != nil {
					if mapping, ok := operatorConfig.Spec.Jumpstarter.TargetMappings[build.Spec.GetTarget()]; ok {
						jumpstarterInfo.ExporterSelector = mapping.Selector
						flashCmd := build.Spec.GetFlashCmd()
						if flashCmd == "" {
							flashCmd = mapping.FlashCmd
						}
						// Replace placeholders in flash command using translated URLs
						if flashCmd != "" {
							imageURI := diskImage
							if imageURI == "" {
								imageURI = containerImage
							}
							if imageURI != "" {
								flashCmd = strings.ReplaceAll(flashCmd, "{image_uri}", imageURI)
								flashCmd = strings.ReplaceAll(flashCmd, "{artifact_url}", imageURI)
							}
						}
						jumpstarterInfo.FlashCmd = flashCmd
					}
				}
			}
		}
	}

	// Mint a fresh registry token only for completed/failed internal registry builds
	// that belong to the requesting user
	var registryToken string
	requester := a.resolveRequester(c)
	buildOwner := build.Annotations[labels.RequestedBy]
	if requester == buildOwner &&
		build.Spec.GetUseServiceAccountAuth() &&
		isTerminalPhase(build.Status.Phase) {
		var tokenErr error
		tokenLifetime := resolveTokenLifetime(ctx, k8sClient, namespace)
		registryToken, _, tokenErr = a.mintRegistryToken(ctx, c, namespace, tokenLifetime)
		if tokenErr != nil {
			a.log.Error(tokenErr, "failed to mint registry token", "build", name)
			tokenWarning := fmt.Sprintf("failed to mint registry token: %v", tokenErr)
			if warning != "" {
				warning = warning + "; " + tokenWarning
			} else {
				warning = tokenWarning
			}
		}
	}

	writeJSON(c, http.StatusOK, BuildResponse{
		Name:        build.Name,
		Phase:       build.Status.Phase,
		Message:     build.Status.Message,
		RequestedBy: build.Annotations[labels.RequestedBy],
		TraceID:     build.Annotations[automotivev1alpha1.AnnotationTraceID],
		StartTime: func() string {
			if build.Status.StartTime != nil {
				return build.Status.StartTime.Format(time.RFC3339)
			}
			return ""
		}(),
		CompletionTime: func() string {
			if build.Status.CompletionTime != nil {
				return build.Status.CompletionTime.Format(time.RFC3339)
			}
			return ""
		}(),
		ContainerImage: containerImage,
		DiskImage:      diskImage,
		RegistryToken:  registryToken,
		Warning:        warning,
		ExpiresAt: func() string {
			if build.Status.ExpiresAt != nil {
				return build.Status.ExpiresAt.Format(time.RFC3339)
			}
			return ""
		}(),
		Jumpstarter: jumpstarterInfo,
		Parameters: &BuildParameters{
			Architecture:           build.Spec.Architecture,
			Distro:                 build.Spec.GetDistro(),
			Target:                 build.Spec.GetTarget(),
			Mode:                   build.Spec.GetMode(),
			ExportFormat:           build.Spec.GetExportFormat(),
			Compression:            build.Spec.GetCompression(),
			StorageClass:           build.Spec.StorageClass,
			AutomotiveImageBuilder: build.Spec.GetAIBImage(),
			BuilderImage:           build.Spec.GetBuilderImage(),
			ContainerRef:           build.Spec.GetContainerRef(),
			BuildDiskImage:         build.Spec.GetBuildDiskImage(),
			FlashEnabled:           build.Spec.IsFlashEnabled(),
			FlashLeaseDuration:     build.Spec.GetFlashLeaseDuration(),
			FlashLeaseName:         build.Spec.GetFlashLeaseName(),
			UseServiceAccountAuth:  build.Spec.GetUseServiceAccountAuth(),
		},
	})
}

// getBuildTemplate returns a BuildRequest-like struct representing the inputs that produced a given build
func getBuildTemplate(c *gin.Context, name string) {
	namespace := resolveNamespace()
	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}

	ctx := c.Request.Context()
	build := &automotivev1alpha1.ImageBuild{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, build, "build"); err != nil {
		return
	}

	manifest := build.Spec.GetManifest()
	manifestFileName := build.Spec.GetManifestFileName()
	if manifestFileName == "" {
		manifestFileName = "manifest.aib.yml"
	}

	sourceFiles := extractManifestSourceFiles(manifest)

	writeJSON(c, http.StatusOK, BuildTemplateResponse{
		BuildRequest: BuildRequest{
			Name:                   build.Name,
			Manifest:               manifest,
			ManifestFileName:       manifestFileName,
			Distro:                 Distro(build.Spec.GetDistro()),
			Target:                 Target(build.Spec.GetTarget()),
			Architecture:           Architecture(build.Spec.Architecture),
			ExportFormat:           ExportFormat(build.Spec.GetExportFormat()),
			Mode:                   Mode(build.Spec.GetMode()),
			AutomotiveImageBuilder: build.Spec.GetAIBImage(),
			CustomDefs:             build.Spec.GetCustomDefs(),
			AIBExtraArgs:           build.Spec.GetAIBExtraArgs(),
			Compression:            Compression(build.Spec.GetCompression()),
			SecureBuild:            build.Spec.SecureBuild,
			Reproducible:           build.Spec.Reproducible,
			TaskBundleRef:          build.Spec.TaskBundleRef,
			RestoreSourcesRef:      build.Spec.RestoreSourcesRef,
			TTL:                    build.Spec.GetTTL(),
		},
		SourceFiles: sourceFiles,
	})
}

func (a *APIServer) handleGetOperatorConfig(c *gin.Context) {
	ctx := c.Request.Context()
	reqID, _ := c.Get("reqID")

	a.log.Info("getting operator config", "reqID", reqID)

	k8sClient, err := getClientFromRequestFn(c)
	if err != nil {
		a.log.Error(err, "failed to get k8s client", "reqID", reqID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create Kubernetes client"})
		return
	}

	namespace := resolveNamespace()

	operatorConfig, err := loadOperatorConfigFn(ctx, k8sClient, namespace)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			a.log.Info("OperatorConfig not found; returning defaults", "reqID", reqID, "namespace", namespace)
			c.JSON(http.StatusOK, OperatorConfigResponse{
				AutomotiveImageBuilder: automotivev1alpha1.DefaultAutomotiveImageBuilderImage,
			})
			return
		}
		a.log.Error(err, "failed to get OperatorConfig", "reqID", reqID, "namespace", namespace)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get operator configuration"})
		return
	}

	// Build the response with Jumpstarter target mappings (flash-specific, from CRD)
	response := OperatorConfigResponse{
		AutomotiveImageBuilder: operatorConfig.Spec.GetImages().GetAutomotiveImageBuilderImage(),
	}

	if operatorConfig.Spec.Jumpstarter != nil && len(operatorConfig.Spec.Jumpstarter.TargetMappings) > 0 {
		response.JumpstarterTargets = make(map[string]JumpstarterTarget)
		for target, mapping := range operatorConfig.Spec.Jumpstarter.TargetMappings {
			response.JumpstarterTargets[target] = JumpstarterTarget{
				Selector: mapping.Selector,
				FlashCmd: mapping.FlashCmd,
			}
		}
	}

	// Load build defaults from target-defaults ConfigMap
	targetDefaults, err := loadTargetDefaultsFn(ctx, k8sClient, namespace)
	if err != nil {
		if !k8serrors.IsNotFound(err) {
			a.log.Error(err, "failed to load target defaults ConfigMap", "reqID", reqID, "namespace", namespace)
		}
		// Non-fatal: continue without target defaults
	} else if len(targetDefaults) > 0 {
		response.TargetDefaults = targetDefaults
	}

	c.JSON(http.StatusOK, response)
}
