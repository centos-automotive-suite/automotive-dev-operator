package buildapi

import (
	"archive/tar"
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	apiserverv1beta1 "k8s.io/apiserver/pkg/apis/apiserver/v1beta1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/catalog"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	authnv1 "k8s.io/api/authentication/v1"
)

const (
	// Build phase constants
	phaseCompleted = "Completed"
	phaseFailed    = "Failed"
	phasePending   = "Pending"
	phaseRunning   = "Running"

	// Image format and compression constants
	formatImage     = "image"
	formatQcow2     = "qcow2"
	compressionGzip = "gzip"
	extensionRaw    = ".raw"
	extensionQcow2  = ".qcow2"
	statusUnknown   = "unknown"
	statusMissing   = "MISSING"
	buildAPIName    = "ado-build-api"

	// Flash TaskRun constants
	flashTaskRunLabel = "automotive.sdv.cloud.redhat.com/flash-taskrun"
)

var getClientFromRequestFn = getClientFromRequest
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

// defaultInternalRegistryURL is an alias for the shared constant.
const defaultInternalRegistryURL = tasks.DefaultInternalRegistryURL

func generateRegistryImageRef(host, namespace, imageName, tag string) string {
	return fmt.Sprintf("%s/%s/%s:%s", host, namespace, imageName, tag)
}

func translateToExternalURL(internalURL, externalRouteHost string) string {
	return strings.Replace(internalURL, defaultInternalRegistryURL, externalRouteHost, 1)
}

func getExternalRegistryRoute(ctx context.Context, k8sClient client.Client, namespace string) (string, error) {
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: "config", Namespace: namespace}, operatorConfig); err != nil {
		if !k8serrors.IsNotFound(err) {
			return "", fmt.Errorf("error reading OperatorConfig: %w", err)
		}
		// OperatorConfig not found, fall through to auto-detection
	} else if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.ClusterRegistryRoute != "" {
		return operatorConfig.Spec.OSBuilds.ClusterRegistryRoute, nil
	}

	// Auto-detect from OpenShift Route
	route := &unstructured.Unstructured{}
	route.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "route.openshift.io",
		Version: "v1",
		Kind:    "Route",
	})
	if err := k8sClient.Get(ctx, types.NamespacedName{
		Name:      "default-route",
		Namespace: "openshift-image-registry",
	}, route); err != nil {
		return "", fmt.Errorf("cannot determine external registry route: set clusterRegistryRoute in OperatorConfig or expose default-route in openshift-image-registry")
	}

	host, _, _ := unstructured.NestedString(route.Object, "spec", "host")
	if host == "" {
		return "", fmt.Errorf("default-route exists but has no host")
	}
	return host, nil
}

func createInternalRegistrySecret(ctx context.Context, restCfg *rest.Config, namespace, buildName string) (string, error) {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return "", fmt.Errorf("error creating clientset: %w", err)
	}

	// Request a 4-hour token for the pipeline SA (covers build + push duration)
	expSeconds := int64(4 * 3600)
	tokenReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			ExpirationSeconds: &expSeconds,
		},
	}
	tokenResp, err := clientset.CoreV1().ServiceAccounts(namespace).
		CreateToken(ctx, "pipeline", tokenReq, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("error creating SA token: %w", err)
	}

	// Build dockerconfigjson
	auth := base64.StdEncoding.EncodeToString([]byte("serviceaccount:" + tokenResp.Status.Token))
	dockerConfig := fmt.Sprintf(`{"auths":{"%s":{"auth":"%s"}}}`, defaultInternalRegistryURL, auth)

	secretName := buildName + "-registry-auth"
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                  "build-api",
				"app.kubernetes.io/part-of":                     "automotive-dev",
				"automotive.sdv.cloud.redhat.com/resource-type": "registry-auth",
				"automotive.sdv.cloud.redhat.com/build-name":    buildName,
				"automotive.sdv.cloud.redhat.com/transient":     "true",
			},
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			".dockerconfigjson": []byte(dockerConfig),
		},
	}

	if _, err := clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return "", fmt.Errorf("error creating internal registry secret: %w", err)
	}
	return secretName, nil
}

// ensureImageStream creates an ImageStream if it doesn't already exist.
// The OpenShift internal registry requires an ImageStream before oras can push to it.
func ensureImageStream(ctx context.Context, k8sClient client.Client, namespace, name string) error {
	is := &unstructured.Unstructured{}
	is.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "image.openshift.io",
		Version: "v1",
		Kind:    "ImageStream",
	})

	// Check if it already exists
	err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, is)
	if err == nil {
		return nil // already exists
	}
	if !k8serrors.IsNotFound(err) {
		return fmt.Errorf("error checking ImageStream %s: %w", name, err)
	}

	// Create it
	newIS := &unstructured.Unstructured{}
	newIS.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "image.openshift.io",
		Version: "v1",
		Kind:    "ImageStream",
	})
	newIS.SetName(name)
	newIS.SetNamespace(namespace)
	newIS.SetLabels(map[string]string{
		"app.kubernetes.io/managed-by":              "build-api",
		"app.kubernetes.io/part-of":                 "automotive-dev",
		"automotive.sdv.cloud.redhat.com/transient": "true",
	})

	if err := k8sClient.Create(ctx, newIS); err != nil {
		if k8serrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("error creating ImageStream %s: %w", name, err)
	}
	return nil
}

// mintRegistryToken creates a fresh short-lived token for the pipeline SA
// so the caller can pull images from the internal registry.
func (a *APIServer) mintRegistryToken(ctx context.Context, c *gin.Context, namespace string) (string, error) {
	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		return "", fmt.Errorf("error getting REST config for token mint: %w", err)
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return "", fmt.Errorf("error creating clientset for token mint: %w", err)
	}
	expSeconds := int64(4 * 3600)
	tokenReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			ExpirationSeconds: &expSeconds,
		},
	}
	tokenResp, err := clientset.CoreV1().ServiceAccounts(namespace).
		CreateToken(ctx, "pipeline", tokenReq, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("error creating token for SA pipeline in %s: %w", namespace, err)
	}
	return tokenResp.Status.Token, nil
}

// APILimits holds configurable limits for the API server
type APILimits struct {
	MaxManifestSize             int64
	MaxUploadFileSize           int64
	MaxTotalUploadSize          int64
	MaxLogStreamDurationMinutes int32
}

// DefaultAPILimits returns the default limits
func DefaultAPILimits() APILimits {
	return APILimits{
		MaxManifestSize:             10 * 1024 * 1024,       // 10MB
		MaxUploadFileSize:           1 * 1024 * 1024 * 1024, // 1GB
		MaxTotalUploadSize:          2 * 1024 * 1024 * 1024, // 2GB
		MaxLogStreamDurationMinutes: 120,                    // 2 hours
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
	a.server = &http.Server{Addr: addr, Handler: a.router}
	return a
}

// LoadLimitsFromConfig loads API limits from OperatorConfig, using defaults for unset values
func LoadLimitsFromConfig(cfg *automotivev1alpha1.BuildAPIConfig) APILimits {
	limits := DefaultAPILimits()
	if cfg == nil {
		return limits
	}
	if cfg.MaxManifestSize > 0 {
		limits.MaxManifestSize = cfg.MaxManifestSize
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
	return limits
}

// safeFilename validates that a filename is safe for use in shell commands
// It only allows alphanumeric characters, dots, hyphens, underscores, at signs, and single forward slashes for paths
func safeFilename(filename string) bool {
	if filename == "" {
		return false
	}

	// Reject dangerous characters that could be used for command injection
	for _, char := range filename {
		switch char {
		case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
			'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
			'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'.', '-', '_', '/', '@':
			// Safe characters
			continue
		default:
			// Reject any other character including quotes, semicolons, backticks, pipes, etc.
			return false
		}
	}

	// Reject path traversal attempts
	if strings.Contains(filename, "..") {
		return false
	}

	// Reject absolute paths (should be relative)
	if strings.HasPrefix(filename, "/") {
		return false
	}

	// Reject filenames that are just dots or empty components after splitting
	parts := strings.Split(filename, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}

	return true
}

// Start implements manager.Runnable
func (a *APIServer) Start(ctx context.Context) error {

	go func() {
		a.log.Info("build-api listening", "addr", a.addr)
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.log.Error(err, "build-api server error")
		}
	}()

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
		a.log.Info("http request", "method", c.Request.Method, "path", c.Request.URL.Path, "reqID", reqID)
		c.Next()
	})

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
			buildsGroup.POST("", a.handleCreateBuild)
			buildsGroup.GET("", a.handleListBuilds)
			buildsGroup.GET("/:name", a.handleGetBuild)
			buildsGroup.GET("/:name/logs", a.handleStreamLogs)
			buildsGroup.GET("/:name/template", a.handleGetBuildTemplate)
			buildsGroup.POST("/:name/uploads", a.handleUploadFiles)
		}

		flashGroup := v1.Group("/flash")
		flashGroup.Use(a.authMiddleware())
		{
			flashGroup.POST("", a.handleCreateFlash)
			flashGroup.GET("", a.handleListFlash)
			flashGroup.GET("/:name", a.handleGetFlash)
			flashGroup.GET("/:name/logs", a.handleFlashLogs)
		}

		configGroup := v1.Group("/config")
		configGroup.Use(a.authMiddleware())
		{
			configGroup.GET("", a.handleGetOperatorConfig)
		}

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

// authMiddleware provides authentication middleware for Gin
func (a *APIServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		username, authType, authErr := a.authenticateRequest(c)
		if authErr != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"reason":  authErr.Reason,
				"details": authErr.Details,
			})
			c.Abort()
			return
		}
		if username != "" {
			c.Set("requester", username)
			c.Set("authType", authType)
		}
		c.Next()
	}
}

func (a *APIServer) handleCreateBuild(c *gin.Context) {
	a.log.Info("create build", "reqID", c.GetString("reqID"))
	a.createBuild(c)
}

func (a *APIServer) handleListBuilds(c *gin.Context) {
	a.log.Info("list builds", "reqID", c.GetString("reqID"))
	listBuilds(c)
}

func (a *APIServer) handleGetBuild(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("get build", "build", name, "reqID", c.GetString("reqID"))
	a.getBuild(c, name)
}

func (a *APIServer) handleStreamLogs(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("logs requested", "build", name, "reqID", c.GetString("reqID"))
	a.streamLogs(c, name)
}

func (a *APIServer) handleGetBuildTemplate(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("template requested", "build", name, "reqID", c.GetString("reqID"))
	getBuildTemplate(c, name)
}

func (a *APIServer) handleUploadFiles(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("uploads", "build", name, "reqID", c.GetString("reqID"))
	a.uploadFiles(c, name)
}

// setupLogStreamHeaders configures HTTP headers for log streaming
func setupLogStreamHeaders(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header().Set("Pragma", "no-cache")
	c.Writer.WriteHeader(http.StatusOK)
	_, _ = c.Writer.Write([]byte("Waiting for logs...\n"))
	c.Writer.Flush()
}

// getStepContainerNames returns container names for pipeline steps
func getStepContainerNames(pod corev1.Pod) []string {
	stepNames := make([]string, 0, len(pod.Spec.Containers))
	for _, cont := range pod.Spec.Containers {
		if strings.HasPrefix(cont.Name, "step-") {
			stepNames = append(stepNames, cont.Name)
		}
	}
	if len(stepNames) == 0 {
		for _, cont := range pod.Spec.Containers {
			stepNames = append(stepNames, cont.Name)
		}
	}
	return stepNames
}

// streamContainerLogs streams logs from a single container.
// Returns true if logs were successfully streamed, false if the stream could not be opened.
func streamContainerLogs(
	ctx context.Context, c *gin.Context, cs *kubernetes.Clientset,
	namespace, podName, containerName, taskName string, sinceTime *metav1.Time,
) bool {
	req := cs.CoreV1().Pods(namespace).GetLogs(
		podName, &corev1.PodLogOptions{Container: containerName, Follow: true, SinceTime: sinceTime},
	)
	stream, err := req.Stream(ctx)
	if err != nil {
		return false
	}

	_, _ = c.Writer.Write([]byte(
		"\n===== Logs from " + taskName + "/" + strings.TrimPrefix(containerName, "step-") + " =====\n\n",
	))
	c.Writer.Flush()

	defer func() {
		if err := stream.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close stream: %v\n", err)
		}
	}()

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return true
		default:
		}
		line := scanner.Bytes()
		if _, writeErr := c.Writer.Write(line); writeErr != nil {
			return true
		}
		if _, writeErr := c.Writer.Write([]byte("\n")); writeErr != nil {
			return true
		}
		c.Writer.Flush()
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		var errMsg []byte
		errMsg = fmt.Appendf(errMsg, "\n[Stream error: %v]\n", err)
		_, _ = c.Writer.Write(errMsg)
		c.Writer.Flush()
	}
	return true
}

// processPodLogs processes logs for all containers in a pod
func processPodLogs(
	ctx context.Context, c *gin.Context, cs *kubernetes.Clientset,
	pod corev1.Pod, namespace string, sinceTime *metav1.Time,
	streamedContainers map[string]bool, hadStream *bool,
) {
	stepNames := getStepContainerNames(pod)
	taskName := pod.Labels["tekton.dev/pipelineTask"]
	if taskName == "" {
		taskName = pod.Name
	}

	for _, cName := range stepNames {
		if streamedContainers[cName] {
			continue
		}

		if !*hadStream {
			c.Writer.Flush()
		}

		if streamContainerLogs(ctx, c, cs, namespace, pod.Name, cName, taskName, sinceTime) {
			*hadStream = true
			streamedContainers[cName] = true
		}
	}
}

func (a *APIServer) streamLogs(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	sinceTime := parseSinceTime(c.Query("since"))
	streamDuration := time.Duration(a.limits.MaxLogStreamDurationMinutes) * time.Minute
	ctx, cancel := context.WithTimeout(c.Request.Context(), streamDuration)
	defer cancel()

	ib := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, ib); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	tr := strings.TrimSpace(ib.Status.PipelineRunName)
	if tr == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "logs not available yet"})
		return
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	cs, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	setupLogStreamHeaders(c)

	pipelineRunSelector := "tekton.dev/pipelineRun=" + tr + ",tekton.dev/memberOf=tasks"
	var hadStream bool
	streamedContainers := make(map[string]map[string]bool)
	completedPods := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: pipelineRunSelector})
		if err != nil {
			if _, writeErr := fmt.Fprintf(c.Writer, "\n[Error listing pods: %v]\n", err); writeErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to write error message: %v\n", writeErr)
			}
			c.Writer.Flush()
			time.Sleep(2 * time.Second)
			continue
		}

		if len(pods.Items) == 0 {
			if !hadStream {
				_, _ = c.Writer.Write([]byte("."))
				c.Writer.Flush()
			}
			time.Sleep(2 * time.Second)
			continue
		}

		// Sort pods by start time so logs appear in execution order
		sort.Slice(pods.Items, func(i, j int) bool {
			// Pods without start time go last
			if pods.Items[i].Status.StartTime == nil {
				return false
			}
			if pods.Items[j].Status.StartTime == nil {
				return true
			}
			return pods.Items[i].Status.StartTime.Before(pods.Items[j].Status.StartTime)
		})

		allPodsComplete := true
		for _, pod := range pods.Items {
			if completedPods[pod.Name] {
				continue
			}

			if streamedContainers[pod.Name] == nil {
				streamedContainers[pod.Name] = make(map[string]bool)
			}

			processPodLogs(ctx, c, cs, pod, namespace, sinceTime, streamedContainers[pod.Name], &hadStream)

			stepNames := getStepContainerNames(pod)
			if len(streamedContainers[pod.Name]) == len(stepNames) &&
				(pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed) {
				completedPods[pod.Name] = true
			} else {
				allPodsComplete = false
			}
		}

		// Check if build is complete AND all pod logs have been streamed
		if shouldExitLogStream(ctx, k8sClient, name, namespace, ib, allPodsComplete) {
			break
		}

		if !hadStream || !allPodsComplete {
			time.Sleep(2 * time.Second)
		}
		if !hadStream {
			_, _ = c.Writer.Write([]byte("."))
			if f, ok := c.Writer.(http.Flusher); ok {
				f.Flush()
			}
		}
	}

	writeLogStreamFooter(c, hadStream)
}

// shouldExitLogStream checks if the log streaming loop should exit
func shouldExitLogStream(
	ctx context.Context,
	k8sClient client.Client,
	name, namespace string,
	ib *automotivev1alpha1.ImageBuild,
	allPodsComplete bool,
) bool {
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, ib); err == nil {
		if (ib.Status.Phase == phaseCompleted || ib.Status.Phase == phaseFailed) && allPodsComplete {
			return true
		}
	}
	return false
}

// writeLogStreamFooter writes the final message after log streaming ends
func writeLogStreamFooter(c *gin.Context, hadStream bool) {
	if !hadStream {
		_, _ = c.Writer.Write([]byte("\n[No logs available]\n"))
	} else {
		_, _ = c.Writer.Write([]byte("\n[Log streaming completed]\n"))
	}
	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}
}

func createRegistrySecret(
	ctx context.Context, k8sClient client.Client, namespace, buildName string, creds *RegistryCredentials,
) (string, error) {
	if creds == nil || !creds.Enabled {
		return "", nil
	}

	secretName := fmt.Sprintf("%s-external-registry-auth", buildName)
	secretData := make(map[string][]byte)

	switch creds.AuthType {
	case "username-password":
		if creds.RegistryURL == "" || creds.Username == "" || creds.Password == "" {
			return "", fmt.Errorf("registry URL, username, and password are required for username-password authentication")
		}
		secretData["REGISTRY_URL"] = []byte(creds.RegistryURL)
		secretData["REGISTRY_USERNAME"] = []byte(creds.Username)
		secretData["REGISTRY_PASSWORD"] = []byte(creds.Password)

		// Also create dockerconfigjson format for tools that need it (oras, skopeo, etc.)
		auth := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
		dockerConfig, err := json.Marshal(map[string]interface{}{
			"auths": map[string]interface{}{
				creds.RegistryURL: map[string]string{
					"auth": auth,
				},
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to create docker config: %w", err)
		}
		secretData[".dockerconfigjson"] = dockerConfig
	case "token":
		if creds.RegistryURL == "" || creds.Token == "" {
			return "", fmt.Errorf("registry URL and token are required for token authentication")
		}
		secretData["REGISTRY_URL"] = []byte(creds.RegistryURL)
		secretData["REGISTRY_TOKEN"] = []byte(creds.Token)
	case "docker-config":
		if creds.DockerConfig == "" {
			return "", fmt.Errorf("docker config is required for docker-config authentication")
		}
		secretData["REGISTRY_AUTH_FILE_CONTENT"] = []byte(creds.DockerConfig)
		secretData[".dockerconfigjson"] = []byte(creds.DockerConfig)
	default:
		return "", fmt.Errorf("unsupported authentication type: %s", creds.AuthType)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                  "build-api",
				"app.kubernetes.io/part-of":                     "automotive-dev",
				"app.kubernetes.io/created-by":                  "automotive-dev-build-api",
				"automotive.sdv.cloud.redhat.com/resource-type": "registry-auth",
				"automotive.sdv.cloud.redhat.com/build-name":    buildName,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: secretData,
	}

	if err := k8sClient.Create(ctx, secret); err != nil {
		return "", fmt.Errorf("failed to create registry secret: %w", err)
	}

	return secretName, nil
}

// createPushSecret creates a kubernetes.io/dockerconfigjson secret for pushing artifacts to a registry
func createPushSecret(
	ctx context.Context, k8sClient client.Client, namespace, buildName string, creds *RegistryCredentials,
) (string, error) {
	if creds == nil || !creds.Enabled {
		return "", fmt.Errorf("registry credentials are required for push")
	}

	secretName := fmt.Sprintf("%s-push-auth", buildName)

	var dockerConfigJSON []byte
	var err error

	switch creds.AuthType {
	case "username-password":
		if creds.RegistryURL == "" || creds.Username == "" || creds.Password == "" {
			return "", fmt.Errorf("registry URL, username, and password are required for push")
		}
		// Create dockerconfigjson format
		auth := base64.StdEncoding.EncodeToString([]byte(creds.Username + ":" + creds.Password))
		dockerConfigJSON, err = json.Marshal(map[string]interface{}{
			"auths": map[string]interface{}{
				creds.RegistryURL: map[string]string{
					"auth": auth,
				},
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to marshal docker config: %w", err)
		}
	case "token":
		if creds.RegistryURL == "" || creds.Token == "" {
			return "", fmt.Errorf("registry URL and token are required for push with token auth")
		}
		// For token auth, use the token as password with empty username
		auth := base64.StdEncoding.EncodeToString([]byte(":" + creds.Token))
		dockerConfigJSON, err = json.Marshal(map[string]interface{}{
			"auths": map[string]interface{}{
				creds.RegistryURL: map[string]string{
					"auth": auth,
				},
			},
		})
		if err != nil {
			return "", fmt.Errorf("failed to marshal docker config: %w", err)
		}
	case "docker-config":
		if creds.DockerConfig == "" {
			return "", fmt.Errorf("docker config is required for push with docker-config auth")
		}
		dockerConfigJSON = []byte(creds.DockerConfig)
	default:
		return "", fmt.Errorf("unsupported authentication type for push: %s", creds.AuthType)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                  "build-api",
				"app.kubernetes.io/part-of":                     "automotive-dev",
				"app.kubernetes.io/created-by":                  "automotive-dev-build-api",
				"automotive.sdv.cloud.redhat.com/resource-type": "push-auth",
				"automotive.sdv.cloud.redhat.com/build-name":    buildName,
				"automotive.sdv.cloud.redhat.com/transient":     "true",
			},
		},
		Type: corev1.SecretTypeDockerConfigJson,
		Data: map[string][]byte{
			".dockerconfigjson": dockerConfigJSON,
		},
	}

	if err := k8sClient.Create(ctx, secret); err != nil {
		return "", fmt.Errorf("failed to create push secret: %w", err)
	}

	return secretName, nil
}

// Shell metacharacters that must be blocked to prevent injection attacks
var shellMetachars = []string{";", "|", "&", "$", "`", "(", ")", "{", "}", "<", ">", "!", "\\", "'", "\"", "\n", "\r"}

// validateInput validates a string for dangerous characters and length
func validateInput(value, fieldName string, maxLen int, allowEmpty bool, extraChars ...string) error {
	if value == "" {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("%s is required", fieldName)
	}

	// Combine shell metacharacters with any additional blocked characters
	blockedChars := append(shellMetachars, extraChars...)
	for _, char := range blockedChars {
		if strings.Contains(value, char) {
			return fmt.Errorf("%s contains invalid character: %q", fieldName, char)
		}
	}

	if len(value) > maxLen {
		return fmt.Errorf("%s too long (max %d characters)", fieldName, maxLen)
	}
	return nil
}

func validateContainerRef(ref string) error {
	return validateInput(ref, "container reference", 500, true)
}

func validateBuildName(name string) error {
	return validateInput(name, "build name", 253, false, "/")
}

// validateBuildRequest validates the build request and applies defaults
func validateBuildRequest(req *BuildRequest, maxManifestSize int64) error {
	if err := validateBuildName(req.Name); err != nil {
		return err
	}

	if int64(len(req.Manifest)) > maxManifestSize {
		return fmt.Errorf("manifest too large (max %d bytes)", maxManifestSize)
	}

	if req.Mode == ModeDisk {
		if req.ContainerRef == "" {
			return fmt.Errorf("container-ref is required for disk mode")
		}
		if err := validateContainerRef(req.ContainerRef); err != nil {
			return err
		}
	} else if req.Manifest == "" {
		return fmt.Errorf("manifest is required")
	}

	for field, value := range map[string]string{"container-push": req.ContainerPush, "export-oci": req.ExportOCI} {
		if err := validateContainerRef(value); err != nil {
			return fmt.Errorf("invalid %s: %v", field, err)
		}
	}

	return nil
}

// applyBuildDefaults sets default values for build request fields
func applyBuildDefaults(req *BuildRequest) error {
	if req.Distro == "" {
		req.Distro = "autosd"
	}
	if req.Target == "" {
		req.Target = "qemu"
	}
	if req.Architecture == "" {
		req.Architecture = "arm64"
	}
	if req.ExportFormat == "" {
		req.ExportFormat = formatImage
	}
	if req.Mode == "" {
		req.Mode = ModeBootc
	}
	if strings.TrimSpace(req.Compression) == "" {
		req.Compression = compressionGzip
	}
	if req.Compression != "lz4" && req.Compression != compressionGzip {
		return fmt.Errorf("invalid compression: must be lz4 or gzip")
	}
	if !req.Distro.IsValid() {
		return fmt.Errorf("distro cannot be empty")
	}
	if !req.Target.IsValid() {
		return fmt.Errorf("target cannot be empty")
	}
	if !req.Architecture.IsValid() {
		return fmt.Errorf("architecture cannot be empty")
	}
	// ExportFormat validation removed - allow AIB to handle format validation
	if !req.Mode.IsValid() {
		return fmt.Errorf("mode cannot be empty")
	}
	if req.AutomotiveImageBuilder == "" {
		req.AutomotiveImageBuilder = "quay.io/centos-sig-automotive/automotive-image-builder:1.0.0"
	}
	if req.ManifestFileName == "" {
		req.ManifestFileName = "manifest.aib.yml"
	}
	return nil
}

// createManifestConfigMap creates a ConfigMap for the build manifest
func createManifestConfigMap(
	ctx context.Context, k8sClient client.Client,
	namespace string, req *BuildRequest,
) (string, error) {
	cfgName := fmt.Sprintf("%s-manifest", req.Name)
	cmData := map[string]string{req.ManifestFileName: req.Manifest}

	if len(req.CustomDefs) > 0 {
		cmData["custom-definitions.env"] = strings.Join(req.CustomDefs, "\n")
	}
	if len(req.AIBExtraArgs) > 0 {
		cmData["aib-extra-args.txt"] = strings.Join(req.AIBExtraArgs, " ")
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      cfgName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                  "build-api",
				"app.kubernetes.io/part-of":                     "automotive-dev",
				"app.kubernetes.io/created-by":                  "automotive-dev-build-api",
				"automotive.sdv.cloud.redhat.com/resource-type": "manifest-config",
			},
		},
		Data: cmData,
	}

	if err := k8sClient.Create(ctx, cm); err != nil {
		return "", fmt.Errorf("error creating manifest ConfigMap: %w", err)
	}

	return cfgName, nil
}

// setupBuildSecrets creates necessary secrets for the build
func setupBuildSecrets(
	ctx context.Context, k8sClient client.Client,
	namespace string, req *BuildRequest,
) (envSecretRef, pushSecretName string, err error) {
	if req.RegistryCredentials != nil && req.RegistryCredentials.Enabled {
		envSecretRef, err = createRegistrySecret(ctx, k8sClient, namespace, req.Name, req.RegistryCredentials)
		if err != nil {
			return "", "", fmt.Errorf("error creating registry secret: %w", err)
		}
	}

	// Create push secret if pushing to registry (PushRepository for bootc, ExportOCI for disk images)
	if req.PushRepository != "" || req.ExportOCI != "" {
		if req.RegistryCredentials == nil || !req.RegistryCredentials.Enabled {
			return "", "", fmt.Errorf("registry credentials are required when push repository is specified")
		}
		pushSecretName, err = createPushSecret(ctx, k8sClient, namespace, req.Name, req.RegistryCredentials)
		if err != nil {
			return "", "", fmt.Errorf("error creating push secret: %w", err)
		}
	}

	return envSecretRef, pushSecretName, nil
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
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
	if tag == "" {
		tag = req.Name
	}

	// Set concrete URLs based on build mode.
	// When ContainerPush is already set (hybrid: external container push),
	// keep it and only generate internal URLs for what's missing.
	externalContainerPush := req.ContainerPush != ""
	if req.Mode.IsBootc() {
		if !externalContainerPush {
			req.ContainerPush = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
		}
		// Flash requires a disk image
		if req.FlashEnabled && !req.BuildDiskImage {
			req.BuildDiskImage = true
		}
		if req.BuildDiskImage {
			req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName+"-disk", tag)
		}
	} else {
		// Traditional/disk modes: push disk image as OCI artifact
		req.ExportOCI = generateRegistryImageRef(defaultInternalRegistryURL, namespace, imageName, tag)
	}

	// Pre-create ImageStream(s) for internal registry pushes only
	var imageStreams []string
	if !externalContainerPush {
		imageStreams = append(imageStreams, imageName)
	}
	if req.Mode.IsBootc() && req.BuildDiskImage {
		imageStreams = append(imageStreams, imageName+"-disk")
	}
	if !req.Mode.IsBootc() {
		imageStreams = append(imageStreams, imageName)
	}
	for _, isName := range imageStreams {
		if err := ensureImageStream(ctx, k8sClient, namespace, isName); err != nil {
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
	secretName, err := createInternalRegistrySecret(ctx, restCfg, namespace, req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return "", "", err
	}
	// Return as both envSecretRef (for pipeline registry-auth workspace + WhenExpression)
	// and pushSecretName (for push credential binding)
	return secretName, secretName, nil
}

// buildExportSpec creates ExportSpec configuration from build request
func buildExportSpec(req *BuildRequest) *automotivev1alpha1.ExportSpec {
	export := &automotivev1alpha1.ExportSpec{
		Format:                string(req.ExportFormat),
		Compression:           req.Compression,
		BuildDiskImage:        req.BuildDiskImage,
		Container:             req.ContainerPush,
		UseServiceAccountAuth: req.UseInternalRegistry,
	}

	// Set disk export if OCI URL is specified
	if req.ExportOCI != "" {
		export.Disk = &automotivev1alpha1.DiskExport{
			OCI: req.ExportOCI,
		}
	}

	return export
}

// buildAIBSpec creates AIBSpec configuration from build request
func buildAIBSpec(req *BuildRequest, manifestConfigMap string, inputFilesServer bool) *automotivev1alpha1.AIBSpec {
	return &automotivev1alpha1.AIBSpec{
		Distro:            string(req.Distro),
		Target:            string(req.Target),
		Mode:              string(req.Mode),
		ManifestConfigMap: manifestConfigMap,
		Image:             req.AutomotiveImageBuilder,
		BuilderImage:      req.BuilderImage,
		InputFilesServer:  inputFilesServer,
		ContainerRef:      req.ContainerRef,
	}
}

func (a *APIServer) createBuild(c *gin.Context) {
	var req BuildRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}

	needsUpload := strings.Contains(req.Manifest, "source_path")

	if err := validateBuildRequest(&req, a.limits.MaxManifestSize); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := applyBuildDefaults(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	ctx := c.Request.Context()
	namespace := resolveNamespace()
	requestedBy := a.resolveRequester(c)

	existing := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: req.Name, Namespace: namespace}, existing); err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("ImageBuild %s already exists", req.Name)})
		return
	} else if !k8serrors.IsNotFound(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error checking existing build: %v", err)})
		return
	}

	cfgName, err := createManifestConfigMap(ctx, k8sClient, namespace, &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	labels := map[string]string{
		"app.kubernetes.io/managed-by":                 "build-api",
		"app.kubernetes.io/part-of":                    "automotive-dev",
		"app.kubernetes.io/created-by":                 "automotive-dev-build-api",
		"automotive.sdv.cloud.redhat.com/distro":       string(req.Distro),
		"automotive.sdv.cloud.redhat.com/target":       string(req.Target),
		"automotive.sdv.cloud.redhat.com/architecture": string(req.Architecture),
	}

	envSecretRef, pushSecretName, apiErr := a.resolveRegistryForBuild(ctx, c, k8sClient, namespace, &req)
	if apiErr != nil {
		return
	}

	var flashSpec *automotivev1alpha1.FlashSpec
	var flashSecretName string
	if req.FlashEnabled {
		if req.FlashClientConfig == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "flash enabled but client config is required"})
			return
		}
		flashSecretName = req.Name + "-jumpstarter-client"
		if err := createFlashClientSecret(ctx, k8sClient, namespace, flashSecretName, req.FlashClientConfig); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error creating flash client secret: %v", err)})
			return
		}
		flashSpec = &automotivev1alpha1.FlashSpec{
			ClientConfigSecretRef: flashSecretName,
			LeaseDuration:         req.FlashLeaseDuration,
		}
	}

	imageBuild := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: namespace,
			Labels:    labels,
			Annotations: map[string]string{
				"automotive.sdv.cloud.redhat.com/requested-by": requestedBy,
			},
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			Architecture:  string(req.Architecture),
			StorageClass:  req.StorageClass,
			SecretRef:     envSecretRef,
			PushSecretRef: pushSecretName,
			AIB:           buildAIBSpec(&req, cfgName, needsUpload),
			Export:        buildExportSpec(&req),
			Flash:         flashSpec,
		},
	}
	if err := k8sClient.Create(ctx, imageBuild); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error creating ImageBuild: %v", err)})
		return
	}

	// Set owner references for cascading deletion
	if err := setConfigMapOwnerRef(ctx, k8sClient, namespace, cfgName, imageBuild); err != nil {
		log.Printf(
			"WARNING: failed to set owner reference on ConfigMap %s: %v (cleanup may require manual intervention)",
			cfgName, err,
		)
	}

	if envSecretRef != "" {
		if err := setSecretOwnerRef(ctx, k8sClient, namespace, envSecretRef, imageBuild); err != nil {
			log.Printf(
				"WARNING: failed to set owner reference on registry secret %s: %v "+
					"(cleanup may require manual intervention)",
				envSecretRef, err,
			)
		}
	}

	if pushSecretName != "" {
		if err := setSecretOwnerRef(ctx, k8sClient, namespace, pushSecretName, imageBuild); err != nil {
			log.Printf(
				"WARNING: failed to set owner reference on push secret %s: %v "+
					"(cleanup may require manual intervention)",
				pushSecretName, err,
			)
		}
	}

	if flashSecretName != "" {
		if err := setSecretOwnerRef(ctx, k8sClient, namespace, flashSecretName, imageBuild); err != nil {
			log.Printf(
				"WARNING: failed to set owner reference on flash client secret %s: %v "+
					"(cleanup may require manual intervention)",
				flashSecretName, err,
			)
		}
	}

	writeJSON(c, http.StatusAccepted, BuildResponse{
		Name:        req.Name,
		Phase:       "Building",
		Message:     "Build triggered",
		RequestedBy: requestedBy,
	})
}

func listBuilds(c *gin.Context) {
	namespace := resolveNamespace()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
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

	// Resolve external route once for translating internal registry URLs
	externalRoute, _ := getExternalRegistryRoute(ctx, k8sClient, namespace)

	resp := make([]BuildListItem, 0, len(list.Items))
	for _, b := range list.Items {
		var startStr, compStr string
		if b.Status.StartTime != nil {
			startStr = b.Status.StartTime.Format(time.RFC3339)
		}
		if b.Status.CompletionTime != nil {
			compStr = b.Status.CompletionTime.Format(time.RFC3339)
		}

		containerImage := b.Spec.GetContainerPush()
		diskImage := b.Spec.GetExportOCI()
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
			RequestedBy:    b.Annotations["automotive.sdv.cloud.redhat.com/requested-by"],
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
	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	ctx := c.Request.Context()
	build := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, build); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching build: %v", err)})
		return
	}

	containerImage := build.Spec.GetContainerPush()
	diskImage := build.Spec.GetExportOCI()
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

	// For completed builds, check if Jumpstarter is available and get target mapping
	var jumpstarterInfo *JumpstarterInfo
	if build.Status.Phase == "Completed" {
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
						flashCmd := mapping.FlashCmd
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
	var registryToken string
	if build.Spec.GetUseServiceAccountAuth() &&
		(build.Status.Phase == phaseCompleted || build.Status.Phase == phaseFailed) {
		var tokenErr error
		registryToken, tokenErr = a.mintRegistryToken(ctx, c, namespace)
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
		RequestedBy: build.Annotations["automotive.sdv.cloud.redhat.com/requested-by"],
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
		Jumpstarter:    jumpstarterInfo,
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
			UseServiceAccountAuth:  build.Spec.GetUseServiceAccountAuth(),
		},
	})
}

// getBuildTemplate returns a BuildRequest-like struct representing the inputs that produced a given build
func getBuildTemplate(c *gin.Context, name string) {
	namespace := resolveNamespace()
	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	ctx := c.Request.Context()
	build := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, build); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching build: %v", err)})
		return
	}

	cm := &corev1.ConfigMap{}
	manifestKey := types.NamespacedName{Name: build.Spec.GetManifestConfigMap(), Namespace: namespace}
	if err := k8sClient.Get(ctx, manifestKey, cm); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching manifest config: %v", err)})
		return
	}

	// Rehydrate advanced args
	var aibExtra []string
	if v, ok := cm.Data["aib-extra-args.txt"]; ok {
		fields := strings.Fields(strings.TrimSpace(v))
		aibExtra = append(aibExtra, fields...)
	}

	manifestFileName := "manifest.aib.yml"
	var manifest string
	for k, v := range cm.Data {
		if k == "custom-definitions.env" || k == "aib-extra-args.txt" {
			continue
		}
		manifestFileName = k
		manifest = v
		break
	}

	var sourceFiles []string
	for _, line := range strings.Split(manifest, "\n") {
		s := strings.TrimSpace(line)
		if strings.HasPrefix(s, "source:") || strings.HasPrefix(s, "source_path:") {
			parts := strings.SplitN(s, ":", 2)
			if len(parts) == 2 {
				p := strings.TrimSpace(parts[1])
				p = strings.Trim(p, "'\"")
				if p != "" && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "http") {
					sourceFiles = append(sourceFiles, p)
				}
			}
		}
	}

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
			CustomDefs:             nil,
			AIBExtraArgs:           aibExtra,
			Compression:            build.Spec.GetCompression(),
		},
		SourceFiles: sourceFiles,
	})
}

// uploadContext holds the context needed for file upload operations.
type uploadContext struct {
	restCfg   *rest.Config
	namespace string
	podName   string
	container string
	limits    *APILimits
}

// processFilePartResult contains the result of processing a single file part.
type processFilePartResult struct {
	bytesWritten int64
}

// validateDestPath checks if the destination path is safe for upload.
func validateDestPath(dest string) (string, error) {
	if dest == "" {
		return "", fmt.Errorf("missing destination filename")
	}
	if !safeFilename(dest) {
		return "", fmt.Errorf("invalid destination filename: %s", dest)
	}
	cleanDest := path.Clean(dest)
	if strings.HasPrefix(cleanDest, "..") || strings.HasPrefix(cleanDest, "/") {
		return "", fmt.Errorf("invalid destination path: %s", dest)
	}
	return cleanDest, nil
}

// processFilePart handles a single file part from the multipart upload.
func processFilePart(part *multipart.Part, pendingPath string, uctx *uploadContext) (processFilePartResult, error) {
	dest := pendingPath
	if dest == "" {
		dest = strings.TrimSpace(part.FileName())
	}

	cleanDest, err := validateDestPath(dest)
	if err != nil {
		return processFilePartResult{}, err
	}

	tmp, err := os.CreateTemp("", "upload-*")
	if err != nil {
		return processFilePartResult{}, err
	}
	tmpName := tmp.Name()
	defer func() {
		if closeErr := tmp.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close temp file: %v\n", closeErr)
		}
	}()
	defer func() {
		if removeErr := os.Remove(tmpName); removeErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove temp file: %v\n", removeErr)
		}
	}()

	limitedReader := io.LimitReader(part, uctx.limits.MaxUploadFileSize+1)
	n, err := io.Copy(tmp, limitedReader)
	if err != nil {
		return processFilePartResult{}, err
	}
	if n > uctx.limits.MaxUploadFileSize {
		return processFilePartResult{}, fmt.Errorf("file %s exceeds maximum size (%d bytes)", dest, uctx.limits.MaxUploadFileSize)
	}

	destPath := "/workspace/shared/" + cleanDest
	if err := copyFileToPod(uctx.restCfg, uctx.namespace, uctx.podName, uctx.container, tmpName, destPath); err != nil {
		return processFilePartResult{}, fmt.Errorf("stream to pod failed: %w", err)
	}

	return processFilePartResult{bytesWritten: n}, nil
}

// findRunningUploadPod finds a running upload pod for the given build.
func findRunningUploadPod(ctx context.Context, k8sClient client.Client, namespace, buildName string) (*corev1.Pod, error) {
	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList,
		client.InNamespace(namespace),
		client.MatchingLabels{
			"automotive.sdv.cloud.redhat.com/imagebuild-name": buildName,
			"app.kubernetes.io/name":                          "upload-pod",
		},
	); err != nil {
		return nil, fmt.Errorf("error listing upload pods: %w", err)
	}
	for i := range podList.Items {
		p := &podList.Items[i]
		if p.Status.Phase == corev1.PodRunning {
			return p, nil
		}
	}
	return nil, nil
}

func (a *APIServer) uploadFiles(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}
	build := &automotivev1alpha1.ImageBuild{}
	buildKey := types.NamespacedName{Name: name, Namespace: namespace}
	if err := k8sClient.Get(c.Request.Context(), buildKey, build); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching build: %v", err)})
		return
	}

	uploadPod, err := findRunningUploadPod(c.Request.Context(), k8sClient, namespace, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if uploadPod == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upload pod not ready"})
		return
	}

	if c.Request.ContentLength > a.limits.MaxTotalUploadSize {
		errMsg := fmt.Sprintf("upload too large (max %d bytes)", a.limits.MaxTotalUploadSize)
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": errMsg})
		return
	}

	reader, err := c.Request.MultipartReader()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid multipart: %v", err)})
		return
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("rest config: %v", err)})
		return
	}

	uctx := &uploadContext{
		restCfg:   restCfg,
		namespace: namespace,
		podName:   uploadPod.Name,
		container: uploadPod.Spec.Containers[0].Name,
		limits:    &a.limits,
	}

	var totalBytesUploaded int64
	var pendingPath string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("read part: %v", err)})
			return
		}

		// Handle "path" field - stores the destination path for the next file
		if part.FormName() == "path" {
			pathBytes, err := io.ReadAll(io.LimitReader(part, 4096))
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("read path: %v", err)})
				return
			}
			pendingPath = strings.TrimSpace(string(pathBytes))
			continue
		}

		if part.FormName() != "file" {
			continue
		}

		result, err := processFilePart(part, pendingPath, uctx)
		pendingPath = ""
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		totalBytesUploaded += result.bytesWritten
		if totalBytesUploaded > a.limits.MaxTotalUploadSize {
			errMsg := fmt.Sprintf("total upload size exceeds maximum (%d bytes)", a.limits.MaxTotalUploadSize)
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": errMsg})
			return
		}
	}

	original := build
	patched := original.DeepCopy()
	if patched.Annotations == nil {
		patched.Annotations = map[string]string{}
	}
	patched.Annotations["automotive.sdv.cloud.redhat.com/uploads-complete"] = "true"
	if err := k8sClient.Patch(c.Request.Context(), patched, client.MergeFrom(original)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("mark complete failed: %v", err)})
		return
	}
	writeJSON(c, http.StatusOK, map[string]string{"status": "ok"})
}

func copyFileToPod(config *rest.Config, namespace, podName, containerName, localPath, podPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close file: %v\n", err)
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return err
	}

	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		defer func() {
			if err := tw.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close tar writer: %v\n", err)
			}
			if err := pw.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to close pipe writer: %v\n", err)
			}
		}()
		hdr := &tar.Header{Name: path.Base(podPath), Mode: 0600, Size: info.Size(), ModTime: info.ModTime()}
		if err := tw.WriteHeader(hdr); err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(tw, f); err != nil {
			pw.CloseWithError(err)
			return
		}
	}()

	destDir := path.Dir(podPath)
	cmd := []string{"/bin/sh", "-c", "mkdir -p \"$1\" && tar -x -C \"$1\"", "--", destDir}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
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
	executor, err := remotecommand.NewSPDYExecutor(config, http.MethodPost, req.URL())
	if err != nil {
		return err
	}
	streamOpts := remotecommand.StreamOptions{Stdin: pr, Stdout: io.Discard, Stderr: io.Discard}
	return executor.StreamWithContext(context.Background(), streamOpts)
}

func setConfigMapOwnerRef(
	ctx context.Context,
	c client.Client,
	namespace, configMapName string,
	owner *automotivev1alpha1.ImageBuild,
) error {
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: namespace}, cm); err != nil {
		return err
	}
	cm.OwnerReferences = []metav1.OwnerReference{
		*metav1.NewControllerRef(owner, automotivev1alpha1.GroupVersion.WithKind("ImageBuild")),
	}
	return c.Update(ctx, cm)
}

func setSecretOwnerRef(
	ctx context.Context,
	c client.Client,
	namespace, secretName string,
	owner *automotivev1alpha1.ImageBuild,
) error {
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
		return err
	}
	secret.OwnerReferences = []metav1.OwnerReference{
		*metav1.NewControllerRef(owner, automotivev1alpha1.GroupVersion.WithKind("ImageBuild")),
	}
	return c.Update(ctx, secret)
}

// createFlashClientSecret creates a secret containing the Jumpstarter client config
func createFlashClientSecret(
	ctx context.Context,
	c client.Client,
	namespace, secretName, base64Config string,
) error {
	// Decode base64 client config
	configBytes, err := base64.StdEncoding.DecodeString(base64Config)
	if err != nil {
		return fmt.Errorf("failed to decode client config: %w", err)
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "build-api",
				"app.kubernetes.io/part-of":    "automotive-dev",
				"app.kubernetes.io/component":  "jumpstarter-client",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"client.yaml": configBytes,
		},
	}

	return c.Create(ctx, secret)
}

func writeJSON(c *gin.Context, status int, v any) {
	c.Header("Cache-Control", "no-store")
	c.IndentedJSON(status, v)
}

func parseSinceTime(sinceParam string) *metav1.Time {
	if sinceParam == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, sinceParam)
	if err != nil {
		return nil
	}
	return &metav1.Time{Time: t}
}

func resolveNamespace() string {
	if ns := strings.TrimSpace(os.Getenv("BUILD_API_NAMESPACE")); ns != "" {
		return ns
	}
	if data, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		ns := strings.TrimSpace(string(data))
		if ns != "" {
			return ns
		}
	}
	return "default"
}

func getRESTConfigFromRequest(_ *gin.Context) (*rest.Config, error) {
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
	cfgCopy := rest.CopyConfig(cfg)
	cfgCopy.Timeout = 30 * time.Minute
	return cfgCopy, nil
}

// getKubernetesClient creates a controller-runtime client for accessing Kubernetes resources
func getKubernetesClient() (client.Client, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to build kube config: %w", err)
		}
	}

	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add scheme: %w", err)
	}

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}
	return k8sClient, nil
}

func getClientFromRequest(c *gin.Context) (client.Client, error) {
	cfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		return nil, err
	}

	scheme := runtime.NewScheme()
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add automotive scheme: %w", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add core scheme: %w", err)
	}
	if err := tektonv1.AddToScheme(scheme); err != nil {
		return nil, fmt.Errorf("failed to add tekton scheme: %w", err)
	}

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}
	return k8sClient, nil
}

// refreshAuthConfigIfNeeded periodically checks and refreshes authentication configuration from OperatorConfig
// IMPORTANT: This function only recreates the OIDC authenticator if the config actually changed.
func (a *APIServer) refreshAuthConfigIfNeeded() {
	a.authConfigMu.Lock()
	defer a.authConfigMu.Unlock()

	// Check if it's time to refresh (every 60 seconds)
	if time.Since(a.lastAuthConfigCheck) < 60*time.Second {
		return
	}
	a.lastAuthConfigCheck = time.Now()

	namespace := resolveNamespace()
	k8sClient, err := getKubernetesClient()
	if err != nil {
		a.log.Error(err, "failed to get k8s client for auth config refresh", "namespace", namespace)
		return
	}

	// Get the OperatorConfig to check if it changed
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	key := types.NamespacedName{Name: "config", Namespace: namespace}
	if err := k8sClient.Get(context.Background(), key, operatorConfig); err != nil {
		a.log.Error(err, "failed to get OperatorConfig during refresh", "namespace", namespace)
		return
	}

	// Build new config from OperatorConfig (without creating authenticator yet)
	var newConfig *AuthenticationConfiguration
	if operatorConfig.Spec.BuildAPI != nil && operatorConfig.Spec.BuildAPI.Authentication != nil {
		auth := operatorConfig.Spec.BuildAPI.Authentication
		// Deep copy JWT config with Prefix handling
		jwtCopy := make([]apiserverv1beta1.JWTAuthenticator, len(auth.JWT))
		for i, jwt := range auth.JWT {
			jwtCopy[i] = jwt
			if jwt.ClaimMappings.Username.Claim != "" && jwt.ClaimMappings.Username.Prefix == nil {
				emptyPrefix := ""
				jwtCopy[i].ClaimMappings.Username.Prefix = &emptyPrefix
			}
			if jwt.ClaimMappings.Groups.Claim != "" && jwt.ClaimMappings.Groups.Prefix == nil {
				emptyPrefix := ""
				jwtCopy[i].ClaimMappings.Groups.Prefix = &emptyPrefix
			}
		}
		newConfig = &AuthenticationConfiguration{
			ClientID: auth.ClientID,
			Internal: InternalAuthConfig{Prefix: "internal:"},
			JWT:      jwtCopy,
		}
		if auth.Internal != nil && auth.Internal.Prefix != "" {
			newConfig.Internal.Prefix = auth.Internal.Prefix
		}
	}

	// Compare with existing config, only recreate authenticator if config changed
	if authConfigsEqual(a.authConfig, newConfig) {
		// Config unchanged, keep existing authenticator (which is already initialized)
		return
	}

	// Config changed - need to recreate authenticator
	a.log.Info("auth config changed, recreating OIDC authenticator")

	if newConfig == nil {
		// No auth config, clear everything
		a.authConfig = nil
		a.externalJWT = nil
		a.internalPrefix = ""
		return
	}

	// Create new authenticator
	authn, err := newJWTAuthenticator(context.Background(), *newConfig)
	if err != nil {
		a.log.Error(err, "failed to create JWT authenticator during refresh, keeping existing config")
		return
	}

	// Update config fields
	a.authConfig = newConfig
	a.internalPrefix = newConfig.Internal.Prefix
	if newConfig.ClientID != "" {
		a.oidcClientID = newConfig.ClientID
	}

	// Update authenticator
	if authn != nil {
		a.externalJWT = authn
	} else {
		if len(newConfig.JWT) == 0 {
			a.externalJWT = nil
		} else {
			a.externalJWT = nil
		}
	}
}

func (a *APIServer) authenticateRequest(c *gin.Context) (string, string, *authError) {
	// Refresh auth config if needed (checks OperatorConfig periodically)
	a.refreshAuthConfigIfNeeded()

	token := extractBearerToken(c)
	if token == "" {
		return "", "", &authError{
			Reason:  "missing_token",
			Details: "No bearer token provided. Set Authorization header with 'Bearer <token>' or use CAIB_TOKEN environment variable.",
		}
	}

	// Track which auth methods were tried for error reporting
	var authAttempts []string
	var oidcError error

	// Try internal JWT first
	a.authConfigMu.RLock()
	internalJWT := a.internalJWT
	internalPrefix := a.internalPrefix
	a.authConfigMu.RUnlock()

	if internalJWT != nil {
		authAttempts = append(authAttempts, "internal_jwt")
		if subject, ok := validateInternalJWT(token, internalJWT); ok {
			username := subject
			if internalPrefix != "" {
				username = internalPrefix + username
			}
			return username, "internal", nil
		}
	}

	// Try external JWT (OIDC)
	a.authConfigMu.RLock()
	externalJWT := a.externalJWT
	a.authConfigMu.RUnlock()

	if externalJWT != nil {
		authAttempts = append(authAttempts, "oidc")
		result := a.authenticateExternalJWT(c, token, externalJWT)
		if result.ok {
			// Store OIDC token in secret after successful authentication
			if a.internalJWT != nil {
				if err := a.ensureClientTokenSecret(c, result.username, token); err != nil {
					a.log.Error(err, "failed to ensure client token secret", "username", result.username)
				}
			}
			return result.username, "external", nil
		}
		oidcError = result.err
	}

	// Fallback to kubeconfig TokenReview authentication
	authAttempts = append(authAttempts, "k8s_token_review")

	cfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		a.log.Error(err, "Failed to get REST config for TokenReview fallback")
		return "", "", &authError{
			Reason:  "server_error",
			Details: "Failed to initialize Kubernetes client for token validation. Check build-api logs.",
		}
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		a.log.Error(err, "Failed to create Kubernetes client for TokenReview")
		return "", "", &authError{
			Reason:  "server_error",
			Details: "Failed to create Kubernetes client for token validation. Check build-api logs.",
		}
	}

	tr := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}}
	res, err := clientset.AuthenticationV1().TokenReviews().Create(c.Request.Context(), tr, metav1.CreateOptions{})
	if err != nil {
		a.log.Error(err, "TokenReview API call failed")
		return "", "", &authError{
			Reason:  "token_review_failed",
			Details: "Failed to validate token with Kubernetes API. The token may be malformed or the server may have connectivity issues.",
		}
	}
	if res.Status.Authenticated {
		username := res.Status.User.Username
		if username == "" {
			return "", "", &authError{
				Reason:  "invalid_token",
				Details: "Token was authenticated but no username was returned.",
			}
		}
		return username, "k8s", nil
	}

	// Build detailed error message for token validation failure
	return "", "", a.buildAuthFailureError(authAttempts, oidcError, res.Status.Error)
}

// buildAuthFailureError constructs a sanitized error message explaining authentication failure.
// Raw error details are logged server-side and not exposed to the client.
func (a *APIServer) buildAuthFailureError(authAttempts []string, oidcError error, tokenReviewError string) *authError {
	// Check if OIDC was attempted
	oidcAttempted := false
	for _, method := range authAttempts {
		if method == "oidc" {
			oidcAttempted = true
			break
		}
	}

	// Log full error details server-side for debugging
	if tokenReviewError != "" {
		a.log.Info("TokenReview authentication failed", "error", tokenReviewError)
	}
	if oidcError != nil {
		a.log.Info("OIDC authentication failed", "error", oidcError.Error())
	}

	// only TokenReview was tried (no OIDC configured)
	if !oidcAttempted {
		return &authError{
			Reason:  "invalid_token",
			Details: "Token validation failed. The token may be expired or invalid. Try 'oc login' to refresh your session, then use 'oc whoami -t' for a fresh token.",
		}
	}

	// OIDC was configured and attempted
	var details strings.Builder
	details.WriteString("Authentication failed. OIDC is configured on this cluster. ")

	if oidcError != nil {
		details.WriteString("OIDC: token validation failed. ")
	} else {
		details.WriteString("OIDC: token not valid for configured issuer. ")
	}

	if tokenReviewError != "" {
		details.WriteString("Kubernetes fallback: token rejected. ")
	} else {
		details.WriteString("Kubernetes fallback: token rejected (may be expired or invalid). ")
	}

	details.WriteString("If using OIDC, ensure you have a valid OIDC token. Otherwise, try 'oc login' to refresh your session.")

	return &authError{
		Reason:  "invalid_token",
		Details: details.String(),
	}
}

// extractBearerToken extracts the bearer token from the request.
func extractBearerToken(c *gin.Context) string {
	authHeader := c.Request.Header.Get("Authorization")
	token, _ := strings.CutPrefix(authHeader, "Bearer ")
	if token != "" {
		return strings.TrimSpace(token)
	}
	token = c.Request.Header.Get("X-Forwarded-Access-Token")
	if token != "" {
		return strings.TrimSpace(token)
	}
	return ""
}

func (a *APIServer) resolveRequester(c *gin.Context) string {
	if v, ok := c.Get("requester"); ok {
		if username, ok := v.(string); ok && username != "" {
			return username
		}
	}
	return "unknown"
}

// handleGetAuthConfig returns OIDC configuration for clients (no auth required)
func (a *APIServer) handleGetAuthConfig(c *gin.Context) {
	// Refresh auth config if needed
	a.refreshAuthConfigIfNeeded()

	type OIDCConfigResponse struct {
		ClientID string `json:"clientId,omitempty"`
		JWT      []struct {
			Issuer struct {
				URL       string   `json:"url"`
				Audiences []string `json:"audiences,omitempty"`
			} `json:"issuer"`
			ClaimMappings struct {
				Username struct {
					Claim  string `json:"claim"`
					Prefix string `json:"prefix,omitempty"`
				} `json:"username"`
			} `json:"claimMappings"`
		} `json:"jwt"`
	}

	// Read auth config with mutex
	a.authConfigMu.RLock()
	clientID := a.oidcClientID
	authConfig := a.authConfig
	a.authConfigMu.RUnlock()

	response := OIDCConfigResponse{
		ClientID: clientID,
	}

	// Validate clientId matches at least one audience if both are set
	if clientID != "" && authConfig != nil {
		clientIDInAudience := false
		for _, jwtConfig := range authConfig.JWT {
			for _, audience := range jwtConfig.Issuer.Audiences {
				if audience == clientID {
					clientIDInAudience = true
					break
				}
			}
		}
		if !clientIDInAudience && len(authConfig.JWT) > 0 {
			a.log.Info("OIDC clientId does not match any JWT audience", "clientId", clientID)
		}
	}

	// Only return OIDC config if externalJWT is actually working (not nil)
	// If externalJWT is nil, OIDC isn't working and clients should use kubeconfig
	a.authConfigMu.RLock()
	externalJWTWorking := a.externalJWT != nil
	a.authConfigMu.RUnlock()

	// Try to get from parsed config first, but only if OIDC is actually working
	if authConfig != nil && len(authConfig.JWT) > 0 && externalJWTWorking {
		for _, jwtConfig := range authConfig.JWT {
			prefix := ""
			if jwtConfig.ClaimMappings.Username.Prefix != nil {
				prefix = *jwtConfig.ClaimMappings.Username.Prefix
			}
			response.JWT = append(response.JWT, struct {
				Issuer struct {
					URL       string   `json:"url"`
					Audiences []string `json:"audiences,omitempty"`
				} `json:"issuer"`
				ClaimMappings struct {
					Username struct {
						Claim  string `json:"claim"`
						Prefix string `json:"prefix,omitempty"`
					} `json:"username"`
				} `json:"claimMappings"`
			}{
				Issuer: struct {
					URL       string   `json:"url"`
					Audiences []string `json:"audiences,omitempty"`
				}{
					URL:       jwtConfig.Issuer.URL,
					Audiences: jwtConfig.Issuer.Audiences,
				},
				ClaimMappings: struct {
					Username struct {
						Claim  string `json:"claim"`
						Prefix string `json:"prefix,omitempty"`
					} `json:"username"`
				}{
					Username: struct {
						Claim  string `json:"claim"`
						Prefix string `json:"prefix,omitempty"`
					}{
						Claim:  jwtConfig.ClaimMappings.Username.Claim,
						Prefix: prefix,
					},
				},
			})
		}
	}

	// OIDC not configured or not working, return 404 so clients use kubeconfig without trying OIDC
	if len(response.JWT) == 0 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	c.JSON(http.StatusOK, response)
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
			a.log.Info("OperatorConfig not found; returning empty operator config response", "reqID", reqID, "namespace", namespace)
			c.JSON(http.StatusOK, OperatorConfigResponse{})
			return
		}
		a.log.Error(err, "failed to get OperatorConfig", "reqID", reqID, "namespace", namespace)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get operator configuration"})
		return
	}

	// Build the response with Jumpstarter target mappings
	response := OperatorConfigResponse{}

	if operatorConfig.Spec.Jumpstarter != nil && len(operatorConfig.Spec.Jumpstarter.TargetMappings) > 0 {
		response.JumpstarterTargets = make(map[string]TargetDefaults)
		for target, mapping := range operatorConfig.Spec.Jumpstarter.TargetMappings {
			response.JumpstarterTargets[target] = TargetDefaults{
				Selector:     mapping.Selector,
				Architecture: mapping.Architecture,
				ExtraArgs:    mapping.ExtraArgs,
			}
		}
	}

	c.JSON(http.StatusOK, response)
}

// Flash API handlers

func (a *APIServer) handleCreateFlash(c *gin.Context) {
	a.log.Info("create flash", "reqID", c.GetString("reqID"))
	a.createFlash(c)
}

func (a *APIServer) handleListFlash(c *gin.Context) {
	a.log.Info("list flash jobs", "reqID", c.GetString("reqID"))
	a.listFlash(c)
}

func (a *APIServer) handleGetFlash(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("get flash", "flash", name, "reqID", c.GetString("reqID"))
	a.getFlash(c, name)
}

func (a *APIServer) handleFlashLogs(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("flash logs requested", "flash", name, "reqID", c.GetString("reqID"))
	a.streamFlashLogs(c, name)
}

func (a *APIServer) createFlash(c *gin.Context) {
	var req FlashRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}

	// Validate required fields
	if req.ImageRef == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "imageRef is required"})
		return
	}
	if req.ClientConfig == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "clientConfig is required"})
		return
	}

	// Auto-generate name if not provided
	if req.Name == "" {
		req.Name = fmt.Sprintf("flash-%s", time.Now().Format("20060102-150405"))
	}

	// Validate name
	if err := validateBuildName(req.Name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	namespace := resolveNamespace()
	requestedBy := a.resolveRequester(c)

	// Get exporter selector from OperatorConfig if target is specified
	exporterSelector := req.ExporterSelector
	flashCmd := req.FlashCmd
	if req.Target != "" && exporterSelector == "" {
		operatorConfig := &automotivev1alpha1.OperatorConfig{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: "config", Namespace: namespace}, operatorConfig); err == nil {
			if operatorConfig.Spec.Jumpstarter != nil {
				if mapping, ok := operatorConfig.Spec.Jumpstarter.TargetMappings[req.Target]; ok {
					exporterSelector = mapping.Selector
					if flashCmd == "" {
						flashCmd = mapping.FlashCmd
					}
				}
			}
		}
	}

	if exporterSelector == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exporterSelector or valid target is required"})
		return
	}

	// Replace placeholders in flash command
	if flashCmd != "" {
		flashCmd = strings.ReplaceAll(flashCmd, "{image_uri}", req.ImageRef)
		flashCmd = strings.ReplaceAll(flashCmd, "{artifact_url}", req.ImageRef)
	}

	// Decode client config to verify it's valid base64
	clientConfigBytes, err := base64.StdEncoding.DecodeString(req.ClientConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "clientConfig must be base64 encoded"})
		return
	}

	// Create secret for client config
	secretName := fmt.Sprintf("%s-jumpstarter-client", req.Name)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                  "build-api",
				"app.kubernetes.io/part-of":                     "automotive-dev",
				flashTaskRunLabel:                               req.Name,
				"automotive.sdv.cloud.redhat.com/resource-type": "jumpstarter-client",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"client.yaml": clientConfigBytes,
		},
	}

	createdSecret, err := clientset.CoreV1().Secrets(namespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("flash %s already exists", req.Name)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create secret: %v", err)})
		return
	}

	// Get the flash task spec
	flashTask := tasks.GenerateFlashTask(namespace)

	// Lease duration
	leaseDuration := req.LeaseDuration
	if leaseDuration == "" {
		leaseDuration = "03:00:00" // Default 3 hours
	}

	// Create the flash TaskRun
	taskRun := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "build-api",
				"app.kubernetes.io/part-of":    "automotive-dev",
				"app.kubernetes.io/name":       "flash-taskrun",
				flashTaskRunLabel:              req.Name,
			},
			Annotations: map[string]string{
				"automotive.sdv.cloud.redhat.com/requested-by": requestedBy,
				"automotive.sdv.cloud.redhat.com/image-ref":    req.ImageRef,
			},
		},
		Spec: tektonv1.TaskRunSpec{
			TaskSpec: &flashTask.Spec,
			Params: []tektonv1.Param{
				{Name: "image-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: req.ImageRef}},
				{Name: "exporter-selector", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: exporterSelector}},
				{Name: "flash-cmd", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: flashCmd}},
				{Name: "lease-duration", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: leaseDuration}},
			},
			Workspaces: []tektonv1.WorkspaceBinding{
				{
					Name: "jumpstarter-client",
					Secret: &corev1.SecretVolumeSource{
						SecretName: secretName,
					},
				},
			},
		},
	}

	if err := k8sClient.Create(ctx, taskRun); err != nil {
		// Clean up the secret if TaskRun creation fails
		_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create flash TaskRun: %v", err)})
		return
	}

	// Set owner reference on secret for automatic cleanup
	createdSecret.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: "tekton.dev/v1",
			Kind:       "TaskRun",
			Name:       taskRun.Name,
			UID:        taskRun.UID,
		},
	}
	if _, err := clientset.CoreV1().Secrets(namespace).Update(ctx, createdSecret, metav1.UpdateOptions{}); err != nil {
		log.Printf("WARNING: failed to set owner reference on secret %s: %v", secretName, err)
	}

	writeJSON(c, http.StatusAccepted, FlashResponse{
		Name:        req.Name,
		Phase:       phasePending,
		Message:     "Flash TaskRun created",
		RequestedBy: requestedBy,
		TaskRunName: taskRun.Name,
	})
}

func (a *APIServer) listFlash(c *gin.Context) {
	namespace := resolveNamespace()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	ctx := c.Request.Context()

	// List TaskRuns with flash label
	taskRunList := &tektonv1.TaskRunList{}
	if err := k8sClient.List(ctx, taskRunList, client.InNamespace(namespace), client.HasLabels{flashTaskRunLabel}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list flash TaskRuns: %v", err)})
		return
	}

	// Sort by creation time, newest first
	sort.Slice(taskRunList.Items, func(i, j int) bool {
		return taskRunList.Items[j].CreationTimestamp.Before(&taskRunList.Items[i].CreationTimestamp)
	})

	resp := make([]FlashListItem, 0, len(taskRunList.Items))
	for _, tr := range taskRunList.Items {
		phase, message := getTaskRunStatus(&tr)
		var compStr string
		if tr.Status.CompletionTime != nil {
			compStr = tr.Status.CompletionTime.Format(time.RFC3339)
		}
		resp = append(resp, FlashListItem{
			Name:           tr.Name,
			Phase:          phase,
			Message:        message,
			RequestedBy:    tr.Annotations["automotive.sdv.cloud.redhat.com/requested-by"],
			CreatedAt:      tr.CreationTimestamp.Format(time.RFC3339),
			CompletionTime: compStr,
		})
	}
	writeJSON(c, http.StatusOK, resp)
}

func (a *APIServer) getFlash(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	ctx := c.Request.Context()
	taskRun := &tektonv1.TaskRun{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, taskRun); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "flash TaskRun not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get flash TaskRun: %v", err)})
		return
	}

	// Verify it's a flash TaskRun
	if taskRun.Labels[flashTaskRunLabel] == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "flash TaskRun not found"})
		return
	}

	phase, message := getTaskRunStatus(taskRun)
	var startStr, compStr string
	if taskRun.Status.StartTime != nil {
		startStr = taskRun.Status.StartTime.Format(time.RFC3339)
	}
	if taskRun.Status.CompletionTime != nil {
		compStr = taskRun.Status.CompletionTime.Format(time.RFC3339)
	}

	writeJSON(c, http.StatusOK, FlashResponse{
		Name:           taskRun.Name,
		Phase:          phase,
		Message:        message,
		RequestedBy:    taskRun.Annotations["automotive.sdv.cloud.redhat.com/requested-by"],
		StartTime:      startStr,
		CompletionTime: compStr,
		TaskRunName:    taskRun.Name,
	})
}

func getTaskRunStatus(tr *tektonv1.TaskRun) (phase, message string) {
	// Check if completed
	if tr.Status.CompletionTime != nil {
		// Check conditions for success/failure
		for _, cond := range tr.Status.Conditions {
			if cond.Type == "Succeeded" {
				if cond.Status == corev1.ConditionTrue {
					return phaseCompleted, "Flash completed successfully"
				}
				return phaseFailed, cond.Message
			}
		}
		return phaseFailed, "Flash failed"
	}

	// Check if running
	if tr.Status.StartTime != nil {
		return phaseRunning, "Flash in progress"
	}

	return phasePending, "Waiting to start"
}

func (a *APIServer) streamFlashLogs(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	// Verify the TaskRun exists and is a flash TaskRun
	taskRun := &tektonv1.TaskRun{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, taskRun); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "flash TaskRun not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to get flash TaskRun: %v", err)})
		return
	}
	if taskRun.Labels[flashTaskRunLabel] == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "flash TaskRun not found"})
		return
	}

	sinceTime := parseSinceTime(c.Query("since"))
	streamDuration := time.Duration(a.limits.MaxLogStreamDurationMinutes) * time.Minute
	streamCtx, cancel := context.WithTimeout(ctx, streamDuration)
	defer cancel()

	// Get the pod name from TaskRun status
	podName := taskRun.Status.PodName
	if podName == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "flash pod not ready"})
		return
	}

	setupLogStreamHeaders(c)

	// TaskRun pods use step containers with naming convention "step-<step-name>"
	containerName := "step-flash"

	// Stream logs
	req := clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Container: containerName,
		Follow:    true,
		SinceTime: sinceTime,
	})
	stream, err := req.Stream(streamCtx)
	if err != nil {
		_, _ = fmt.Fprintf(c.Writer, "\n[Error streaming logs: %v]\n", err)
		c.Writer.Flush()
		return
	}
	defer func() {
		if err := stream.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close stream: %v\n", err)
		}
	}()

	_, _ = c.Writer.Write([]byte("\n===== Flash TaskRun Logs =====\n\n"))
	c.Writer.Flush()

	scanner := bufio.NewScanner(stream)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	for scanner.Scan() {
		select {
		case <-streamCtx.Done():
			return
		default:
		}
		line := scanner.Bytes()
		if _, writeErr := c.Writer.Write(line); writeErr != nil {
			return
		}
		if _, writeErr := c.Writer.Write([]byte("\n")); writeErr != nil {
			return
		}
		c.Writer.Flush()
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		var errMsg []byte
		errMsg = fmt.Appendf(errMsg, "\n[Stream error: %v]\n", err)
		_, _ = c.Writer.Write(errMsg)
		c.Writer.Flush()
	}

	_, _ = c.Writer.Write([]byte("\n[Log streaming completed]\n"))
	c.Writer.Flush()
}
