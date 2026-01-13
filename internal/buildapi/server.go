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
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-logr/logr"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/catalog"
	authnv1 "k8s.io/api/authentication/v1"
)

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

type APIServer struct {
	server *http.Server
	router *gin.Engine
	addr   string
	log    logr.Logger
	limits APILimits
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

		buildsGroup := v1.Group("/builds")
		buildsGroup.Use(a.authMiddleware())
		{
			buildsGroup.POST("", a.handleCreateBuild)
			buildsGroup.GET("", a.handleListBuilds)
			buildsGroup.GET("/:name", a.handleGetBuild)
			buildsGroup.GET("/:name/logs", a.handleStreamLogs)
			buildsGroup.GET("/:name/artifact", a.handleStreamDefaultArtifact)
			buildsGroup.GET("/:name/artifacts", a.handleListArtifacts)
			buildsGroup.GET("/:name/artifacts/:file", a.handleStreamArtifactPart)
			buildsGroup.GET("/:name/artifact/:filename", a.handleStreamArtifactByFilename)
			buildsGroup.GET("/:name/template", a.handleGetBuildTemplate)
			buildsGroup.POST("/:name/uploads", a.handleUploadFiles)
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

// authMiddleware provides authentication middleware for Gin
func (a *APIServer) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.isAuthenticated(c) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			c.Abort()
			return
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
	getBuild(c, name)
}

func (a *APIServer) handleStreamLogs(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("logs requested", "build", name, "reqID", c.GetString("reqID"))
	a.streamLogs(c, name)
}

func (a *APIServer) handleListArtifacts(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("artifacts list requested", "build", name, "reqID", c.GetString("reqID"))
	a.listArtifacts(c, name)
}

func (a *APIServer) handleStreamArtifactPart(c *gin.Context) {
	name := c.Param("name")
	file := c.Param("file")
	a.log.Info("artifact item requested", "build", name, "file", file, "reqID", c.GetString("reqID"))
	a.streamArtifactPart(c, name, file)
}

func (a *APIServer) handleStreamDefaultArtifact(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("default artifact requested", "build", name, "reqID", c.GetString("reqID"))
	a.streamDefaultArtifact(c, name)
}

func (a *APIServer) handleStreamArtifactByFilename(c *gin.Context) {
	name := c.Param("name")
	filename := c.Param("filename")
	a.log.Info("artifact by filename requested", "build", name, "filename", filename, "reqID", c.GetString("reqID"))
	a.streamArtifactByFilename(c, name, filename)
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

func (a *APIServer) streamLogs(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Parse optional 'since' parameter to prevent log replay on reconnect
	sinceTime := parseSinceTime(c.Query("since"))

	// Limit maximum streaming duration
	streamDuration := time.Duration(a.limits.MaxLogStreamDurationMinutes) * time.Minute
	ctx, cancel := context.WithTimeout(c.Request.Context(), streamDuration)
	defer cancel()
	var podName string

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

	// Get REST config and create Kubernetes clientset
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

	// Set up streaming response with anti-buffering headers
	c.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	c.Writer.Header().Set("Transfer-Encoding", "chunked")
	c.Writer.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no") // nginx
	c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
	c.Writer.Header().Set("Pragma", "no-cache") // HTTP/1.0 compat

	c.Writer.WriteHeader(http.StatusOK)
	_, _ = c.Writer.Write([]byte("Waiting for logs...\n"))
	c.Writer.Flush()

	pipelineRunSelector := "tekton.dev/pipelineRun=" + tr + ",tekton.dev/memberOf=tasks"

	var hadStream bool
	// Track streamed containers per pod: map[podName]map[containerName]bool
	streamedContainers := make(map[string]map[string]bool)
	// Track completed pods
	completedPods := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// List all pods for this PipelineRun
		pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: pipelineRunSelector})
		if err != nil {
			fmt.Fprintf(c.Writer, "\n[Error listing pods: %v]\n", err)
			c.Writer.Flush()
			time.Sleep(2 * time.Second)
			continue
		}

		if len(pods.Items) == 0 {
			// No pods yet, keep waiting
			if !hadStream {
				_, _ = c.Writer.Write([]byte("."))
				c.Writer.Flush()
			}
			time.Sleep(2 * time.Second)
			continue
		}

		// Process each pod
		allPodsComplete := true
		for _, pod := range pods.Items {
			podName = pod.Name

			// Skip already completed pods
			if completedPods[podName] {
				continue
			}

			// Initialize container tracking for this pod
			if streamedContainers[podName] == nil {
				streamedContainers[podName] = make(map[string]bool)
			}

			// Get step containers
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

			// Stream logs from each container
			for _, cName := range stepNames {
				if streamedContainers[podName][cName] {
					continue
				}

				req := cs.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{Container: cName, Follow: true, SinceTime: sinceTime})
				stream, err := req.Stream(ctx)
				if err != nil {
					// Container might not be ready yet
					continue
				}

				if !hadStream {
					c.Writer.Flush()
				}
				hadStream = true

				// Show which task/step we're streaming from
				taskName := pod.Labels["tekton.dev/pipelineTask"]
				if taskName == "" {
					taskName = podName
				}
				_, _ = c.Writer.Write([]byte("\n===== Logs from " + taskName + "/" + strings.TrimPrefix(cName, "step-") + " =====\n\n"))
				c.Writer.Flush()

				// Stream line-by-line for real-time output
				func() {
					defer stream.Close()
					scanner := bufio.NewScanner(stream)
					// Increase max line size to handle long log lines
					scanner.Buffer(make([]byte, 64*1024), 1024*1024)
					for scanner.Scan() {
						select {
						case <-ctx.Done():
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
				}()

				streamedContainers[podName][cName] = true
			}

			// Check if this pod is complete
			if len(streamedContainers[podName]) == len(stepNames) &&
				(pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed) {
				completedPods[podName] = true
			} else {
				allPodsComplete = false
			}
		}

		// Check if build is complete by looking at ImageBuild status
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, ib); err == nil {
			if ib.Status.Phase == "Completed" || ib.Status.Phase == "Failed" {
				// Build is done, stop streaming
				break
			}
		}

		// Don't break based on pod completion - rely on ImageBuild status.
		// There can be gaps between tasks where new pods haven't started yet.
		// Only sleep if we haven't streamed anything yet (waiting for first pod)
		if !hadStream || allPodsComplete {
			time.Sleep(2 * time.Second)
		}
		if !hadStream {
			_, _ = c.Writer.Write([]byte("."))
			if f, ok := c.Writer.(http.Flusher); ok {
				f.Flush()
			}
		}
	}

	if !hadStream {
		_, _ = c.Writer.Write([]byte("\n[No logs available]\n"))
	} else {
		_, _ = c.Writer.Write([]byte("\n[Log streaming completed]\n"))
	}
	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}
}

func createRegistrySecret(ctx context.Context, k8sClient client.Client, namespace, buildName string, creds *RegistryCredentials) (string, error) {
	if creds == nil || !creds.Enabled {
		return "", nil
	}

	secretName := fmt.Sprintf("%s-registry-auth", buildName)
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
func createPushSecret(ctx context.Context, k8sClient client.Client, namespace, buildName string, creds *RegistryCredentials) (string, error) {
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

func (a *APIServer) createBuild(c *gin.Context) {
	var req BuildRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}

	needsUpload := strings.Contains(req.Manifest, "source_path")

	// Validate build name
	if err := validateBuildName(req.Name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validate manifest size
	if int64(len(req.Manifest)) > a.limits.MaxManifestSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("manifest too large (max %d bytes)", a.limits.MaxManifestSize)})
		return
	}

	// Validate mode-specific requirements
	if req.Mode == ModeDisk {
		if req.ContainerRef == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "container-ref is required for disk mode"})
			return
		}
		if err := validateContainerRef(req.ContainerRef); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	} else if req.Manifest == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "manifest is required"})
		return
	}

	// Validate optional container references
	for field, value := range map[string]string{"container-push": req.ContainerPush, "export-oci": req.ExportOCI} {
		if err := validateContainerRef(value); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid %s: %v", field, err)})
			return
		}
	}

	if req.Distro == "" {
		req.Distro = "cs9"
	}
	if req.Target == "" {
		req.Target = "qemu"
	}
	if req.Architecture == "" {
		req.Architecture = "arm64"
	}
	if req.ExportFormat == "" {
		req.ExportFormat = "image"
	}
	if req.Mode == "" {
		req.Mode = ModeBootc
	}

	if strings.TrimSpace(req.Compression) == "" {
		req.Compression = "gzip"
	}
	if req.Compression != "lz4" && req.Compression != "gzip" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid compression: must be lz4 or gzip"})
		return
	}

	if !req.Distro.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "distro cannot be empty"})
		return
	}
	if !req.Target.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target cannot be empty"})
		return
	}
	if !req.Architecture.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "architecture cannot be empty"})
		return
	}
	if !req.ExportFormat.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exportFormat cannot be empty"})
		return
	}
	if !req.Mode.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "mode cannot be empty"})
		return
	}
	if req.AutomotiveImageBuilder == "" {
		req.AutomotiveImageBuilder = "quay.io/centos-sig-automotive/automotive-image-builder:1.0.0"
	}
	if req.ManifestFileName == "" {
		req.ManifestFileName = "manifest.aib.yml"
	}

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	ctx := c.Request.Context()
	namespace := resolveNamespace()

	requestedBy := resolveRequester(c)

	existing := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: req.Name, Namespace: namespace}, existing); err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("ImageBuild %s already exists", req.Name)})
		return
	} else if !k8serrors.IsNotFound(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error checking existing build: %v", err)})
		return
	}

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
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error creating manifest ConfigMap: %v", err)})
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

	serveExpiryHours := int32(24)
	{
		operatorConfig := &automotivev1alpha1.OperatorConfig{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: "config", Namespace: namespace}, operatorConfig); err == nil {
			if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.ServeExpiryHours > 0 {
				serveExpiryHours = operatorConfig.Spec.OSBuilds.ServeExpiryHours
			}
		}
	}

	var envSecretRef string
	if req.RegistryCredentials != nil && req.RegistryCredentials.Enabled {
		secretName, err := createRegistrySecret(ctx, k8sClient, namespace, req.Name, req.RegistryCredentials)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error creating registry secret: %v", err)})
			return
		}
		envSecretRef = secretName
	}

	// Handle push configuration
	var publishers *automotivev1alpha1.Publishers
	var pushSecretName string
	if req.PushRepository != "" {
		if req.RegistryCredentials == nil || !req.RegistryCredentials.Enabled {
			c.JSON(http.StatusBadRequest, gin.H{"error": "registry credentials are required when push repository is specified"})
			return
		}
		var err error
		pushSecretName, err = createPushSecret(ctx, k8sClient, namespace, req.Name, req.RegistryCredentials)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error creating push secret: %v", err)})
			return
		}
		publishers = &automotivev1alpha1.Publishers{
			Registry: &automotivev1alpha1.RegistryPublisher{
				RepositoryURL: req.PushRepository,
				Secret:        pushSecretName,
			},
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
			Distro:                 string(req.Distro),
			Target:                 string(req.Target),
			Architecture:           string(req.Architecture),
			ExportFormat:           string(req.ExportFormat),
			Mode:                   string(req.Mode),
			AutomotiveImageBuilder: req.AutomotiveImageBuilder,
			StorageClass:           req.StorageClass,
			ServeArtifact:          req.ServeArtifact,
			ExposeRoute:            req.ServeArtifact,
			ServeExpiryHours:       serveExpiryHours,
			ManifestConfigMap:      cfgName,
			InputFilesServer:       needsUpload,
			EnvSecretRef:           envSecretRef,
			Compression:            req.Compression,
			Publishers:             publishers,
			ContainerPush:          req.ContainerPush,
			BuildDiskImage:         req.BuildDiskImage,
			ExportOCI:              req.ExportOCI,
			BuilderImage:           req.BuilderImage,
			ContainerRef:           req.ContainerRef,
		},
	}
	if err := k8sClient.Create(ctx, imageBuild); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error creating ImageBuild: %v", err)})
		return
	}

	// Set owner references for cascading deletion
	if err := setConfigMapOwnerRef(ctx, k8sClient, namespace, cfgName, imageBuild); err != nil {
		log.Printf("WARNING: failed to set owner reference on ConfigMap %s: %v (cleanup may require manual intervention)", cfgName, err)
	}

	if envSecretRef != "" {
		if err := setSecretOwnerRef(ctx, k8sClient, namespace, envSecretRef, imageBuild); err != nil {
			log.Printf("WARNING: failed to set owner reference on registry secret %s: %v (cleanup may require manual intervention)", envSecretRef, err)
		}
	}

	if pushSecretName != "" {
		if err := setSecretOwnerRef(ctx, k8sClient, namespace, pushSecretName, imageBuild); err != nil {
			log.Printf("WARNING: failed to set owner reference on push secret %s: %v (cleanup may require manual intervention)", pushSecretName, err)
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

	resp := make([]BuildListItem, 0, len(list.Items))
	for _, b := range list.Items {
		var startStr, compStr string
		if b.Status.StartTime != nil {
			startStr = b.Status.StartTime.Time.Format(time.RFC3339)
		}
		if b.Status.CompletionTime != nil {
			compStr = b.Status.CompletionTime.Time.Format(time.RFC3339)
		}
		resp = append(resp, BuildListItem{
			Name:           b.Name,
			Phase:          b.Status.Phase,
			Message:        b.Status.Message,
			RequestedBy:    b.Annotations["automotive.sdv.cloud.redhat.com/requested-by"],
			CreatedAt:      b.CreationTimestamp.Time.Format(time.RFC3339),
			StartTime:      startStr,
			CompletionTime: compStr,
		})
	}
	writeJSON(c, http.StatusOK, resp)
}

func getBuild(c *gin.Context, name string) {
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

	writeJSON(c, http.StatusOK, BuildResponse{
		Name:             build.Name,
		Phase:            build.Status.Phase,
		Message:          build.Status.Message,
		RequestedBy:      build.Annotations["automotive.sdv.cloud.redhat.com/requested-by"],
		ArtifactURL:      build.Status.ArtifactURL,
		ArtifactFileName: strings.TrimSpace(build.Status.ArtifactFileName),
		StartTime: func() string {
			if build.Status.StartTime != nil {
				return build.Status.StartTime.Time.Format(time.RFC3339)
			}
			return ""
		}(),
		CompletionTime: func() string {
			if build.Status.CompletionTime != nil {
				return build.Status.CompletionTime.Time.Format(time.RFC3339)
			}
			return ""
		}(),
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
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: build.Spec.ManifestConfigMap, Namespace: namespace}, cm); err != nil {
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
			Distro:                 Distro(build.Spec.Distro),
			Target:                 Target(build.Spec.Target),
			Architecture:           Architecture(build.Spec.Architecture),
			ExportFormat:           ExportFormat(build.Spec.ExportFormat),
			Mode:                   Mode(build.Spec.Mode),
			AutomotiveImageBuilder: build.Spec.AutomotiveImageBuilder,
			CustomDefs:             nil,
			AIBExtraArgs:           aibExtra,
			ServeArtifact:          build.Spec.ServeArtifact,
			Compression:            build.Spec.Compression,
		},
		SourceFiles: sourceFiles,
	})
}

func (a *APIServer) uploadFiles(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}
	build := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(c.Request.Context(), types.NamespacedName{Name: name, Namespace: namespace}, build); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching build: %v", err)})
		return
	}

	// Find upload pod
	podList := &corev1.PodList{}
	if err := k8sClient.List(c.Request.Context(), podList,
		client.InNamespace(namespace),
		client.MatchingLabels{
			"automotive.sdv.cloud.redhat.com/imagebuild-name": name,
			"app.kubernetes.io/name":                          "upload-pod",
		},
	); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error listing upload pods: %v", err)})
		return
	}
	var uploadPod *corev1.Pod
	for i := range podList.Items {
		p := &podList.Items[i]
		if p.Status.Phase == corev1.PodRunning {
			uploadPod = p
			break
		}
	}
	if uploadPod == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upload pod not ready"})
		return
	}

	if c.Request.ContentLength > a.limits.MaxTotalUploadSize {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("upload too large (max %d bytes)", a.limits.MaxTotalUploadSize)})
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

	var totalBytesUploaded int64
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("read part: %v", err)})
			return
		}
		if part.FormName() != "file" {
			continue
		}
		dest := strings.TrimSpace(part.FileName())
		if dest == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "missing destination filename"})
			return
		}

		cleanDest := path.Clean(dest)
		if strings.HasPrefix(cleanDest, "..") || strings.HasPrefix(cleanDest, "/") {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid destination path: %s", dest)})
			return
		}

		tmp, err := os.CreateTemp("", "upload-*")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		tmpName := tmp.Name()
		defer tmp.Close()
		defer func() {
			_ = os.Remove(tmpName)
		}()

		limitedReader := io.LimitReader(part, a.limits.MaxUploadFileSize+1)
		n, err := io.Copy(tmp, limitedReader)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if n > a.limits.MaxUploadFileSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("file %s exceeds maximum size (%d bytes)", dest, a.limits.MaxUploadFileSize)})
			return
		}

		totalBytesUploaded += n
		if totalBytesUploaded > a.limits.MaxTotalUploadSize {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("total upload size exceeds maximum (%d bytes)", a.limits.MaxTotalUploadSize)})
			return
		}

		if err := copyFileToPod(restCfg, namespace, uploadPod.Name, uploadPod.Spec.Containers[0].Name, tmpName, "/workspace/shared/"+cleanDest); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("stream to pod failed: %v", err)})
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

func (a *APIServer) listArtifacts(c *gin.Context, name string) {
	namespace := resolveNamespace()
	ctx := c.Request.Context()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	build := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, build); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching build: %v", err)})
		return
	}

	if build.Status.Phase != "Completed" {
		c.JSON(http.StatusConflict, gin.H{"error": "artifact not available until build completes"})
		return
	}

	artifactFileName := strings.TrimSpace(build.Status.ArtifactFileName)
	if artifactFileName == "" {
		var ext string
		switch build.Spec.ExportFormat {
		case "image":
			ext = ".raw"
		case "qcow2":
			ext = ".qcow2"
		default:
			ext = "." + build.Spec.ExportFormat
		}
		artifactFileName = fmt.Sprintf("%s-%s%s", build.Spec.Distro, build.Spec.Target, ext)
	}

	artifactPod, err := findReadyArtifactPod(ctx, k8sClient, namespace, name, time.Now().Add(2*time.Minute))
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("rest config: %v", err)})
		return
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("clientset: %v", err)})
		return
	}

	partsDir := "/workspace/shared/" + artifactFileName + "-parts"
	listReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(artifactPod.Name).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "fileserver",
			Command:   []string{"sh", "-c", "set -e; dir=\"" + partsDir + "\"; if [ ! -d \"$dir\" ]; then echo MISSING; exit 0; fi; for f in \"$dir\"/*; do [ -f \"$f\" ] || continue; n=$(basename \"$f\"); s=$(wc -c < \"$f\"); printf '%s:%s\\n' \"$n\" \"$s\"; done"},
			Stdout:    true,
			Stderr:    true,
		}, kscheme.ParameterCodec)
	listExec, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, listReq.URL())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("executor (list): %v", err)})
		return
	}
	var out strings.Builder
	if err := listExec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &out, Stderr: io.Discard}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("list stream: %v", err)})
		return
	}
	trim := strings.TrimSpace(out.String())
	if trim == "" || trim == "MISSING" {
		// No parts available
		writeJSON(c, http.StatusOK, map[string]any{"items": []any{}})
		return
	}
	lines := strings.Split(trim, "\n")
	type item struct {
		Name      string `json:"name"`
		SizeBytes string `json:"sizeBytes"`
	}
	items := make([]item, 0, len(lines))
	for _, ln := range lines {
		p := strings.SplitN(strings.TrimSpace(ln), ":", 2)
		if len(p) != 2 {
			continue
		}
		items = append(items, item{Name: p[0], SizeBytes: strings.TrimSpace(p[1])})
	}
	writeJSON(c, http.StatusOK, map[string]any{"items": items})
}

func (a *APIServer) streamArtifactPart(c *gin.Context, name, file string) {
	namespace := resolveNamespace()
	ctx := c.Request.Context()

	if strings.Contains(file, "/") || strings.Contains(file, "..") || strings.TrimSpace(file) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
		return
	}

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	build := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, build); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching build: %v", err)})
		return
	}

	if build.Status.Phase != "Completed" {
		c.JSON(http.StatusConflict, gin.H{"error": "artifact not available until build completes"})
		return
	}

	artifactFileName := strings.TrimSpace(build.Status.ArtifactFileName)
	if artifactFileName == "" {
		var ext string
		switch build.Spec.ExportFormat {
		case "image":
			ext = ".raw"
		case "qcow2":
			ext = ".qcow2"
		default:
			ext = "." + build.Spec.ExportFormat
		}
		artifactFileName = fmt.Sprintf("%s-%s%s", build.Spec.Distro, build.Spec.Target, ext)
	}

	artifactPod, err := findReadyArtifactPod(ctx, k8sClient, namespace, name, time.Now().Add(2*time.Minute))
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("rest config: %v", err)})
		return
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("clientset: %v", err)})
		return
	}

	gzPath := "/workspace/shared/" + artifactFileName + "-parts/" + file
	// Check existence and size
	sizeReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(artifactPod.Name).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "fileserver",
			Command:   []string{"sh", "-c", "if [ -f \"" + gzPath + "\" ]; then wc -c < \"" + gzPath + "\"; else echo MISSING; fi"},
			Stdout:    true,
			Stderr:    true,
		}, kscheme.ParameterCodec)
	sizeExec, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, sizeReq.URL())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("executor (size): %v", err)})
		return
	}
	var sizeStdout strings.Builder
	if err := sizeExec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &sizeStdout, Stderr: io.Discard}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("size stream: %v", err)})
		return
	}
	sz := strings.TrimSpace(sizeStdout.String())
	if sz == "" || sz == "MISSING" {
		c.JSON(http.StatusNotFound, gin.H{"error": "artifact item not found"})
		return
	}

	streamReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(artifactPod.Name).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "fileserver",
			Command:   []string{"cat", gzPath},
			Stdout:    true,
			Stderr:    true,
		}, kscheme.ParameterCodec)
	streamExec, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, streamReq.URL())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("executor (stream): %v", err)})
		return
	}

	c.Writer.Header().Set("Content-Type", "application/gzip")
	c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", file))
	c.Writer.Header().Set("Content-Length", sz)
	c.Writer.Header().Set("X-AIB-Artifact-Type", "file")
	c.Writer.Header().Set("X-AIB-Compression", "gzip")
	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}

	_ = streamExec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: c.Writer, Stderr: io.Discard})
}

func (a *APIServer) streamDefaultArtifact(c *gin.Context, name string) {
	namespace := resolveNamespace()
	ctx := c.Request.Context()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	build := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, build); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching build: %v", err)})
		return
	}

	if build.Status.Phase != "Completed" {
		c.JSON(http.StatusConflict, gin.H{"error": "artifact not available until build completes"})
		return
	}

	artifactFileName := strings.TrimSpace(build.Status.ArtifactFileName)
	if artifactFileName == "" {
		var ext string
		switch build.Spec.ExportFormat {
		case "image":
			ext = ".raw"
		case "qcow2":
			ext = ".qcow2"
		default:
			ext = "." + build.Spec.ExportFormat
		}
		artifactFileName = fmt.Sprintf("%s-%s%s", build.Spec.Distro, build.Spec.Target, ext)
	}

	var compressionExt string
	if build.Spec.Compression != "" {
		switch build.Spec.Compression {
		case "gzip":
			compressionExt = ".gz"
		case "lz4":
			compressionExt = ".lz4"
		}
	}

	if compressionExt != "" && !strings.HasSuffix(artifactFileName, compressionExt) {
		artifactFileName = artifactFileName + compressionExt
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("rest config: %v", err)})
		return
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("clientset: %v", err)})
		return
	}

	artifactPod, err := findReadyArtifactPod(ctx, k8sClient, namespace, name, time.Now().Add(2*time.Minute))
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	podPath := "/workspace/shared/" + artifactFileName
	a.log.Info("checking artifact file existence", "build", name, "artifactFileName", artifactFileName, "podPath", podPath, "podName", artifactPod.Name)

	// Check if file exists and get size
	sizeReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(artifactPod.Name).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "fileserver",
			Command:   []string{"sh", "-c", "if [ -f '" + podPath + "' ]; then wc -c < '" + podPath + "'; else echo MISSING; fi"},
			Stdout:    true,
			Stderr:    true,
		}, kscheme.ParameterCodec)

	sizeExec, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, sizeReq.URL())
	if err != nil {
		a.log.Error(err, "failed to create executor", "build", name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("executor (size): %v", err)})
		return
	}

	var sizeStdout strings.Builder
	if err := sizeExec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &sizeStdout, Stderr: io.Discard}); err != nil {
		a.log.Error(err, "size stream failed", "build", name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("size stream: %v", err)})
		return
	}

	sz := strings.TrimSpace(sizeStdout.String())
	a.log.Info("file size check result", "build", name, "result", sz, "artifactFileName", artifactFileName)
	if sz == "" || sz == "MISSING" {
		a.log.Info("file not found in artifact pod", "build", name, "artifactFileName", artifactFileName, "podPath", podPath)
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	// Determine artifact type from filename
	artifactType := "file"
	if strings.Contains(artifactFileName, ".tar") {
		artifactType = "directory"
	}

	// Set appropriate content type based on file extension
	var contentType string
	if strings.HasSuffix(strings.ToLower(artifactFileName), ".lz4") {
		contentType = "application/x-lz4"
	} else if strings.Contains(strings.ToLower(artifactFileName), ".tar.") {
		if strings.HasSuffix(strings.ToLower(artifactFileName), ".gz") {
			contentType = "application/gzip"
		} else {
			contentType = "application/x-lz4"
		}
	} else if strings.HasSuffix(strings.ToLower(artifactFileName), ".gz") {
		contentType = "application/gzip"
	} else {
		contentType = "application/octet-stream"
	}

	// Set response headers
	c.Writer.Header().Set("Content-Type", contentType)
	c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", artifactFileName))
	c.Writer.Header().Set("Content-Length", sz)
	c.Writer.Header().Set("X-AIB-Artifact-Type", artifactType)
	if build.Spec.Compression != "" {
		c.Writer.Header().Set("X-AIB-Compression", build.Spec.Compression)
	}

	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}

	// Stream the file content
	streamReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(artifactPod.Name).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "fileserver",
			Command:   []string{"cat", podPath},
			Stdout:    true,
			Stderr:    true,
		}, kscheme.ParameterCodec)

	streamExec, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, streamReq.URL())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("executor (stream): %v", err)})
		return
	}

	_ = streamExec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: c.Writer, Stderr: io.Discard})
}

// streamArtifactByFilename streams the specified artifact file from the artifact pod to the client over HTTP
func (a *APIServer) streamArtifactByFilename(c *gin.Context, name, filename string) {
	namespace := resolveNamespace()
	ctx := c.Request.Context()

	if strings.Contains(filename, "/") || strings.Contains(filename, "..") || strings.TrimSpace(filename) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
		return
	}

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("k8s client error: %v", err)})
		return
	}

	build := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, build); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("error fetching build: %v", err)})
		return
	}

	if build.Status.Phase != "Completed" {
		c.JSON(http.StatusConflict, gin.H{"error": "artifact not available until build completes"})
		return
	}

	// Only allow the exact final artifact file name or files from the -parts directory
	expected := strings.TrimSpace(build.Status.ArtifactFileName)
	base := path.Base(filename)
	allowed := base == expected

	if !allowed {
		// Check if it's a part file (from -parts directory)
		if strings.HasSuffix(base, ".gz") || strings.HasSuffix(base, ".lz4") {
			// Allow parts that follow the pattern: <expected>-parts/<filename>
			if strings.Contains(base, ".tar.") || strings.HasPrefix(base, strings.TrimSuffix(expected, path.Ext(expected))) {
				allowed = true
			}
		}
	}

	if !allowed {
		c.JSON(http.StatusForbidden, gin.H{"error": "file not allowed"})
		return
	}

	// Get REST config and clientset for pod operations
	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("rest config: %v", err)})
		return
	}
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("clientset: %v", err)})
		return
	}

	artifactPod, err := findReadyArtifactPod(ctx, k8sClient, namespace, name, time.Now().Add(2*time.Minute))
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	podPath := "/workspace/shared/" + base

	// Check if file exists and get size
	sizeReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(artifactPod.Name).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "fileserver",
			Command:   []string{"sh", "-c", "if [ -f '" + podPath + "' ]; then wc -c < '" + podPath + "'; else echo MISSING; fi"},
			Stdout:    true,
			Stderr:    true,
		}, kscheme.ParameterCodec)

	sizeExec, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, sizeReq.URL())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("executor (size): %v", err)})
		return
	}

	var sizeStdout strings.Builder
	if err := sizeExec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &sizeStdout, Stderr: io.Discard}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("size stream: %v", err)})
		return
	}

	sz := strings.TrimSpace(sizeStdout.String())
	if sz == "" || sz == "MISSING" {
		c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
		return
	}

	if strings.HasSuffix(strings.ToLower(base), ".lz4") {
		c.Writer.Header().Set("Content-Type", "application/x-lz4")
	} else if strings.Contains(strings.ToLower(base), ".tar.") {
		if strings.HasSuffix(strings.ToLower(base), ".gz") {
			c.Writer.Header().Set("Content-Type", "application/gzip")
		} else {
			c.Writer.Header().Set("Content-Type", "application/x-lz4")
		}
	} else if strings.HasSuffix(strings.ToLower(base), ".gz") {
		c.Writer.Header().Set("Content-Type", "application/gzip")
	} else {
		c.Writer.Header().Set("Content-Type", "application/octet-stream")
	}

	c.Writer.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", base))
	c.Writer.Header().Set("Content-Length", sz)

	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}

	// Stream the file content
	streamReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(artifactPod.Name).
		Namespace(namespace).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "fileserver",
			Command:   []string{"cat", podPath},
			Stdout:    true,
			Stderr:    true,
		}, kscheme.ParameterCodec)

	streamExec, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, streamReq.URL())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("executor (stream): %v", err)})
		return
	}

	_ = streamExec.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: c.Writer, Stderr: io.Discard})
}

func copyFileToPod(config *rest.Config, namespace, podName, containerName, localPath, podPath string) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}

	pr, pw := io.Pipe()
	go func() {
		tw := tar.NewWriter(pw)
		defer func() { tw.Close(); pw.Close() }()
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
	cmd := []string{"/bin/sh", "-c", fmt.Sprintf("mkdir -p %s && tar -x -C %s", destDir, destDir)}

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
	return executor.StreamWithContext(context.Background(), remotecommand.StreamOptions{Stdin: pr, Stdout: io.Discard, Stderr: io.Discard})
}

func setConfigMapOwnerRef(ctx context.Context, c client.Client, namespace, configMapName string, owner *automotivev1alpha1.ImageBuild) error {
	cm := &corev1.ConfigMap{}
	if err := c.Get(ctx, types.NamespacedName{Name: configMapName, Namespace: namespace}, cm); err != nil {
		return err
	}
	cm.OwnerReferences = []metav1.OwnerReference{
		*metav1.NewControllerRef(owner, automotivev1alpha1.GroupVersion.WithKind("ImageBuild")),
	}
	return c.Update(ctx, cm)
}

func setSecretOwnerRef(ctx context.Context, c client.Client, namespace, secretName string, owner *automotivev1alpha1.ImageBuild) error {
	secret := &corev1.Secret{}
	if err := c.Get(ctx, types.NamespacedName{Name: secretName, Namespace: namespace}, secret); err != nil {
		return err
	}
	secret.OwnerReferences = []metav1.OwnerReference{
		*metav1.NewControllerRef(owner, automotivev1alpha1.GroupVersion.WithKind("ImageBuild")),
	}
	return c.Update(ctx, secret)
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

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, fmt.Errorf("failed to create k8s client: %w", err)
	}
	return k8sClient, nil
}

func (a *APIServer) isAuthenticated(c *gin.Context) bool {
	token := extractBearerToken(c)
	if token == "" {
		return false
	}

	cfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		return false
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return false
	}

	tr := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}}
	res, err := clientset.AuthenticationV1().TokenReviews().Create(c.Request.Context(), tr, metav1.CreateOptions{})
	return err == nil && res.Status.Authenticated
}

// extractBearerToken extracts the bearer token from the request
func extractBearerToken(c *gin.Context) string {
	authHeader := c.Request.Header.Get("Authorization")
	token, _ := strings.CutPrefix(authHeader, "Bearer ")
	if token == "" {
		token = c.Request.Header.Get("X-Forwarded-Access-Token")
	}
	return strings.TrimSpace(token)
}

// findReadyArtifactPod finds a running and ready artifact pod for the given ImageBuild
func findReadyArtifactPod(ctx context.Context, k8sClient client.Client, namespace, buildName string, deadline time.Time) (*corev1.Pod, error) {
	for {
		podList := &corev1.PodList{}
		if err := k8sClient.List(ctx, podList,
			client.InNamespace(namespace),
			client.MatchingLabels{
				"app.kubernetes.io/name":                          "artifact-pod",
				"automotive.sdv.cloud.redhat.com/imagebuild-name": buildName,
			}); err != nil {
			return nil, fmt.Errorf("error listing artifact pods: %w", err)
		}

		for i := range podList.Items {
			p := &podList.Items[i]
			if p.Status.Phase == corev1.PodRunning {
				for _, cs := range p.Status.ContainerStatuses {
					if cs.Name == "fileserver" && cs.Ready {
						return p, nil
					}
				}
			}
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("artifact pod not ready")
		}
		time.Sleep(2 * time.Second)
	}
}

func resolveRequester(c *gin.Context) string {
	token := extractBearerToken(c)
	if token == "" {
		return "unknown"
	}

	cfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		return "unknown"
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "unknown"
	}

	tr := &authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}}
	res, err := clientset.AuthenticationV1().TokenReviews().Create(c.Request.Context(), tr, metav1.CreateOptions{})
	if err != nil || !res.Status.Authenticated || res.Status.User.Username == "" {
		return "unknown"
	}

	return res.Status.User.Username
}
