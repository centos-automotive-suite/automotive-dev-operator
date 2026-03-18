package buildapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	workspaceContainerName = "toolchain"
)

// shellQuote returns s wrapped in POSIX single quotes with embedded single
// quotes escaped, safe for interpolation into a /bin/sh -c script.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// WorkspaceRequest is the payload to create a workspace.
type WorkspaceRequest struct {
	Name          string `json:"name"`
	FromBuild     string `json:"fromBuild,omitempty"` // ImageBuild name to extract lease from
	Lease         string `json:"lease,omitempty"`     // Direct lease ID
	Arch          string `json:"architecture,omitempty"`
	Image         string `json:"toolchainImage,omitempty"`
	ClientConfig  string `json:"clientConfig,omitempty"`  // Base64-encoded Jumpstarter client config
	CPU           string `json:"cpu,omitempty"`           // CPU request (e.g., "1", "500m")
	Memory        string `json:"memory,omitempty"`        // Memory request (e.g., "2Gi", "512Mi")
	TmpfsBuildDir bool   `json:"tmpfsBuildDir,omitempty"` // Mount tmpfs at /tmp/build for fast compilation
}

// WorkspaceResponse is returned by workspace operations.
type WorkspaceResponse struct {
	Name    string `json:"name"`
	Phase   string `json:"phase"`
	Lease   string `json:"lease,omitempty"`
	Arch    string `json:"architecture"`
	PodName string `json:"podName,omitempty"`
	Age     string `json:"age,omitempty"`
}

// WorkspaceExecRequest is the payload to execute a command in a workspace.
type WorkspaceExecRequest struct {
	Command string `json:"command"`
}

// WorkspaceDeployRequest is the payload to deploy an artifact to a board.
type WorkspaceDeployRequest struct {
	ArtifactPath string `json:"artifactPath"`       // Path inside workspace
	DestPath     string `json:"destPath"`           // Path on the board
	Password     string `json:"password,omitempty"` // SSH password for key injection (default: "password")
}

// registerWorkspaceRoutes registers the workspace API routes on the v1 group.
func (a *APIServer) registerWorkspaceRoutes(v1 *gin.RouterGroup) {
	workspaceGroup := v1.Group("/workspaces")
	workspaceGroup.Use(a.authMiddleware())
	{
		workspaceGroup.POST("", a.handleCreateWorkspace)
		workspaceGroup.GET("", a.handleListWorkspaces)
		workspaceGroup.GET("/:name", a.handleGetWorkspace)
		workspaceGroup.DELETE("/:name", a.handleDeleteWorkspace)
		workspaceGroup.POST("/:name/sync", a.handleSyncWorkspace)
		workspaceGroup.POST("/:name/exec", a.handleExecWorkspace)
		workspaceGroup.GET("/:name/shell", a.handleShellWorkspace)
		workspaceGroup.POST("/:name/deploy", a.handleDeployWorkspace)
	}
}

func (a *APIServer) handleCreateWorkspace(c *gin.Context) {
	a.log.Info("create workspace", "reqID", c.GetString("reqID"))
	a.createWorkspace(c)
}

func (a *APIServer) handleListWorkspaces(c *gin.Context) {
	a.log.Info("list workspaces", "reqID", c.GetString("reqID"))
	a.listWorkspaces(c)
}

func (a *APIServer) handleGetWorkspace(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("get workspace", "name", name, "reqID", c.GetString("reqID"))
	a.getWorkspace(c, name)
}

func (a *APIServer) handleDeleteWorkspace(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("delete workspace", "name", name, "reqID", c.GetString("reqID"))
	a.deleteWorkspace(c, name)
}

func (a *APIServer) handleSyncWorkspace(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("sync workspace", "name", name, "reqID", c.GetString("reqID"))
	a.syncWorkspace(c, name)
}

func (a *APIServer) handleExecWorkspace(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("exec workspace", "name", name, "reqID", c.GetString("reqID"))
	a.execWorkspace(c, name)
}

func (a *APIServer) handleShellWorkspace(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("shell workspace", "name", name, "reqID", c.GetString("reqID"))
	a.shellWorkspace(c, name)
}

func (a *APIServer) handleDeployWorkspace(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("deploy workspace", "name", name, "reqID", c.GetString("reqID"))
	a.deployWorkspace(c, name)
}

func (a *APIServer) createWorkspace(c *gin.Context) {
	var req WorkspaceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}

	if strings.TrimSpace(req.Name) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create kubernetes client"})
		return
	}

	namespace := resolveNamespace()
	requester := a.resolveRequester(c)

	// Load workspace configuration from OperatorConfig
	operatorConfig, _ := loadOperatorConfigFn(c.Request.Context(), k8sClient, namespace)
	var wsConfig *automotivev1alpha1.WorkspacesConfig
	if operatorConfig != nil {
		wsConfig = operatorConfig.Spec.Workspaces
	}

	arch := req.Arch
	if arch == "" {
		arch = wsConfig.GetDefaultArchitecture()
	}
	image := req.Image
	if image == "" {
		image = wsConfig.GetToolchainImage()
	}
	pvcSize := wsConfig.GetPVCSize()

	// Resolve lease from ImageBuild if --from-build was used
	leaseID := req.Lease
	if leaseID == "" && req.FromBuild != "" {
		leaseID, err = a.resolveLeaseFromBuild(c.Request.Context(), k8sClient, namespace, req.FromBuild, requester)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("failed to resolve lease from build %q: %v", req.FromBuild, err)})
			return
		}
	}

	// Create secret for Jumpstarter client config if provided
	var jmpClientSecret string
	if req.ClientConfig != "" {
		clientConfigBytes, decErr := base64.StdEncoding.DecodeString(req.ClientConfig)
		if decErr != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "clientConfig must be base64 encoded"})
			return
		}
		jmpClientSecret = req.Name + "-jumpstarter-client"
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      jmpClientSecret,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				"client.yaml": clientConfigBytes,
			},
		}
		if createErr := k8sClient.Create(c.Request.Context(), secret); createErr != nil && !k8serrors.IsAlreadyExists(createErr) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create client config secret: %v", createErr)})
			return
		}
	}

	// Check if workspace CR already exists
	existing := &automotivev1alpha1.Workspace{}
	err = k8sClient.Get(c.Request.Context(), client.ObjectKey{Namespace: namespace, Name: req.Name}, existing)
	if err == nil {
		if existing.DeletionTimestamp != nil {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("workspace %q is still terminating, try again shortly", req.Name)})
		} else {
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("workspace %q already exists", req.Name)})
		}
		return
	}
	if !k8serrors.IsNotFound(err) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check existing workspace"})
		return
	}

	// Validate tmpfs: only allowed if enabled in OperatorConfig
	if req.TmpfsBuildDir && !wsConfig.GetTmpfsBuildDir() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "--tmpfs requires workspaces.tmpfsBuildDir to be enabled in OperatorConfig"})
		return
	}

	// Build resource requirements: user-requested → OperatorConfig default → controller default
	resources, err := buildWorkspaceResources(req.CPU, req.Memory, wsConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Create Workspace CR — the controller will create Pod, PVC, etc.
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: namespace,
		},
		Spec: automotivev1alpha1.WorkspaceSpec{
			Architecture:          arch,
			Image:                 image,
			LeaseID:               leaseID,
			Owner:                 requester,
			ClientConfigSecretRef: jmpClientSecret,
			PVCSize:               pvcSize,
			Resources:             resources,
			StorageClass:          wsConfig.GetStorageClass(),
			NodeSelector:          wsConfig.GetNodeSelector(),
			TmpfsBuildDir:         req.TmpfsBuildDir,
		},
	}
	if err := k8sClient.Create(c.Request.Context(), ws); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create workspace: %v", err)})
		return
	}

	c.JSON(http.StatusCreated, workspaceResponseFromCR(ws))
}

func (a *APIServer) listWorkspaces(c *gin.Context) {
	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create kubernetes client"})
		return
	}

	namespace := resolveNamespace()
	requester := a.resolveRequester(c)

	wsList := &automotivev1alpha1.WorkspaceList{}
	if err := k8sClient.List(c.Request.Context(), wsList, &client.ListOptions{Namespace: namespace}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list workspaces"})
		return
	}

	workspaces := make([]WorkspaceResponse, 0, len(wsList.Items))
	for i := range wsList.Items {
		ws := &wsList.Items[i]
		if ws.Spec.Owner != requester {
			continue
		}
		workspaces = append(workspaces, workspaceResponseFromCR(ws))
	}

	c.JSON(http.StatusOK, workspaces)
}

func (a *APIServer) getWorkspace(c *gin.Context, name string) {
	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return // response already sent
	}
	c.JSON(http.StatusOK, workspaceResponseFromCR(ws))
}

func (a *APIServer) deleteWorkspace(c *gin.Context, name string) {
	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return // response already sent
	}

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create kubernetes client"})
		return
	}

	// Delete client config secret
	if ws.Spec.ClientConfigSecretRef != "" {
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: ws.Spec.ClientConfigSecretRef, Namespace: ws.Namespace}}
		if delErr := k8sClient.Delete(c.Request.Context(), secret); delErr != nil && !k8serrors.IsNotFound(delErr) {
			a.log.Error(delErr, "Failed to delete client config secret", "secret", ws.Spec.ClientConfigSecretRef)
		}
	}

	// Delete Workspace CR
	if err := k8sClient.Delete(c.Request.Context(), ws); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to delete workspace: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("workspace %q deleted", name)})
}

func (a *APIServer) getOwnedWorkspace(c *gin.Context, name string) (*automotivev1alpha1.Workspace, error) {
	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create kubernetes client"})
		return nil, err
	}

	namespace := resolveNamespace()
	requester := a.resolveRequester(c)

	ws := &automotivev1alpha1.Workspace{}
	if err := k8sClient.Get(c.Request.Context(), client.ObjectKey{Namespace: namespace, Name: name}, ws); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("workspace %q not found", name)})
			return nil, err
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get workspace"})
		return nil, err
	}

	if ws.Spec.Owner != requester {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("workspace %q not found", name)})
		return nil, fmt.Errorf("workspace %q not owned by %q", name, requester)
	}

	return ws, nil
}

func (a *APIServer) syncWorkspace(c *gin.Context, name string) {
	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return
	}
	if ws.Status.Phase != phaseRunning {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("workspace %q is not running (phase: %s)", name, ws.Status.Phase)})
		return
	}

	namespace := ws.Namespace
	podName := ws.Status.PodName

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes config"})
		return
	}

	// Buffer the tar stream so that EOF propagates cleanly to the SPDY executor.
	tarData, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to read upload: %v", err)})
		return
	}

	if err := copyToPod(c.Request.Context(), restCfg, namespace, podName, workspaceContainerName, bytes.NewReader(tarData), "/workspace/src/"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to sync files: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "files synced"})
}

func (a *APIServer) execWorkspace(c *gin.Context, name string) {
	var req WorkspaceExecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}

	if strings.TrimSpace(req.Command) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "command is required"})
		return
	}

	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return
	}
	if ws.Status.Phase != phaseRunning {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("workspace %q is not running (phase: %s)", name, ws.Status.Phase)})
		return
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes config"})
		return
	}

	setupLogStreamHeaders(c)

	cmd := []string{"/bin/sh", "-c", "cd /workspace/src && " + req.Command}
	if err := execInPod(c.Request.Context(), restCfg, ws.Namespace, ws.Status.PodName, workspaceContainerName, cmd, c.Writer); err != nil {
		_, _ = fmt.Fprintf(c.Writer, "\n[exec failed: %v]\n", err)
	}
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(_ *http.Request) bool { return true },
}

func (a *APIServer) shellWorkspace(c *gin.Context, name string) {
	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return
	}
	if ws.Status.Phase != phaseRunning {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("workspace %q is not running (phase: %s)", name, ws.Status.Phase)})
		return
	}

	namespace := ws.Namespace
	podName := ws.Status.PodName

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes config"})
		return
	}

	// Upgrade to WebSocket
	wsConn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		a.log.Error(err, "websocket upgrade failed", "workspace", name)
		return
	}
	defer func() { _ = wsConn.Close() }()

	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		_ = wsConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "failed to create kubernetes client"))
		return
	}

	execReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(podName).Namespace(namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: workspaceContainerName,
			Command:   []string{"/bin/sh"},
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       true,
		}, kscheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, execReq.URL())
	if err != nil {
		_ = wsConn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "failed to create executor"))
		return
	}

	// Bridge: WebSocket <-> pod exec
	stdinR, stdinW := io.Pipe()
	stdoutR, stdoutW := io.Pipe()

	// WS -> stdin pipe
	go func() {
		defer func() { _ = stdinW.Close() }()
		for {
			_, msg, rerr := wsConn.ReadMessage()
			if rerr != nil {
				return
			}
			if _, werr := stdinW.Write(msg); werr != nil {
				return
			}
		}
	}()

	// stdout pipe -> WS
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := stdoutR.Read(buf)
			if n > 0 {
				if werr := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	err = executor.StreamWithContext(c.Request.Context(), remotecommand.StreamOptions{
		Stdin:  stdinR,
		Stdout: stdoutW,
		Stderr: stdoutW,
		Tty:    true,
	})
	_ = stdoutW.Close()

	// Send a clean WebSocket close so the client doesn't see "unexpected EOF"
	closeMsg := "shell exited"
	closeCode := websocket.CloseNormalClosure
	if err != nil {
		a.log.Error(err, "shell session ended with error", "workspace", name)
		closeMsg = fmt.Sprintf("shell error: %v", err)
		closeCode = websocket.CloseInternalServerErr
	}
	_ = wsConn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(closeCode, closeMsg))
}

func (a *APIServer) deployWorkspace(c *gin.Context, name string) {
	var req WorkspaceDeployRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}

	if strings.TrimSpace(req.ArtifactPath) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "artifactPath is required"})
		return
	}
	if strings.TrimSpace(req.DestPath) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "destPath is required"})
		return
	}

	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return
	}
	if ws.Status.Phase != phaseRunning {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("workspace %q is not running (phase: %s)", name, ws.Status.Phase)})
		return
	}

	if ws.Spec.LeaseID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no Jumpstarter lease associated with this workspace"})
		return
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes config"})
		return
	}

	setupLogStreamHeaders(c)

	// Use jmp shell to get the board's TCP address, inject SSH key, then rsync.
	// timeout is needed because jmp shell may hang if the lease/board is unavailable.
	sshPassword := req.Password
	if sshPassword == "" {
		sshPassword = "password"
	}
	sshOpts := "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
	deployScript := fmt.Sprintf(
		`set -e
SSH_PASS=%s
ARTIFACT_PATH=%s
DEST_PATH=%s
echo "Resolving board address via Jumpstarter..."
ADDR=$(timeout 30 jmp shell -- j tcp address < /dev/null 2>&1 | grep -E ':[0-9]+$' | tail -1 | tr -d '[:space:]')
if [ -z "$ADDR" ]; then
  echo "ERROR: failed to get board TCP address from Jumpstarter" >&2
  exit 1
fi
HOST=${ADDR%%%%:*}
PORT=${ADDR#*:}
[ "$PORT" = "$HOST" ] && PORT=22
echo "Board address: $HOST:$PORT"
echo "Injecting SSH key..."
cat /workspace/.ssh/id_ed25519.pub | sshpass -p "$SSH_PASS" ssh -p $PORT %s root@$HOST 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys'
echo "Deploying artifact..."
rsync -e "ssh -p $PORT -i /workspace/.ssh/id_ed25519 %s" -avz "$ARTIFACT_PATH" root@$HOST:"$DEST_PATH"`,
		shellQuote(sshPassword), shellQuote(req.ArtifactPath), shellQuote(req.DestPath), sshOpts, sshOpts)
	cmd := []string{"/bin/sh", "-c", deployScript}
	if err := execInPod(c.Request.Context(), restCfg, ws.Namespace, ws.Status.PodName, workspaceContainerName, cmd, c.Writer); err != nil {
		_, _ = fmt.Fprintf(c.Writer, "\n[deploy failed: %v]\n", err)
	}
}

// buildWorkspaceResources constructs resource requirements from user input and config.
// If the user specifies CPU/memory, those values are used for both requests and limits.
// Values are validated against maxResources from the OperatorConfig if set.
// Returns nil (use controller defaults) when no user input and no config defaults.
func buildWorkspaceResources(cpu, memory string, wsConfig *automotivev1alpha1.WorkspacesConfig) (*corev1.ResourceRequirements, error) {
	if cpu == "" && memory == "" {
		// No user override — use OperatorConfig defaults (or nil for controller defaults)
		if wsConfig != nil && wsConfig.Resources != nil {
			return wsConfig.Resources, nil
		}
		return nil, nil
	}

	// Start from OperatorConfig defaults, then overlay user values
	res := &corev1.ResourceRequirements{
		Requests: corev1.ResourceList{},
		Limits:   corev1.ResourceList{},
	}
	if wsConfig != nil && wsConfig.Resources != nil {
		res = wsConfig.Resources.DeepCopy()
	}

	if cpu != "" {
		q, err := resource.ParseQuantity(cpu)
		if err != nil {
			return nil, fmt.Errorf("invalid --cpu value %q: %v", cpu, err)
		}
		if wsConfig != nil && wsConfig.MaxResources != nil {
			if maxCPU, ok := wsConfig.MaxResources.Limits[corev1.ResourceCPU]; ok && q.Cmp(maxCPU) > 0 {
				return nil, fmt.Errorf("requested CPU %s exceeds maximum %s", cpu, maxCPU.String())
			}
		}
		res.Requests[corev1.ResourceCPU] = q
		res.Limits[corev1.ResourceCPU] = q
	}

	if memory != "" {
		q, err := resource.ParseQuantity(memory)
		if err != nil {
			return nil, fmt.Errorf("invalid --memory value %q: %v", memory, err)
		}
		if wsConfig != nil && wsConfig.MaxResources != nil {
			if maxMem, ok := wsConfig.MaxResources.Limits[corev1.ResourceMemory]; ok && q.Cmp(maxMem) > 0 {
				return nil, fmt.Errorf("requested memory %s exceeds maximum %s", memory, maxMem.String())
			}
		}
		res.Requests[corev1.ResourceMemory] = q
		res.Limits[corev1.ResourceMemory] = q
	}

	return res, nil
}

func workspaceResponseFromCR(ws *automotivev1alpha1.Workspace) WorkspaceResponse {
	phase := ws.Status.Phase
	if phase == "" {
		phase = "Pending"
	}
	age := ""
	if !ws.CreationTimestamp.IsZero() {
		age = time.Since(ws.CreationTimestamp.Time).Truncate(time.Second).String()
	}
	return WorkspaceResponse{
		Name:    ws.Name,
		Phase:   phase,
		Lease:   ws.Spec.LeaseID,
		Arch:    ws.Spec.Architecture,
		PodName: ws.Status.PodName,
		Age:     age,
	}
}

// buildFlashInfo holds lease and client config extracted from an ImageBuild.
func (a *APIServer) resolveLeaseFromBuild(ctx context.Context, k8sClient client.Client, namespace, buildName, requester string) (string, error) {
	build := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, client.ObjectKey{Namespace: namespace, Name: buildName}, build); err != nil {
		return "", fmt.Errorf("ImageBuild %q not found: %w", buildName, err)
	}
	if owner := build.Annotations["automotive.sdv.cloud.redhat.com/requested-by"]; owner != requester {
		return "", fmt.Errorf("ImageBuild %q is owned by a different user", buildName)
	}
	if build.Status.LeaseID == "" {
		return "", fmt.Errorf("ImageBuild %q has no lease ID (was --flash used?)", buildName)
	}
	return build.Status.LeaseID, nil
}

func copyToPod(ctx context.Context, restCfg *rest.Config, namespace, podName, containerName string, body io.Reader, destDir string) error {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating clientset: %w", err)
	}

	cmd := []string{"/bin/sh", "-c", fmt.Sprintf("tar -xv -C %q", destDir)}
	execReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(podName).Namespace(namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   cmd,
			Stdin:     true,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, kscheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, execReq.URL())
	if err != nil {
		return fmt.Errorf("creating executor: %w", err)
	}

	var stdout, stderr bytes.Buffer
	streamOpts := remotecommand.StreamOptions{Stdin: body, Stdout: &stdout, Stderr: &stderr}
	if err := executor.StreamWithContext(ctx, streamOpts); err != nil {
		if stderr.Len() > 0 {
			return fmt.Errorf("%w: %s", err, stderr.String())
		}
		return err
	}
	return nil
}

// flushWriter wraps an http.ResponseWriter and flushes after every Write,
// ensuring streamed data reaches the client (and intermediate proxies like
// HAProxy) immediately instead of sitting in Go's response buffer.
type flushWriter struct {
	w       io.Writer
	flusher http.Flusher
}

func newFlushWriter(w http.ResponseWriter) *flushWriter {
	fw := &flushWriter{w: w}
	if f, ok := w.(http.Flusher); ok {
		fw.flusher = f
	}
	return fw
}

func (fw *flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if fw.flusher != nil {
		fw.flusher.Flush()
	}
	return n, err
}

// podExec runs a command in a pod, streaming stdout/stderr to the provided writer.
func podExec(ctx context.Context, restCfg *rest.Config, namespace, podName, containerName string, cmd []string, out io.Writer) error {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return fmt.Errorf("creating clientset: %w", err)
	}

	execReq := clientset.CoreV1().RESTClient().Post().
		Resource("pods").Name(podName).Namespace(namespace).SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: containerName,
			Command:   cmd,
			Stdin:     false,
			Stdout:    true,
			Stderr:    true,
			TTY:       false,
		}, kscheme.ParameterCodec)

	executor, err := remotecommand.NewSPDYExecutor(restCfg, http.MethodPost, execReq.URL())
	if err != nil {
		return fmt.Errorf("creating executor: %w", err)
	}

	return executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdout: out,
		Stderr: out,
	})
}

func execInPod(ctx context.Context, restCfg *rest.Config, namespace, podName, containerName string, cmd []string, w http.ResponseWriter) error {
	return podExec(ctx, restCfg, namespace, podName, containerName, cmd, newFlushWriter(w))
}
