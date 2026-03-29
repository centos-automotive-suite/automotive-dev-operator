package buildapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
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
	Name                    string `json:"name"`
	FromBuild               string `json:"fromBuild,omitempty"` // ImageBuild name to extract lease from
	Lease                   string `json:"lease,omitempty"`     // Direct lease ID
	Arch                    string `json:"architecture,omitempty"`
	Image                   string `json:"toolchainImage,omitempty"`
	ClientConfig            string `json:"clientConfig,omitempty"`            // Base64-encoded Jumpstarter client config
	CPU                     string `json:"cpu,omitempty"`                     // CPU request (e.g., "1", "500m")
	Memory                  string `json:"memory,omitempty"`                  // Memory request (e.g., "2Gi", "512Mi")
	TmpfsBuildDir           bool   `json:"tmpfsBuildDir,omitempty"`           // Mount tmpfs at /tmp/build for fast compilation
	AutoPauseTimeoutMinutes *int32 `json:"autoPauseTimeoutMinutes,omitempty"` // nil = use global default, 0 = disable
}

// WorkspaceResponse is returned by workspace operations.
type WorkspaceResponse struct {
	Name             string `json:"name"`
	Phase            string `json:"phase"`
	Lease            string `json:"lease,omitempty"`
	Arch             string `json:"architecture"`
	PodName          string `json:"podName,omitempty"`
	Age              string `json:"age,omitempty"`
	AutoPauseTimeout string `json:"autoPauseTimeout,omitempty"` // e.g., "30m", "disabled"
	LastActivity     string `json:"lastActivity,omitempty"`     // e.g., "2m ago", "just now"
}

// WorkspaceExecRequest is the payload to execute a command in a workspace.
type WorkspaceExecRequest struct {
	Command string `json:"command"`
}

// SyncPlanRequest is the manifest sent by the client to compute a sync diff.
type SyncPlanRequest struct {
	Files map[string]string `json:"files"` // relative path -> hex-encoded sha256
}

// SyncPlanResponse tells the client which files need uploading.
type SyncPlanResponse struct {
	Changed   []string `json:"changed"`   // files to upload (new or modified)
	Unchanged int      `json:"unchanged"` // count of files already up to date
}

// ArtifactMapping maps a source path inside the workspace to a destination on the board.
type ArtifactMapping struct {
	Src  string `json:"src"`  // Path inside workspace (file or directory)
	Dest string `json:"dest"` // Path on the board
}

// WorkspaceDeployRequest is the payload to deploy artifacts to a board.
type WorkspaceDeployRequest struct {
	Artifacts []ArtifactMapping `json:"artifacts"`
	Password  string            `json:"password,omitempty"` // SSH password for key injection (default: "password")
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
		workspaceGroup.POST("/:name/start", a.handleStartWorkspace)
		workspaceGroup.POST("/:name/stop", a.handleStopWorkspace)
		workspaceGroup.POST("/:name/sync", a.handleSyncWorkspace)
		workspaceGroup.POST("/:name/sync/plan", a.handleSyncPlanWorkspace)
		workspaceGroup.POST("/:name/exec", a.handleExecWorkspace)
		workspaceGroup.GET("/:name/shell", a.handleShellWorkspace)
		workspaceGroup.POST("/:name/deploy", a.handleDeployWorkspace)
		workspaceGroup.PUT("/:name/lease", a.handleSetWorkspaceLease)
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

func (a *APIServer) handleSyncPlanWorkspace(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("sync plan workspace", "name", name, "reqID", c.GetString("reqID"))
	a.syncPlanWorkspace(c, name)
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

func (a *APIServer) handleStartWorkspace(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("start workspace", "name", name, "reqID", c.GetString("reqID"))
	a.setWorkspaceStopped(c, name, false)
}

func (a *APIServer) handleStopWorkspace(c *gin.Context) {
	name := c.Param("name")
	a.log.Info("stop workspace", "name", name, "reqID", c.GetString("reqID"))
	a.setWorkspaceStopped(c, name, true)
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
	operatorConfig, cfgErr := loadOperatorConfigFn(c.Request.Context(), k8sClient, namespace)
	if cfgErr != nil && !k8serrors.IsNotFound(cfgErr) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load operator config"})
		return
	}
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
			Architecture:            arch,
			Image:                   image,
			LeaseID:                 leaseID,
			Owner:                   requester,
			ClientConfigSecretRef:   jmpClientSecret,
			PVCSize:                 pvcSize,
			Resources:               resources,
			StorageClass:            wsConfig.GetStorageClass(),
			NodeSelector:            wsConfig.GetNodeSelector(),
			TmpfsBuildDir:           req.TmpfsBuildDir,
			AutoPauseTimeoutMinutes: req.AutoPauseTimeoutMinutes,
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
	limit, offset := parsePagination(c)

	wsList := &automotivev1alpha1.WorkspaceList{}
	if err := k8sClient.List(c.Request.Context(), wsList, &client.ListOptions{Namespace: namespace}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list workspaces"})
		return
	}

	// Sort by creation time (newest first) for stable pagination
	sort.Slice(wsList.Items, func(i, j int) bool {
		return wsList.Items[j].CreationTimestamp.Before(&wsList.Items[i].CreationTimestamp)
	})

	// Filter to owner's workspaces, then paginate
	owned := make([]WorkspaceResponse, 0, len(wsList.Items))
	for i := range wsList.Items {
		ws := &wsList.Items[i]
		if ws.Spec.Owner != requester {
			continue
		}
		owned = append(owned, workspaceResponseFromCR(ws))
	}

	c.JSON(http.StatusOK, applyPagination(owned, limit, offset))
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

func (a *APIServer) setWorkspaceStopped(c *gin.Context, name string, stopped bool) {
	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return
	}

	if ws.Spec.Stopped == stopped {
		c.JSON(http.StatusOK, workspaceResponseFromCR(ws))
		return
	}

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create kubernetes client"})
		return
	}

	patch := client.MergeFrom(ws.DeepCopy())
	ws.Spec.Stopped = stopped
	if err := k8sClient.Patch(c.Request.Context(), ws, patch); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update workspace: %v", err)})
		return
	}

	c.JSON(http.StatusOK, workspaceResponseFromCR(ws))
}

func (a *APIServer) handleSetWorkspaceLease(c *gin.Context) {
	name := c.Param("name")
	var req struct {
		LeaseID string `json:"leaseID"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "leaseID required"})
		return
	}

	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return
	}

	if ws.Spec.LeaseID == req.LeaseID {
		c.JSON(http.StatusOK, workspaceResponseFromCR(ws))
		return
	}

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create kubernetes client"})
		return
	}

	patch := client.MergeFrom(ws.DeepCopy())
	ws.Spec.LeaseID = req.LeaseID
	if err := k8sClient.Patch(c.Request.Context(), ws, patch); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update workspace lease: %v", err)})
		return
	}

	c.JSON(http.StatusOK, workspaceResponseFromCR(ws))
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

// touchWorkspaceActivity updates LastActivityTime on the workspace status.
// Called from handlers that represent actual workspace usage (exec, shell, sync, deploy)
// so the auto-pause controller knows the workspace is in use.
func (a *APIServer) touchWorkspaceActivity(c *gin.Context, ws *automotivev1alpha1.Workspace) {
	if ws.Spec.Stopped {
		return
	}
	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		return // best-effort, don't fail the operation
	}

	now := metav1.Now()
	patch := client.MergeFrom(ws.DeepCopy())
	ws.Status.LastActivityTime = &now
	_ = k8sClient.Status().Patch(c.Request.Context(), ws, patch)
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
	a.touchWorkspaceActivity(c, ws)

	namespace := ws.Namespace
	podName := ws.Status.PodName

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes config"})
		return
	}

	// Spool the tar stream to a temp file so that EOF propagates cleanly to
	// the SPDY executor, without buffering the entire upload in memory.
	const maxSyncSize int64 = 512 << 20 // 512 MiB
	tmpFile, err := os.CreateTemp("", "workspace-sync-*.tar")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create temp file for upload"})
		return
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	defer func() { _ = tmpFile.Close() }()

	written, err := io.Copy(tmpFile, io.LimitReader(c.Request.Body, maxSyncSize+1))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to read upload: %v", err)})
		return
	}
	if written > maxSyncSize {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("upload exceeds maximum size of %d MiB", maxSyncSize>>20)})
		return
	}
	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rewind temp file"})
		return
	}

	if err := copyToPod(c.Request.Context(), restCfg, namespace, podName, workspaceContainerName, tmpFile, "/workspace/src/"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to sync files: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "files synced"})
}

func (a *APIServer) syncPlanWorkspace(c *gin.Context, name string) {
	var req SyncPlanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}
	if len(req.Files) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "manifest is empty"})
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

	// Build a shell script that hashes only the files the client cares about.
	// This avoids scanning build artifacts or other untracked content.
	var scriptBuf strings.Builder
	scriptBuf.WriteString("cd /workspace/src\n")
	for path := range req.Files {
		// Only hash regular files that exist; skip missing ones silently
		scriptBuf.WriteString(fmt.Sprintf("[ -f %s ] && sha256sum %s\n", shellQuote(path), shellQuote(path)))
	}
	scriptBuf.WriteString("true\n") // ensure exit 0

	var checksumBuf bytes.Buffer
	cmd := []string{"/bin/sh", "-c", scriptBuf.String()}
	if err := podExec(c.Request.Context(), restCfg, ws.Namespace, ws.Status.PodName, workspaceContainerName, cmd, &checksumBuf); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to compute remote checksums: %v", err)})
		return
	}

	// Parse remote checksums into map: relativePath -> hash
	remote := make(map[string]string, len(req.Files))
	for _, line := range strings.Split(checksumBuf.String(), "\n") {
		// sha256sum output: "hash  path/to/file"
		parts := strings.SplitN(strings.TrimSpace(line), "  ", 2)
		if len(parts) != 2 {
			continue
		}
		remote[parts[1]] = parts[0]
	}

	// Compare client manifest against remote
	var changed []string
	unchanged := 0
	for path, localHash := range req.Files {
		if remote[path] != localHash {
			changed = append(changed, path)
		} else {
			unchanged++
		}
	}

	c.JSON(http.StatusOK, SyncPlanResponse{
		Changed:   changed,
		Unchanged: unchanged,
	})
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
	a.touchWorkspaceActivity(c, ws)

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
	a.touchWorkspaceActivity(c, ws)

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
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
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
	<-stdoutDone

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

	if len(req.Artifacts) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one artifact mapping is required"})
		return
	}
	for i, a := range req.Artifacts {
		if strings.TrimSpace(a.Src) == "" || strings.TrimSpace(a.Dest) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("artifact[%d]: src and dest are required", i)})
			return
		}
	}

	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return
	}
	if ws.Status.Phase != phaseRunning {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("workspace %q is not running (phase: %s)", name, ws.Status.Phase)})
		return
	}
	a.touchWorkspaceActivity(c, ws)

	if ws.Spec.LeaseID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no Jumpstarter lease associated with this workspace"})
		return
	}

	restCfg, err := getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes config"})
		return
	}

	// Use jmp shell to forward a local TCP port to the board, then SSH/rsync through it.
	// The board's IP is behind the Jumpstarter lab network and not directly routable
	// from the workspace pod, so we must tunnel through Jumpstarter.
	sshPassword := req.Password
	if sshPassword == "" {
		sshPassword = "password"
	}

	// Ensure a Jumpstarter tunnel is running. The tunnel is a long-lived background
	// process that persists across deploys. On first deploy it takes ~8s to start
	// (lease acquisition + TCP forwarding); subsequent deploys reuse it (~0s).
	//
	// The tunnel runs in a separate exec from the deploy to avoid SPDY fd inheritance:
	// background processes inherit SPDY pipe fds (even with >/dev/null redirects),
	// keeping the stream open until the process exits. By splitting into two execs,
	// phase 2 has zero background processes so its SPDY stream closes immediately.
	// PID is exchanged via /tmp/.tunnel.pid (not stdout) because SPDY has a race
	// condition where the stream closes before output is delivered for fast execs.
	tunnelScript := fmt.Sprintf(
		`SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=3"
SSH_KEY="-i /workspace/.ssh/id_ed25519"

# Reuse existing tunnel if it's alive and reachable
if [ -f /tmp/.tunnel.pid ]; then
  OLD_PID=$(cat /tmp/.tunnel.pid)
  if kill -0 $OLD_PID 2>/dev/null && ssh -p 2222 $SSH_OPTS $SSH_KEY root@127.0.0.1 true 2>/dev/null; then
    exit 0
  fi
  kill $OLD_PID 2>/dev/null; pkill -P $OLD_PID 2>/dev/null; sleep 1
fi
jmp shell --lease %s -- j tcp forward-tcp --address 0.0.0.0 2222 </dev/null >/dev/null 2>&1 &
echo $! > /tmp/.tunnel.pid`,
		shellQuote(ws.Spec.LeaseID))

	tunnelCtx, tunnelCancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer tunnelCancel()
	_ = podExec(tunnelCtx, restCfg, ws.Namespace, ws.Status.PodName, workspaceContainerName,
		[]string{"/bin/sh", "-c", tunnelScript}, io.Discard)

	// Phase 2: Deploy artifacts (streaming, no background processes).
	// Reads tunnel PID from /tmp/.tunnel.pid. The tunnel is left running for reuse.
	setupLogStreamHeaders(c)

	// Build rsync commands for each artifact mapping
	var rsyncCmds strings.Builder
	for _, a := range req.Artifacts {
		fmt.Fprintf(&rsyncCmds, "echo \"Deploying %s -> %s\"\n", a.Src, a.Dest)
		fmt.Fprintf(&rsyncCmds, "rsync -avz --chmod=+x -e \"ssh -p $LOCAL_PORT $SSH_OPTS $SSH_KEY\" %s root@127.0.0.1:%s\n",
			shellQuote(a.Src), shellQuote(a.Dest))
	}

	deployScript := fmt.Sprintf(
		`set -e
LOCAL_PORT=2222
CTL_PATH="/tmp/.ssh-mux-%%r@%%h:%%p"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=3 -o ControlMaster=auto -o ControlPath=$CTL_PATH -o ControlPersist=60"
SSH_CMD="ssh -p $LOCAL_PORT $SSH_OPTS"
SSH_KEY="-i /workspace/.ssh/id_ed25519"
TUNNEL_PID=$(cat /tmp/.tunnel.pid 2>/dev/null)
if [ -z "$TUNNEL_PID" ]; then echo "Failed to start Jumpstarter tunnel"; exit 1; fi

echo "Waiting for tunnel..."
SSH_READY=false
for i in $(seq 1 60); do
  if ! kill -0 $TUNNEL_PID 2>/dev/null; then echo "Tunnel process died"; exit 1; fi
  if $SSH_CMD $SSH_KEY root@127.0.0.1 true 2>/dev/null; then SSH_READY=true; break; fi
  if cat /workspace/.ssh/id_ed25519.pub | sshpass -p %s $SSH_CMD root@127.0.0.1 'mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys' 2>/dev/null; then
    echo "SSH key injected"; SSH_READY=true; break
  fi
  sleep 1
done
if [ "$SSH_READY" != "true" ]; then echo "Timed out waiting for SSH"; exit 1; fi
echo "Tunnel ready"
%s
echo "Deploy complete: %d artifact(s)"
ssh -p $LOCAL_PORT -o ControlPath=$CTL_PATH -O exit root@127.0.0.1 2>/dev/null; true`,
		shellQuote(sshPassword), rsyncCmds.String(), len(req.Artifacts))

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
	if res.Requests == nil {
		res.Requests = corev1.ResourceList{}
	}
	if res.Limits == nil {
		res.Limits = corev1.ResourceList{}
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
	// Reflect spec intent when status hasn't caught up yet
	if ws.Spec.Stopped && phase != "Stopped" {
		phase = "Stopping"
	} else if !ws.Spec.Stopped && phase == "Stopped" {
		phase = "Starting"
	}
	age := ""
	if !ws.CreationTimestamp.IsZero() {
		age = time.Since(ws.CreationTimestamp.Time).Truncate(time.Second).String()
	}
	var autoPauseTimeout string
	switch {
	case ws.Spec.AutoPauseTimeoutMinutes == nil:
		autoPauseTimeout = "default"
	case *ws.Spec.AutoPauseTimeoutMinutes == 0:
		autoPauseTimeout = "disabled"
	default:
		autoPauseTimeout = fmt.Sprintf("%dm", *ws.Spec.AutoPauseTimeoutMinutes)
	}

	lastActivity := ""
	if ws.Status.LastActivityTime != nil {
		elapsed := time.Since(ws.Status.LastActivityTime.Time)
		if elapsed < time.Minute {
			lastActivity = "just now"
		} else {
			lastActivity = elapsed.Truncate(time.Minute).String() + " ago"
		}
	}

	return WorkspaceResponse{
		Name:             ws.Name,
		Phase:            phase,
		Lease:            ws.Spec.LeaseID,
		Arch:             ws.Spec.Architecture,
		PodName:          ws.Status.PodName,
		Age:              age,
		AutoPauseTimeout: autoPauseTimeout,
		LastActivity:     lastActivity,
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
// A mutex serializes writes because the SPDY executor copies stdout and stderr
// in separate goroutines — concurrent writes corrupt HTTP chunked encoding.
type flushWriter struct {
	mu      sync.Mutex
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
	fw.mu.Lock()
	defer fw.mu.Unlock()
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
