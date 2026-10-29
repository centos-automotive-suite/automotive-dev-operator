package buildapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspacerun"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	kexec "k8s.io/client-go/util/exec"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type workspaceRunResult struct {
	Run   buildcontract.WorkspaceRun   `json:"run"`
	Runs  []buildcontract.WorkspaceRun `json:"runs"`
	Code  int                          `json:"code"`
	Error string                       `json:"error"`
}

// runWorkspaceOperation always separates protocol output from exec diagnostics.
// Each operation is short; the detached supervisor owns the command lifetime.
func (a *APIServer) runWorkspaceOperation(ctx context.Context, cfg *rest.Config, ws *automotivev1alpha1.Workspace, action string, args ...string) (workspaceRunResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	command, input := workspacerun.Command(action, args...)
	err := a.exec.stream(ctx, cfg, ws.Namespace, ws.Status.PodName, workspaceContainerName,
		command, strings.NewReader(input), &stdout, &stderr)
	if err != nil {
		return workspaceRunResult{}, wrapPodStreamError("workspace run "+action, err, &stderr)
	}
	var result workspaceRunResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return result, fmt.Errorf("invalid workspace run response: %w", err)
	}
	return result, nil
}

func (a *APIServer) workspaceRunTarget(c *gin.Context, name string) (*automotivev1alpha1.Workspace, *rest.Config, bool) {
	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return nil, nil, false
	}
	if ws.Spec.Stopped || ws.Status.Phase != phaseRunning || ws.Status.PodName == "" {
		c.JSON(http.StatusConflict, gin.H{"error": "start the workspace to access its runs and retained logs"})
		return nil, nil, false
	}
	cfg, err := a.deps.getRESTConfigFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes config"})
		return nil, nil, false
	}
	return ws, cfg, true
}

func (a *APIServer) workspaceRunError(c *gin.Context, result workspaceRunResult, err error) bool {
	if err != nil {
		a.log.Error(err, "Workspace run operation failed")
		code, message := workspaceRunExecFailure(err)
		c.JSON(code, gin.H{"error": message})
		return true
	}
	if result.Error != "" {
		code := result.Code
		if code < 400 || code > 599 {
			code = http.StatusInternalServerError
		}
		c.JSON(code, gin.H{"error": result.Error})
		return true
	}
	return false
}

func (a *APIServer) createWorkspaceRun(c *gin.Context, name string) {
	var req buildcontract.WorkspaceRunRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 128<<10)
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}
	if strings.TrimSpace(req.Command) == "" || len(req.Command) > buildcontract.MaxWorkspaceRunCommandBytes || strings.ContainsRune(req.Command, 0) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "command must contain 1 to 65536 bytes and no NUL"})
		return
	}
	if req.ID == "" {
		req.ID = uuid.NewString()
	}
	if !workspacerun.ValidID(req.ID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid run ID"})
		return
	}
	ws, cfg, ok := a.workspaceRunTarget(c, name)
	if !ok {
		return
	}
	options, ok := a.workspaceRunOptions(c, ws, req.TimeoutSeconds)
	if !ok {
		return
	}
	if !a.recordWorkspaceRunActivity(c, ws) {
		return
	}
	// Finish the bounded launch handshake even if the initiating HTTP connection
	// disappears. Retrying this ID returns the existing run, never another command.
	result, err := a.runWorkspaceOperation(context.WithoutCancel(c.Request.Context()), cfg, ws, "create", req.ID, req.Command, options.JSON())
	if a.workspaceRunError(c, result, err) {
		return
	}
	c.Header("Location", "/v1/workspaces/"+name+"/runs/"+req.ID)
	c.JSON(http.StatusAccepted, result.Run)
}

// Reserve an inactivity window before launching. This must succeed, and must
// conflict with a simultaneous stop decision; a best-effort activity update
// could allow the pod to disappear between the readiness check and launch.
func (a *APIServer) recordWorkspaceRunActivity(c *gin.Context, ws *automotivev1alpha1.Workspace) bool {
	kube, err := a.deps.getClientFromRequest(c)
	if err == nil {
		patch := client.MergeFromWithOptions(ws.DeepCopy(), client.MergeFromWithOptimisticLock{})
		now := metav1.Now()
		ws.Status.LastActivityTime = &now
		err = kube.Status().Patch(c.Request.Context(), ws, patch)
	}
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not record workspace activity; retry using the same run ID"})
		return false
	}
	return true
}

func (a *APIServer) workspaceRunAction(c *gin.Context, name, action string) {
	if !validWorkspaceRunParam(c) {
		return
	}
	ws, cfg, ok := a.workspaceRunTarget(c, name)
	if !ok {
		return
	}
	result, err := a.runWorkspaceOperation(c.Request.Context(), cfg, ws, action, c.Param("run"))
	if a.workspaceRunError(c, result, err) {
		return
	}
	if action == "delete" {
		c.Status(http.StatusNoContent)
		return
	}
	c.JSON(http.StatusOK, result.Run)
}

func validWorkspaceRunParam(c *gin.Context) bool {
	if !workspacerun.ValidID(c.Param("run")) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid run ID"})
		return false
	}
	return true
}

func (a *APIServer) getWorkspaceRun(c *gin.Context, name string) {
	a.workspaceRunAction(c, name, "get")
}

func (a *APIServer) cancelWorkspaceRun(c *gin.Context, name string) {
	a.workspaceRunAction(c, name, "cancel")
}

func (a *APIServer) workspaceRunLogs(c *gin.Context, name string) {
	if !validWorkspaceRunParam(c) {
		return
	}
	offset, err := strconv.ParseInt(c.DefaultQuery("offset", "0"), 10, 64)
	if err != nil || offset < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "offset must be a non-negative byte offset"})
		return
	}
	followValue, follow := c.GetQuery("follow")
	// Gin's GetQuery treats an empty query value as absent; ?follow is valid.
	if c.Request.URL.Query().Has("follow") {
		follow = true
		if followValue != "" {
			follow, err = strconv.ParseBool(followValue)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "follow must be a boolean"})
				return
			}
		}
	}
	ws, cfg, ok := a.workspaceRunTarget(c, name)
	if !ok {
		return
	}
	duration := time.Duration(a.limits.MaxLogStreamDurationMinutes) * time.Minute
	if duration <= 0 {
		duration = 120 * time.Minute
	}
	helperDuration := duration
	if follow {
		helperDuration = min(duration, 40*time.Second)
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), duration)
	defer cancel()
	// Check log format support before committing headers or interpreting offsets.
	result, err := a.runWorkspaceOperation(ctx, cfg, ws, "log-info", c.Param("run"))
	if a.workspaceRunError(c, result, err) {
		return
	}
	if offset > result.Run.LogBytes {
		c.JSON(http.StatusRequestedRangeNotSatisfiable, gin.H{"error": "offset exceeds available log bytes"})
		return
	}
	offset = max(offset, result.Run.LogStartOffset)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-store, no-transform")
	c.Header("X-Accel-Buffering", "no")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Log-Offset", strconv.FormatInt(offset, 10))
	c.Header("X-Log-Stream-Seconds", strconv.FormatFloat(helperDuration.Seconds(), 'f', -1, 64))
	c.Header("Trailer", "X-Log-Error, X-Run-Status, X-Run-Exit-Code")
	c.Writer.Flush()
	var stderr bytes.Buffer
	// One persistent pod exec streams raw bytes. Polling the local volume happens
	// in the pod, and never holds a run lock while waiting for HTTP backpressure.
	// The advertised cap bounds idle helpers even when a remote exec disconnect
	// does not terminate its process. Clients allow a grace period beyond it.
	command, input := workspacerun.Command("stream", c.Param("run"), strconv.FormatInt(offset, 10),
		strconv.FormatInt(result.Run.LogBytes, 10), strconv.FormatBool(follow),
		strconv.FormatFloat(helperDuration.Seconds(), 'f', -1, 64))
	err = a.exec.stream(ctx, cfg, ws.Namespace, ws.Status.PodName, workspaceContainerName,
		command, strings.NewReader(input), newFlushWriter(c.Writer), &stderr)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		_, message := workspaceRunExecFailure(wrapPodStreamError("workspace log stream", err, &stderr))
		c.Header("X-Log-Error", message)
		return
	}
	if err := json.Unmarshal(stderr.Bytes(), &result); err != nil {
		c.Header("X-Log-Error", "invalid log stream result; reconnect to resume")
		return
	}
	if result.Error != "" {
		c.Header("X-Log-Error", result.Error)
	}
	c.Header("X-Run-Status", result.Run.Status)
	if result.Run.ExitCode != nil {
		c.Header("X-Run-Exit-Code", strconv.Itoa(*result.Run.ExitCode))
	}
}

func workspaceRunExecFailure(err error) (int, string) {
	detail := err.Error()
	if len(detail) > 1024 {
		detail = detail[len(detail)-1024:]
	}
	if k8serrors.IsForbidden(err) {
		return http.StatusForbidden, "workspace execution is not permitted: " + detail
	}
	var exitError kexec.ExitError
	if errors.As(err, &exitError) && (exitError.ExitStatus() == 126 || exitError.ExitStatus() == 127) {
		return http.StatusUnprocessableEntity, "workspace run helper could not execute; the image requires an executable Python 3.12 or newer: " + detail
	}
	return http.StatusBadGateway, "workspace run operation failed: " + detail
}

func (a *APIServer) listWorkspaceRuns(c *gin.Context, name string) {
	offset, offsetErr := strconv.ParseInt(c.DefaultQuery("offset", "0"), 10, 64)
	limit, limitErr := strconv.ParseInt(c.DefaultQuery("limit", "100"), 10, 64)
	if offsetErr != nil || limitErr != nil || offset < 0 || limit < 1 || limit > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "offset must be non-negative and limit must be between 1 and 100"})
		return
	}
	ws, cfg, ok := a.workspaceRunTarget(c, name)
	if !ok {
		return
	}
	result, err := a.runWorkspaceOperation(c.Request.Context(), cfg, ws, "list", strconv.FormatInt(offset, 10), strconv.FormatInt(limit, 10))
	if a.workspaceRunError(c, result, err) {
		return
	}
	if result.Runs == nil {
		result.Runs = []buildcontract.WorkspaceRun{}
	}
	c.JSON(http.StatusOK, result.Runs)
}

func (a *APIServer) deleteWorkspaceRun(c *gin.Context, name string) {
	a.workspaceRunAction(c, name, "delete")
}
