package buildapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// workspaceAgentTimeout bounds every agent call except log streams.
const workspaceAgentTimeout = 30 * time.Second

// maxRunRequestBytes fits the largest command with every byte JSON-escaped
// to six, as encoders do for '<', '>', '&' and control characters.
const maxRunRequestBytes = 6*buildcontract.MaxWorkspaceRunCommandBytes + 4<<10

// The build API stays the public face of runs and syncs: it authenticates
// users, checks ownership and resolves limits, and the workspace's agent
// enforces them. runningWorkspaceAgent returns the caller's running workspace
// and a client for its agent, or writes the error response.
func (a *APIServer) runningWorkspaceAgent(c *gin.Context, name string) (*automotivev1alpha1.Workspace, *workspaceagent.Client, bool) {
	ws, err := a.getOwnedWorkspace(c, name)
	if err != nil {
		return nil, nil, false
	}
	if ws.Spec.Stopped || ws.Status.Phase != phaseRunning || ws.Status.PodName == "" {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("workspace %q is not running; start it first", name)})
		return nil, nil, false
	}
	kube, err := a.deps.getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get kubernetes client"})
		return nil, nil, false
	}
	agent, err := a.deps.workspaceAgent(c.Request.Context(), kube, ws)
	if err != nil {
		a.log.Error(err, "Workspace agent is not available", "workspace", name)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "workspace agent is not available; retry, or stop and start the workspace"})
		return nil, nil, false
	}
	return ws, agent, true
}

// workspaceAgentError reports an agent failure with the agent's own status, and
// a failure to reach the agent as a bad gateway, without the agent's address.
func (a *APIServer) workspaceAgentError(c *gin.Context, err error) bool {
	if err == nil {
		return false
	}
	var agentErr *workspaceagent.Error
	if errors.As(err, &agentErr) {
		c.JSON(agentErr.Code, gin.H{"error": agentErr.Message})
		return true
	}
	a.log.Error(err, "Workspace agent request failed")
	c.JSON(http.StatusBadGateway, gin.H{"error": "workspace agent request failed; retry"})
	return true
}

func contractRun(run workspaceagent.Run) buildcontract.WorkspaceRun {
	return buildcontract.WorkspaceRun{
		ID:             run.ID,
		Command:        run.Command,
		Status:         run.Status,
		ExitCode:       run.ExitCode,
		StartedAt:      run.StartedAt,
		FinishedAt:     run.FinishedAt,
		LogBytes:       run.LogBytes,
		LogStartOffset: run.LogStartOffset,
		LogTruncated:   run.LogTruncated,
		LogsEvicted:    run.LogsEvicted,
		TimeoutSeconds: run.TimeoutSeconds,
		Message:        run.Message,
	}
}

func (a *APIServer) createWorkspaceRun(c *gin.Context, name string) {
	var req buildcontract.WorkspaceRunRequest
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxRunRequestBytes)
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
	if !workspaceagent.ValidID(req.ID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid run ID"})
		return
	}
	ws, agent, ok := a.runningWorkspaceAgent(c, name)
	if !ok {
		return
	}
	a.startWorkspaceRun(c, name, ws, agent, workspaceagent.CreateRequest{ID: req.ID, Command: req.Command}, req.TimeoutSeconds)
}

// startWorkspaceRun resolves the run's limits, reserves workspace activity and
// starts the run in the agent, then answers 202 with the run.
func (a *APIServer) startWorkspaceRun(c *gin.Context, name string, ws *automotivev1alpha1.Workspace, agent *workspaceagent.Client,
	create workspaceagent.CreateRequest, timeoutSeconds int64) {
	options, ok := a.workspaceRunOptions(c, ws, timeoutSeconds)
	if !ok {
		return
	}
	if !a.recordWorkspaceRunActivity(c, ws) {
		return
	}
	create.Options = options
	// Finish the create even if the initiating HTTP connection disappears.
	// Retrying this ID returns the existing run, never another command.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.Request.Context()), workspaceAgentTimeout)
	defer cancel()
	run, err := agent.Create(ctx, create)
	if a.workspaceAgentError(c, err) {
		return
	}
	c.Header("Location", "/v1/workspaces/"+name+"/runs/"+create.ID)
	c.JSON(http.StatusAccepted, contractRun(run))
}

// Reserve an inactivity window before launching. This must succeed, and must
// conflict with a simultaneous stop decision; a best-effort activity update
// could allow the pod to disappear between the readiness check and launch.
func (a *APIServer) recordWorkspaceRunActivity(c *gin.Context, ws *automotivev1alpha1.Workspace) bool {
	if err := a.patchWorkspaceActivity(c, ws, client.MergeFromWithOptimisticLock{}); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not record workspace activity; retry using the same run ID"})
		return false
	}
	return true
}

func validWorkspaceRunParam(c *gin.Context) bool {
	if !workspaceagent.ValidID(c.Param("run")) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid run ID"})
		return false
	}
	return true
}

func (a *APIServer) workspaceRunAction(c *gin.Context, name string, action func(*workspaceagent.Client, context.Context, string) (workspaceagent.Run, error)) {
	if !validWorkspaceRunParam(c) {
		return
	}
	_, agent, ok := a.runningWorkspaceAgent(c, name)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), workspaceAgentTimeout)
	defer cancel()
	run, err := action(agent, ctx, c.Param("run"))
	if a.workspaceAgentError(c, err) {
		return
	}
	c.JSON(http.StatusOK, contractRun(run))
}

func (a *APIServer) getWorkspaceRun(c *gin.Context, name string) {
	a.workspaceRunAction(c, name, (*workspaceagent.Client).Get)
}

func (a *APIServer) cancelWorkspaceRun(c *gin.Context, name string) {
	a.workspaceRunAction(c, name, (*workspaceagent.Client).Cancel)
}

func (a *APIServer) deleteWorkspaceRun(c *gin.Context, name string) {
	if !validWorkspaceRunParam(c) {
		return
	}
	_, agent, ok := a.runningWorkspaceAgent(c, name)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), workspaceAgentTimeout)
	defer cancel()
	if a.workspaceAgentError(c, agent.Delete(ctx, c.Param("run"))) {
		return
	}
	c.Status(http.StatusNoContent)
}

func (a *APIServer) listWorkspaceRuns(c *gin.Context, name string) {
	offset, offsetErr := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, limitErr := strconv.Atoi(c.DefaultQuery("limit", "100"))
	if offsetErr != nil || limitErr != nil || offset < 0 || limit < 1 || limit > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "offset must be non-negative and limit must be between 1 and 100"})
		return
	}
	_, agent, ok := a.runningWorkspaceAgent(c, name)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), workspaceAgentTimeout)
	defer cancel()
	runs, err := agent.List(ctx, offset, limit)
	if a.workspaceAgentError(c, err) {
		return
	}
	result := make([]buildcontract.WorkspaceRun, 0, len(runs))
	for _, run := range runs {
		result = append(result, contractRun(run))
	}
	c.JSON(http.StatusOK, result)
}

var workspaceLogTrailers = []string{"X-Log-Error", "X-Run-Status", "X-Run-Exit-Code"}

// workspaceRunLogs relays the agent's log stream. With follow, one response
// lasts until the run ends or the stream limit passes; the client resumes from
// the bytes it received.
func (a *APIServer) workspaceRunLogs(c *gin.Context, name string) {
	if !validWorkspaceRunParam(c) {
		return
	}
	offset, err := strconv.ParseInt(c.DefaultQuery("offset", "0"), 10, 64)
	if err != nil || offset < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "offset must be a non-negative byte offset"})
		return
	}
	// A bare ?follow is present with an empty value and enables following.
	followValue, follow := c.GetQuery("follow")
	if followValue != "" {
		if follow, err = strconv.ParseBool(followValue); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "follow must be a boolean"})
			return
		}
	}
	_, agent, ok := a.runningWorkspaceAgent(c, name)
	if !ok {
		return
	}
	duration := time.Duration(a.limits.MaxLogStreamDurationMinutes) * time.Minute
	ctx, cancel := context.WithTimeout(c.Request.Context(), duration)
	defer cancel()
	// The agent checks the offset before it commits headers, so its errors
	// arrive as ordinary responses.
	resp, err := agent.Logs(ctx, c.Param("run"), offset, follow)
	if a.workspaceAgentError(c, err) {
		return
	}
	defer func() { _ = resp.Body.Close() }()
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.Header("Cache-Control", "no-store, no-transform")
	c.Header("X-Accel-Buffering", "no")
	c.Header("X-Content-Type-Options", "nosniff")
	c.Header("X-Log-Offset", resp.Header.Get("X-Log-Offset"))
	c.Header("X-Log-Stream-Seconds", strconv.FormatFloat(duration.Seconds(), 'f', -1, 64))
	c.Header("Trailer", strings.Join(workspaceLogTrailers, ", "))
	c.Status(http.StatusOK)
	c.Writer.Flush()
	_, err = io.Copy(newFlushWriter(c.Writer), resp.Body)
	if ctx.Err() != nil {
		return // the client resumes from the bytes it received
	}
	if err != nil {
		c.Header("X-Log-Error", "workspace log stream was interrupted; reconnect to resume")
		return
	}
	for _, name := range workspaceLogTrailers {
		if value := resp.Trailer.Get(name); value != "" {
			c.Header(name, value)
		}
	}
}
