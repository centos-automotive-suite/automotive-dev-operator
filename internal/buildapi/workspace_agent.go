package buildapi

import (
	"context"
	"net"
	"strconv"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// workspaceFileGrantTTL covers a build's whole life: waiting for uploads,
// queueing and the build itself, so a late fetch still finds its grant.
func workspaceFileGrantTTL(config *automotivev1alpha1.OperatorConfig) time.Duration {
	build := time.Duration(automotivev1alpha1.DefaultBuildTimeoutMinutes) * time.Minute
	upload := 30 * time.Minute
	if config != nil && config.Spec.OSBuilds != nil {
		if minutes := config.Spec.OSBuilds.BuildTimeoutMinutes; minutes > 0 {
			build = time.Duration(minutes) * time.Minute
		}
		if minutes := config.Spec.OSBuilds.UploadTimeoutMinutes; minutes > 0 {
			upload = time.Duration(minutes) * time.Minute
		}
	}
	return min(upload+build+time.Hour, workspaceagent.MaxGrantTTL)
}

// grantWorkspaceFiles mints a grant on ws's agent for one build and returns
// the URL of the workspace's /workspace/export as build pods reach it.
func (a *APIServer) grantWorkspaceFiles(ctx context.Context, k8sClient client.Client, ws *automotivev1alpha1.Workspace, podIP string, ttl time.Duration) (string, error) {
	agent, err := a.deps.workspaceAgent(ctx, k8sClient, ws)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	grant, err := agent.Grant(ctx, ttl)
	if err != nil {
		return "", err
	}
	host := net.JoinHostPort(podIP, strconv.Itoa(workspaceagent.FilesPort))
	return "http://" + host + "/f/" + grant.Token, nil
}
