package buildapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
)

// UploadPodReady reports whether the build's upload pod is ready, which it is
// once its agent answers. The controller uses it to defer starting a
// background workspace hydrate until the destination is available.
func UploadPodReady(ctx context.Context, k8sClient client.Client, namespace, buildName string) (bool, error) {
	podList := &corev1.PodList{}
	if err := k8sClient.List(ctx, podList,
		client.InNamespace(namespace),
		client.MatchingLabels{
			labels.ImageBuildName: buildName,
			labels.Name:           "upload-pod",
		},
	); err != nil {
		return false, fmt.Errorf("error listing upload pods: %w", err)
	}
	for i := range podList.Items {
		for _, condition := range podList.Items[i].Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				return true, nil
			}
		}
	}
	return false, nil
}

// uploadFiles relays the client's upload, a SyncUploadRequest and the build's
// files as a zstd-compressed tar stream, to the agent in the build's upload
// pod without decoding it, as a workspace sync goes to the workspace's agent.
// The agent applies all of it or none, bounded by the build API's limits,
// and takes only regular files with plain names. It accepts files only while
// the build is uploading and before its uploads are marked complete.
func (a *APIServer) uploadFiles(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := a.getK8sClientOrFail(c)
	if err != nil {
		return
	}
	build := &automotivev1alpha1.ImageBuild{}
	if err := getResourceOrFail(c.Request.Context(), c, k8sClient, name, namespace, build, "build"); err != nil {
		return
	}
	if build.Annotations[labels.RequestedBy] != a.resolveRequester(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "you can only upload to your own builds"})
		return
	}
	if build.Annotations[labels.UploadsComplete] == labels.ValueTrue {
		c.JSON(http.StatusConflict, gin.H{"error": "uploads for this build are already complete"})
		return
	}
	if build.Status.Phase != phaseUploading {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("build is %q; uploads are accepted only while it is %q", build.Status.Phase, phaseUploading)})
		return
	}
	ready, err := UploadPodReady(c.Request.Context(), k8sClient, namespace, name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !ready {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upload pod not ready"})
		return
	}
	agent, err := a.deps.uploadAgent(c.Request.Context(), k8sClient, build)
	if err != nil {
		// Its token or serving certificate may not be there yet.
		a.log.Error(err, "Upload agent is not available", "build", name)
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upload pod not ready"})
		return
	}
	resp, err := agent.SyncUpload(c.Request.Context(), c.Request.Body)
	if err != nil {
		var agentErr *workspaceagent.Error
		if errors.As(err, &agentErr) {
			c.JSON(agentErr.Code, gin.H{"error": agentErr.Message})
		} else {
			// The agent did not answer, as when its pod turns ready a moment
			// before its Service routes to it. That is the not-ready state the
			// CLI retries.
			a.log.Error(err, "Upload agent is unreachable", "build", name)
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "upload pod not ready"})
		}
		return
	}
	defer func() { _ = resp.Body.Close() }()
	var result workspaceagent.SyncUploadResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		a.log.Error(err, "Upload agent sent an invalid response", "build", name)
		c.JSON(http.StatusBadGateway, gin.H{"error": "upload agent sent an invalid response; retry"})
		return
	}
	if result.Files == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "at least one file is required"})
		return
	}

	original := build
	patched := original.DeepCopy()
	if patched.Annotations == nil {
		patched.Annotations = map[string]string{}
	}
	patched.Annotations[labels.UploadsComplete] = labels.ValueTrue
	if err := k8sClient.Patch(c.Request.Context(), patched, client.MergeFrom(original)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("mark complete failed: %v", err)})
		return
	}
	writeJSON(c, http.StatusOK, map[string]string{"status": "ok"})
}
