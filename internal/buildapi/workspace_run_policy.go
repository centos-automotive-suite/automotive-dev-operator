package buildapi

import (
	"fmt"
	"net/http"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspacerun"
	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (a *APIServer) workspaceRunOptions(c *gin.Context, ws *automotivev1alpha1.Workspace, requested int64) (workspacerun.Options, bool) {
	options := workspacerun.DefaultOptions()
	kube, err := a.deps.getClientFromRequest(c)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not load workspace run limits"})
		return options, false
	}
	config, err := a.deps.loadOperatorConfig(c.Request.Context(), kube, resolveNamespace())
	if err != nil && !k8serrors.IsNotFound(err) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not load workspace run limits"})
		return options, false
	}
	var settings *automotivev1alpha1.WorkspacesConfig
	if config != nil {
		settings = config.Spec.Workspaces
	}
	size := ws.Spec.PVCSize
	if size == "" {
		size = automotivev1alpha1.DefaultWorkspacePVCSize
	}
	capacity, err := resource.ParseQuantity(size)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "workspace PVC size is invalid"})
		return options, false
	}
	if ws.Status.PVCName != "" {
		var pvc corev1.PersistentVolumeClaim
		if err := kube.Get(c.Request.Context(), client.ObjectKey{Namespace: ws.Namespace, Name: ws.Status.PVCName}, &pvc); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "could not read workspace PVC capacity"})
			return options, false
		}
		if actual, ok := pvc.Status.Capacity[corev1.ResourceStorage]; ok && actual.Sign() > 0 {
			capacity = actual
		}
	}
	options, err = resolveWorkspaceRunOptions(settings, requested, capacity.Value())
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return options, false
	}
	return options, true
}

func resolveWorkspaceRunOptions(settings *automotivev1alpha1.WorkspacesConfig, requested, pvcBytes int64) (workspacerun.Options, error) {
	options := workspacerun.DefaultOptions()
	maxTimeout := int64(24 * 60 * 60)
	if settings != nil {
		if settings.RunDefaultTimeoutMinutes > 0 {
			options.TimeoutSeconds = int64(settings.RunDefaultTimeoutMinutes) * 60
		}
		if settings.RunMaxTimeoutMinutes > 0 {
			maxTimeout = min(maxTimeout, int64(settings.RunMaxTimeoutMinutes)*60)
		}
		if settings.RunRetentionDays > 0 {
			options.RetentionSeconds = int64(min(settings.RunRetentionDays, 30)) * 24 * 60 * 60
		}
		if settings.RunMaxRecords > 0 {
			options.MaxRecords = min(int64(settings.RunMaxRecords), options.MaxRecords)
		}
		if settings.RunMaxLogSizeMiB > 0 {
			options.MaxLogBytes = int64(settings.RunMaxLogSizeMiB) << 20
		}
		if settings.RunCompletedLogBudgetMiB > 0 {
			options.CompletedLogBudgetBytes = int64(settings.RunCompletedLogBudgetMiB) << 20
		}
	}
	if requested < 0 || requested > maxTimeout {
		return options, fmt.Errorf("timeoutSeconds must be between 1 and %d, or omitted to use the default", maxTimeout)
	}
	options.TimeoutSeconds = min(options.TimeoutSeconds, maxTimeout)
	options.RequestedTimeoutSeconds = requested
	if requested > 0 {
		options.TimeoutSeconds = requested
	}
	options.CompletedLogBudgetBytes = min(options.CompletedLogBudgetBytes, pvcBytes/10)
	if options.CompletedLogBudgetBytes <= 0 {
		return options, fmt.Errorf("workspace PVC capacity is too small for retained logs")
	}
	options.MaxLogBytes = min(options.MaxLogBytes, options.CompletedLogBudgetBytes)
	return options, nil
}
