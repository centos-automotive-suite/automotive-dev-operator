package buildapi

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/terminal"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/notifications"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
)

func (a *APIServer) createFlash(c *gin.Context) {
	var req FlashRequest
	if !bindOperationRequest(c, &req) {
		return
	}
	if !validateAndNormalizeFlashRequest(c, &req) {
		return
	}

	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}

	ctx := c.Request.Context()
	namespace := resolveNamespace()
	if !a.prepareFlashRequest(ctx, c, k8sClient, namespace, &req) {
		return
	}

	clientset, err := getClientsetOrFail(c)
	if err != nil {
		return
	}

	requestedBy := a.resolveRequester(c)

	// Load OperatorConfig for target mappings, image overrides, and lease duration defaults
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: "config", Namespace: namespace}, operatorConfig); err != nil {
		if !k8serrors.IsNotFound(err) {
			a.log.Error(err, "failed to load OperatorConfig for flash, using defaults")
		}
		operatorConfig = &automotivev1alpha1.OperatorConfig{}
	}

	// Auto-detect target from OCI image annotations when not specified
	if req.Target == "" && req.ExporterSelector == "" {
		if detected := resolveTargetFromImage(ctx, req.ImageRef, req.RegistryCredentials); detected != "" {
			req.Target = detected
			a.log.Info("auto-detected target from image annotations", "target", detected, "image", req.ImageRef)
		}
	}

	// Resolve exporter selector and flash command from OperatorConfig
	exporterSelector, flashCmd := resolveFlashTargetConfig(req, operatorConfig)
	if exporterSelector == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "exporterSelector or valid target is required"})
		return
	}

	// Replace placeholders in flash command
	if flashCmd != "" {
		flashCmd = strings.ReplaceAll(flashCmd, "{image_uri}", req.ImageRef)
		flashCmd = strings.ReplaceAll(flashCmd, "{artifact_url}", req.ImageRef)
	}

	// Create Jumpstarter client config secret
	secretName, createdSecret, secretErr := createFlashClientConfigSecret(ctx, clientset, namespace, req)
	if secretErr != nil {
		c.JSON(secretErr.code, gin.H{"error": secretErr.message})
		return
	}

	// Create OCI auth secret for flash image pull credentials
	flashOCIAuthSecretName, createdOCIAuthSecret, ociErr := createFlashOCIAuthSecret(ctx, clientset, namespace, req.Name, req.RegistryCredentials)
	if ociErr != nil {
		_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		c.JSON(ociErr.code, gin.H{"error": ociErr.message})
		return
	}

	// Build task config from OperatorConfig for flash task generation
	var flashBuildConfig *tasks.BuildConfig
	if operatorConfig.Spec.OSBuilds != nil {
		flashBuildConfig = &tasks.BuildConfig{
			FlashTimeoutMinutes:  operatorConfig.Spec.OSBuilds.GetFlashTimeoutMinutes(),
			DefaultLeaseDuration: operatorConfig.Spec.Jumpstarter.GetDefaultLeaseDuration(),
		}
	}

	// Get the flash task spec
	flashTask := tasks.GenerateFlashTask(namespace, flashBuildConfig)

	// Lease duration: only resolve when not using an existing lease
	// Fallback: request > FlashTimeoutMinutes (as HH:MM:SS) > Jumpstarter default > constant
	leaseDuration := req.LeaseDuration
	if req.LeaseName == "" && leaseDuration == "" {
		if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.FlashTimeoutMinutes > 0 {
			m := operatorConfig.Spec.OSBuilds.FlashTimeoutMinutes
			leaseDuration = fmt.Sprintf("%02d:%02d:00", m/60, m%60)
		} else {
			leaseDuration = operatorConfig.Spec.Jumpstarter.GetDefaultLeaseDuration()
		}
	}

	leaseTags := BuildLeaseTags(operatorConfig.Spec.Jumpstarter.GetDefaultLeaseTags(), req.Name, req.LeaseTags)

	// Build workspace bindings
	workspaces := []tektonv1.WorkspaceBinding{
		{
			Name: "jumpstarter-client",
			Secret: &corev1.SecretVolumeSource{
				SecretName: secretName,
			},
		},
	}
	if flashOCIAuthSecretName != "" {
		workspaces = append(workspaces, tektonv1.WorkspaceBinding{
			Name: "flash-oci-auth",
			Secret: &corev1.SecretVolumeSource{
				SecretName: flashOCIAuthSecretName,
			},
		})
	}

	callbackSecret, callbackErr := createCallbackSecret(
		ctx,
		k8sClient,
		namespace,
		notifications.CallbackSecretName(notifications.SubjectTaskRun, req.Name, uuid.NewString()),
		notifications.SubjectTaskRun,
		req.Name,
		"",
		req.Callback,
	)
	if callbackErr != nil {
		_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		if flashOCIAuthSecretName != "" {
			_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, flashOCIAuthSecretName, metav1.DeleteOptions{})
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist callback configuration"})
		return
	}

	// Create the flash TaskRun
	taskAnnotations := flashTaskAnnotations(ctx, req, requestedBy, callbackSecret)
	taskRun := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: namespace,
			Labels: map[string]string{
				labels.ManagedBy:    labels.ValueBuildAPI,
				labels.PartOf:       labels.ValueAutomotiveDev,
				labels.Name:         "flash-taskrun",
				labels.FlashTaskRun: req.Name,
			},
			Annotations: taskAnnotations,
		},
		Spec: tektonv1.TaskRunSpec{
			ServiceAccountName: automotivev1alpha1.BuildServiceAccountName,
			TaskSpec:           &flashTask.Spec,
			Params: []tektonv1.Param{
				{Name: "image-ref", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: req.ImageRef}},
				{Name: "exporter-selector", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: exporterSelector}},
				{Name: "flash-cmd", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: flashCmd}},
				{Name: "lease-duration", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: leaseDuration}},
				{Name: "lease-name", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: req.LeaseName}},
				{Name: "lease-tags", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: leaseTags}},
			},
			Workspaces: workspaces,
		},
	}

	if err := k8sClient.Create(ctx, taskRun); err != nil {
		// Clean up secrets if TaskRun creation fails
		_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		if flashOCIAuthSecretName != "" {
			_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, flashOCIAuthSecretName, metav1.DeleteOptions{})
		}
		deleteCallbackSecret(ctx, k8sClient, callbackSecret)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create flash TaskRun: %v", err)})
		return
	}
	if err := a.finalizeFlashCallback(ctx, k8sClient, taskRun, callbackSecret); err != nil {
		_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		if flashOCIAuthSecretName != "" {
			_ = clientset.CoreV1().Secrets(namespace).Delete(ctx, flashOCIAuthSecretName, metav1.DeleteOptions{})
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to persist callback ownership"})
		return
	}

	// Set owner reference on secrets for automatic cleanup
	ownerRef := []metav1.OwnerReference{
		{
			APIVersion: "tekton.dev/v1",
			Kind:       "TaskRun",
			Name:       taskRun.Name,
			UID:        taskRun.UID,
		},
	}
	createdSecret.OwnerReferences = ownerRef
	if _, err := clientset.CoreV1().Secrets(namespace).Update(ctx, createdSecret, metav1.UpdateOptions{}); err != nil {
		a.log.Error(err, "failed to set owner reference on secret", "secret", secretName)
	}
	if createdOCIAuthSecret != nil {
		createdOCIAuthSecret.OwnerReferences = ownerRef
		if _, updErr := clientset.CoreV1().Secrets(namespace).Update(ctx, createdOCIAuthSecret, metav1.UpdateOptions{}); updErr != nil {
			a.log.Error(updErr, "failed to set owner reference on flash OCI auth secret", "secret", flashOCIAuthSecretName)
		}
	}

	FlashCreatedTotal.Inc()

	writeJSON(c, http.StatusAccepted, FlashResponse{
		ExternalID:   req.ExternalID,
		Notification: pendingNotification(req.Callback != nil),
		Name:         req.Name,
		Phase:        phasePending,
		Message:      "Flash TaskRun created",
		RequestedBy:  requestedBy,
		TaskRunName:  taskRun.Name,
	})
}

func validateAndNormalizeFlashRequest(c *gin.Context, req *FlashRequest) bool {
	if err := validateOperationMetadata(req.ExternalID, req.Callback); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "InvalidRequest"})
		return false
	}

	// Validate required fields
	if req.ClientConfig == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "clientConfig is required"})
		return false
	}

	// Auto-generate name if not provided
	if req.Name == "" {
		req.Name = fmt.Sprintf("flash-%s", uuid.New().String()[:5])
	}

	// Validate and sanitize name for Kubernetes compatibility
	if err := validateBuildName(req.Name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}
	req.Name = sanitizeBuildNameForValidation(req.Name)

	// Validate mutual exclusivity of lease-name and lease-duration
	if req.LeaseName != "" && req.LeaseDuration != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "lease-name and lease-duration are mutually exclusive"})
		return false
	}
	return true
}

func (a *APIServer) prepareFlashRequest(
	ctx context.Context,
	c *gin.Context,
	k8sClient client.Client,
	namespace string,
	req *FlashRequest,
) bool {
	if httpErr := validateCallbackAdmission(ctx, k8sClient, namespace, req.Callback); httpErr != nil {
		c.JSON(httpErr.code, gin.H{"error": httpErr.message})
		return false
	}
	if httpErr := a.applyFlashImageSource(ctx, k8sClient, namespace, req); httpErr != nil {
		c.JSON(httpErr.code, gin.H{"error": httpErr.message})
		return false
	}
	return true
}

func flashTaskAnnotations(ctx context.Context, req FlashRequest, requestedBy string, callbackSecret *corev1.Secret) map[string]string {
	annotations := map[string]string{
		labels.RequestedBy: requestedBy,
		labels.ImageRef:    req.ImageRef,
	}
	if traceID := extractTraceID(ctx); traceID != "" {
		annotations[automotivev1alpha1.AnnotationTraceID] = traceID
	}
	if req.ExternalID != "" {
		annotations[notifications.AnnotationExternalID] = req.ExternalID
	}
	if callbackSecret != nil {
		annotations[notifications.AnnotationCallbackSecretRef] = callbackSecret.Name
	}
	return annotations
}

func (a *APIServer) finalizeFlashCallback(
	ctx context.Context,
	k8sClient client.Client,
	taskRun *tektonv1.TaskRun,
	callbackSecret *corev1.Secret,
) error {
	if callbackSecret == nil {
		return nil
	}
	if err := adoptCallbackSecret(
		ctx,
		k8sClient,
		callbackSecret,
		notifications.SubjectTaskRun,
		taskRun.Name,
		taskRun.UID,
	); err != nil {
		a.log.Error(err, "failed to adopt callback secret", "flash", taskRun.Name)
		if rollbackErr := rollbackCallbackSubject(ctx, k8sClient, taskRun, callbackSecret); rollbackErr != nil {
			a.log.Error(rollbackErr, "failed to roll back flash after callback adoption failure", "flash", taskRun.Name)
		}
		return err
	}
	return nil
}

func (a *APIServer) applyFlashImageSource(ctx context.Context, k8sClient client.Client, namespace string, req *FlashRequest) *httpError {
	if req.CatalogImage != "" {
		ref, httpErr := resolveFlashImageFromCatalog(ctx, k8sClient, namespace, req.CatalogImage)
		if httpErr != nil {
			return httpErr
		}
		req.ImageRef = ref
		a.log.Info("resolved catalog image for flash", "catalogImage", req.CatalogImage, "imageRef", req.ImageRef)
	}
	if req.ImageRef == "" {
		return &httpError{code: http.StatusBadRequest, message: "imageRef or catalogImage is required"}
	}
	return nil
}

func (a *APIServer) listFlash(c *gin.Context) {
	namespace := resolveNamespace()
	limit, offset := parsePagination(c)

	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}

	ctx := c.Request.Context()

	// List TaskRuns with flash label
	taskRunList := &tektonv1.TaskRunList{}
	if err := k8sClient.List(ctx, taskRunList, client.InNamespace(namespace), client.HasLabels{labels.FlashTaskRun}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list flash TaskRuns: %v", err)})
		return
	}

	// Sort by creation time, newest first
	sort.Slice(taskRunList.Items, func(i, j int) bool {
		return taskRunList.Items[j].CreationTimestamp.Before(&taskRunList.Items[i].CreationTimestamp)
	})

	page := applyPagination(taskRunList.Items, limit, offset)
	needsNotifications := false
	for i := range page {
		if page[i].Annotations[notifications.AnnotationCallbackSecretRef] != "" {
			needsNotifications = true
			break
		}
	}
	notificationStatuses, err := listNotificationStatuses(ctx, k8sClient, namespace, needsNotifications)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load flash notifications"})
		return
	}

	resp := make([]FlashListItem, 0, len(page))
	for _, tr := range page {
		phase, message := getTaskRunStatus(&tr)
		var compStr string
		if tr.Status.CompletionTime != nil {
			compStr = tr.Status.CompletionTime.Format(time.RFC3339)
		}
		resp = append(resp, FlashListItem{
			ExternalID:     tr.Annotations[notifications.AnnotationExternalID],
			Notification:   projectedNotification(notificationStatuses, tr.UID, tr.Annotations[notifications.AnnotationCallbackSecretRef] != ""),
			Name:           tr.Name,
			Phase:          phase,
			Message:        message,
			RequestedBy:    tr.Annotations[labels.RequestedBy],
			CreatedAt:      tr.CreationTimestamp.Format(time.RFC3339),
			CompletionTime: compStr,
		})
	}
	writeJSON(c, http.StatusOK, resp)
}

func (a *APIServer) getFlash(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}

	ctx := c.Request.Context()
	taskRun := &tektonv1.TaskRun{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, taskRun, "flash TaskRun"); err != nil {
		return
	}

	// Verify it's a flash TaskRun
	if taskRun.Labels[labels.FlashTaskRun] == "" {
		c.JSON(http.StatusNotFound, gin.H{"error": "flash TaskRun not found"})
		return
	}

	phase, message := getTaskRunStatus(taskRun)
	notificationStatus, err := getNotificationStatus(
		ctx,
		k8sClient,
		namespace,
		taskRun.UID,
		taskRun.Annotations[notifications.AnnotationCallbackSecretRef] != "",
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load flash notification"})
		return
	}
	var startStr, compStr string
	if taskRun.Status.StartTime != nil {
		startStr = taskRun.Status.StartTime.Format(time.RFC3339)
	}
	if taskRun.Status.CompletionTime != nil {
		compStr = taskRun.Status.CompletionTime.Format(time.RFC3339)
	}

	writeJSON(c, http.StatusOK, FlashResponse{
		ExternalID:     taskRun.Annotations[notifications.AnnotationExternalID],
		Notification:   notificationStatus,
		Name:           taskRun.Name,
		Phase:          phase,
		Message:        message,
		RequestedBy:    taskRun.Annotations[labels.RequestedBy],
		StartTime:      startStr,
		CompletionTime: compStr,
		TaskRunName:    taskRun.Name,
		LeaseID:        terminal.Bound(extractTaskRunResult(taskRun, "lease-id"), 253),
	})
}

func extractTaskRunResult(tr *tektonv1.TaskRun, name string) string {
	for _, result := range tr.Status.Results {
		if result.Name == name {
			return result.Value.StringVal
		}
	}
	return ""
}

func getTaskRunStatus(tr *tektonv1.TaskRun) (phase, message string) {
	if result := terminal.FlashResult(tr); result != nil {
		return result.Phase, result.Message
	}
	return terminal.TaskPhase(tr)
}

func (a *APIServer) streamFlashLogs(c *gin.Context, name string) {
	namespace := resolveNamespace()

	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		return
	}
	clientset, err := getClientsetOrFail(c)
	if err != nil {
		return
	}

	ctx := c.Request.Context()

	// Verify the TaskRun exists and is a flash TaskRun
	taskRun := &tektonv1.TaskRun{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, taskRun, "flash TaskRun"); err != nil {
		return
	}
	if taskRun.Labels[labels.FlashTaskRun] == "" {
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

	// Stream logs, retrying while the container is still initializing
	logReq := clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Container: containerName,
		Follow:    true,
		SinceTime: sinceTime,
	})
	var stream io.ReadCloser
	for {
		stream, err = logReq.Stream(streamCtx)
		if err == nil {
			break
		}
		pod, getErr := clientset.CoreV1().Pods(namespace).Get(streamCtx, podName, metav1.GetOptions{})
		if getErr != nil || !isPodInitializing(pod) {
			_, _ = fmt.Fprintf(c.Writer, "\n[Error streaming logs: %v]\n", err)
			c.Writer.Flush()
			return
		}
		select {
		case <-streamCtx.Done():
			_, _ = fmt.Fprintf(c.Writer, "\n[Timed out waiting for container]\n")
			c.Writer.Flush()
			return
		case <-time.After(500 * time.Millisecond):
		}
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

func isPodInitializing(pod *corev1.Pod) bool {
	if pod.Status.Phase == corev1.PodPending {
		return true
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil {
			switch cs.State.Waiting.Reason {
			case "ContainerCreating", "PodInitializing":
				return true
			}
		}
	}
	for _, cs := range pod.Status.InitContainerStatuses {
		if cs.State.Running != nil || cs.State.Waiting != nil {
			return true
		}
	}
	return false
}
