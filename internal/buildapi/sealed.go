package buildapi

import (
	"bufio"
	"context"
	"errors"
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
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"go.opentelemetry.io/otel/attribute"
)

// sealedPathToOperation maps the API path prefix to the AIB sealed operation.
var sealedPathToOperation = map[string]SealedOperation{
	"/v1/prepare-reseals":      SealedPrepareReseal,
	"/v1/reseals":              SealedReseal,
	"/v1/extract-for-signings": SealedExtractForSigning,
	"/v1/inject-signeds":       SealedInjectSigned,
}

// resolveSealedOperation extracts the sealed operation from the request URL path.
func resolveSealedOperation(c *gin.Context) SealedOperation {
	p := c.Request.URL.Path
	for prefix, op := range sealedPathToOperation {
		if strings.HasPrefix(p, prefix) {
			return op
		}
	}
	return ""
}

// validateSealedRequest validates and normalizes a SealedRequest, returning the resolved stages or an error message.
func validateSealedRequest(req *SealedRequest) ([]string, string) {
	validOps := map[string]bool{
		"prepare-reseal": true, "reseal": true, "extract-for-signing": true, "inject-signed": true,
	}
	var stages []string
	if len(req.Stages) > 0 {
		stages = req.Stages
		for _, op := range stages {
			if !validOps[op] {
				return nil, "stages must contain only: prepare-reseal, reseal, extract-for-signing, inject-signed"
			}
		}
	} else if req.Operation != "" {
		if !validOps[string(req.Operation)] {
			return nil, "operation must be one of: prepare-reseal, reseal, extract-for-signing, inject-signed"
		}
		stages = []string{string(req.Operation)}
	} else {
		return nil, "operation or stages is required"
	}
	if strings.TrimSpace(req.InputRef) == "" {
		return nil, "inputRef is required"
	}
	if err := validateContainerRef(req.InputRef); err != nil {
		return nil, fmt.Sprintf("invalid inputRef: %v", err)
	}
	if strings.TrimSpace(req.OutputRef) != "" {
		if err := validateContainerRef(req.OutputRef); err != nil {
			return nil, fmt.Sprintf("invalid outputRef: %v", err)
		}
	}
	if strings.TrimSpace(req.SignedRef) != "" {
		if err := validateContainerRef(req.SignedRef); err != nil {
			return nil, fmt.Sprintf("invalid signedRef: %v", err)
		}
	}
	for _, op := range stages {
		if op == "inject-signed" && strings.TrimSpace(req.SignedRef) == "" {
			return nil, "signedRef is required when inject-signed is in stages"
		}
	}
	if req.Name == "" {
		req.Name = fmt.Sprintf("%s-%s", stages[0], uuid.New().String()[:5])
	}
	if err := validateBuildName(req.Name); err != nil {
		return nil, err.Error()
	}
	return stages, ""
}

func (a *APIServer) registerSealedRoutes(v1 *gin.RouterGroup) {
	for _, opPath := range []string{"/prepare-reseals", "/reseals", "/extract-for-signings", "/inject-signeds"} {
		grp := v1.Group(opPath)
		grp.Use(sealedMetricsMiddleware(), a.authMiddleware())
		{
			grp.POST("", a.handleCreateSealed)
			grp.GET("", a.wrapHandler("list reseal jobs", a.listSealed))
			grp.GET("/:name", a.wrapNamedHandler("get reseal", a.getSealed))
			grp.GET("/:name/logs", a.wrapNamedHandler("reseal logs requested", a.streamSealedLogs))
		}
	}
}

func (a *APIServer) handleCreateSealed(c *gin.Context) {
	op := resolveSealedOperation(c)
	a.log.Info("create reseal", "operation", op, "reqID", c.GetString("reqID"))
	a.createSealed(c, op)
}

func (a *APIServer) createSealed(c *gin.Context, pathOp SealedOperation) {
	ctx, span := apiTracer.Start(c.Request.Context(), "createSealed")
	defer span.End()
	opLabel := sealedOperationLabel(pathOp, nil)

	var req SealedRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		spanError(span, err)
		SealedCreateRequestsTotal.WithLabelValues(opLabel, "bad_request").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid JSON request"})
		return
	}

	// Auto-set operation from the URL path if the request body doesn't specify one
	if req.Operation == "" && len(req.Stages) == 0 {
		req.Operation = pathOp
	}

	stages, errMsg := validateSealedRequest(&req)
	if errMsg != "" {
		spanError(span, errors.New(errMsg))
		SealedCreateRequestsTotal.WithLabelValues(opLabel, "bad_request").Inc()
		c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
		return
	}
	opLabel = sealedOperationLabel(req.Operation, stages)
	span.SetAttributes(
		attribute.String("sealed.name", req.Name),
		attribute.String("sealed.operation", opLabel),
	)

	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		spanError(span, err)
		SealedCreateRequestsTotal.WithLabelValues(opLabel, "error").Inc()
		return
	}
	clientset, err := getClientsetOrFail(c)
	if err != nil {
		spanError(span, err)
		SealedCreateRequestsTotal.WithLabelValues(opLabel, "error").Inc()
		return
	}
	namespace := resolveNamespace()
	requestedBy := a.resolveRequester(c)

	refs, err := createSealedSecrets(ctx, clientset, namespace, &req)
	if err != nil {
		if k8serrors.IsAlreadyExists(err) {
			spanError(span, err)
			SealedCreateRequestsTotal.WithLabelValues(opLabel, "conflict").Inc()
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("job %s already exists", req.Name)})
			return
		}
		spanError(span, err)
		SealedCreateRequestsTotal.WithLabelValues(opLabel, "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	aibImage := req.AIBImage
	if aibImage == "" {
		aibImage = automotivev1alpha1.DefaultAutomotiveImageBuilderImage
	}

	imageSealed := &automotivev1alpha1.ImageReseal{
		ObjectMeta: metav1.ObjectMeta{
			Name:      req.Name,
			Namespace: namespace,
			Labels: map[string]string{
				labels.ManagedBy: labels.ValueBuildAPI,
				labels.PartOf:    labels.ValueAutomotiveDev,
			},
			Annotations: map[string]string{
				labels.RequestedBy: requestedBy,
			},
		},
		Spec: automotivev1alpha1.ImageResealSpec{
			Operation:            string(req.Operation),
			Stages:               stages,
			InputRef:             req.InputRef,
			OutputRef:            req.OutputRef,
			SignedRef:            req.SignedRef,
			AIBImage:             aibImage,
			BuilderImage:         req.BuilderImage,
			Architecture:         req.Architecture,
			StorageClass:         req.StorageClass,
			SecretRef:            refs.secretRef,
			KeySecretRef:         refs.keySecretRef,
			KeyPasswordSecretRef: refs.keyPasswordSecretRef,
			AIBExtraArgs:         req.AIBExtraArgs,
		},
	}

	if err := k8sClient.Create(ctx, imageSealed); err != nil {
		cleanupSealedSecrets(ctx, clientset, namespace, &req, refs)
		if k8serrors.IsAlreadyExists(err) {
			spanError(span, err)
			SealedCreateRequestsTotal.WithLabelValues(opLabel, "conflict").Inc()
			c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("job %s already exists", req.Name)})
			return
		}
		spanError(span, err)
		SealedCreateRequestsTotal.WithLabelValues(opLabel, "error").Inc()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to create ImageReseal: %v", err)})
		return
	}

	for _, secretName := range transientSealedSecretRefs(&req, refs) {
		if err := setImageResealSecretOwnerRef(ctx, clientset, namespace, secretName, imageSealed); err != nil {
			a.log.Error(err, "failed to set owner reference on sealed secret", "secret", secretName, "job", imageSealed.Name)
		}
	}
	SealedCreateRequestsTotal.WithLabelValues(opLabel, "accepted").Inc()

	writeJSON(c, http.StatusAccepted, SealedResponse{
		Name:        req.Name,
		Phase:       phasePending,
		Message:     "Reseal job created",
		RequestedBy: requestedBy,
		OutputRef:   req.OutputRef,
	})
}

func (a *APIServer) listSealed(c *gin.Context) {
	ctx, span := apiTracer.Start(c.Request.Context(), "listSealed")
	defer span.End()

	namespace := resolveNamespace()
	limit, offset := parsePagination(c)

	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		spanError(span, err)
		return
	}
	list := &automotivev1alpha1.ImageResealList{}
	if err := k8sClient.List(ctx, list, client.InNamespace(namespace)); err != nil {
		spanError(span, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to list ImageReseal: %v", err)})
		return
	}
	// Sort by creation time, newest first
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[j].CreationTimestamp.Before(&list.Items[i].CreationTimestamp)
	})

	page := applyPagination(list.Items, limit, offset)

	resp := make([]SealedListItem, 0, len(page))
	for _, s := range page {
		var compStr string
		if s.Status.CompletionTime != nil {
			compStr = s.Status.CompletionTime.Format(time.RFC3339)
		}
		resp = append(resp, SealedListItem{
			Name:           s.Name,
			Phase:          s.Status.Phase,
			Message:        s.Status.Message,
			RequestedBy:    s.Annotations[labels.RequestedBy],
			CreatedAt:      s.CreationTimestamp.Format(time.RFC3339),
			CompletionTime: compStr,
		})
	}
	writeJSON(c, http.StatusOK, resp)
}

func (a *APIServer) getSealed(c *gin.Context, name string) {
	ctx, span := apiTracer.Start(c.Request.Context(), "getSealed")
	defer span.End()
	span.SetAttributes(attribute.String("sealed.name", name))

	namespace := resolveNamespace()
	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		spanError(span, err)
		return
	}
	sealed := &automotivev1alpha1.ImageReseal{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, sealed, "job"); err != nil {
		spanError(span, err)
		return
	}
	var startStr, compStr string
	if sealed.Status.StartTime != nil {
		startStr = sealed.Status.StartTime.Format(time.RFC3339)
	}
	if sealed.Status.CompletionTime != nil {
		compStr = sealed.Status.CompletionTime.Format(time.RFC3339)
	}
	writeJSON(c, http.StatusOK, SealedResponse{
		Name:            sealed.Name,
		Phase:           sealed.Status.Phase,
		Message:         sealed.Status.Message,
		RequestedBy:     sealed.Annotations[labels.RequestedBy],
		StartTime:       startStr,
		CompletionTime:  compStr,
		TaskRunName:     sealed.Status.TaskRunName,
		PipelineRunName: sealed.Status.PipelineRunName,
		OutputRef:       sealed.Status.OutputRef,
	})
}

func (a *APIServer) streamSealedLogs(c *gin.Context, name string) {
	ctx, span := apiTracer.Start(c.Request.Context(), "streamSealedLogs")
	defer span.End()
	span.SetAttributes(attribute.String("sealed.name", name))

	namespace := resolveNamespace()
	k8sClient, err := getK8sClientOrFail(c)
	if err != nil {
		spanError(span, err)
		return
	}
	clientset, err := getClientsetOrFail(c)
	if err != nil {
		spanError(span, err)
		return
	}
	sealed := &automotivev1alpha1.ImageReseal{}
	if err := getResourceOrFail(ctx, c, k8sClient, name, namespace, sealed, "job"); err != nil {
		spanError(span, err)
		return
	}
	var taskRun *tektonv1.TaskRun
	if sealed.Status.TaskRunName != "" {
		tr := &tektonv1.TaskRun{}
		if err := k8sClient.Get(ctx, types.NamespacedName{Name: sealed.Status.TaskRunName, Namespace: namespace}, tr); err != nil {
			if k8serrors.IsNotFound(err) {
				c.JSON(http.StatusServiceUnavailable, gin.H{"error": "TaskRun not found yet"})
				return
			}
			spanError(span, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		taskRun = tr
	} else if sealed.Status.PipelineRunName != "" {
		trList := &tektonv1.TaskRunList{}
		if err := k8sClient.List(ctx, trList, client.InNamespace(namespace), client.MatchingLabels{"tekton.dev/pipelineRun": sealed.Status.PipelineRunName}); err != nil {
			spanError(span, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if len(trList.Items) == 0 {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "pipeline not ready (no TaskRuns yet)"})
			return
		}
		taskRun = &trList.Items[0]
	} else {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "job not ready (no TaskRun or PipelineRun yet)"})
		return
	}
	podName := taskRun.Status.PodName
	if podName == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "pod not ready"})
		return
	}
	sinceTime := parseSinceTime(c.Query("since"))
	streamDuration := time.Duration(a.limits.MaxLogStreamDurationMinutes) * time.Minute
	streamCtx, cancel := context.WithTimeout(ctx, streamDuration)
	defer cancel()
	setupLogStreamHeaders(c)
	containerName := "step-run-op"

	// Retry getting the log stream if the container is still initializing
	var stream io.ReadCloser
	for range 30 {
		req := clientset.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
			Container: containerName,
			Follow:    true,
			SinceTime: sinceTime,
		})
		s, err := req.Stream(streamCtx)
		if err == nil {
			stream = s
			break
		}
		errMsg := err.Error()
		if strings.Contains(errMsg, "PodInitializing") || strings.Contains(errMsg, "is waiting to start") || strings.Contains(errMsg, "ContainerCreating") {
			select {
			case <-streamCtx.Done():
				fmt.Fprintf(c.Writer, "\n[Error: timed out waiting for container to start]\n") //nolint:errcheck
				c.Writer.Flush()
				return
			case <-time.After(2 * time.Second):
				continue
			}
		}
		_, _ = fmt.Fprintf(c.Writer, "\n[Error streaming logs: %v]\n", err)
		c.Writer.Flush()
		return
	}
	if stream == nil {
		fmt.Fprintf(c.Writer, "\n[Error: container did not start in time]\n") //nolint:errcheck
		c.Writer.Flush()
		return
	}
	defer func() {
		if err := stream.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to close stream: %v\n", err)
		}
	}()
	_, _ = c.Writer.Write([]byte("\n===== TaskRun Logs =====\n\n"))
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
		fmt.Fprintf(c.Writer, "\n[Stream error: %v]\n", err) //nolint:errcheck
		c.Writer.Flush()
	}
	_, _ = c.Writer.Write([]byte("\n[Log streaming completed]\n"))
	c.Writer.Flush()
}
