// Package imagebuild provides the controller for managing ImageBuild custom resources.
package imagebuild

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/bundleverify"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/registryutil"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/featuregates"
	"github.com/go-logr/logr"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	routev1 "github.com/openshift/api/route/v1"
	ociremote "github.com/sigstore/cosign/v3/pkg/oci/remote"
	pod "github.com/tektoncd/pipeline/pkg/apis/pipeline/pod"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kuberneteslib "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

var ibTracer = otel.Tracer("imagebuild-controller")

const (
	// Phase constants — aliases for readability; canonical values in api/v1alpha1
	phaseBuilding  = automotivev1alpha1.ImageBuildPhaseBuilding
	phaseCancelled = automotivev1alpha1.ImageBuildPhaseCancelled
	phaseCompleted = automotivev1alpha1.ImageBuildPhaseCompleted
	phaseFailed    = automotivev1alpha1.ImageBuildPhaseFailed

	// Tekton condition type for completion status
	conditionSucceeded = "Succeeded"

	maxK8sNameLength = 63
)

// digestPinnedRef matches an OCI reference with a sha256 digest.
var digestPinnedRef = regexp.MustCompile(`^.+@sha256:[a-fA-F0-9]{64}$`)

const (
	eventReasonBuildExpired     = "BuildExpired"
	eventReasonPhaseChanged     = "PhaseChanged"
	eventReasonPipelineRunReady = "PipelineRunReady"
	eventReasonUploadPodReady   = "UploadPodReady"
	eventReasonBuildCompleted   = "BuildCompleted"
	eventReasonBuildStarted     = "BuildStarted"
	eventReasonBuildRunning     = "BuildRunning"
	eventReasonBuildFailed      = "BuildFailed"
	eventReasonUploadStarted    = "UploadStarted"
	eventReasonDiskBuildStarted = "DiskBuildStarted"
	eventReasonDiskBuildRunning = "DiskBuildRunning"
	eventReasonDiskBuildFailed  = "DiskBuildFailed"
	eventReasonDiskBuildDone    = "DiskBuildCompleted"
)

var isTerminalPhase = automotivev1alpha1.IsTerminalBuildPhase

// safeDerivedName generates a Kubernetes-safe derived resource name by truncating
// the base name and appending a hash to preserve uniqueness. The final name will
// never exceed maxK8sNameLength (63 chars for DNS label names) characters.
func safeDerivedName(baseName, suffix string) string {
	maxBaseLength := maxK8sNameLength - len(suffix) - 9

	if maxBaseLength >= len(baseName) {
		return fmt.Sprintf("%s%s", baseName, suffix)
	}

	hash := sha256.Sum256([]byte(baseName))
	hexHash := fmt.Sprintf("%x", hash[:4]) // 8-char hex

	if maxBaseLength <= 0 {
		// suffix + hash overhead exceed the limit; use hex hash + suffix only
		name := hexHash + suffix
		if len(name) > maxK8sNameLength {
			name = name[:maxK8sNameLength]
		}
		return name
	}

	truncated := baseName[:maxBaseLength]
	return fmt.Sprintf("%s-%s%s", truncated, hexHash, suffix)
}

func getTraceID(imageBuild *automotivev1alpha1.ImageBuild) string {
	if imageBuild.Annotations != nil {
		return imageBuild.Annotations[automotivev1alpha1.AnnotationTraceID]
	}
	return ""
}

func buildLabels(imageBuild *automotivev1alpha1.ImageBuild, taskType string) map[string]string {
	labels := map[string]string{
		tektonv1.ManagedByLabelKey:             "automotive-dev-operator",
		automotivev1alpha1.LabelImageBuildName: imageBuild.Name,
		automotivev1alpha1.LabelDistro:         controllerutils.SanitizeLabelValue(imageBuild.Spec.GetDistro()),
		automotivev1alpha1.LabelArchitecture:   controllerutils.SanitizeLabelValue(imageBuild.Spec.Architecture),
		automotivev1alpha1.LabelTarget:         controllerutils.SanitizeLabelValue(imageBuild.Spec.GetTarget()),
		automotivev1alpha1.LabelBuildMode:      controllerutils.SanitizeLabelValue(imageBuild.Spec.GetMode()),
	}
	if traceID := getTraceID(imageBuild); traceID != "" {
		labels[automotivev1alpha1.LabelTraceID] = traceID
	}
	if taskType != "" {
		labels[automotivev1alpha1.LabelTaskType] = taskType
	}
	return labels
}

func ensureTraceID(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) string {
	if id := getTraceID(imageBuild); id != "" {
		return id
	}
	if imageBuild.Annotations == nil {
		imageBuild.Annotations = map[string]string{}
	}

	// Use the OTel trace ID from the active span when tracing is enabled.
	// When tracing is disabled (noop provider), generate a random trace ID
	// in the same 32-hex-char format so log correlation always works and
	// the value matches OTel conventions if tracing is enabled later.
	sc := trace.SpanFromContext(ctx).SpanContext()
	var id string
	if sc.TraceID().IsValid() {
		id = sc.TraceID().String()
	} else {
		id = generateTraceID()
	}

	imageBuild.Annotations[automotivev1alpha1.AnnotationTraceID] = id
	return id
}

func generateTraceID() string {
	var tid trace.TraceID
	_, _ = rand.Read(tid[:])
	return tid.String()
}

func (r *ImageBuildReconciler) buildLogger(imageBuild *automotivev1alpha1.ImageBuild) logr.Logger {
	log := r.Log.WithValues("imagebuild", types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace})
	if traceID := getTraceID(imageBuild); traceID != "" {
		log = log.WithValues("traceID", traceID)
	}
	return log
}

// ImageBuildReconciler reconciles a ImageBuild object
//
//nolint:revive // Name follows Kubebuilder convention for reconcilers
type ImageBuildReconciler struct {
	client.Client
	APIReader  client.Reader
	Scheme     *runtime.Scheme
	Log        logr.Logger
	Recorder   record.EventRecorder
	RestConfig *rest.Config
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=workspaces,verbs=get;update
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=imagebuilds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=imagebuilds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=imagebuilds/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch;create
// +kubebuilder:rbac:groups="",namespace=system,resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=persistentvolumeclaims,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=secrets,verbs=get;list;watch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=serviceaccounts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=serviceaccounts/token,verbs=create
// +kubebuilder:rbac:groups=image.openshift.io,namespace=system,resources=imagestreams,verbs=get;create;update;delete
// +kubebuilder:rbac:groups=image.openshift.io,namespace=system,resources=imagestreamtags,verbs=delete
// +kubebuilder:rbac:groups=tekton.dev,namespace=system,resources=tasks;pipelines;pipelineruns;taskruns,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=pods,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=pods/exec,verbs=create;get
// +kubebuilder:rbac:groups="",namespace=system,resources=pods/log,verbs=get
// +kubebuilder:rbac:groups="",namespace=system,resources=services,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=route.openshift.io,resources=routes,verbs=get
// +kubebuilder:rbac:groups=route.openshift.io,namespace=system,resources=routes,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups="",namespace=system,resources=events,verbs=create;patch

// Reconcile handles ImageBuild reconciliation and manages the build lifecycle
func (r *ImageBuildReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.Reconcile",
		trace.WithAttributes(
			attribute.String("imagebuild.name", req.Name),
			attribute.String("imagebuild.namespace", req.Namespace),
		),
	)
	defer controllerutils.EndSpanWithError(span, &err)

	log := r.Log.WithValues("imagebuild", req.NamespacedName)

	imageBuild := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, req.NamespacedName, imageBuild); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if getTraceID(imageBuild) == "" {
		ensureTraceID(ctx, imageBuild)
		if err := r.Update(ctx, imageBuild); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to set trace-id annotation: %w", err)
		}
	}
	log = log.WithValues("traceID", getTraceID(imageBuild))

	span.SetAttributes(
		attribute.String("imagebuild.phase", imageBuild.Status.Phase),
	)

	expiryResult, expired, expiryErr := r.checkExpiry(ctx, imageBuild)
	if expired || expiryErr != nil {
		return expiryResult, expiryErr
	}

	var phaseResult ctrl.Result
	var phaseErr error
	switch imageBuild.Status.Phase {
	case "":
		phaseResult, phaseErr = r.handleInitialState(ctx, imageBuild)
	case "Uploading":
		phaseResult, phaseErr = r.handleUploadingState(ctx, imageBuild)
	case phaseBuilding:
		phaseResult, phaseErr = r.handleBuildingState(ctx, imageBuild)
	case "Pushing":
		phaseResult, phaseErr = r.handlePushingState(ctx, imageBuild)
	case "Flashing":
		phaseResult, phaseErr = r.handleFlashingState(ctx, imageBuild)
	case phaseCompleted:
		phaseResult = r.handleCompletedState(ctx, imageBuild)
	case automotivev1alpha1.ImageBuildPhaseExpired:
		phaseResult = r.handleExpiredState(ctx, imageBuild)
	case phaseCancelled, phaseFailed:
		if shutdownErr := r.shutdownUploadPod(ctx, imageBuild); shutdownErr != nil {
			log.Error(shutdownErr, "Failed to shutdown upload pod, will retry")
			phaseResult = ctrl.Result{RequeueAfter: secretCleanupRequeue}
		} else if cleanupErr := r.cleanupTransientSecrets(ctx, imageBuild, r.Log); cleanupErr != nil {
			log.Error(cleanupErr, "Failed to cleanup transient secrets, will retry")
			phaseResult = ctrl.Result{RequeueAfter: secretCleanupRequeue}
		}
	default:
		log.Info("Unknown phase", "phase", imageBuild.Status.Phase)
	}
	if traceID := getTraceID(imageBuild); traceID != "" {
		span.SetAttributes(attribute.String("imagebuild.trace_id", traceID))
	}

	if phaseErr != nil {
		return phaseResult, phaseErr
	}

	if expiryResult.RequeueAfter > 0 &&
		(phaseResult.RequeueAfter == 0 || expiryResult.RequeueAfter < phaseResult.RequeueAfter) {
		phaseResult.RequeueAfter = expiryResult.RequeueAfter
	}
	return phaseResult, nil
}

// ensureImageStreamOwnerRef adds a non-controller owner reference from the
// ImageBuild to the ImageStream used by the internal registry, so that the
// ImageStream is garbage collected when all owning ImageBuilds are deleted.
func (r *ImageBuildReconciler) ensureImageStreamOwnerRef(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) error {
	if !imageBuild.Spec.GetUseServiceAccountAuth() {
		return nil
	}

	streamName := extractImageStreamName(imageBuild)
	if streamName == "" {
		return nil
	}

	log := r.buildLogger(imageBuild)

	is := &unstructured.Unstructured{}
	is.SetGroupVersionKind(schema.GroupVersionKind{
		Group:   "image.openshift.io",
		Version: "v1",
		Kind:    "ImageStream",
	})

	if err := r.Get(ctx, types.NamespacedName{
		Name:      streamName,
		Namespace: imageBuild.Namespace,
	}, is); err != nil {
		if errors.IsNotFound(err) {
			log.Info("ImageStream not found, skipping owner ref", "imageStream", streamName)
			return nil
		}
		return fmt.Errorf("failed to get ImageStream %s: %w", streamName, err)
	}

	existingCount := len(is.GetOwnerReferences())

	if err := controllerutil.SetOwnerReference(imageBuild, is, r.Scheme); err != nil {
		return fmt.Errorf("failed to set owner reference on ImageStream %s: %w", streamName, err)
	}

	// Skip the Update if SetOwnerReference didn't add a new entry
	if len(is.GetOwnerReferences()) == existingCount {
		return nil
	}

	if err := r.Update(ctx, is); err != nil {
		return fmt.Errorf("failed to update ImageStream %s with owner reference: %w", streamName, err)
	}

	log.Info("Set owner reference on ImageStream", "imageStream", streamName)
	return nil
}

// extractInternalImageStreamTags returns ImageStreamTag names ("name:tag") for
// any internal registry URLs in the ImageBuild's export configuration.
func extractInternalImageStreamTags(imageBuild *automotivev1alpha1.ImageBuild) []string {
	prefix := tasks.DefaultInternalRegistryURL + "/"
	refs := []string{imageBuild.Spec.GetContainerPush(), imageBuild.Spec.GetExportOCI()}
	tags := make([]string, 0, len(refs))
	for _, ref := range refs {
		after, ok := strings.CutPrefix(ref, prefix)
		if !ok {
			continue
		}
		parts := strings.SplitN(after, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			continue
		}
		ist := parts[1]
		if !strings.Contains(ist, ":") {
			ist += ":latest"
		}
		tags = append(tags, ist)
	}
	return tags
}

func extractImageStreamName(imageBuild *automotivev1alpha1.ImageBuild) string {
	tags := extractInternalImageStreamTags(imageBuild)
	if len(tags) == 0 {
		return ""
	}
	name, _, _ := strings.Cut(tags[0], ":")
	return name
}

func (r *ImageBuildReconciler) handleInitialState(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (result ctrl.Result, err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.HandleInitialState")
	defer controllerutils.EndSpanWithError(span, &err)

	log := r.buildLogger(imageBuild)

	if err := r.ensureImageStreamOwnerRef(ctx, imageBuild); err != nil {
		return ctrl.Result{}, err
	}

	if imageBuild.Spec.GetInputFilesServer() {
		if err := r.createUploadPod(ctx, imageBuild); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to create upload server: %w", err)
		}
		if err := r.updateStatus(ctx, imageBuild, "Uploading", "Waiting for file uploads"); err != nil {
			log.Error(err, "Failed to update status to Uploading")
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}

	if err := r.updateStatus(ctx, imageBuild, phaseBuilding, "Build started"); err != nil {
		log.Error(err, "Failed to update status to Building")
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil
}

func (r *ImageBuildReconciler) handleUploadingState(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (result ctrl.Result, err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.HandleUploadingState")
	defer controllerutils.EndSpanWithError(span, &err)

	log := r.buildLogger(imageBuild)

	// Fail the build if uploads have not completed within the configured timeout
	uploadTimeout := 30 * time.Minute // default
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: "config", Namespace: controllerutils.OperatorNamespace()}, operatorConfig); err == nil {
		if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.UploadTimeoutMinutes > 0 {
			uploadTimeout = time.Duration(operatorConfig.Spec.OSBuilds.UploadTimeoutMinutes) * time.Minute
		}
	}
	if time.Since(imageBuild.CreationTimestamp.Time) > uploadTimeout {
		log.Info("Upload timed out", "age", time.Since(imageBuild.CreationTimestamp.Time), "timeout", uploadTimeout)
		cleanupErr := r.cleanupTransientSecrets(ctx, imageBuild, r.Log)
		if err := r.shutdownUploadPod(ctx, imageBuild); err != nil {
			log.Error(err, "Failed to shutdown upload pod during timeout cleanup")
		}
		timeoutMinutes := int(uploadTimeout.Minutes())
		if err := r.updateStatus(ctx, imageBuild, phaseFailed,
			fmt.Sprintf("Upload timed out: file uploads were not completed within %d minutes", timeoutMinutes)); err != nil {
			log.Error(err, "Failed to update status to Failed")
			return ctrl.Result{}, err
		}
		if cleanupErr != nil {
			return ctrl.Result{RequeueAfter: secretCleanupRequeue}, nil
		}
		return ctrl.Result{}, nil
	}

	uploadsComplete := imageBuild.Annotations != nil &&
		imageBuild.Annotations["automotive.sdv.cloud.redhat.com/uploads-complete"] == "true"

	if !uploadsComplete {
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	if err := r.shutdownUploadPod(ctx, imageBuild); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to shutdown upload server: %w", err)
	}

	if err := r.updateStatus(ctx, imageBuild, phaseBuilding, "Build started"); err != nil {
		log.Error(err, "Failed to update status to Building")
		return ctrl.Result{}, err
	}
	return ctrl.Result{Requeue: true}, nil
}

func (r *ImageBuildReconciler) handleBuildingState(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (result ctrl.Result, err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.HandleBuildingState")
	defer controllerutils.EndSpanWithError(span, &err)
	log := r.buildLogger(imageBuild)

	if imageBuild.Status.PipelineRunName != "" {
		return r.checkBuildProgress(ctx, imageBuild)
	}

	// Look for existing PipelineRuns for this ImageBuild
	pipelineRunList := &tektonv1.PipelineRunList{}
	if err := r.List(ctx, pipelineRunList,
		client.InNamespace(imageBuild.Namespace),
		client.MatchingLabels{
			"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
		}); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to list existing pipeline runs: %w", err)
	}

	for _, pr := range pipelineRunList.Items {
		if pr.DeletionTimestamp == nil {
			log.Info("Found existing PipelineRun for this ImageBuild", "pipelineRun", pr.Name)

			latestImageBuild := &automotivev1alpha1.ImageBuild{}
			if err := r.Get(ctx, types.NamespacedName{
				Name:      imageBuild.Name,
				Namespace: imageBuild.Namespace,
			}, latestImageBuild); err != nil {
				log.Error(err, "Failed to get latest ImageBuild")
				return ctrl.Result{}, err
			}

			// Only update status if PipelineRunName is not already set
			if latestImageBuild.Status.PipelineRunName != pr.Name {
				latestImageBuild.Status.PipelineRunName = pr.Name
				if err := r.Status().Update(ctx, latestImageBuild); err != nil {
					log.Error(err, "Failed to update ImageBuild with PipelineRun name")
					return ctrl.Result{}, err
				}
			}

			// Update local imageBuild and immediately check build progress
			imageBuild.Status.PipelineRunName = pr.Name
			return r.checkBuildProgress(ctx, imageBuild)
		}
	}

	return r.startNewBuild(ctx, imageBuild)
}

// checkExpiry returns (result, expired, error). Caller should return immediately if expired.
func (r *ImageBuildReconciler) checkExpiry(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (ctrl.Result, bool, error) {
	log := r.buildLogger(imageBuild)

	if imageBuild.Status.Phase == automotivev1alpha1.ImageBuildPhaseExpired {
		return ctrl.Result{}, false, nil
	}

	if imageBuild.Annotations[automotivev1alpha1.NoExpireAnnotation] == "true" ||
		imageBuild.Spec.Workspace != "" {
		if err := r.updateExpiresAt(ctx, imageBuild, nil); err != nil {
			return ctrl.Result{}, false, err
		}
		return ctrl.Result{}, false, nil
	}

	ttl, err := r.resolveEffectiveTTL(ctx, imageBuild)
	if err != nil {
		log.Error(err, "Failed to resolve TTL, skipping expiry check")
		r.emitEventf(imageBuild, corev1.EventTypeWarning, "InvalidTTL",
			"Failed to resolve TTL, expiry disabled for this build: %v", err)
		return ctrl.Result{}, false, nil
	}
	if ttl == 0 {
		if err := r.updateExpiresAt(ctx, imageBuild, nil); err != nil {
			return ctrl.Result{}, false, err
		}
		return ctrl.Result{}, false, nil
	}

	if imageBuild.Status.CompletionTime == nil {
		return ctrl.Result{}, false, nil
	}
	anchor := imageBuild.Status.CompletionTime.Time

	expiresAt := anchor.Add(ttl)
	remaining := time.Until(expiresAt)

	if err := r.updateExpiresAt(ctx, imageBuild, &expiresAt); err != nil {
		return ctrl.Result{}, false, err
	}

	if remaining > 0 {
		log.Info("Build not yet expired", "expiresAt", expiresAt, "remaining", remaining.Truncate(time.Second))
		return ctrl.Result{RequeueAfter: remaining}, false, nil
	}

	log.Info("Build expired, transitioning to Expired phase", "ttl", ttl, "anchor", anchor,
		"previousPhase", imageBuild.Status.Phase)
	r.emitEventf(imageBuild, corev1.EventTypeNormal, eventReasonBuildExpired,
		"Build expired after %s, cleaning up resources", ttl)

	if err := r.updateStatus(ctx, imageBuild, automotivev1alpha1.ImageBuildPhaseExpired,
		fmt.Sprintf("Build expired after %s", ttl)); err != nil {
		return ctrl.Result{}, false, fmt.Errorf("failed to transition expired build: %w", err)
	}
	return ctrl.Result{}, true, nil
}

// resolveEffectiveTTL returns 0 if expiry is disabled.
func (r *ImageBuildReconciler) resolveEffectiveTTL(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (time.Duration, error) {
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, types.NamespacedName{
		Name: "config", Namespace: controllerutils.OperatorNamespace(),
	}, operatorConfig); err != nil && !errors.IsNotFound(err) {
		return 0, fmt.Errorf("failed to load OperatorConfig: %w", err)
	}
	return controllerutils.ResolveBuildTTL(imageBuild.Spec.GetTTL(), operatorConfig.Spec.OSBuilds)
}

// updateExpiresAt sets or clears status.ExpiresAt. Pass nil to clear.
func (r *ImageBuildReconciler) updateExpiresAt(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
	expiresAt *time.Time,
) error {
	desired, needsUpdate := controllerutils.ComputeExpiresAt(imageBuild.Status.ExpiresAt, expiresAt)
	if !needsUpdate {
		return nil
	}
	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{
		Name: imageBuild.Name, Namespace: imageBuild.Namespace,
	}, fresh); err != nil {
		return err
	}
	fresh.Status.ExpiresAt = desired
	return r.Status().Update(ctx, fresh)
}

// secretCleanupRequeue is the interval for retrying transient secret deletion
// in terminal state handlers.
const secretCleanupRequeue = 30 * time.Second

func (r *ImageBuildReconciler) handleCompletedState(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) ctrl.Result {
	if err := r.cleanupTransientSecrets(ctx, imageBuild, r.Log); err != nil {
		return ctrl.Result{RequeueAfter: secretCleanupRequeue}
	}
	return ctrl.Result{}
}

func (r *ImageBuildReconciler) handleExpiredState(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) ctrl.Result {
	log := r.buildLogger(imageBuild)

	var retryNeeded bool
	deleteObj := func(obj client.Object, kind string) {
		if err := r.Delete(ctx, obj); err != nil {
			if !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete "+kind, "name", obj.GetName())
				retryNeeded = true
			}
		} else {
			log.Info("Deleted "+kind, "name", obj.GetName())
		}
	}

	ns := imageBuild.Namespace

	if err := r.shutdownUploadPod(ctx, imageBuild); err != nil {
		log.Error(err, "Failed to shutdown upload pod")
		retryNeeded = true
	}

	if name := imageBuild.Status.PipelineRunName; name != "" {
		deleteObj(&tektonv1.PipelineRun{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}, "PipelineRun")
	}
	if name := imageBuild.Status.PushTaskRunName; name != "" {
		deleteObj(&tektonv1.TaskRun{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}, "push TaskRun")
	}
	if name := imageBuild.Status.FlashTaskRunName; name != "" {
		deleteObj(&tektonv1.TaskRun{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}, "flash TaskRun")
	}
	if name := imageBuild.Status.PVCName; name != "" {
		if name == imageBuild.Spec.BuildCachePVC {
			log.Info("Skipping PVC deletion: shared build-cache PVC", "pvc", name)
		} else {
			deleteObj(&corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}, "PVC")
		}
	}

	cmName := safeDerivedName(imageBuild.Name, "-manifest")
	deleteObj(&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: cmName, Namespace: ns}}, "manifest ConfigMap")

	if r.deleteExpiredImageStreams(ctx, imageBuild, log) {
		retryNeeded = true
	}

	if err := r.cleanupTransientSecrets(ctx, imageBuild, log); err != nil {
		retryNeeded = true
	}

	if retryNeeded {
		log.Info("Some expired resources could not be cleaned up, will retry",
			"requeueAfter", secretCleanupRequeue)
		return ctrl.Result{RequeueAfter: secretCleanupRequeue}
	}
	return ctrl.Result{}
}

func (r *ImageBuildReconciler) deleteExpiredImageStreams(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
	log logr.Logger,
) bool {
	var failed bool
	tags := extractInternalImageStreamTags(imageBuild)
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		name, _, _ := strings.Cut(tag, ":")
		if _, ok := seen[name]; ok || name == "" {
			continue
		}
		seen[name] = struct{}{}

		is := &unstructured.Unstructured{}
		is.SetGroupVersionKind(schema.GroupVersionKind{
			Group: "image.openshift.io", Version: "v1", Kind: "ImageStream",
		})
		is.SetName(name)
		is.SetNamespace(imageBuild.Namespace)

		if err := r.Delete(ctx, is); err != nil {
			if !errors.IsNotFound(err) {
				log.Error(err, "Failed to delete ImageStream", "name", name)
				failed = true
			}
		} else {
			log.Info("Deleted ImageStream", "name", name)
		}
	}
	return failed
}

func (r *ImageBuildReconciler) checkBuildProgress(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (result ctrl.Result, err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.CheckBuildProgress")
	defer controllerutils.EndSpanWithError(span, &err)

	log := r.buildLogger(imageBuild)

	pipelineRun := &tektonv1.PipelineRun{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      imageBuild.Status.PipelineRunName,
		Namespace: imageBuild.Namespace,
	}, pipelineRun)
	if err != nil && !errors.IsNotFound(err) {
		return ctrl.Result{}, err
	}

	if errors.IsNotFound(err) {
		return r.startNewBuild(ctx, imageBuild)
	}

	if !isPipelineRunCompleted(pipelineRun) {
		return ctrl.Result{RequeueAfter: time.Second * 30}, nil
	}

	if isPipelineRunSuccessful(pipelineRun) {
		fresh := &automotivev1alpha1.ImageBuild{}
		nsName := types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}
		if err := r.Get(ctx, nsName, fresh); err != nil {
			return ctrl.Result{}, err
		}

		patch := client.MergeFrom(fresh.DeepCopy())

		// Extract and populate build provenance
		aibImageUsed, builderImageUsed := extractProvenance(pipelineRun, fresh.Spec.GetAIBImage())
		fresh.Status.AIBImageUsed = aibImageUsed
		fresh.Status.BuilderImageUsed = builderImageUsed

		// Extract lease ID if flash was enabled
		if fresh.Spec.IsFlashEnabled() {
			fresh.Status.LeaseID = extractLeaseID(pipelineRun)
		}

		// Pipeline includes push-disk-artifact and flash-image tasks (when enabled)
		// Pipeline completion means everything succeeded
		fresh.Status.Phase = phaseCompleted
		if fresh.Spec.IsFlashEnabled() {
			fresh.Status.Message = "Build and flash completed successfully"
		} else {
			fresh.Status.Message = "Build completed successfully"
		}
		if fresh.Status.CompletionTime == nil {
			now := metav1.Now()
			fresh.Status.CompletionTime = &now
		}

		if err := r.Status().Patch(ctx, fresh, patch); err != nil {
			log.Error(err, "Failed to patch status to Completed")
			return ctrl.Result{}, err
		}
		adjustActiveBuildsGauge(phaseBuilding, phaseCompleted)
		recordBuildMetrics(fresh, pipelineRun, buildStatusSuccess)
		if fresh.Spec.IsFlashEnabled() {
			r.recordPipelineFlashMetrics(ctx, fresh, pipelineRun, buildStatusSuccess)
		}

		r.emitEventf(
			fresh,
			corev1.EventTypeNormal,
			eventReasonBuildCompleted,
			"Build completed successfully: mode=%s target=%s arch=%s toDisk=%t pipelineRun=%s",
			fresh.Spec.GetMode(),
			fresh.Spec.GetTarget(),
			fresh.Spec.Architecture,
			fresh.Spec.GetBuildDiskImage(),
			pipelineRun.Name,
		)

		// Cleanup transient secrets
		cleanupErr := r.cleanupTransientSecrets(ctx, imageBuild, r.Log)

		// Write lease back to workspace for reuse by subsequent builds
		if fresh.Spec.Workspace != "" && fresh.Status.LeaseID != "" {
			r.updateWorkspaceLease(ctx, fresh, log)
		}

		if cleanupErr != nil {
			return ctrl.Result{RequeueAfter: secretCleanupRequeue}, nil
		}
		return ctrl.Result{}, nil
	}

	cleanupErr := r.cleanupTransientSecrets(ctx, imageBuild, r.Log)

	if pipelineRun.Spec.Status == tektonv1.PipelineRunSpecStatusCancelled {
		if imageBuild.Status.Phase == phaseCancelled {
			if cleanupErr != nil {
				return ctrl.Result{RequeueAfter: secretCleanupRequeue}, nil
			}
			return ctrl.Result{}, nil
		}
		if err := r.updateStatus(ctx, imageBuild, phaseCancelled, "Build cancelled by user"); err != nil {
			log.Error(err, "Failed to update status to Cancelled")
			return ctrl.Result{}, err
		}
		recordBuildMetrics(imageBuild, pipelineRun, buildStatusFailure)
		if imageBuild.Spec.IsFlashEnabled() {
			r.recordPipelineFlashMetrics(ctx, imageBuild, pipelineRun, buildStatusFailure)
		}
		if cleanupErr != nil {
			return ctrl.Result{RequeueAfter: secretCleanupRequeue}, nil
		}
		return ctrl.Result{}, nil
	}

	if err := r.updateStatus(ctx, imageBuild, phaseFailed, r.pipelineRunFailureDetail(ctx, pipelineRun)); err != nil {
		log.Error(err, "Failed to update status to Failed")
		return ctrl.Result{}, err
	}
	recordBuildMetrics(imageBuild, pipelineRun, buildStatusFailure)
	if imageBuild.Spec.IsFlashEnabled() {
		r.recordPipelineFlashMetrics(ctx, imageBuild, pipelineRun, buildStatusFailure)
	}
	if cleanupErr != nil {
		return ctrl.Result{RequeueAfter: secretCleanupRequeue}, nil
	}
	return ctrl.Result{}, nil
}

func (r *ImageBuildReconciler) startNewBuild(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (result ctrl.Result, err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.StartNewBuild")
	defer controllerutils.EndSpanWithError(span, &err)

	// PVC is now created via VolumeClaimTemplate in createBuildTaskRun
	// to ensure proper zone affinity with WaitForFirstConsumer
	if err := r.createBuildTaskRun(ctx, imageBuild); err != nil {
		// secureBuild validation errors are terminal — set Failed status
		// instead of returning a reconcile error that causes infinite requeue
		if strings.Contains(err.Error(), "secureBuild") {
			msg := fmt.Sprintf("Build configuration error: %v", err)
			if statusErr := r.updateStatus(ctx, imageBuild, phaseFailed, msg); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("failed to create build task run: %w", err)
	}

	return ctrl.Result{RequeueAfter: time.Second * 30}, nil
}

//nolint:gocyclo // Complex PipelineRun builder with many optional fields based on build configuration
func (r *ImageBuildReconciler) createBuildTaskRun(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) error {
	log := r.buildLogger(imageBuild)
	log.Info("Creating PipelineRun for ImageBuild")

	// Fetch OperatorConfig from the operator namespace to get build configuration
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	err := r.Get(ctx, types.NamespacedName{Name: "config", Namespace: controllerutils.OperatorNamespace()}, operatorConfig)
	if err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to get OperatorConfig configuration: %w", err)
	}

	// Fail closed: secureBuild must not silently fall back to the cluster pipeline
	if imageBuild.Spec.SecureBuild && (err != nil || operatorConfig.Spec.OSBuilds == nil) {
		return fmt.Errorf("secureBuild requested but OperatorConfig or spec.osBuilds is not available")
	}

	var buildConfig *tasks.BuildConfig
	if err == nil && operatorConfig.Spec.OSBuilds != nil {
		// Convert OSBuildsConfig to BuildConfig
		buildConfig = &tasks.BuildConfig{
			UseMemoryVolumes:            operatorConfig.Spec.OSBuilds.UseMemoryVolumes,
			MemoryVolumeSize:            operatorConfig.Spec.OSBuilds.MemoryVolumeSize,
			PVCSize:                     operatorConfig.Spec.OSBuilds.PVCSize,
			RuntimeClassName:            operatorConfig.Spec.OSBuilds.RuntimeClassName,
			AutomotiveImageBuilderImage: operatorConfig.Spec.GetImages().GetAutomotiveImageBuilderImage(),
			YQHelperImage:               operatorConfig.Spec.GetImages().GetYQHelperImage(),
			BuildTimeoutMinutes:         operatorConfig.Spec.OSBuilds.GetBuildTimeoutMinutes(),
			FlashTimeoutMinutes:         operatorConfig.Spec.OSBuilds.GetFlashTimeoutMinutes(),
			DefaultLeaseDuration:        operatorConfig.Spec.Jumpstarter.GetDefaultLeaseDuration(),
			UsePVCScratchVolumes:        operatorConfig.Spec.OSBuilds.GetUsePVCScratchVolumes(),
		}
		controllerutils.ApplyTrustedCABundleFromOSBuilds(buildConfig, operatorConfig.Spec.OSBuilds)
		if imageBuild.Spec.SecureBuild {
			// Use the digest-pinned ref snapshotted on the CR by the Build API,
			// not the current OperatorConfig value (which may have changed).
			ref := strings.TrimSpace(imageBuild.Spec.TaskBundleRef)
			if ref == "" {
				return fmt.Errorf("secureBuild requested but taskBundleRef is not set on the ImageBuild")
			}
			if !digestPinnedRef.MatchString(ref) {
				return fmt.Errorf("secureBuild requires a digest-pinned taskBundleRef (must match image@sha256:<64 hex>), got %q", ref)
			}

			if operatorConfig.Spec.OSBuilds.TaskBundleVerify {
				osb := operatorConfig.Spec.OSBuilds
				gates := featuregates.NewFromConfig(&operatorConfig.Spec)
				if osb.TaskBundleCosignKeyless != nil && !gates.Enabled(featuregates.KeylessSignatureVerification) {
					return fmt.Errorf("keyless signature verification is configured but the KeylessSignatureVerification feature gate is not enabled")
				}
				registryOpts := ociremote.WithRemoteOptions(remote.WithAuthFromKeychain(authn.DefaultKeychain))
				if err := bundleverify.VerifyImage(ctx, ref, osb.TaskBundleCosignKeyless, r.Client, osb.TaskBundleCosignKeyRef, controllerutils.OperatorNamespace(), registryOpts); err != nil {
					return fmt.Errorf("task bundle signature verification failed: %w", err)
				}
			}

			buildConfig.TaskResolver = tasks.TaskResolverBundle
			buildConfig.TaskBundleRef = ref

			// Bundle tasks are exported with nil BuildConfig (defaults only).
			// Reject settings that would silently diverge from the bundle.
			if buildConfig.TrustedCABundleName != "" && buildConfig.TrustedCABundleName != tasks.DefaultTrustedCABundleConfigMap {
				return fmt.Errorf("secureBuild: OperatorConfig specifies custom CA bundle %q but bundle tasks use default %q; build a custom bundle or remove the CA override",
					buildConfig.TrustedCABundleName, tasks.DefaultTrustedCABundleConfigMap)
			}
			if buildConfig.TrustedCABundleKind != "" && !strings.EqualFold(buildConfig.TrustedCABundleKind, "ConfigMap") {
				return fmt.Errorf("secureBuild: OperatorConfig specifies CA bundle kind %q but bundle tasks use ConfigMap; build a custom bundle or remove the CA override",
					buildConfig.TrustedCABundleKind)
			}
			if buildConfig.UseMemoryVolumes {
				r.emitEventf(imageBuild, corev1.EventTypeWarning, "SecureBuildConfigDrift",
					"OperatorConfig.useMemoryVolumes is enabled but bundle tasks use disk-backed emptyDir; memory volumes will not apply to this build")
			}
			if buildConfig.UsePVCScratchVolumes {
				r.emitEventf(imageBuild, corev1.EventTypeWarning, "SecureBuildConfigDrift",
					"OperatorConfig.usePVCScratchVolumes is enabled but bundle tasks use emptyDir; PVC scratch will not apply to this build")
			}
		}
	}
	// PVC is created via VolumeClaimTemplate in the PipelineRun workspace binding
	// to ensure proper zone affinity with WaitForFirstConsumer storage class

	params := []tektonv1.Param{
		{
			Name: "arch",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.Architecture,
			},
		},
		{
			Name: "distro",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetDistro(),
			},
		},
		{
			Name: "target",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetTarget(),
			},
		},
		{
			Name: "mode",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetMode(),
			},
		},
		{
			Name: "export-format",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetExportFormat(),
			},
		},
		{
			Name: "automotive-image-builder",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetAIBImage(),
			},
		},
		{
			Name: "compression",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetCompression(),
			},
		},
		{
			Name: "container-push",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetContainerPush(),
			},
		},
		{
			Name: "build-disk-image",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", imageBuild.Spec.GetBuildDiskImage()),
			},
		},
		{
			Name: "export-oci",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetExportOCI(),
			},
		},
		{
			Name: "builder-image",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetBuilderImage(),
			},
		},
		{
			Name: "rebuild-builder",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", imageBuild.Spec.GetRebuildBuilder()),
			},
		},
		{
			Name: "secret-ref",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.SecretRef,
			},
		},
		{
			Name: "use-persistent-cache",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", imageBuild.Spec.BuildCachePVC != ""),
			},
		},
		{
			Name: "secure-build",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", imageBuild.Spec.SecureBuild),
			},
		},
		{
			Name: "insecure-registry",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.InsecureRegistry),
			},
		},
		{
			Name: "reproducible",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", imageBuild.Spec.Reproducible),
			},
		},
		{
			Name: "task-bundle-ref",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.TaskBundleRef,
			},
		},
		{
			Name: "restore-sources-ref",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.RestoreSourcesRef,
			},
		},
		{
			Name: "custom-defines",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: strings.Join(imageBuild.Spec.GetCustomDefs(), "\n"),
			},
		},
		{
			Name: "aib-extra-args",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: strings.Join(imageBuild.Spec.GetAIBExtraArgs(), "\n"),
			},
		},
		{
			Name: "trace-id",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: getTraceID(imageBuild),
			},
		},
	}

	clusterRegistryRoute := ""
	routeReader := r.APIReader
	if routeReader == nil {
		routeReader = r.Client
	}
	if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.ClusterRegistryRoute != "" {
		clusterRegistryRoute = operatorConfig.Spec.OSBuilds.ClusterRegistryRoute
	} else {
		route := &routev1.Route{}
		routeNS := types.NamespacedName{Name: "default-route", Namespace: "openshift-image-registry"}
		if err := routeReader.Get(ctx, routeNS, route); err == nil {
			clusterRegistryRoute = route.Spec.Host
			log.Info("Auto-detected cluster registry route", "route", clusterRegistryRoute)
		}
	}
	if clusterRegistryRoute != "" {
		params = append(params, tektonv1.Param{
			Name: "cluster-registry-route",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: clusterRegistryRoute,
			},
		})

		// build-image handles building the builder image inline
		// when builder-image is empty for bootc builds
	}

	// Add container-ref param for disk mode
	if imageBuild.Spec.GetContainerRef() != "" {
		params = append(params, tektonv1.Param{
			Name: "container-ref",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.GetContainerRef(),
			},
		})
	}

	// Add flash params if flash is enabled
	var flashExporterSelector, flashCmd, flashOCIAuthSecretName string
	if imageBuild.Spec.IsFlashEnabled() {
		flashExporterSelector = imageBuild.Spec.GetFlashExporterSelector()
		target := imageBuild.Spec.GetTarget()
		// Look up target mapping for selector (if not overridden) and flash command
		if operatorConfig.Spec.Jumpstarter != nil {
			if mapping, ok := operatorConfig.Spec.Jumpstarter.TargetMappings[target]; ok {
				if flashExporterSelector == "" {
					flashExporterSelector = mapping.Selector
				}
				flashCmd = mapping.FlashCmd
			}
		}
		if flashExporterSelector == "" {
			return fmt.Errorf("flash enabled but no Jumpstarter target mapping found for target %q; "+
				"configure OperatorConfig.spec.jumpstarter.targetMappings[%q] with selector and flashCmd, "+
				"or set flash.exporterSelector directly", target, target)
		}
		// User-specified flash command overrides OperatorConfig
		if userCmd := imageBuild.Spec.GetFlashCmd(); userCmd != "" {
			flashCmd = userCmd
		}
		// Internal registry references are cluster-internal and not reachable by the flash exporter.
		// Require an external route and fail fast if unavailable.
		if imageBuild.Spec.GetUseServiceAccountAuth() && clusterRegistryRoute == "" {
			return fmt.Errorf(
				"flash with internal registry requires an external registry route; " +
					"set OperatorConfig.spec.osBuilds.clusterRegistryRoute or expose openshift-image-registry/default-route",
			)
		}

		// Resolve the flash image ref — for internal registry builds, translate to external URL.
		flashImageRef := imageBuild.Spec.GetExportOCI()
		flashOCIAuthSecretName = ""
		if imageBuild.Spec.GetUseServiceAccountAuth() && flashImageRef != "" {
			flashImageRef = strings.Replace(flashImageRef,
				tasks.DefaultInternalRegistryURL,
				clusterRegistryRoute, 1)
			// Create a Secret with SA token credentials for the flash exporter
			if r.RestConfig == nil {
				return fmt.Errorf("RestConfig is nil, cannot create flash OCI credentials")
			}
			clientset, err := kuberneteslib.NewForConfig(r.RestConfig)
			if err != nil {
				return fmt.Errorf("failed to create clientset for flash OCI credentials: %w", err)
			}
			expSeconds := int64(4 * 3600)
			tokenReq := &authnv1.TokenRequest{
				Spec: authnv1.TokenRequestSpec{
					ExpirationSeconds: &expSeconds,
				},
			}
			tokenResp, err := clientset.CoreV1().ServiceAccounts(imageBuild.Namespace).
				CreateToken(ctx, automotivev1alpha1.BuildServiceAccountName, tokenReq, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("failed to create SA token for flash OCI credentials: %w", err)
			}
			flashOCIAuthSecretName = imageBuild.Name + "-flash-oci-auth"
			ociSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      flashOCIAuthSecretName,
					Namespace: imageBuild.Namespace,
					Labels: map[string]string{
						"app.kubernetes.io/managed-by":                  "automotive-dev-operator",
						"app.kubernetes.io/part-of":                     "automotive-dev",
						"automotive.sdv.cloud.redhat.com/build-name":    imageBuild.Name,
						"automotive.sdv.cloud.redhat.com/transient":     "true",
						"automotive.sdv.cloud.redhat.com/resource-type": "flash-oci-auth",
					},
					OwnerReferences: []metav1.OwnerReference{
						*metav1.NewControllerRef(imageBuild, automotivev1alpha1.GroupVersion.WithKind("ImageBuild")),
					},
				},
				Type: corev1.SecretTypeOpaque,
				Data: map[string][]byte{
					"username": []byte("serviceaccount"),
					"password": []byte(tokenResp.Status.Token),
				},
			}
			_, err = clientset.CoreV1().Secrets(imageBuild.Namespace).Create(ctx, ociSecret, metav1.CreateOptions{})
			if errors.IsAlreadyExists(err) {
				existing, getErr := clientset.CoreV1().Secrets(imageBuild.Namespace).Get(ctx, ociSecret.Name, metav1.GetOptions{})
				if getErr != nil {
					return fmt.Errorf("failed to get existing flash OCI auth secret: %w", getErr)
				}
				existing.Data = ociSecret.Data
				_, err = clientset.CoreV1().Secrets(imageBuild.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
			}
			if err != nil {
				return fmt.Errorf("failed to create/update flash OCI auth secret: %w", err)
			}
		} else if imageBuild.Spec.SecretRef != "" && flashImageRef != "" {
			// External registry: read credentials from the registry-auth secret and
			// create a flash-oci-auth secret with username/password keys that the
			// flash script expects.
			registrySecret := &corev1.Secret{}
			if err := r.Get(ctx, client.ObjectKey{
				Namespace: imageBuild.Namespace,
				Name:      imageBuild.Spec.SecretRef,
			}, registrySecret); err != nil {
				return fmt.Errorf("failed to read registry secret %q for flash OCI credentials: %w", imageBuild.Spec.SecretRef, err)
			}
			regUser, regPass := extractFlashCredentials(registrySecret, flashImageRef, log)
			if len(regUser) == 0 && len(regPass) == 0 {
				log.Info("No usable credentials found in registry secret for flash OCI auth",
					"secret", imageBuild.Spec.SecretRef)
			} else if len(regUser) > 0 && len(regPass) > 0 {
				flashOCIAuthSecretName = imageBuild.Name + "-flash-oci-auth"
				ociSecret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      flashOCIAuthSecretName,
						Namespace: imageBuild.Namespace,
						Labels: map[string]string{
							"app.kubernetes.io/managed-by":                  "automotive-dev-operator",
							"app.kubernetes.io/part-of":                     "automotive-dev",
							"automotive.sdv.cloud.redhat.com/build-name":    imageBuild.Name,
							"automotive.sdv.cloud.redhat.com/transient":     "true",
							"automotive.sdv.cloud.redhat.com/resource-type": "flash-oci-auth",
						},
						OwnerReferences: []metav1.OwnerReference{
							*metav1.NewControllerRef(imageBuild, automotivev1alpha1.GroupVersion.WithKind("ImageBuild")),
						},
					},
					Type: corev1.SecretTypeOpaque,
					Data: map[string][]byte{
						"username": regUser,
						"password": regPass,
					},
				}
				if err := r.Create(ctx, ociSecret); err != nil {
					if errors.IsAlreadyExists(err) {
						existing := &corev1.Secret{}
						if err := r.Get(ctx, client.ObjectKey{Namespace: imageBuild.Namespace, Name: flashOCIAuthSecretName}, existing); err != nil {
							return fmt.Errorf("failed to get existing flash OCI auth secret: %w", err)
						}
						existing.Data = ociSecret.Data
						if err := r.Update(ctx, existing); err != nil {
							return fmt.Errorf("failed to update flash OCI auth secret: %w", err)
						}
					} else {
						return fmt.Errorf("failed to create flash OCI auth secret from registry credentials: %w", err)
					}
				}
			}
		}

		params = append(params,
			tektonv1.Param{
				Name:  "flash-enabled",
				Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "true"},
			},
			tektonv1.Param{
				Name:  "flash-image-ref",
				Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: flashImageRef},
			},
			tektonv1.Param{
				Name:  "flash-exporter-selector",
				Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: flashExporterSelector},
			},
			tektonv1.Param{
				Name:  "flash-cmd",
				Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: flashCmd},
			},
			tektonv1.Param{
				Name:  "flash-lease-duration",
				Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageBuild.Spec.GetFlashLeaseDuration()},
			},
			tektonv1.Param{
				Name:  "flash-lease-name",
				Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageBuild.Spec.GetFlashLeaseName()},
			},
			tektonv1.Param{
				Name:  "jumpstarter-image",
				Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: operatorConfig.Spec.Jumpstarter.GetJumpstarterImage()},
			},
		)

	}

	// Determine the shared-workspace binding:
	// - If BuildCachePVC is set, use it as the shared workspace for build cache persistence
	// - If InputFilesServer is enabled and a PVC already exists (from upload phase), use it
	// - Otherwise, use VolumeClaimTemplate to create a new PVC with proper zone affinity
	var sharedWorkspaceBinding tektonv1.WorkspaceBinding
	if imageBuild.Spec.BuildCachePVC != "" {
		log.Info("Using build-cache PVC as shared workspace", "pvc", imageBuild.Spec.BuildCachePVC)
		sharedWorkspaceBinding = tektonv1.WorkspaceBinding{
			Name: "shared-workspace",
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: imageBuild.Spec.BuildCachePVC,
			},
		}
	} else if imageBuild.Spec.GetInputFilesServer() && imageBuild.Status.PVCName != "" {
		// Use existing PVC that contains uploaded files
		log.Info("Using existing PVC with uploaded files", "pvc", imageBuild.Status.PVCName)
		sharedWorkspaceBinding = tektonv1.WorkspaceBinding{
			Name: "shared-workspace",
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: imageBuild.Status.PVCName,
			},
		}
	} else {
		// Create new PVC via VolumeClaimTemplate for proper zone affinity
		storageSize := resource.MustParse("8Gi")
		if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.PVCSize != "" {
			storageSize = resource.MustParse(operatorConfig.Spec.OSBuilds.PVCSize)
		}
		var storageClassName *string
		if imageBuild.Spec.StorageClass != "" {
			storageClassName = &imageBuild.Spec.StorageClass
		} else if operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.StorageClass != "" {
			storageClassName = &operatorConfig.Spec.OSBuilds.StorageClass
		}
		sharedWorkspaceBinding = tektonv1.WorkspaceBinding{
			Name: "shared-workspace",
			VolumeClaimTemplate: &corev1.PersistentVolumeClaim{
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					StorageClassName: storageClassName,
					Resources: corev1.VolumeResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceStorage: storageSize,
						},
					},
				},
			},
		}
	}

	// Create an internal ConfigMap from the inline manifest content
	manifestConfigMapName, err := r.createOrUpdateManifestConfigMap(ctx, imageBuild)
	if err != nil {
		return fmt.Errorf("failed to create manifest ConfigMap: %w", err)
	}

	pipelineWorkspaces := []tektonv1.WorkspaceBinding{
		sharedWorkspaceBinding,
		{
			Name: "manifest-config-workspace",
			ConfigMap: &corev1.ConfigMapVolumeSource{
				LocalObjectReference: corev1.LocalObjectReference{
					Name: manifestConfigMapName,
				},
			},
		},
	}

	if imageBuild.Spec.SecretRef != "" {
		pipelineWorkspaces = append(pipelineWorkspaces, tektonv1.WorkspaceBinding{
			Name: "registry-auth",
			Secret: &corev1.SecretVolumeSource{
				SecretName: imageBuild.Spec.SecretRef,
			},
		})
	}

	if imageBuild.Spec.IsFlashEnabled() {
		pipelineWorkspaces = append(pipelineWorkspaces, tektonv1.WorkspaceBinding{
			Name: "jumpstarter-client",
			Secret: &corev1.SecretVolumeSource{
				SecretName: imageBuild.Spec.GetFlashClientConfigSecretRef(),
			},
		})
		if flashOCIAuthSecretName != "" {
			pipelineWorkspaces = append(pipelineWorkspaces, tektonv1.WorkspaceBinding{
				Name: "flash-oci-auth",
				Secret: &corev1.SecretVolumeSource{
					SecretName: flashOCIAuthSecretName,
				},
			})
		}
	}

	nodeAffinity := &corev1.NodeAffinity{
		RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
			NodeSelectorTerms: []corev1.NodeSelectorTerm{
				{
					MatchExpressions: []corev1.NodeSelectorRequirement{
						{
							Key:      corev1.LabelArchStable,
							Operator: corev1.NodeSelectorOpIn,
							Values:   []string{controllerutils.NormalizeArchToK8s(imageBuild.Spec.Architecture)},
						},
					},
				},
			},
		},
	}

	// prepare podTemplate with runtime class fallback
	podTemplate := &pod.PodTemplate{
		Affinity: &corev1.Affinity{NodeAffinity: nodeAffinity},
	}
	if buildConfig != nil && buildConfig.RuntimeClassName != "" {
		podTemplate.RuntimeClassName = &buildConfig.RuntimeClassName
	}
	if operatorConfig.Spec.OSBuilds != nil && len(operatorConfig.Spec.OSBuilds.NodeSelector) > 0 {
		podTemplate.NodeSelector = operatorConfig.Spec.OSBuilds.NodeSelector
	}
	if operatorConfig.Spec.OSBuilds != nil && len(operatorConfig.Spec.OSBuilds.Tolerations) > 0 {
		podTemplate.Tolerations = operatorConfig.Spec.OSBuilds.Tolerations
	}
	if imageBuild.Spec.RuntimeClassName != "" {
		log.Info("Setting RuntimeClassName from ImageBuild spec", "runtimeClassName", imageBuild.Spec.RuntimeClassName)
		podTemplate.RuntimeClassName = &imageBuild.Spec.RuntimeClassName
	}
	pipelineRunSpec := tektonv1.PipelineRunSpec{
		Params:     params,
		Workspaces: pipelineWorkspaces,
		TaskRunTemplate: tektonv1.PipelineTaskRunTemplate{
			PodTemplate:        podTemplate,
			ServiceAccountName: automotivev1alpha1.BuildServiceAccountName,
		},
	}

	if buildConfig != nil && buildConfig.TaskResolver == tasks.TaskResolverBundle {
		pipelineRunSpec.PipelineRef = &tektonv1.PipelineRef{
			ResolverRef: tektonv1.ResolverRef{
				Resolver: tektonv1.ResolverName(tasks.TektonResolverBundles),
				Params: tektonv1.Params{
					{Name: "bundle", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: buildConfig.TaskBundleRef}},
					{Name: "name", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "automotive-build-pipeline"}},
					{Name: "kind", Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: "pipeline"}},
				},
			},
		}
	} else {
		pipelineRunSpec.PipelineRef = &tektonv1.PipelineRef{
			Name: "automotive-build-pipeline",
		}
	}

	pipelineRun := &tektonv1.PipelineRun{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: safeDerivedName(imageBuild.Name, "-build-"),
			Namespace:    imageBuild.Namespace,
			Labels:       buildLabels(imageBuild, "build"),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: imageBuild.APIVersion,
					Kind:       imageBuild.Kind,
					Name:       imageBuild.Name,
					UID:        imageBuild.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: pipelineRunSpec,
	}

	if err := r.Create(ctx, pipelineRun); err != nil {
		return fmt.Errorf("failed to create PipelineRun: %w", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
		return fmt.Errorf("failed to get fresh ImageBuild: %w", err)
	}

	fresh.Status.PipelineRunName = pipelineRun.Name
	if err := r.Status().Update(ctx, fresh); err != nil {
		return fmt.Errorf("failed to update ImageBuild with PipelineRun name: %w", err)
	}
	r.emitEventf(
		fresh,
		corev1.EventTypeNormal,
		eventReasonPipelineRunReady,
		"PipelineRun created: name=%s mode=%s target=%s arch=%s toDisk=%t flash=%t",
		pipelineRun.Name,
		fresh.Spec.GetMode(),
		fresh.Spec.GetTarget(),
		fresh.Spec.Architecture,
		fresh.Spec.GetBuildDiskImage(),
		fresh.Spec.IsFlashEnabled(),
	)

	log.Info("Successfully created PipelineRun", "name", pipelineRun.Name)
	return nil
}

// createOrUpdateManifestConfigMap creates or updates a ConfigMap containing the inline
// manifest content from the ImageBuild spec
func (r *ImageBuildReconciler) createOrUpdateManifestConfigMap(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (string, error) {
	configMapName := safeDerivedName(imageBuild.Name, "-manifest")
	manifestContent := imageBuild.Spec.GetManifest()

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      configMapName,
			Namespace: imageBuild.Namespace,
		},
	}

	_, err := controllerutil.CreateOrUpdate(ctx, r.Client, cm, func() error {
		cm.Labels = map[string]string{
			"app.kubernetes.io/managed-by":                  "automotive-dev-operator",
			"app.kubernetes.io/part-of":                     "automotive-dev",
			"automotive.sdv.cloud.redhat.com/build-name":    imageBuild.Name,
			"automotive.sdv.cloud.redhat.com/resource-type": "manifest",
		}
		manifestKey := imageBuild.Spec.GetManifestFileName()
		if manifestKey == "" {
			manifestKey = "manifest.aib.yml"
		}
		cm.Data = map[string]string{
			manifestKey: manifestContent,
		}

		if customDefs := imageBuild.Spec.GetCustomDefs(); len(customDefs) > 0 {
			cm.Data["custom-definitions.env"] = strings.Join(customDefs, "\n")
		}
		if extraArgs := imageBuild.Spec.GetAIBExtraArgs(); len(extraArgs) > 0 {
			cm.Data["aib-extra-args.txt"] = strings.Join(extraArgs, "\n")
		}

		return controllerutil.SetControllerReference(imageBuild, cm, r.Scheme)
	})
	if err != nil {
		return "", fmt.Errorf("failed to create or update manifest ConfigMap %q: %w", configMapName, err)
	}

	return configMapName, nil
}

func (r *ImageBuildReconciler) createPushTaskRun(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild, artifactFilename string) (err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.CreatePushTaskRun")
	defer controllerutils.EndSpanWithError(span, &err)

	log := r.buildLogger(imageBuild)
	log.Info("Creating push TaskRun for ImageBuild", "artifactFilename", artifactFilename)

	if !imageBuild.Spec.HasDiskExport() {
		return fmt.Errorf("no disk export configured")
	}

	// Validate required fields for push operation
	repositoryURL := imageBuild.Spec.GetLegacyExportURL()
	if repositoryURL == "" {
		return fmt.Errorf("repository URL is required for push: export.disk.oci must be set")
	}

	distro := imageBuild.Spec.GetDistro()
	if distro == "" {
		return fmt.Errorf("distro is required for push: aib.distro must be set")
	}

	target := imageBuild.Spec.GetTarget()
	if target == "" {
		return fmt.Errorf("target is required for push: aib.target must be set")
	}

	exportFormat := imageBuild.Spec.GetExportFormat()
	// exportFormat has a default of "qcow2", but validate anyway
	if exportFormat == "" {
		return fmt.Errorf("export format is required for push")
	}

	pushSecretRef := imageBuild.Spec.GetPushSecretRef()
	if pushSecretRef == "" {
		return fmt.Errorf("push secret reference is required: pushSecretRef must be set for registry authentication")
	}

	if artifactFilename == "" {
		return fmt.Errorf("artifact filename is required for push")
	}

	// Fetch OperatorConfig to resolve image overrides and registry settings for the push task
	pushBuildConfig := r.resolveBuildConfig(ctx)
	pushTask := tasks.GeneratePushArtifactRegistryTask(controllerutils.OperatorNamespace(), pushBuildConfig)

	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: "config", Namespace: controllerutils.OperatorNamespace()}, operatorConfig); err != nil {
		return fmt.Errorf("failed to fetch OperatorConfig for push task: %w", err)
	}

	params := []tektonv1.Param{
		{
			Name: "arch",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.Architecture,
			},
		},
		{
			Name: "distro",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: distro,
			},
		},
		{
			Name: "target",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: target,
			},
		},
		{
			Name: "export-format",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: exportFormat,
			},
		},
		{
			Name: "repository-url",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: repositoryURL,
			},
		},
		{
			Name: "secret-ref",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: pushSecretRef,
			},
		},
		{
			Name: "artifact-filename",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: artifactFilename,
			},
		},
		{
			Name: "insecure-registry",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.InsecureRegistry),
			},
		},
		{
			Name: "secure-build",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", imageBuild.Spec.SecureBuild),
			},
		},
		{
			Name: "reproducible",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: fmt.Sprintf("%t", imageBuild.Spec.Reproducible),
			},
		},
		{
			Name: "task-bundle-ref",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: imageBuild.Spec.TaskBundleRef,
			},
		},
		{
			Name: "custom-defines",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: strings.Join(imageBuild.Spec.GetCustomDefs(), "\n"),
			},
		},
		{
			Name: "aib-extra-args",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: strings.Join(imageBuild.Spec.GetAIBExtraArgs(), "\n"),
			},
		},
		{
			Name: "trace-id",
			Value: tektonv1.ParamValue{
				Type:      tektonv1.ParamTypeString,
				StringVal: getTraceID(imageBuild),
			},
		},
	}

	workspaces := []tektonv1.WorkspaceBinding{
		{
			Name: "shared-workspace",
			PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
				ClaimName: imageBuild.Status.PVCName,
			},
		},
	}

	taskRun := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: safeDerivedName(imageBuild.Name, "-push-"),
			Namespace:    imageBuild.Namespace,
			Labels:       buildLabels(imageBuild, "push"),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: imageBuild.APIVersion,
					Kind:       imageBuild.Kind,
					Name:       imageBuild.Name,
					UID:        imageBuild.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: tektonv1.TaskRunSpec{
			TaskSpec:   &pushTask.Spec,
			Params:     params,
			Workspaces: workspaces,
		},
	}

	if err := r.Create(ctx, taskRun); err != nil {
		return fmt.Errorf("failed to create push TaskRun: %w", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
		return fmt.Errorf("failed to get fresh ImageBuild: %w", err)
	}

	fresh.Status.PushTaskRunName = taskRun.Name
	if err := r.Status().Update(ctx, fresh); err != nil {
		return fmt.Errorf("failed to update ImageBuild with push TaskRun name: %w", err)
	}

	log.Info("Successfully created push TaskRun", "name", taskRun.Name)
	return nil
}

func (r *ImageBuildReconciler) handlePushingState(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (result ctrl.Result, err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.HandlePushingState")
	defer controllerutils.EndSpanWithError(span, &err)

	log := r.buildLogger(imageBuild)

	if imageBuild.Status.PushTaskRunName == "" {
		// Fetch PipelineRun to get artifact filename from results
		pipelineRun := &tektonv1.PipelineRun{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      imageBuild.Status.PipelineRunName,
			Namespace: imageBuild.Namespace,
		}, pipelineRun); err != nil {
			log.Error(err, "Failed to get PipelineRun for artifact filename")
			return ctrl.Result{}, err
		}
		artifactFilename := extractArtifactFilename(pipelineRun)

		// No push TaskRun yet, create one
		if err := r.createPushTaskRun(ctx, imageBuild, artifactFilename); err != nil {
			log.Error(err, "Failed to create push TaskRun")
			msg := fmt.Sprintf("Failed to create push TaskRun: %v", err)
			if statusErr := r.updateStatus(ctx, imageBuild, phaseFailed, msg); statusErr != nil {
				log.Error(statusErr, "Failed to update status after push TaskRun creation failure")
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	// Check push TaskRun status
	taskRun := &tektonv1.TaskRun{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      imageBuild.Status.PushTaskRunName,
		Namespace: imageBuild.Namespace,
	}, taskRun)
	if err != nil {
		if errors.IsNotFound(err) {
			// TaskRun was deleted, try to recreate
			imageBuild.Status.PushTaskRunName = ""
			if statusErr := r.Status().Update(ctx, imageBuild); statusErr != nil {
				log.Error(statusErr, "Failed to clear PushTaskRunName in status")
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}

	if !isTaskRunCompleted(taskRun) {
		return ctrl.Result{RequeueAfter: time.Second * 15}, nil
	}

	// Push completed - cleanup transient secrets and update status
	cleanupErr := r.cleanupTransientSecrets(ctx, imageBuild, log)

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
		return ctrl.Result{}, err
	}

	patch := client.MergeFrom(fresh.DeepCopy())

	if isTaskRunSuccessful(taskRun) {
		// Check if flash is enabled
		if fresh.Spec.IsFlashEnabled() {
			fresh.Status.Phase = "Flashing"
			fresh.Status.Message = "Flashing image to device"
			if err := r.Status().Patch(ctx, fresh, patch); err != nil {
				log.Error(err, "Failed to patch status to Flashing")
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true}, nil
		}

		fresh.Status.Phase = phaseCompleted
		fresh.Status.Message = "Build and push completed successfully"
	} else {
		fresh.Status.Phase = phaseFailed
		fresh.Status.Message = "Push to registry failed"
	}

	if fresh.Status.CompletionTime == nil {
		now := metav1.Now()
		fresh.Status.CompletionTime = &now
	}

	if err := r.Status().Patch(ctx, fresh, patch); err != nil {
		log.Error(err, "Failed to patch status after push completion")
		return ctrl.Result{}, err
	}

	if cleanupErr != nil {
		return ctrl.Result{RequeueAfter: secretCleanupRequeue}, nil
	}
	return ctrl.Result{}, nil
}

func (r *ImageBuildReconciler) handleFlashingState(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (result ctrl.Result, err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.HandleFlashingState")
	defer controllerutils.EndSpanWithError(span, &err)

	log := r.buildLogger(imageBuild)

	if imageBuild.Status.FlashTaskRunName == "" {
		// No flash TaskRun yet, create one
		if err := r.createFlashTaskRun(ctx, imageBuild); err != nil {
			log.Error(err, "Failed to create flash TaskRun")
			msg := fmt.Sprintf("Failed to create flash TaskRun: %v", err)
			if statusErr := r.updateStatus(ctx, imageBuild, phaseFailed, msg); statusErr != nil {
				log.Error(statusErr, "Failed to update status after flash TaskRun creation failure")
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{}, nil
		}
		return ctrl.Result{RequeueAfter: time.Second * 10}, nil
	}

	// Check flash TaskRun status
	taskRun := &tektonv1.TaskRun{}
	err = r.Get(ctx, types.NamespacedName{
		Name:      imageBuild.Status.FlashTaskRunName,
		Namespace: imageBuild.Namespace,
	}, taskRun)
	if err != nil {
		if errors.IsNotFound(err) {
			// TaskRun was deleted, try to recreate
			imageBuild.Status.FlashTaskRunName = ""
			if statusErr := r.Status().Update(ctx, imageBuild); statusErr != nil {
				log.Error(statusErr, "Failed to clear FlashTaskRunName in status")
				return ctrl.Result{}, statusErr
			}
			return ctrl.Result{Requeue: true}, nil
		}
		return ctrl.Result{}, err
	}

	if !isTaskRunCompleted(taskRun) {
		return ctrl.Result{RequeueAfter: time.Second * 30}, nil
	}

	// Flash completed - cleanup and update status
	cleanupErr := r.cleanupTransientSecrets(ctx, imageBuild, log)

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
		return ctrl.Result{}, err
	}

	patch := client.MergeFrom(fresh.DeepCopy())

	flashSucceeded := isTaskRunSuccessful(taskRun)
	if flashSucceeded {
		fresh.Status.Phase = phaseCompleted
		fresh.Status.Message = "Build, push, and flash completed successfully"
	} else {
		fresh.Status.Phase = phaseFailed
		fresh.Status.Message = taskRunFailureMessage(taskRun, "Flash to device failed")
	}

	if fresh.Status.CompletionTime == nil {
		now := metav1.Now()
		fresh.Status.CompletionTime = &now
	}

	if err := r.Status().Patch(ctx, fresh, patch); err != nil {
		log.Error(err, "Failed to patch status after flash completion")
		return ctrl.Result{}, err
	}

	if flashSucceeded {
		recordFlashMetrics(imageBuild, taskRun, buildStatusSuccess)
	} else {
		recordFlashMetrics(imageBuild, taskRun, buildStatusFailure)
	}

	if cleanupErr != nil {
		return ctrl.Result{RequeueAfter: secretCleanupRequeue}, nil
	}
	return ctrl.Result{}, nil
}

func (r *ImageBuildReconciler) createFlashTaskRun(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (err error) {
	ctx, span := ibTracer.Start(ctx, "ImageBuild.CreateFlashTaskRun")
	defer controllerutils.EndSpanWithError(span, &err)

	log := r.buildLogger(imageBuild)
	log.Info("Creating flash TaskRun for ImageBuild")

	if !imageBuild.Spec.IsFlashEnabled() {
		return fmt.Errorf("flash is not enabled")
	}

	// Get exporter selector from OperatorConfig based on target
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	err = r.Get(ctx, types.NamespacedName{Name: "config", Namespace: controllerutils.OperatorNamespace()}, operatorConfig)
	if err != nil {
		return fmt.Errorf("failed to get OperatorConfig: %w", err)
	}

	target := imageBuild.Spec.GetTarget()
	var exporterSelector, flashCmd string
	if operatorConfig.Spec.Jumpstarter != nil {
		if mapping, ok := operatorConfig.Spec.Jumpstarter.TargetMappings[target]; ok {
			exporterSelector = mapping.Selector
			flashCmd = mapping.FlashCmd
		}
	}
	// User-specified flash command overrides OperatorConfig
	if userCmd := imageBuild.Spec.GetFlashCmd(); userCmd != "" {
		flashCmd = userCmd
	}

	if exporterSelector == "" {
		return fmt.Errorf("no Jumpstarter exporter mapping found for target %q in OperatorConfig", target)
	}

	// Get the image reference to flash (from export.disk.oci)
	imageRef := imageBuild.Spec.GetExportOCI()
	if imageRef == "" {
		return fmt.Errorf("no disk export OCI URL configured for flash")
	}

	// Note: Flash command placeholders are handled in the flash script itself

	leaseDuration := imageBuild.Spec.GetFlashLeaseDuration()
	clientConfigSecretRef := imageBuild.Spec.GetFlashClientConfigSecretRef()
	if clientConfigSecretRef == "" {
		return fmt.Errorf("flash client config secret reference is required but not set")
	}

	flashBuildConfig := &tasks.BuildConfig{
		FlashTimeoutMinutes:  operatorConfig.Spec.OSBuilds.GetFlashTimeoutMinutes(),
		DefaultLeaseDuration: operatorConfig.Spec.Jumpstarter.GetDefaultLeaseDuration(),
	}
	flashTask := tasks.GenerateFlashTask(controllerutils.OperatorNamespace(), flashBuildConfig)

	params := []tektonv1.Param{
		{
			Name:  "image-ref",
			Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageRef},
		},
		{
			Name:  "exporter-selector",
			Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: exporterSelector},
		},
		{
			Name:  "flash-cmd",
			Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: flashCmd},
		},
		{
			Name:  "lease-duration",
			Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: leaseDuration},
		},
		{
			Name:  "lease-name",
			Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: imageBuild.Spec.GetFlashLeaseName()},
		},
		{
			Name:  "trace-id",
			Value: tektonv1.ParamValue{Type: tektonv1.ParamTypeString, StringVal: getTraceID(imageBuild)},
		},
	}

	workspaces := []tektonv1.WorkspaceBinding{
		{
			Name: "jumpstarter-client",
			Secret: &corev1.SecretVolumeSource{
				SecretName: clientConfigSecretRef,
			},
		},
	}

	taskRun := &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: safeDerivedName(imageBuild.Name, "-flash-"),
			Namespace:    imageBuild.Namespace,
			Labels:       buildLabels(imageBuild, "flash"),
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: imageBuild.APIVersion,
					Kind:       imageBuild.Kind,
					Name:       imageBuild.Name,
					UID:        imageBuild.UID,
					Controller: ptr.To(true),
				},
			},
		},
		Spec: tektonv1.TaskRunSpec{
			TaskSpec:   &flashTask.Spec,
			Params:     params,
			Workspaces: workspaces,
		},
	}

	if err := r.Create(ctx, taskRun); err != nil {
		return fmt.Errorf("failed to create flash TaskRun: %w", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}, fresh); err != nil {
		return fmt.Errorf("failed to get fresh ImageBuild: %w", err)
	}

	fresh.Status.FlashTaskRunName = taskRun.Name
	if err := r.Status().Update(ctx, fresh); err != nil {
		return fmt.Errorf("failed to update ImageBuild with flash TaskRun name: %w", err)
	}

	log.Info("Successfully created flash TaskRun", "name", taskRun.Name)
	return nil
}

// updateWorkspaceLease writes the acquired lease back to the workspace so subsequent builds can reuse it.
func (r *ImageBuildReconciler) updateWorkspaceLease(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild, log logr.Logger) {
	ws := &automotivev1alpha1.Workspace{}
	if err := r.Get(ctx, types.NamespacedName{Name: imageBuild.Spec.Workspace, Namespace: imageBuild.Namespace}, ws); err != nil {
		log.Error(err, "Failed to get workspace for lease write-back", "workspace", imageBuild.Spec.Workspace)
		return
	}
	if ws.Spec.LeaseID == imageBuild.Status.LeaseID {
		return
	}
	patch := client.MergeFrom(ws.DeepCopy())
	ws.Spec.LeaseID = imageBuild.Status.LeaseID
	if err := r.Patch(ctx, ws, patch); err != nil {
		log.Error(err, "Failed to write lease back to workspace", "workspace", ws.Name, "lease", imageBuild.Status.LeaseID)
	} else {
		log.Info("Wrote lease back to workspace", "workspace", ws.Name, "lease", imageBuild.Status.LeaseID)
	}
}

// cleanupTransientSecrets attempts to delete all transient secrets for a
// build. It tries every secret (does not short-circuit) and returns an error
// if any deletion failed, so the caller can schedule a retry.
func (r *ImageBuildReconciler) cleanupTransientSecrets(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
	log logr.Logger,
) error {
	var firstErr error
	collect := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if imageBuild.Spec.SecretRef != "" {
		collect(r.deleteSecret(ctx, imageBuild.Namespace, imageBuild.Spec.SecretRef, "registry auth", log))
	}
	if imageBuild.Spec.PushSecretRef != "" {
		collect(r.deleteSecret(ctx, imageBuild.Namespace, imageBuild.Spec.PushSecretRef, "push auth", log))
	}
	if flashSecretRef := imageBuild.Spec.GetFlashClientConfigSecretRef(); flashSecretRef != "" {
		collect(r.deleteSecret(ctx, imageBuild.Namespace, flashSecretRef, "flash client config", log))
	}
	collect(r.deleteSecret(ctx, imageBuild.Namespace, imageBuild.Name+"-flash-oci-auth", "flash OCI auth", log))
	return firstErr
}

// deleteSecret attempts to delete a secret. Returns nil on success or if
// the secret is already gone (NotFound). Returns the error on transient
// failure so the caller can schedule a retry.
func (r *ImageBuildReconciler) deleteSecret(
	ctx context.Context,
	namespace, secretName, secretType string,
	log logr.Logger,
) error {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
	}
	err := r.Delete(ctx, secret)
	if err == nil {
		log.Info("Deleted "+secretType+" secret", "secret", secretName)
		return nil
	}
	if errors.IsNotFound(err) {
		return nil
	}
	log.Error(err, "Failed to delete "+secretType+" secret (will retry)", "secret", secretName)
	return err
}

// SetupWithManager sets up the controller with the Manager.
func (r *ImageBuildReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.Add(r.seedMetricsFromCRs(mgr)); err != nil {
		return fmt.Errorf("failed to register metrics seeder: %w", err)
	}

	builder := ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ImageBuild{}).
		Owns(&tektonv1.PipelineRun{}).
		Owns(&tektonv1.TaskRun{}).
		Owns(&corev1.Pod{}).
		Owns(&corev1.PersistentVolumeClaim{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.ConfigMap{}).
		Owns(&corev1.Secret{})

	return builder.Complete(r)
}

func isTaskRunCompleted(taskRun *tektonv1.TaskRun) bool {
	return taskRun.Status.CompletionTime != nil
}

func isPipelineRunCompleted(pipelineRun *tektonv1.PipelineRun) bool {
	return pipelineRun.Status.CompletionTime != nil
}

func isPipelineRunSuccessful(pipelineRun *tektonv1.PipelineRun) bool {
	conditions := pipelineRun.Status.Conditions
	if len(conditions) == 0 {
		return false
	}

	for _, condition := range conditions {
		if condition.Type == conditionSucceeded {
			return condition.Status == "True"
		}
	}
	return false
}

func pipelineRunFailureMessage(pipelineRun *tektonv1.PipelineRun) string {
	for _, condition := range pipelineRun.Status.Conditions {
		if condition.Type == conditionSucceeded && condition.Status != "True" && condition.Message != "" {
			return fmt.Sprintf("Build failed: %s", condition.Message)
		}
	}
	return "Build failed"
}

// pipelineTaskLabel maps pipeline task names to user-friendly labels for error messages.
var pipelineTaskLabel = map[string]string{
	"build-image":        "Image build failed",
	"push-disk-artifact": "Disk image push failed",
	"flash-image":        "Flash failed",
}

func (r *ImageBuildReconciler) pipelineRunFailureDetail(ctx context.Context, pipelineRun *tektonv1.PipelineRun) string {
	for _, child := range pipelineRun.Status.ChildReferences {
		taskRun := &tektonv1.TaskRun{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      child.Name,
			Namespace: pipelineRun.Namespace,
		}, taskRun); err != nil {
			continue
		}
		if isTaskRunCompleted(taskRun) && !isTaskRunSuccessful(taskRun) {
			label := pipelineTaskLabel[child.PipelineTaskName]
			if label == "" {
				label = fmt.Sprintf("Task %q failed", child.PipelineTaskName)
			}
			return taskRunFailureMessage(taskRun, label)
		}
	}
	return pipelineRunFailureMessage(pipelineRun)
}

func taskRunFailureMessage(taskRun *tektonv1.TaskRun, fallback string) string {
	for _, condition := range taskRun.Status.Conditions {
		if condition.Type == conditionSucceeded && condition.Status != corev1.ConditionTrue && condition.Message != "" {
			return fmt.Sprintf("%s: %s", fallback, condition.Message)
		}
	}
	return fallback
}

// extractProvenance extracts build provenance information from PipelineRun results
// buildTiming holds the timing breakdown written by build_image.sh.
type buildTiming struct {
	SetupS     float64 `json:"setup_s"`
	BuildS     float64 `json:"build_s"`
	PostBuildS float64 `json:"post_build_s"`
}

// recordBuildMetrics records Prometheus metrics from a completed build.
func recordBuildMetrics(imageBuild *automotivev1alpha1.ImageBuild, pipelineRun *tektonv1.PipelineRun, status string) {
	mode := imageBuild.Spec.GetMode()
	distro := imageBuild.Spec.GetDistro()
	target := imageBuild.Spec.GetTarget()
	format := imageBuild.Spec.GetExportFormat()
	arch := imageBuild.Spec.Architecture

	BuildTotal.WithLabelValues(mode, distro, target, format, arch, status).Inc()

	// Record wall-clock duration from CR timestamps
	if imageBuild.Status.StartTime != nil && imageBuild.Status.CompletionTime != nil {
		duration := imageBuild.Status.CompletionTime.Sub(imageBuild.Status.StartTime.Time).Seconds()
		BuildDuration.WithLabelValues(mode, distro, target, format, arch, status).Observe(duration)
	}

	// Record phase-level timing from the build-timing Tekton result
	if status != buildStatusSuccess || pipelineRun == nil {
		return
	}
	for _, result := range pipelineRun.Status.Results {
		if result.Name != "build-timing" {
			continue
		}
		var timing buildTiming
		if err := json.Unmarshal([]byte(result.Value.StringVal), &timing); err != nil {
			break
		}
		labels := []string{mode, distro, target}
		BuildPhaseDuration.WithLabelValues(append(labels, "setup")...).Observe(timing.SetupS)
		BuildPhaseDuration.WithLabelValues(append(labels, "build")...).Observe(timing.BuildS)
		BuildPhaseDuration.WithLabelValues(append(labels, "post_build")...).Observe(timing.PostBuildS)
		break
	}
}

func (r *ImageBuildReconciler) recordPipelineFlashMetrics(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
	pipelineRun *tektonv1.PipelineRun,
	status string,
) {
	target := imageBuild.Spec.GetTarget()

	for _, child := range pipelineRun.Status.ChildReferences {
		if child.PipelineTaskName != "flash-image" {
			continue
		}
		taskRun := &tektonv1.TaskRun{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      child.Name,
			Namespace: pipelineRun.Namespace,
		}, taskRun); err != nil {
			break
		}
		FlashTotal.WithLabelValues(target, status).Inc()
		if taskRun.Status.CompletionTime != nil {
			duration := taskRun.Status.CompletionTime.Sub(taskRun.CreationTimestamp.Time).Seconds()
			FlashDuration.WithLabelValues(target, status).Observe(duration)
		}
		return
	}
}

func recordFlashMetrics(imageBuild *automotivev1alpha1.ImageBuild, taskRun *tektonv1.TaskRun, status string) {
	target := imageBuild.Spec.GetTarget()
	FlashTotal.WithLabelValues(target, status).Inc()

	if taskRun.Status.CompletionTime != nil {
		duration := taskRun.Status.CompletionTime.Sub(taskRun.CreationTimestamp.Time).Seconds()
		FlashDuration.WithLabelValues(target, status).Observe(duration)
	}
}

func extractProvenance(pipelineRun *tektonv1.PipelineRun, aibImage string) (aibImageUsed, builderImageUsed string) {
	aibImageUsed = aibImage // Always record the AIB image that was requested

	// Extract builder image from pipeline result (written by build-image task)
	for _, result := range pipelineRun.Status.Results {
		if result.Name == "builder-image" {
			builderImageUsed = result.Value.StringVal
			break
		}
	}

	return aibImageUsed, builderImageUsed
}

// extractArtifactFilename extracts the artifact filename from PipelineRun results
func extractArtifactFilename(pipelineRun *tektonv1.PipelineRun) string {
	for _, result := range pipelineRun.Status.Results {
		if result.Name == "artifact-filename" {
			return result.Value.StringVal
		}
	}
	return ""
}

// extractLeaseID extracts the Jumpstarter lease ID from PipelineRun results
func extractLeaseID(pipelineRun *tektonv1.PipelineRun) string {
	for _, result := range pipelineRun.Status.Results {
		if result.Name == "lease-id" {
			return result.Value.StringVal
		}
	}
	return ""
}

func isTaskRunSuccessful(taskRun *tektonv1.TaskRun) bool {
	conditions := taskRun.Status.Conditions
	if len(conditions) == 0 {
		return false
	}

	return conditions[0].Status == corev1.ConditionTrue
}

func (r *ImageBuildReconciler) createUploadPod(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) error {
	log := r.buildLogger(imageBuild)

	podName := safeDerivedName(imageBuild.Name, "-upload-pod")
	existingPod := &corev1.Pod{}
	err := r.Get(ctx, types.NamespacedName{
		Name:      podName,
		Namespace: imageBuild.Namespace,
	}, existingPod)

	if err == nil {
		if existingPod.Status.Phase == corev1.PodRunning {
			log.Info("Upload pod already exists and is running", "pod", podName)
			return nil
		}
	} else if !errors.IsNotFound(err) {
		return fmt.Errorf("error checking for existing pod: %w", err)
	}

	// When a build-cache PVC exists (from --workspace), use it for uploads too
	// so files land on the same PVC the TaskRun will mount as shared-workspace.
	var workspacePVCName string
	if imageBuild.Spec.BuildCachePVC != "" {
		pvc := &corev1.PersistentVolumeClaim{}
		if err := r.Get(ctx, types.NamespacedName{
			Name:      imageBuild.Spec.BuildCachePVC,
			Namespace: imageBuild.Namespace,
		}, pvc); err != nil {
			return fmt.Errorf("buildCachePVC %q is not available: %w", imageBuild.Spec.BuildCachePVC, err)
		}
		workspacePVCName = pvc.Name
	} else {
		var err error
		workspacePVCName, err = r.getOrCreateWorkspacePVC(ctx, imageBuild)
		if err != nil {
			return err
		}
	}

	if imageBuild.Status.PVCName != workspacePVCName {
		fresh := &automotivev1alpha1.ImageBuild{}
		nsName := types.NamespacedName{Name: imageBuild.Name, Namespace: imageBuild.Namespace}
		if err := r.Get(ctx, nsName, fresh); err != nil {
			return fmt.Errorf("failed to get fresh ImageBuild: %w", err)
		}

		fresh.Status.PVCName = workspacePVCName
		if err := r.Status().Update(ctx, fresh); err != nil {
			return fmt.Errorf("failed to update ImageBuild status with PVC name: %w", err)
		}

		imageBuild.Status.PVCName = workspacePVCName
	}

	labels := map[string]string{
		"app.kubernetes.io/managed-by":                    "automotive-dev-operator",
		"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
		"app.kubernetes.io/name":                          "upload-pod",
	}

	// Fetch OperatorConfig to inherit nodeSelector and tolerations for the upload pod.
	// This ensures the upload pod (the PVC's first consumer) schedules in the same
	// availability zone as the build pod.
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: "config", Namespace: controllerutils.OperatorNamespace()}, operatorConfig); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to get OperatorConfig: %w", err)
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: imageBuild.Namespace,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         imageBuild.APIVersion,
					Kind:               imageBuild.Kind,
					Name:               imageBuild.Name,
					UID:                imageBuild.UID,
					Controller:         ptr.To(true),
					BlockOwnerDeletion: ptr.To(true),
				},
			},
		},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsUser:    ptr.To[int64](1000),
				RunAsGroup:   ptr.To[int64](1000),
				FSGroup:      ptr.To[int64](1000),
				RunAsNonRoot: ptr.To(true),
			},
			Containers: []corev1.Container{
				{
					Name:    "fileserver",
					Image:   "registry.access.redhat.com/ubi10-minimal:latest",
					Command: []string{"sleep", "infinity"},
					Resources: corev1.ResourceRequirements{
						Requests: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("100m"),
							corev1.ResourceMemory: resource.MustParse("64Mi"),
						},
						Limits: corev1.ResourceList{
							corev1.ResourceCPU:    resource.MustParse("200m"),
							corev1.ResourceMemory: resource.MustParse("128Mi"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "workspace",
							MountPath: "/workspace/shared",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "workspace",
					VolumeSource: corev1.VolumeSource{
						PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
							ClaimName: workspacePVCName,
						},
					},
				},
			},
		},
	}

	// Apply the same scheduling constraints used by build pods so the upload
	// pod lands in the same AZ and architecture, ensuring the WaitForFirstConsumer
	// PVC is provisioned on a topology reachable by the build pod.
	if operatorConfig.Spec.OSBuilds != nil && len(operatorConfig.Spec.OSBuilds.NodeSelector) > 0 {
		pod.Spec.NodeSelector = operatorConfig.Spec.OSBuilds.NodeSelector
	}
	if operatorConfig.Spec.OSBuilds != nil && len(operatorConfig.Spec.OSBuilds.Tolerations) > 0 {
		pod.Spec.Tolerations = operatorConfig.Spec.OSBuilds.Tolerations
	}
	if imageBuild.Spec.Architecture != "" {
		pod.Spec.Affinity = &corev1.Affinity{
			NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{
					NodeSelectorTerms: []corev1.NodeSelectorTerm{
						{
							MatchExpressions: []corev1.NodeSelectorRequirement{
								{
									Key:      corev1.LabelArchStable,
									Operator: corev1.NodeSelectorOpIn,
									Values:   []string{controllerutils.NormalizeArchToK8s(imageBuild.Spec.Architecture)},
								},
							},
						},
					},
				},
			},
		}
	}

	if err := r.Create(ctx, pod); err != nil && !errors.IsAlreadyExists(err) {
		return fmt.Errorf("failed to create upload pod: %w", err)
	}
	r.emitEventf(
		imageBuild,
		corev1.EventTypeNormal,
		eventReasonUploadPodReady,
		"Upload pod ready: pod=%s pvc=%s",
		podName,
		workspacePVCName,
	)

	log.Info("Created upload pod, will check status on next reconciliation", "pod", podName)
	return nil
}

// resolveBuildConfig fetches OperatorConfig and returns a BuildConfig for task generation.
// Returns a minimal BuildConfig with defaults if OperatorConfig is unavailable.
func (r *ImageBuildReconciler) resolveBuildConfig(ctx context.Context) *tasks.BuildConfig {
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	if err := r.Get(ctx, types.NamespacedName{Name: "config", Namespace: controllerutils.OperatorNamespace()}, operatorConfig); err != nil {
		return &tasks.BuildConfig{}
	}
	bc := &tasks.BuildConfig{
		AutomotiveImageBuilderImage: operatorConfig.Spec.GetImages().GetAutomotiveImageBuilderImage(),
		YQHelperImage:               operatorConfig.Spec.GetImages().GetYQHelperImage(),
		DefaultLeaseDuration:        operatorConfig.Spec.Jumpstarter.GetDefaultLeaseDuration(),
	}
	if operatorConfig.Spec.OSBuilds != nil {
		bc.UseMemoryVolumes = operatorConfig.Spec.OSBuilds.UseMemoryVolumes
		bc.MemoryVolumeSize = operatorConfig.Spec.OSBuilds.MemoryVolumeSize
		bc.PVCSize = operatorConfig.Spec.OSBuilds.PVCSize
		bc.RuntimeClassName = operatorConfig.Spec.OSBuilds.RuntimeClassName
		bc.BuildTimeoutMinutes = operatorConfig.Spec.OSBuilds.GetBuildTimeoutMinutes()
		bc.FlashTimeoutMinutes = operatorConfig.Spec.OSBuilds.GetFlashTimeoutMinutes()
		controllerutils.ApplyTrustedCABundleFromOSBuilds(bc, operatorConfig.Spec.OSBuilds)
	}
	return bc
}

func (r *ImageBuildReconciler) updateStatus(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
	phase, message string,
) error {
	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, types.NamespacedName{
		Name:      imageBuild.Name,
		Namespace: imageBuild.Namespace,
	}, fresh); err != nil {
		return err
	}

	if fresh.Status.Phase == phaseCancelled && phase != phaseCancelled {
		return nil
	}
	if fresh.Status.Phase == automotivev1alpha1.ImageBuildPhaseExpired && phase != automotivev1alpha1.ImageBuildPhaseExpired {
		return nil
	}

	patch := client.MergeFrom(fresh.DeepCopy())
	oldPhase := fresh.Status.Phase
	oldMessage := fresh.Status.Message

	if phase == automotivev1alpha1.ImageBuildPhaseExpired {
		fresh.Status.PreviousPhase = fresh.Status.Phase
	}

	fresh.Status.Phase = phase
	fresh.Status.Message = message

	if phase == phaseBuilding && fresh.Status.StartTime == nil {
		now := metav1.Now()
		fresh.Status.StartTime = &now
	} else if isTerminalPhase(phase) && fresh.Status.CompletionTime == nil {
		now := metav1.Now()
		fresh.Status.CompletionTime = &now
	}

	setImageBuildConditions(fresh, phase, message)

	if err := r.Status().Patch(ctx, fresh, patch); err != nil {
		return err
	}
	adjustActiveBuildsGauge(oldPhase, phase)
	if oldPhase != phase || oldMessage != message {
		r.emitEventf(
			fresh,
			eventTypeForPhase(phase),
			eventReasonPhaseChanged,
			"Phase transitioned: %s -> %s, message=%s, mode=%s target=%s arch=%s toDisk=%t",
			oldPhase,
			phase,
			message,
			fresh.Spec.GetMode(),
			fresh.Spec.GetTarget(),
			fresh.Spec.Architecture,
			fresh.Spec.GetBuildDiskImage(),
		)
		r.emitImageBuildLifecycleEvent(fresh, oldPhase, phase, message)
	}
	return nil
}

func (r *ImageBuildReconciler) emitImageBuildLifecycleEvent(
	imageBuild *automotivev1alpha1.ImageBuild,
	oldPhase, newPhase, message string,
) {
	switch newPhase {
	case "Uploading":
		r.emitEventf(
			imageBuild,
			corev1.EventTypeNormal,
			eventReasonUploadStarted,
			"Upload started: mode=%s target=%s arch=%s toDisk=%t message=%s",
			imageBuild.Spec.GetMode(),
			imageBuild.Spec.GetTarget(),
			imageBuild.Spec.Architecture,
			imageBuild.Spec.GetBuildDiskImage(),
			message,
		)
	case phaseBuilding:
		reason := eventReasonBuildStarted
		if oldPhase == phaseBuilding {
			reason = eventReasonBuildRunning
		}
		r.emitEventf(
			imageBuild,
			corev1.EventTypeNormal,
			reason,
			"Build %s: mode=%s target=%s arch=%s toDisk=%t flash=%t message=%s",
			strings.ToLower(strings.TrimPrefix(reason, "Build")),
			imageBuild.Spec.GetMode(),
			imageBuild.Spec.GetTarget(),
			imageBuild.Spec.Architecture,
			imageBuild.Spec.GetBuildDiskImage(),
			imageBuild.Spec.IsFlashEnabled(),
			message,
		)
		if imageBuild.Spec.GetBuildDiskImage() {
			diskReason := eventReasonDiskBuildStarted
			if oldPhase == phaseBuilding {
				diskReason = eventReasonDiskBuildRunning
			}
			r.emitEventf(
				imageBuild,
				corev1.EventTypeNormal,
				diskReason,
				"Disk image path active: exportFormat=%s exportOCI=%s mode=%s message=%s",
				imageBuild.Spec.GetExportFormat(),
				imageBuild.Spec.GetExportOCI(),
				imageBuild.Spec.GetMode(),
				message,
			)
		}
	case phaseFailed:
		r.emitEventf(
			imageBuild,
			corev1.EventTypeWarning,
			eventReasonBuildFailed,
			"Build failed: mode=%s target=%s arch=%s toDisk=%t message=%s",
			imageBuild.Spec.GetMode(),
			imageBuild.Spec.GetTarget(),
			imageBuild.Spec.Architecture,
			imageBuild.Spec.GetBuildDiskImage(),
			message,
		)
		if imageBuild.Spec.GetBuildDiskImage() {
			r.emitEventf(
				imageBuild,
				corev1.EventTypeWarning,
				eventReasonDiskBuildFailed,
				"Disk image build failed: exportFormat=%s exportOCI=%s message=%s",
				imageBuild.Spec.GetExportFormat(),
				imageBuild.Spec.GetExportOCI(),
				message,
			)
		}
	case phaseCompleted:
		r.emitEventf(
			imageBuild,
			corev1.EventTypeNormal,
			eventReasonBuildCompleted,
			"Build completed: mode=%s target=%s arch=%s toDisk=%t message=%s",
			imageBuild.Spec.GetMode(),
			imageBuild.Spec.GetTarget(),
			imageBuild.Spec.Architecture,
			imageBuild.Spec.GetBuildDiskImage(),
			message,
		)
		if imageBuild.Spec.GetBuildDiskImage() {
			r.emitEventf(
				imageBuild,
				corev1.EventTypeNormal,
				eventReasonDiskBuildDone,
				"Disk image build completed: exportFormat=%s exportOCI=%s message=%s",
				imageBuild.Spec.GetExportFormat(),
				imageBuild.Spec.GetExportOCI(),
				message,
			)
		}
	}
}

func eventTypeForPhase(phase string) string {
	if phase == phaseFailed {
		return corev1.EventTypeWarning
	}
	return corev1.EventTypeNormal
}

func setImageBuildConditions(imageBuild *automotivev1alpha1.ImageBuild, phase, message string) {
	switch phase {
	case phaseCompleted:
		meta.SetStatusCondition(&imageBuild.Status.Conditions, metav1.Condition{
			Type:    automotivev1alpha1.ImageBuildConditionProgressing,
			Status:  metav1.ConditionFalse,
			Reason:  "Completed",
			Message: message,
		})
		meta.SetStatusCondition(&imageBuild.Status.Conditions, metav1.Condition{
			Type:    automotivev1alpha1.ImageBuildConditionReady,
			Status:  metav1.ConditionTrue,
			Reason:  "BuildSucceeded",
			Message: message,
		})
	case phaseFailed, phaseCancelled, automotivev1alpha1.ImageBuildPhaseExpired:
		meta.SetStatusCondition(&imageBuild.Status.Conditions, metav1.Condition{
			Type:    automotivev1alpha1.ImageBuildConditionProgressing,
			Status:  metav1.ConditionFalse,
			Reason:  phase,
			Message: message,
		})
		meta.SetStatusCondition(&imageBuild.Status.Conditions, metav1.Condition{
			Type:    automotivev1alpha1.ImageBuildConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  phase,
			Message: message,
		})
	default:
		meta.SetStatusCondition(&imageBuild.Status.Conditions, metav1.Condition{
			Type:    automotivev1alpha1.ImageBuildConditionProgressing,
			Status:  metav1.ConditionTrue,
			Reason:  phase,
			Message: message,
		})
		meta.SetStatusCondition(&imageBuild.Status.Conditions, metav1.Condition{
			Type:    automotivev1alpha1.ImageBuildConditionReady,
			Status:  metav1.ConditionFalse,
			Reason:  phase,
			Message: message,
		})
	}
}

func (r *ImageBuildReconciler) emitEventf(
	imageBuild *automotivev1alpha1.ImageBuild,
	eventType, reason, messageFmt string,
	args ...interface{},
) {
	if r.Recorder == nil || imageBuild == nil {
		return
	}
	r.Recorder.Eventf(imageBuild, eventType, reason, messageFmt, args...)
}

func (r *ImageBuildReconciler) getOrCreateWorkspacePVC(
	ctx context.Context,
	imageBuild *automotivev1alpha1.ImageBuild,
) (string, error) {
	log := r.buildLogger(imageBuild)

	if imageBuild.Status.PVCName != "" {
		existingPVC := &corev1.PersistentVolumeClaim{}
		err := r.Get(ctx, types.NamespacedName{
			Name:      imageBuild.Status.PVCName,
			Namespace: imageBuild.Namespace,
		}, existingPVC)

		if err == nil && existingPVC.DeletionTimestamp == nil {
			log.Info("Using existing workspace PVC from status", "pvc", imageBuild.Status.PVCName)
			return imageBuild.Status.PVCName, nil
		}

		log.Info("PVC from status is not available, creating a new one",
			"old-pvc", imageBuild.Status.PVCName)
	}

	// Fetch OperatorConfig to get PVC size and storage class configuration
	operatorConfig := &automotivev1alpha1.OperatorConfig{}
	err := r.Get(ctx, types.NamespacedName{Name: "config", Namespace: controllerutils.OperatorNamespace()}, operatorConfig)

	storageSize := resource.MustParse("8Gi")
	if err == nil && operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.PVCSize != "" {
		storageSize = resource.MustParse(operatorConfig.Spec.OSBuilds.PVCSize)
		log.Info("Using OSBuilds PVCSize", "size", operatorConfig.Spec.OSBuilds.PVCSize)
	}

	timestamp := fmt.Sprintf("%d", time.Now().Unix())
	uniquePVCName := safeDerivedName(fmt.Sprintf("%s-%s", imageBuild.Name, timestamp), "-ws")

	pvc := &corev1.PersistentVolumeClaim{
		ObjectMeta: metav1.ObjectMeta{
			Name:      uniquePVCName,
			Namespace: imageBuild.Namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by":                    "automotive-dev-operator",
				"automotive.sdv.cloud.redhat.com/imagebuild-name": imageBuild.Name,
			},
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         imageBuild.APIVersion,
					Kind:               imageBuild.Kind,
					Name:               imageBuild.Name,
					UID:                imageBuild.UID,
					Controller:         ptr.To(true),
					BlockOwnerDeletion: ptr.To(true),
				},
			},
		},
		Spec: corev1.PersistentVolumeClaimSpec{
			AccessModes: []corev1.PersistentVolumeAccessMode{
				corev1.ReadWriteOnce,
			},
			Resources: corev1.VolumeResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceStorage: storageSize,
				},
			},
		},
	}

	if imageBuild.Spec.StorageClass != "" {
		pvc.Spec.StorageClassName = &imageBuild.Spec.StorageClass
	} else if err == nil && operatorConfig.Spec.OSBuilds != nil && operatorConfig.Spec.OSBuilds.StorageClass != "" {
		pvc.Spec.StorageClassName = &operatorConfig.Spec.OSBuilds.StorageClass
	}

	if err := r.Create(ctx, pvc); err != nil {
		return "", fmt.Errorf("failed to create workspace PVC: %w", err)
	}

	log.Info("Created new workspace PVC with unique name", "pvc", uniquePVCName)
	return uniquePVCName, nil
}

func (r *ImageBuildReconciler) shutdownUploadPod(ctx context.Context, imageBuild *automotivev1alpha1.ImageBuild) error {
	log := r.buildLogger(imageBuild)

	podName := safeDerivedName(imageBuild.Name, "-upload-pod")
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: imageBuild.Namespace,
		},
	}

	if err := r.Delete(ctx, pod); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete upload pod: %w", err)
	}

	log.Info("Upload pod deleted")
	return nil
}

// extractFlashCredentials extracts username/password from a registry secret for flash OCI auth.
// It first checks for explicit REGISTRY_USERNAME/REGISTRY_PASSWORD keys, then falls back
// to parsing .dockerconfigjson or REGISTRY_AUTH_FILE_CONTENT to decode credentials.
func extractFlashCredentials(secret *corev1.Secret, registryURL string, log logr.Logger) ([]byte, []byte) {
	regUser := secret.Data["REGISTRY_USERNAME"]
	regPass := secret.Data["REGISTRY_PASSWORD"]
	if len(regUser) > 0 && len(regPass) > 0 {
		return regUser, regPass
	}

	// Fall back to docker config JSON
	dockerConfig := secret.Data[".dockerconfigjson"]
	if len(dockerConfig) == 0 {
		dockerConfig = secret.Data["REGISTRY_AUTH_FILE_CONTENT"]
	}
	if len(dockerConfig) == 0 {
		log.Error(nil, "No docker config found in secret", "secret", secret.Name)
		return nil, nil
	}

	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(dockerConfig, &cfg); err != nil {
		log.Error(err, "Failed to parse docker config JSON from secret", "secret", secret.Name)
		return nil, nil
	}

	for key, entry := range cfg.Auths {
		if !registryutil.RegistryHostMatches(key, registryURL) {
			continue
		}
		if user, pass := decodeAuthEntry(entry.Auth, log); user != nil {
			return user, pass
		}
	}
	log.Error(nil, "No matching credentials found in docker config", "secret", secret.Name, "registry", registryURL)
	return nil, nil
}

func decodeAuthEntry(auth string, log logr.Logger) ([]byte, []byte) {
	if auth == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(auth)
	if err != nil {
		log.Error(err, "Failed to base64-decode auth entry")
		return nil, nil
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) == 2 {
		return []byte(parts[0]), []byte(parts[1])
	}
	log.Error(nil, "Auth entry missing ':' separator after decoding")
	return nil, nil
}
