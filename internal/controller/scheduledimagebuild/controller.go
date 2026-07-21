/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package scheduledimagebuild implements the ScheduledImageBuild controller.
package scheduledimagebuild

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-logr/logr"
	"github.com/robfig/cron/v3"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	clockutil "k8s.io/utils/clock"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/catalogimage"
)

// Controller constants.
const (
	maxK8sNameLength = 63

	AnnotationCatalogPublished      = "automotive.sdv.cloud.redhat.com/catalog-published"
	AnnotationCatalogPublishedValue = "true"

	ConditionScheduled            = "Scheduled"
	ConditionLastBuildSucceeded   = "LastBuildSucceeded"
	ConditionLastPublishSucceeded = "LastPublishSucceeded"
)

var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// CatalogPublisher abstracts catalog publishing for testability.
type CatalogPublisher interface {
	PublishFromImageBuild(
		ctx context.Context,
		imageBuild *automotivev1alpha1.ImageBuild,
		catalogName string,
		tags []string,
		authSecretRef *automotivev1alpha1.AuthSecretReference,
	) (*catalogimage.PublishResult, error)
}

// Reconciler reconciles ScheduledImageBuild objects.
//
//nolint:revive // Name follows Kubebuilder convention
type Reconciler struct {
	client.Client
	Scheme    *runtime.Scheme
	Log       logr.Logger
	Recorder  record.EventRecorder
	Clock     clockutil.Clock
	Publisher CatalogPublisher
}

// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=scheduledimagebuilds,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=scheduledimagebuilds/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=scheduledimagebuilds/finalizers,verbs=update
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=imagebuilds,verbs=get;list;watch;create;delete;update;patch
// +kubebuilder:rbac:groups=automotive.sdv.cloud.redhat.com,namespace=system,resources=catalogimages,verbs=get;list;create
// +kubebuilder:rbac:groups="",namespace=system,resources=events,verbs=create;patch

// Reconcile handles a single ScheduledImageBuild reconciliation loop.
func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := r.Log.WithValues("scheduledimagebuild", req.NamespacedName)

	sib := &automotivev1alpha1.ScheduledImageBuild{}
	if err := r.Get(ctx, req.NamespacedName, sib); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	savedStatus := sib.Status.DeepCopy()

	now := r.now()

	childBuilds, err := r.listOwnedBuilds(ctx, sib)
	if err != nil {
		log.Error(err, "Failed to list owned ImageBuilds")
		return ctrl.Result{}, err
	}

	active, finished := classifyBuilds(childBuilds)

	r.handleCompletedBuilds(ctx, sib, finished)

	if err := r.cleanupHistory(ctx, sib, finished); err != nil {
		log.Error(err, "Failed to cleanup history")
		return ctrl.Result{}, err
	}

	r.updateActiveStatus(sib, active)

	if isSuspended(sib) {
		return r.handleSuspended(ctx, sib, savedStatus)
	}

	schedule, err := parseScheduleUTC(sib.Spec.Schedule)
	if err != nil {
		log.Error(err, "Invalid cron schedule", "schedule", sib.Spec.Schedule)
		r.setScheduledCondition(sib, metav1.ConditionFalse, "InvalidSchedule", err.Error())
		if !apiequality.Semantic.DeepEqual(savedStatus, &sib.Status) {
			if statusErr := r.Status().Update(ctx, sib); statusErr != nil {
				return ctrl.Result{}, statusErr
			}
		}
		return ctrl.Result{}, nil
	}

	missedRun, nextRun := r.getMissedAndNext(sib, schedule, now)

	shouldCreate, err := r.checkConcurrency(ctx, sib, active, missedRun)
	if err != nil {
		return ctrl.Result{}, err
	}

	if shouldCreate && missedRun != nil {
		count, err := r.createImageBuilds(ctx, sib, *missedRun)
		if err != nil {
			log.Error(err, "Failed to create ImageBuild")
			r.Recorder.Eventf(sib, corev1.EventTypeWarning, "CreateFailed", "Failed to create ImageBuild: %v", err)
			return ctrl.Result{}, err
		}

		sib.Status.LastScheduleTime = &metav1.Time{Time: *missedRun}
		r.Recorder.Eventf(sib, corev1.EventTypeNormal, "BuildCreated", "Created %d scheduled ImageBuild(s)", count)
	}

	requeueAfter := nextRun.Sub(now)
	if requeueAfter < 0 {
		requeueAfter = time.Second
	}

	sib.Status.Phase = automotivev1alpha1.ScheduledImageBuildPhaseActive
	sib.Status.ObservedGeneration = sib.Generation
	r.setScheduledCondition(sib, metav1.ConditionTrue, "Scheduled", fmt.Sprintf("Next run at %s", nextRun.Format(time.RFC3339)))

	if !apiequality.Semantic.DeepEqual(savedStatus, &sib.Status) {
		if err := r.Status().Update(ctx, sib); err != nil {
			return ctrl.Result{}, err
		}
	}

	return ctrl.Result{RequeueAfter: requeueAfter}, nil
}

func (r *Reconciler) handleSuspended(ctx context.Context, sib *automotivev1alpha1.ScheduledImageBuild, savedStatus *automotivev1alpha1.ScheduledImageBuildStatus) (ctrl.Result, error) {
	sib.Status.Phase = automotivev1alpha1.ScheduledImageBuildPhaseSuspended
	sib.Status.ObservedGeneration = sib.Generation
	r.setScheduledCondition(sib, metav1.ConditionFalse, "Suspended", "Schedule is suspended")

	if !apiequality.Semantic.DeepEqual(savedStatus, &sib.Status) {
		if err := r.Status().Update(ctx, sib); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (r *Reconciler) listOwnedBuilds(ctx context.Context, sib *automotivev1alpha1.ScheduledImageBuild) ([]automotivev1alpha1.ImageBuild, error) {
	var buildList automotivev1alpha1.ImageBuildList
	err := r.List(ctx, &buildList,
		client.InNamespace(sib.Namespace),
		client.MatchingLabels{automotivev1alpha1.LabelScheduledImageBuildName: sib.Name},
	)
	if err != nil {
		return nil, err
	}

	var owned []automotivev1alpha1.ImageBuild
	for i := range buildList.Items {
		build := &buildList.Items[i]
		if isOwnedBy(build, sib) {
			owned = append(owned, *build)
		}
	}
	return owned, nil
}

func classifyBuilds(builds []automotivev1alpha1.ImageBuild) (active, finished []automotivev1alpha1.ImageBuild) {
	for i := range builds {
		if automotivev1alpha1.IsTerminalBuildPhase(builds[i].Status.Phase) {
			finished = append(finished, builds[i])
		} else {
			active = append(active, builds[i])
		}
	}
	return
}

func (r *Reconciler) cleanupHistory(ctx context.Context, sib *automotivev1alpha1.ScheduledImageBuild, finished []automotivev1alpha1.ImageBuild) error {
	successLimit := int32(3)
	if sib.Spec.SuccessfulBuildsHistoryLimit != nil {
		successLimit = *sib.Spec.SuccessfulBuildsHistoryLimit
	}
	failedLimit := int32(1)
	if sib.Spec.FailedBuildsHistoryLimit != nil {
		failedLimit = *sib.Spec.FailedBuildsHistoryLimit
	}

	var successful, failed []automotivev1alpha1.ImageBuild
	for i := range finished {
		if finished[i].Status.Phase == automotivev1alpha1.ImageBuildPhaseCompleted {
			successful = append(successful, finished[i])
		} else {
			failed = append(failed, finished[i])
		}
	}

	sortByCreation(successful)
	sortByCreation(failed)

	retainUnpublished := sib.Spec.PublishToCatalog != nil && sib.Spec.PublishToCatalog.Enabled
	if err := r.deleteExcess(ctx, successful, int(successLimit), retainUnpublished); err != nil {
		return err
	}
	return r.deleteExcess(ctx, failed, int(failedLimit), false)
}

func sortByCreation(builds []automotivev1alpha1.ImageBuild) {
	sort.Slice(builds, func(i, j int) bool {
		return builds[i].CreationTimestamp.Before(&builds[j].CreationTimestamp)
	})
}

func (r *Reconciler) deleteExcess(ctx context.Context, builds []automotivev1alpha1.ImageBuild, limit int, retainUnpublished bool) error {
	if len(builds) <= limit {
		return nil
	}
	maxUnpublished := limit * 2
	if maxUnpublished < 5 {
		maxUnpublished = 5
	}
	unpublishedCount := 0
	excess := builds[:len(builds)-limit]
	for i := range excess {
		if retainUnpublished && excess[i].Annotations[AnnotationCatalogPublished] == "" {
			unpublishedCount++
			if unpublishedCount <= maxUnpublished {
				r.Log.Info("Retaining unpublished ImageBuild", "name", excess[i].Name)
				continue
			}
			r.Log.Info("Deleting unpublished ImageBuild (exceeded retention cap)", "name", excess[i].Name, "cap", maxUnpublished)
		}
		if err := r.Delete(ctx, &excess[i]); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to delete old ImageBuild %s: %w", excess[i].Name, err)
		}
		r.Log.Info("Deleted old ImageBuild", "name", excess[i].Name)
	}
	return nil
}

func (r *Reconciler) handleCompletedBuilds(ctx context.Context, sib *automotivev1alpha1.ScheduledImageBuild, finished []automotivev1alpha1.ImageBuild) {
	for i := range finished {
		build := &finished[i]

		switch build.Status.Phase {
		case automotivev1alpha1.ImageBuildPhaseCompleted:
			completionTime := build.Status.CompletionTime
			if completionTime == nil {
				completionTime = &metav1.Time{Time: build.CreationTimestamp.Time}
			}
			if sib.Status.LastSuccessfulTime == nil || completionTime.After(sib.Status.LastSuccessfulTime.Time) {
				sib.Status.LastSuccessfulTime = completionTime
				r.Recorder.Eventf(sib, corev1.EventTypeNormal, "BuildSucceeded",
					"ImageBuild %s completed successfully", build.Name)
				r.setLastBuildCondition(sib, metav1.ConditionTrue, "BuildSucceeded",
					fmt.Sprintf("ImageBuild %s completed successfully", build.Name))
			}

			if r.shouldPublish(sib, build) {
				r.publishToCatalog(ctx, sib, build)
			}

		case automotivev1alpha1.ImageBuildPhaseFailed:
			completionTime := build.Status.CompletionTime
			if completionTime == nil {
				completionTime = &metav1.Time{Time: build.CreationTimestamp.Time}
			}
			if sib.Status.LastFailedTime == nil || completionTime.After(sib.Status.LastFailedTime.Time) {
				sib.Status.LastFailedTime = completionTime
				msg := build.Status.Message
				if msg == "" {
					msg = "unknown error"
				}
				r.Recorder.Eventf(sib, corev1.EventTypeWarning, "BuildFailed",
					"ImageBuild %s failed: %s", build.Name, msg)
				r.setLastBuildCondition(sib, metav1.ConditionFalse, "BuildFailed",
					fmt.Sprintf("ImageBuild %s failed: %s", build.Name, msg))
			}
		}
	}
}

func (r *Reconciler) shouldPublish(sib *automotivev1alpha1.ScheduledImageBuild, build *automotivev1alpha1.ImageBuild) bool {
	if sib.Spec.PublishToCatalog == nil || !sib.Spec.PublishToCatalog.Enabled {
		return false
	}
	if build.Annotations != nil && build.Annotations[AnnotationCatalogPublished] == AnnotationCatalogPublishedValue {
		return false
	}
	return true
}

func (r *Reconciler) publishToCatalog(ctx context.Context, sib *automotivev1alpha1.ScheduledImageBuild, build *automotivev1alpha1.ImageBuild) {
	log := r.Log.WithValues("imagebuild", build.Name)

	if r.Publisher == nil {
		log.Info("No publisher configured, skipping catalog publish")
		return
	}

	// Re-fetch to avoid double-publish when two reconciles race
	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(ctx, client.ObjectKeyFromObject(build), fresh); err != nil {
		log.Error(err, "Failed to re-fetch ImageBuild before publish")
		return
	}
	if fresh.Annotations != nil && fresh.Annotations[AnnotationCatalogPublished] == AnnotationCatalogPublishedValue {
		log.Info("ImageBuild already published (detected on re-fetch), skipping")
		return
	}

	var tags []string
	var authSecretRef *automotivev1alpha1.AuthSecretReference
	if sib.Spec.PublishToCatalog != nil {
		tags = sib.Spec.PublishToCatalog.Tags
		authSecretRef = sib.Spec.PublishToCatalog.AuthSecretRef
	}

	result, err := r.Publisher.PublishFromImageBuild(ctx, build, "", tags, authSecretRef)
	if err != nil {
		log.Error(err, "Failed to publish to catalog")
		r.Recorder.Eventf(sib, corev1.EventTypeWarning, "PublishFailed",
			"Failed to publish ImageBuild %s to catalog: %v", build.Name, err)
		meta.SetStatusCondition(&sib.Status.Conditions, metav1.Condition{
			Type:               ConditionLastPublishSucceeded,
			Status:             metav1.ConditionFalse,
			Reason:             "PublishFailed",
			Message:            fmt.Sprintf("Failed to publish ImageBuild %s: %v", build.Name, err),
			ObservedGeneration: sib.Generation,
		})
		return
	}

	patch := client.MergeFrom(build.DeepCopy())
	if build.Annotations == nil {
		build.Annotations = make(map[string]string)
	}
	build.Annotations[AnnotationCatalogPublished] = AnnotationCatalogPublishedValue
	if err := r.Patch(ctx, build, patch); err != nil {
		log.Error(err, "Failed to annotate ImageBuild as published")
	}

	reason := "Published"
	if result != nil && result.Verified {
		reason = "PublishedAndVerified"
	}
	meta.SetStatusCondition(&sib.Status.Conditions, metav1.Condition{
		Type:               ConditionLastPublishSucceeded,
		Status:             metav1.ConditionTrue,
		Reason:             reason,
		Message:            fmt.Sprintf("ImageBuild %s published to catalog", build.Name),
		ObservedGeneration: sib.Generation,
	})
	r.Recorder.Eventf(sib, corev1.EventTypeNormal, "Published",
		"Published ImageBuild %s to catalog", build.Name)
}

func (r *Reconciler) updateActiveStatus(sib *automotivev1alpha1.ScheduledImageBuild, active []automotivev1alpha1.ImageBuild) {
	gvk := automotivev1alpha1.GroupVersion.WithKind("ImageBuild")
	sib.Status.Active = make([]corev1.ObjectReference, 0, len(active))
	for i := range active {
		sib.Status.Active = append(sib.Status.Active, corev1.ObjectReference{
			APIVersion: gvk.GroupVersion().String(),
			Kind:       gvk.Kind,
			Name:       active[i].Name,
			Namespace:  active[i].Namespace,
			UID:        active[i].UID,
		})
	}
}

func (r *Reconciler) checkConcurrency(ctx context.Context, sib *automotivev1alpha1.ScheduledImageBuild, active []automotivev1alpha1.ImageBuild, missedRun *time.Time) (bool, error) {
	if len(active) == 0 {
		return true, nil
	}

	if missedRun == nil {
		return false, nil
	}

	switch sib.Spec.ConcurrencyPolicy {
	case automotivev1alpha1.AllowConcurrent:
		return true, nil

	case automotivev1alpha1.ReplaceConcurrent:
		for i := range active {
			r.Log.Info("Deleting active ImageBuild for Replace policy", "name", active[i].Name)
			if err := r.Delete(ctx, &active[i]); err != nil && !apierrors.IsNotFound(err) {
				return false, fmt.Errorf("failed to delete active ImageBuild %s: %w", active[i].Name, err)
			}
			r.Recorder.Eventf(sib, corev1.EventTypeNormal, "Replaced",
				"Deleted active ImageBuild %s for replacement", active[i].Name)
		}
		return true, nil

	default: // Forbid
		r.Log.Info("Skipping build creation, active build exists (Forbid policy)", "active", len(active))
		return false, nil
	}
}

func (r *Reconciler) getMissedAndNext(
	sib *automotivev1alpha1.ScheduledImageBuild,
	schedule cron.Schedule,
	now time.Time,
) (*time.Time, time.Time) {
	var refTime time.Time
	if sib.Status.LastScheduleTime != nil {
		refTime = sib.Status.LastScheduleTime.Time
	} else {
		refTime = sib.CreationTimestamp.Time
	}

	// Pre-clamp refTime with deadline window to avoid iterating over a huge gap
	if sib.Spec.StartingDeadlineSeconds != nil {
		earliest := now.Add(-time.Duration(*sib.Spec.StartingDeadlineSeconds) * time.Second)
		if refTime.Before(earliest) {
			refTime = earliest
		}
	}

	const maxIterations = 1000
	var mostRecent *time.Time
	count := 0
	for t := schedule.Next(refTime); !t.After(now); t = schedule.Next(t) {
		ts := t
		mostRecent = &ts
		count++
		if count >= maxIterations {
			r.Log.Info("Missed-run scan capped", "iterations", maxIterations)
			break
		}
	}

	if sib.Spec.StartingDeadlineSeconds != nil && mostRecent != nil {
		deadline := now.Add(-time.Duration(*sib.Spec.StartingDeadlineSeconds) * time.Second)
		if mostRecent.Before(deadline) {
			mostRecent = nil
		}
	}

	nextRun := schedule.Next(now)

	if mostRecent == nil {
		return nil, nextRun
	}

	return mostRecent, nextRun
}

type matrixCombo struct {
	Architecture string
	Distro       string
	Target       string
}

func expandMatrix(sib *automotivev1alpha1.ScheduledImageBuild) []matrixCombo {
	if sib.Spec.Matrix == nil {
		return []matrixCombo{{}}
	}

	arches := sib.Spec.Matrix.Architectures
	if len(arches) == 0 {
		arches = []string{""}
	}
	distros := sib.Spec.Matrix.Distros
	if len(distros) == 0 {
		distros = []string{""}
	}
	targets := sib.Spec.Matrix.Targets
	if len(targets) == 0 {
		targets = []string{""}
	}

	combos := make([]matrixCombo, 0, len(arches)*len(distros)*len(targets))
	for _, arch := range arches {
		for _, distro := range distros {
			for _, target := range targets {
				combos = append(combos, matrixCombo{
					Architecture: arch,
					Distro:       distro,
					Target:       target,
				})
			}
		}
	}
	return combos
}

func sanitizeNamePart(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "_", "-")
}

func (c matrixCombo) suffix() string {
	var parts []string
	if c.Architecture != "" {
		parts = append(parts, sanitizeNamePart(c.Architecture))
	}
	if c.Distro != "" {
		parts = append(parts, sanitizeNamePart(c.Distro))
	}
	if c.Target != "" {
		parts = append(parts, sanitizeNamePart(c.Target))
	}
	if len(parts) == 0 {
		return ""
	}
	return "-" + strings.Join(parts, "-")
}

func (r *Reconciler) createImageBuilds(ctx context.Context, sib *automotivev1alpha1.ScheduledImageBuild, scheduledTime time.Time) (int, error) {
	combos := expandMatrix(sib)
	for _, combo := range combos {
		if err := r.createSingleImageBuild(ctx, sib, scheduledTime, combo); err != nil {
			return 0, err
		}
	}
	return len(combos), nil
}

func (r *Reconciler) createSingleImageBuild(ctx context.Context, sib *automotivev1alpha1.ScheduledImageBuild, scheduledTime time.Time, combo matrixCombo) error {
	tsSuffix := fmt.Sprintf("-%x", scheduledTime.Unix())
	name := safeDerivedName(sib.Name, combo.suffix()+tsSuffix)

	labels := make(map[string]string)
	for k, v := range sib.Spec.ImageBuildTemplate.Metadata.Labels {
		labels[k] = v
	}
	labels[automotivev1alpha1.LabelScheduledImageBuildName] = sib.Name

	if combo.Architecture != "" {
		labels[automotivev1alpha1.LabelArchitecture] = combo.Architecture
	}
	if combo.Distro != "" {
		labels[automotivev1alpha1.LabelDistro] = combo.Distro
	}
	if combo.Target != "" {
		labels[automotivev1alpha1.LabelTarget] = combo.Target
	}

	annotations := make(map[string]string)
	for k, v := range sib.Spec.ImageBuildTemplate.Metadata.Annotations {
		annotations[k] = v
	}

	spec := sib.Spec.ImageBuildTemplate.Spec.DeepCopy()
	if combo.Architecture != "" {
		spec.Architecture = combo.Architecture
	}
	if combo.Distro != "" && spec.AIB != nil {
		spec.AIB.Distro = combo.Distro
	}
	if combo.Target != "" && spec.AIB != nil {
		spec.AIB.Target = combo.Target
	}

	if suffix := combo.suffix(); suffix != "" {
		if spec.Export != nil && spec.Export.Disk != nil && spec.Export.Disk.OCI != "" {
			spec.Export.Disk.OCI = appendOCITagSuffix(spec.Export.Disk.OCI, suffix)
		}
		if spec.Export != nil && spec.Export.Container != "" {
			spec.Export.Container = appendOCITagSuffix(spec.Export.Container, suffix)
		}
	}

	imageBuild := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   sib.Namespace,
			Labels:      labels,
			Annotations: annotations,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion:         automotivev1alpha1.GroupVersion.String(),
					Kind:               "ScheduledImageBuild",
					Name:               sib.Name,
					UID:                sib.UID,
					Controller:         ptr.To(true),
					BlockOwnerDeletion: ptr.To(true),
				},
			},
		},
		Spec: *spec,
	}

	if err := r.Create(ctx, imageBuild); err != nil {
		if apierrors.IsAlreadyExists(err) {
			existing := &automotivev1alpha1.ImageBuild{}
			if getErr := r.Get(ctx, client.ObjectKeyFromObject(imageBuild), existing); getErr != nil {
				return fmt.Errorf("failed to get existing ImageBuild %s: %w", name, getErr)
			}
			if metav1.IsControlledBy(existing, sib) {
				r.Log.Info("ImageBuild already exists (owned by this SIB), treating as success", "name", name)
				return nil
			}
		}
		return fmt.Errorf("failed to create ImageBuild %s: %w", name, err)
	}

	r.Log.Info("Created ImageBuild", "name", name, "scheduledTime", scheduledTime, "matrix", combo)
	return nil
}

func (r *Reconciler) setScheduledCondition(sib *automotivev1alpha1.ScheduledImageBuild, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&sib.Status.Conditions, metav1.Condition{
		Type:               ConditionScheduled,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: sib.Generation,
	})
}

func (r *Reconciler) setLastBuildCondition(sib *automotivev1alpha1.ScheduledImageBuild, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&sib.Status.Conditions, metav1.Condition{
		Type:               ConditionLastBuildSucceeded,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: sib.Generation,
	})
}

func (r *Reconciler) now() time.Time {
	if r.Clock != nil {
		return r.Clock.Now()
	}
	return time.Now()
}

// SetupWithManager registers the controller with the manager.
func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&automotivev1alpha1.ScheduledImageBuild{}).
		Owns(&automotivev1alpha1.ImageBuild{}).
		Complete(r)
}

func isSuspended(sib *automotivev1alpha1.ScheduledImageBuild) bool {
	return sib.Spec.Suspend != nil && *sib.Spec.Suspend
}

func isOwnedBy(build *automotivev1alpha1.ImageBuild, owner *automotivev1alpha1.ScheduledImageBuild) bool {
	for _, ref := range build.OwnerReferences {
		if ref.UID == owner.UID {
			return true
		}
	}
	return false
}

func parseScheduleUTC(expr string) (cron.Schedule, error) {
	sched, err := cronParser.Parse(expr)
	if err != nil {
		return nil, err
	}
	if specSched, ok := sched.(*cron.SpecSchedule); ok {
		specSched.Location = time.UTC
	}
	return sched, nil
}

func appendOCITagSuffix(ref, suffix string) string {
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		return ref[:i] + ":" + ref[i+1:] + suffix
	}
	return ref + ":latest" + suffix
}

func safeDerivedName(baseName, suffix string) string {
	maxBaseLength := maxK8sNameLength - len(suffix) - 9

	if maxBaseLength >= len(baseName) {
		return fmt.Sprintf("%s%s", baseName, suffix)
	}

	hash := sha256.Sum256([]byte(baseName))
	hexHash := fmt.Sprintf("%x", hash[:4])

	if maxBaseLength <= 0 {
		name := hexHash + suffix
		if len(name) > maxK8sNameLength {
			name = name[:maxK8sNameLength]
		}
		return name
	}

	truncated := baseName[:maxBaseLength]
	return fmt.Sprintf("%s-%s%s", truncated, hexHash, suffix)
}
