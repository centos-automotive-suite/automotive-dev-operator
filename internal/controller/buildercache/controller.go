// Package buildercache manages discoverable helper digests separately from reusable cache tags.
package buildercache

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	automotivev1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	imagev1 "github.com/openshift/api/image/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

const (
	streamName         = "aib-build"
	lastUsedAnnotation = "automotive.sdv.cloud.redhat.com/builder-cache-last-used"
	cleanupCondition   = "BuilderCacheCleanupDeferred"
	// Leave time for task results and catalog publication to become visible.
	orphanPinGrace = 24 * time.Hour
)

var (
	cacheTagPattern = regexp.MustCompile(`^.+-(amd64|arm64)-[a-f0-9]{8}(-[a-f0-9]{16})?$`)
	digestPattern   = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	pinPattern      = regexp.MustCompile(`^pin-[a-f0-9]{64}$`)
)

// Reconciler uses uncached reads for retention decisions and updates the existing ImageStream.
// It deliberately does not watch ImageStreams or require additional registry/task permissions.
type Reconciler struct {
	client.Client
	APIReader client.Reader
	Recorder  events.EventRecorder
	Now       func() time.Time
}

func (r *Reconciler) SetupWithManager(mgr ctrl.Manager) error {
	enqueue := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
		return []reconcile.Request{{NamespacedName: client.ObjectKey{Namespace: obj.GetNamespace(), Name: "config"}}}
	})
	return ctrl.NewControllerManagedBy(mgr).Named("builder-cache").
		WithEventFilter(retentionEvents()).
		For(&automotivev1.OperatorConfig{}).
		Watches(&automotivev1.ImageBuild{}, enqueue).
		Watches(&automotivev1.CatalogImage{}, enqueue).
		Watches(&automotivev1.ImageReseal{}, enqueue).Complete(r)
}

func (r *Reconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if req.Name != "config" {
		return ctrl.Result{}, nil
	}
	again := ctrl.Result{RequeueAfter: time.Hour}
	config := &automotivev1.OperatorConfig{}
	if err := r.APIReader.Get(ctx, req.NamespacedName, config); err != nil {
		return again, client.IgnoreNotFound(err)
	}
	ttl, err := config.Spec.OSBuilds.GetBuilderCacheTTL()
	if err != nil {
		return again, err
	}
	stream := &imagev1.ImageStream{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: streamName}, stream); err != nil {
		if apierrors.IsNotFound(err) || apimeta.IsNoMatchError(err) {
			return again, nil
		}
		return again, err
	}
	inputs, err := r.readInputs(ctx, stream.Namespace)
	if err != nil {
		return again, err
	}
	if err := r.backfillCatalog(ctx, inputs); err != nil {
		return again, err
	}
	refs := r.references(stream, config, inputs)
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	lastUsed, changed, err := maintainLastUsed(stream, refs.used, now)
	if err != nil {
		return again, err
	}
	var reasons []string
	if refs.unresolved {
		reasons = append(reasons, "catalog helper metadata is unresolved")
	}
	if err := r.reportCleanup(ctx, config, reasons); err != nil {
		return again, err
	}
	if changed {
		if err := r.Update(ctx, stream); err != nil {
			return again, err
		}
	}
	if refs.unresolved {
		return again, nil
	}
	for name, last := range lastUsed {
		remove := false
		switch {
		case pinPattern.MatchString(name):
			remove = !refs.active && !refs.digests["sha256:"+strings.TrimPrefix(name, "pin-")] && now.Sub(last) > orphanPinGrace
		case cacheTagPattern.MatchString(name):
			remove = ttl > 0 && !refs.tags[name] && now.Sub(last) > ttl
		}
		if !remove {
			continue
		}
		// Removing an ImageStreamTag removes its history, not just its spec entry.
		ist := &imagev1.ImageStreamTag{ObjectMeta: metav1.ObjectMeta{Namespace: req.Namespace, Name: streamName + ":" + name}}
		if err := r.Delete(ctx, ist); err != nil && !apierrors.IsNotFound(err) {
			return again, err
		}
		log.FromContext(ctx).Info("Expired builder tag", "tag", name)
	}
	return again, nil
}

func (r *Reconciler) reportCleanup(ctx context.Context, config *automotivev1.OperatorConfig, reasons []string) error {
	before := config.DeepCopy()
	condition := metav1.Condition{
		Type: cleanupCondition, Status: metav1.ConditionFalse, Reason: "CleanupEnabled",
		Message:            "Cache cleanup enabled; active operations and grace periods protect orphan pins",
		ObservedGeneration: config.Generation,
	}
	if len(reasons) > 0 {
		condition.Status = metav1.ConditionTrue
		condition.Reason = "CleanupDeferred"
		condition.Message = strings.Join(reasons, "; ")
	}
	if !apimeta.SetStatusCondition(&config.Status.Conditions, condition) {
		return nil
	}
	if err := r.Status().Patch(ctx, config, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
		return err
	}
	log.FromContext(ctx).Info("Builder cleanup status changed", "deferred", condition.Status, "message", condition.Message)
	return nil
}

type retentionInputs struct {
	builds  automotivev1.ImageBuildList
	catalog automotivev1.CatalogImageList
	reseals automotivev1.ImageResealList
}

type builderReferences struct {
	digests    map[string]bool
	tags       map[string]bool
	used       map[string]time.Time
	active     bool
	unresolved bool
}

func (r *Reconciler) readInputs(ctx context.Context, namespace string) (*retentionInputs, error) {
	inputs := &retentionInputs{}
	for _, list := range []client.ObjectList{&inputs.builds, &inputs.catalog, &inputs.reseals} {
		if err := r.APIReader.List(ctx, list, client.InNamespace(namespace)); err != nil {
			return nil, err
		}
	}
	return inputs, nil
}

// Expired source builds still provide durable provenance for older catalog entries.
func (r *Reconciler) backfillCatalog(ctx context.Context, inputs *retentionInputs) error {
	byName := map[string]string{}
	for _, build := range inputs.builds.Items {
		byName[build.Name] = build.Status.BuilderImageUsed
	}
	for i := range inputs.catalog.Items {
		entry := &inputs.catalog.Items[i]
		ref := byName[entry.Status.SourceImageBuild]
		if entry.Spec.BuilderImage != "" || ref == "" {
			continue
		}
		before := entry.DeepCopy()
		entry.Spec.BuilderImage = ref
		if err := r.Patch(ctx, entry, client.MergeFromWithOptions(before, client.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
	}
	return nil
}

// Unknown catalog metadata blocks deletion rather than guessing that a helper is unused.
func (r *Reconciler) references(stream *imagev1.ImageStream, config *automotivev1.OperatorConfig, inputs *retentionInputs) builderReferences {
	refs := builderReferences{digests: map[string]bool{}, tags: map[string]bool{}, used: map[string]time.Time{}}
	pinned := map[string]bool{}
	for _, history := range stream.Status.Tags {
		if len(history.Items) > 0 && history.Tag == "pin-"+strings.TrimPrefix(history.Items[0].Image, "sha256:") {
			pinned[history.Items[0].Image] = true
		}
	}
	add := func(obj client.Object, ref string) {
		digest := managedDigest(ref, stream, config)
		if digest == "" {
			return
		}
		if !strings.Contains(ref, "@") {
			// A digest pin cannot preserve the mutable tags recorded by older builds.
			refs.tags[ref[strings.LastIndex(ref, ":")+1:]] = true
			return
		}
		refs.digests[digest] = true
		if !pinned[digest] && r.Recorder != nil {
			r.Recorder.Eventf(obj, nil, corev1.EventTypeWarning, "BuilderImageUnavailable", "RetainBuilder",
				"Builder %s has no pin in ImageStream %s; restore the pin or rebuild the helper", ref, stream.Name)
		}
	}
	for i := range inputs.builds.Items {
		build := &inputs.builds.Items[i]
		if build.Status.Phase != automotivev1.ImageBuildPhaseExpired {
			refs.active = refs.active || !automotivev1.IsTerminalBuildPhase(build.Status.Phase)
			add(build, build.Spec.GetBuilderImage())
			add(build, build.Status.BuilderImageUsed)
		}
		digest := managedDigest(build.Status.BuilderImageUsed, stream, config)
		if digest != "" && build.Status.CompletionTime != nil && build.Status.CompletionTime.After(refs.used[digest]) {
			refs.used[digest] = build.Status.CompletionTime.Time
		}
	}
	for i := range inputs.catalog.Items {
		entry := &inputs.catalog.Items[i]
		add(entry, entry.Spec.BuilderImage)
		metadata := entry.Status.RegistryMetadata
		if metadata != nil {
			for _, ref := range metadata.BuilderImages {
				add(entry, ref)
			}
		}
		if entry.Spec.BuilderImage == "" && (metadata == nil || !metadata.BuilderImageResolved) {
			refs.unresolved = true
		}
	}
	for i := range inputs.reseals.Items {
		reseal := &inputs.reseals.Items[i]
		add(reseal, reseal.Spec.BuilderImage)
		refs.active = refs.active || !resealFinished(reseal)
	}
	return refs
}

func managedDigest(ref string, stream *imagev1.ImageStream, config *automotivev1.OperatorConfig) string {
	// Only this namespace's integrated-registry repository is ours to retain.
	repos := []string{stream.Status.DockerImageRepository, stream.Status.PublicDockerImageRepository,
		"image-registry.openshift-image-registry.svc:5000/" + stream.Namespace + "/" + streamName}
	if config.Spec.OSBuilds != nil && config.Spec.OSBuilds.ClusterRegistryRoute != "" {
		repos = append(repos, strings.TrimSuffix(config.Spec.OSBuilds.ClusterRegistryRoute, "/")+"/"+stream.Namespace+"/"+streamName)
	}
	for _, repo := range repos {
		if repo == "" {
			continue
		}
		if digest, ok := strings.CutPrefix(ref, repo+"@"); ok && digestPattern.MatchString(digest) {
			return digest
		}
		if tag, ok := strings.CutPrefix(ref, repo+":"); ok {
			for _, history := range stream.Status.Tags {
				if history.Tag == tag && len(history.Items) > 0 {
					return history.Items[0].Image
				}
			}
		}
	}
	return ""
}

// maintainLastUsed records completed uses without creating or modifying spec tags.
func maintainLastUsed(stream *imagev1.ImageStream, used map[string]time.Time, now time.Time) (map[string]time.Time, bool, error) {
	previous := map[string]time.Time{}
	if value := stream.Annotations[lastUsedAnnotation]; value != "" {
		if err := json.Unmarshal([]byte(value), &previous); err != nil {
			return nil, false, fmt.Errorf("invalid builder cache last-use annotation: %w", err)
		}
	}
	lastUsed := map[string]time.Time{}
	// Read old per-tag annotations during migration, but leave spec.tags untouched.
	legacy := map[string]string{}
	for _, tag := range stream.Spec.Tags {
		legacy[tag.Name] = tag.Annotations[lastUsedAnnotation]
	}
	for _, history := range stream.Status.Tags {
		name := history.Tag
		if !cacheTagPattern.MatchString(name) && !pinPattern.MatchString(name) {
			continue
		}
		last := previous[name]
		if last.IsZero() {
			last, _ = time.Parse(time.RFC3339Nano, legacy[name])
			if last.IsZero() {
				last = now
			}
		}
		for _, item := range history.Items {
			if item.Created.After(last) {
				last = item.Created.Time
			}
			if used[item.Image].After(last) {
				last = used[item.Image]
			}
		}
		lastUsed[name] = last.UTC()
	}
	value, err := json.Marshal(lastUsed)
	if err != nil {
		return nil, false, err
	}
	changed := stream.Annotations[lastUsedAnnotation] != string(value)
	if changed {
		if stream.Annotations == nil {
			stream.Annotations = map[string]string{}
		}
		stream.Annotations[lastUsedAnnotation] = string(value)
	}
	return lastUsed, changed, nil
}
