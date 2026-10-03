// Package buildercache manages discoverable helper digests separately from reusable cache tags.
package buildercache

import (
	"context"
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
	defaultTTL         = 30 * 24 * time.Hour
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
	ttl := defaultTTL
	if c := config.Spec.OSBuilds; c != nil && c.BuilderCacheTTL != "" {
		var err error
		ttl, err = time.ParseDuration(c.BuilderCacheTTL)
		if err != nil || ttl < 0 {
			return again, fmt.Errorf("invalid builderCacheTTL %q", c.BuilderCacheTTL)
		}
	}
	stream := &imagev1.ImageStream{}
	if err := r.APIReader.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: streamName}, stream); err != nil {
		return again, client.IgnoreNotFound(err)
	}
	refs, used, active, unresolved, err := r.references(ctx, stream, config)
	if err != nil {
		return again, err
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	changed, protected := maintainTags(stream, refs, used, now)
	reasons := []string{}
	if unresolved {
		reasons = append(reasons, "catalog helper metadata is unresolved")
	}
	if !protected {
		reasons = append(reasons, "referenced helper pins are awaiting registry visibility")
	}
	if err := r.reportCleanup(ctx, config, reasons); err != nil {
		return again, err
	}
	if changed {
		if err := r.Update(ctx, stream); err != nil {
			return again, err
		}
		// An ImageStreamImage tag needs to appear in status before cache tags can go.
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	if unresolved || !protected {
		return again, nil
	}
	for _, tag := range stream.Spec.Tags {
		lastUsed, err := time.Parse(time.RFC3339Nano, tag.Annotations[lastUsedAnnotation])
		if err != nil {
			continue
		}
		remove := false
		switch {
		case pinPattern.MatchString(tag.Name):
			remove = !active && !refs["sha256:"+strings.TrimPrefix(tag.Name, "pin-")] && now.Sub(lastUsed) > orphanPinGrace
		case cacheTagPattern.MatchString(tag.Name):
			remove = ttl > 0 && !refs["tag:"+tag.Name] && now.Sub(lastUsed) > ttl
		}
		if !remove {
			continue
		}
		// Removing an ImageStreamTag removes its history, not just its spec entry.
		ist := &imagev1.ImageStreamTag{ObjectMeta: metav1.ObjectMeta{Namespace: req.Namespace, Name: streamName + ":" + tag.Name}}
		if err := r.Delete(ctx, ist); err != nil && !apierrors.IsNotFound(err) {
			return again, err
		}
		log.FromContext(ctx).Info("Expired builder tag", "tag", tag.Name)
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

// references also migrates catalog entries while their source build still exists.
// Unknown catalog metadata blocks deletion rather than guessing that a helper is unused.
func (r *Reconciler) references(ctx context.Context, stream *imagev1.ImageStream, config *automotivev1.OperatorConfig) (map[string]bool, map[string]time.Time, bool, bool, error) {
	refs := map[string]bool{}
	used := map[string]time.Time{}
	active, unresolved := false, false
	present := map[string]bool{}
	for _, history := range stream.Status.Tags {
		for _, item := range history.Items {
			present[item.Image] = true
		}
	}
	add := func(obj client.Object, ref string) string {
		digest := managedDigest(ref, stream, config)
		if digest != "" && !strings.Contains(ref, "@") {
			// Old published images recorded mutable tags. A digest pin cannot
			// preserve those tag references, so retain the original tag too.
			refs["tag:"+ref[strings.LastIndex(ref, ":")+1:]] = true
		}
		if digest != "" {
			refs[digest] = true
			if !present[digest] && r.Recorder != nil {
				r.Recorder.Eventf(obj, nil, corev1.EventTypeWarning, "BuilderImageUnavailable", "RetainBuilder",
					"Builder %s is absent from ImageStream %s history and cannot be pinned; rebuild or restore the helper", ref, stream.Name)
			}
		}
		return digest
	}
	var builds automotivev1.ImageBuildList
	if err := r.APIReader.List(ctx, &builds, client.InNamespace(stream.Namespace)); err != nil {
		return nil, nil, false, false, err
	}
	byName := map[string]*automotivev1.ImageBuild{}
	for i := range builds.Items {
		build := &builds.Items[i]
		byName[build.Name] = build
		active = active || !automotivev1.IsTerminalBuildPhase(build.Status.Phase)
		add(build, build.Spec.GetBuilderImage())
		digest := add(build, build.Status.BuilderImageUsed)
		if digest != "" && build.Status.CompletionTime != nil && build.Status.CompletionTime.After(used[digest]) {
			used[digest] = build.Status.CompletionTime.Time
		}
	}
	var catalog automotivev1.CatalogImageList
	if err := r.APIReader.List(ctx, &catalog, client.InNamespace(stream.Namespace)); err != nil {
		return nil, nil, false, false, err
	}
	for i := range catalog.Items {
		entry := &catalog.Items[i]
		ref := entry.Spec.BuilderImage
		if ref == "" {
			if build := byName[entry.Status.SourceImageBuild]; build != nil && build.Status.BuilderImageUsed != "" {
				ref = build.Status.BuilderImageUsed
				entry.Spec.BuilderImage = ref
				if err := r.Update(ctx, entry); err != nil {
					return nil, nil, false, false, err
				}
			}
		}
		add(entry, ref)
		metadata := entry.Status.RegistryMetadata
		if metadata != nil {
			for _, ref := range metadata.BuilderImages {
				add(entry, ref)
			}
		}
		if ref == "" && (metadata == nil || !metadata.BuilderImageResolved) {
			unresolved = true
		}
	}
	var reseals automotivev1.ImageResealList
	if err := r.APIReader.List(ctx, &reseals, client.InNamespace(stream.Namespace)); err != nil {
		return nil, nil, false, false, err
	}
	for _, reseal := range reseals.Items {
		add(&reseal, reseal.Spec.BuilderImage)
		active = active || !resealFinished(&reseal)
	}
	return refs, used, active, unresolved, nil
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

// maintainTags records actual completed uses against every matching cache history,
// seeds legacy tags with a grace period, and backfills pins for existing references.
func maintainTags(stream *imagev1.ImageStream, refs map[string]bool, used map[string]time.Time, now time.Time) (changed, protected bool) {
	tags := map[string]int{}
	history := map[string][]imagev1.TagEvent{}
	for i := range stream.Spec.Tags {
		tags[stream.Spec.Tags[i].Name] = i
	}
	for _, tag := range stream.Status.Tags {
		history[tag.Tag] = tag.Items
		if !cacheTagPattern.MatchString(tag.Tag) && !pinPattern.MatchString(tag.Tag) {
			continue
		}
		if _, exists := tags[tag.Tag]; !exists {
			tags[tag.Tag] = len(stream.Spec.Tags)
			stream.Spec.Tags = append(stream.Spec.Tags, imagev1.TagReference{Name: tag.Tag})
			changed = true
		}
	}
	for name, index := range tags {
		if !cacheTagPattern.MatchString(name) && !pinPattern.MatchString(name) {
			continue
		}
		tag := &stream.Spec.Tags[index]
		last, err := time.Parse(time.RFC3339Nano, tag.Annotations[lastUsedAnnotation])
		if err != nil {
			last = now
		}
		for _, item := range history[name] {
			if item.Created.After(last) {
				last = item.Created.Time
			}
			if used[item.Image].After(last) {
				last = used[item.Image]
			}
		}
		value := last.UTC().Format(time.RFC3339Nano)
		if tag.Annotations[lastUsedAnnotation] != value {
			if tag.Annotations == nil {
				tag.Annotations = map[string]string{}
			}
			tag.Annotations[lastUsedAnnotation] = value
			changed = true
		}
	}
	protected = true
	for digest := range refs {
		if !digestPattern.MatchString(digest) {
			continue
		}
		name := "pin-" + strings.TrimPrefix(digest, "sha256:")
		items := history[name]
		if len(items) > 0 && items[0].Image == digest {
			continue
		}
		// Do not create dangling tags when a digest has already disappeared.
		present := false
		for _, items := range history {
			for _, item := range items {
				present = present || item.Image == digest
			}
		}
		if !present {
			continue
		}
		protected = false
		from := &corev1.ObjectReference{Kind: "ImageStreamImage", Name: streamName + "@" + digest}
		if index, ok := tags[name]; ok {
			tag := &stream.Spec.Tags[index]
			if tag.From != nil && tag.From.Kind == from.Kind && tag.From.Name == from.Name {
				continue
			}
			tag.From = from
		} else {
			stream.Spec.Tags = append(stream.Spec.Tags, imagev1.TagReference{Name: name, From: from,
				Annotations: map[string]string{lastUsedAnnotation: now.Format(time.RFC3339Nano)}})
		}
		changed = true
	}
	return changed, protected
}
