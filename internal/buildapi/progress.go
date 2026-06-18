package buildapi

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
)

const (
	progressCacheTTL        = 10 * time.Second
	progressCacheMaxEntries = 256
)

type progressCacheEntry struct {
	tasks []taskProgress
	time  time.Time
}

func pruneProgressCache(cache map[string]progressCacheEntry, now time.Time) {
	if len(cache) == 0 {
		return
	}

	// Fast path: drop all stale entries first.
	for key, entry := range cache {
		if now.Sub(entry.time) > progressCacheTTL {
			delete(cache, key)
		}
	}
	if len(cache) <= progressCacheMaxEntries {
		return
	}

	// If still too large, evict oldest entries.
	type cacheItem struct {
		key string
		ts  time.Time
	}
	items := make([]cacheItem, 0, len(cache))
	for key, entry := range cache {
		items = append(items, cacheItem{key: key, ts: entry.time})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].ts.Before(items[j].ts) })
	for i := 0; i < len(items)-progressCacheMaxEntries; i++ {
		delete(cache, items[i].key)
	}
}

// BuildProgress is the response for GET /v1/builds/{name}/progress
type BuildProgress struct {
	Phase string     `json:"phase"`
	Step  *BuildStep `json:"step,omitempty"`
}

// BuildStep represents a progress checkpoint emitted by the build script.
type BuildStep struct {
	Stage string `json:"stage"`
	Done  int    `json:"done"`
	Total int    `json:"total"`
}

// taskProgress holds the latest marker from a single pipeline task pod.
type taskProgress struct {
	taskName string
	marker   BuildStep
}

// parseProgressAnnotation parses a pod annotation value with the format
// "stage|done|total" (pipe-delimited) into a BuildStep.
func parseProgressAnnotation(value string) (*BuildStep, bool) {
	parts := strings.SplitN(value, "|", 3)
	if len(parts) != 3 {
		return nil, false
	}
	done, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, false
	}
	total, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, false
	}
	return &BuildStep{Stage: parts[0], Done: done, Total: total}, true
}

// stageForPipelineTask returns a human-readable stage name for pipeline tasks
// that may not have a progress annotation yet.
func stageForPipelineTask(taskName string) string {
	switch taskName {
	case "push-disk-artifact":
		return "Pushing artifact"
	case "flash-image":
		return "Flashing device"
	default:
		return taskName
	}
}

// pendingPodStage returns a human-readable stage name for a pod that is
// still in the Pending phase, based on container waiting reasons.
func pendingPodStage(pod *corev1.Pod) string {
	statuses := slices.Concat(pod.Status.InitContainerStatuses, pod.Status.ContainerStatuses)
	for _, cs := range statuses {
		if cs.State.Waiting == nil {
			continue
		}
		switch cs.State.Waiting.Reason {
		case "ContainerCreating", "PodInitializing":
			return "Pulling image"
		case "ErrImagePull", "ImagePullBackOff":
			return "Pulling image (retrying)"
		}
	}
	return ""
}

// readTaskProgressFromPods reads the progress annotation from each pipeline
// task pod, sorted by pod start time. For pods that don't have the annotation
// yet (e.g. just started), a synthetic marker is generated when the pod is
// running or has completed.
func readTaskProgressFromPods(ctx context.Context, cs *kubernetes.Clientset, pipelineRunName, namespace string) []taskProgress {
	selector := "tekton.dev/pipelineRun=" + pipelineRunName + ",tekton.dev/memberOf=tasks"
	pods, err := cs.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil || len(pods.Items) == 0 {
		return nil
	}

	// Sort pods by start time so earlier tasks come first.
	sort.Slice(pods.Items, func(i, j int) bool {
		if pods.Items[i].Status.StartTime == nil {
			return false
		}
		if pods.Items[j].Status.StartTime == nil {
			return true
		}
		return pods.Items[i].Status.StartTime.Before(pods.Items[j].Status.StartTime)
	})

	var results []taskProgress

	for _, pod := range pods.Items {
		taskName := pod.Labels["tekton.dev/pipelineTask"]

		if ann, ok := pod.Annotations[labels.Progress]; ok {
			if step, parsed := parseProgressAnnotation(ann); parsed {
				results = append(results, taskProgress{taskName: taskName, marker: *step})
				continue
			}
		}

		// Synthesize a marker for pods that don't have the annotation
		// yet so the progress bar advances when tasks start running.
		switch pod.Status.Phase {
		case corev1.PodRunning, corev1.PodSucceeded:
			done := 0
			if pod.Status.Phase == corev1.PodSucceeded {
				done = 1
			}
			results = append(results, taskProgress{
				taskName: taskName,
				marker:   BuildStep{Stage: stageForPipelineTask(taskName), Done: done, Total: 1},
			})
		case corev1.PodPending:
			// Surface image-pull or container-creating status so the
			// user knows the pod is making progress, not stuck.
			if stage := pendingPodStage(&pod); stage != "" {
				results = append(results, taskProgress{
					taskName: taskName,
					marker:   BuildStep{Stage: stage, Done: 0, Total: 1},
				})
			}
		}
	}

	return results
}

// estimateBuildSteps calculates the expected number of build-script steps
// from the ImageBuild spec, mirroring build_image.sh's PROGRESS_TOTAL logic.
// SYNC: keep in sync with internal/common/tasks/scripts/build_image.sh (PROGRESS_TOTAL calculation).
// This is used before any markers arrive so the total is stable from the start.
func estimateBuildSteps(build *automotivev1alpha1.ImageBuild, hasClusterRegistryRoute bool) int {
	mode := Mode(build.Spec.GetMode())
	total := 3 // base: preparing, building, finalizing

	// Builder preparation (bootc/disk without explicit builder):
	// "Preparing builder" (cache check + optional build/push) + "Pulling builder" = 2 steps
	// Builder image pull only (bootc/disk with explicit builder): 1 step
	if build.Spec.GetBuilderImage() == "" && (mode == ModeBootc || mode == ModeDisk) && hasClusterRegistryRoute {
		total += 2
	} else if build.Spec.GetBuilderImage() != "" && (mode == ModeBootc || mode == ModeDisk) {
		total++
	}

	if build.Spec.GetContainerPush() != "" && mode == ModeBootc {
		total++
	}

	if build.Spec.GetBuildDiskImage() || mode == ModeImage || mode == ModePackage || mode == ModeDisk {
		total++
	}

	return total
}

// buildProgressStep calculates a pipeline-wide progress step by combining
// per-task markers with phase transitions for push/flash.
func clampDone(done, total int) int {
	if done < 0 {
		return 0
	}
	if total > 0 && done > total {
		return total
	}
	return done
}

func buildProgressStep(
	build *automotivev1alpha1.ImageBuild,
	tasks []taskProgress,
	hasClusterRegistryRoute bool,
) *BuildStep {
	hasPushTask := strings.TrimSpace(build.Spec.GetExportOCI()) != "" && strings.TrimSpace(build.Spec.SecretRef) != ""
	hasFlashTask := build.Spec.IsFlashEnabled()

	// Sum up totals from all task markers and find the active task.
	// Also track whether push/flash tasks already reported markers
	// so we don't double-count them in the pipeline total.
	var combinedTotal, combinedDone int
	var activeStage string
	var pushReported, flashReported bool
	for _, tp := range tasks {
		combinedTotal += tp.marker.Total
		combinedDone += tp.marker.Done
		activeStage = tp.marker.Stage
		if tp.taskName == "push-disk-artifact" {
			pushReported = true
		}
		if tp.taskName == "flash-image" {
			flashReported = true
		}
	}

	// Use spec-based estimate when no markers have arrived yet
	if combinedTotal == 0 {
		combinedTotal = estimateBuildSteps(build, hasClusterRegistryRoute)
	}

	// Pipeline total = build task steps + push + flash.
	// Only add push/flash increments when those tasks haven't reported
	// their own markers yet (avoids double-counting).
	pipelineTotal := combinedTotal
	if hasPushTask && !pushReported {
		pipelineTotal++
	}
	if hasFlashTask && !flashReported {
		pipelineTotal++
	}

	switch build.Status.Phase {
	case "", phasePending, phaseUploading:
		return &BuildStep{Stage: "Waiting to start", Done: 0, Total: pipelineTotal}

	case phaseBuilding, phaseRunning:
		if len(tasks) > 0 {
			return &BuildStep{Stage: activeStage, Done: clampDone(combinedDone, pipelineTotal), Total: pipelineTotal}
		}
		return &BuildStep{Stage: "Starting build", Done: 0, Total: pipelineTotal}

	case "Pushing":
		return &BuildStep{Stage: "Pushing artifact", Done: clampDone(combinedDone, pipelineTotal), Total: pipelineTotal}

	case "Flashing":
		done := combinedDone
		if hasPushTask && !pushReported {
			done++
		}
		return &BuildStep{Stage: "Flashing device", Done: clampDone(done, pipelineTotal), Total: pipelineTotal}

	case phaseCompleted:
		return &BuildStep{Stage: "Complete", Done: pipelineTotal, Total: pipelineTotal}

	case phaseFailed:
		if len(tasks) > 0 {
			return &BuildStep{Stage: activeStage, Done: clampDone(combinedDone, pipelineTotal), Total: pipelineTotal}
		}
		return &BuildStep{Stage: "Failed", Done: 0, Total: pipelineTotal}

	default:
		return &BuildStep{Stage: build.Status.Phase, Done: 0, Total: pipelineTotal}
	}
}

func (a *APIServer) handleGetProgress(c *gin.Context) {
	name := c.Param("name")
	namespace := resolveNamespace()

	k8sClient, err := getClientFromRequest(c)
	if err != nil {
		a.log.Error(err, "failed to get k8s client for progress", "name", name)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	ctx := c.Request.Context()
	build := &automotivev1alpha1.ImageBuild{}
	if err := k8sClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, build); err != nil {
		if k8serrors.IsNotFound(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
			return
		}
		a.log.Error(err, "failed to get ImageBuild for progress", "name", name, "namespace", namespace)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
		return
	}

	// Read pod annotations during all active phases. Unlike log streaming,
	// reading pod metadata is cheap (single list call, no streaming).
	var tasks []taskProgress
	hasClusterRegistryRoute := false
	tr := strings.TrimSpace(build.Status.PipelineRunName)
	phase := build.Status.Phase
	if tr != "" && (phase == phaseBuilding || phase == phaseRunning || phase == "Pushing" || phase == "Flashing") {
		cacheKey := namespace + "/" + tr
		a.progressCacheMu.RLock()
		cached, ok := a.progressCache[cacheKey]
		a.progressCacheMu.RUnlock()
		if ok && time.Since(cached.time) < progressCacheTTL {
			tasks = cached.tasks
		} else {
			restCfg, err := getRESTConfigFromRequest(c)
			if err != nil {
				a.log.Error(err, "failed to get REST config for progress pod read")
			} else {
				cs, err := kubernetes.NewForConfig(restCfg)
				if err != nil {
					a.log.Error(err, "failed to create kubernetes client for progress pod read")
				} else {
					tasks = readTaskProgressFromPods(ctx, cs, tr, namespace)
					a.progressCacheMu.Lock()
					if a.progressCache == nil {
						a.progressCache = make(map[string]progressCacheEntry)
					}
					now := time.Now()
					a.progressCache[cacheKey] = progressCacheEntry{tasks: tasks, time: now}
					pruneProgressCache(a.progressCache, now)
					a.progressCacheMu.Unlock()
				}
			}
		}
	} else if tr != "" {
		cacheKey := namespace + "/" + tr
		a.progressCacheMu.Lock()
		delete(a.progressCache, cacheKey)
		a.progressCacheMu.Unlock()
	}

	// Estimate builder-prepare steps only when no task markers exist yet.
	if len(tasks) == 0 {
		mode := Mode(build.Spec.GetMode())
		if build.Spec.GetBuilderImage() == "" && (mode == ModeBootc || mode == ModeDisk) {
			if route, err := getExternalRegistryRoute(ctx, k8sClient, namespace); err == nil && strings.TrimSpace(route) != "" {
				hasClusterRegistryRoute = true
			}
		}
	}

	progress := BuildProgress{
		Phase: build.Status.Phase,
		Step:  buildProgressStep(build, tasks, hasClusterRegistryRoute),
	}

	c.JSON(http.StatusOK, progress)
}
