package imagebuild

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/tasks"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/go-logr/logr"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	knativev1 "knative.dev/pkg/apis/duck/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func TestPipelineRunFailureMessage(t *testing.T) {
	tests := []struct {
		name        string
		pipelineRun *tektonv1.PipelineRun
		want        string
	}{
		{
			name: "returns condition message on failure",
			pipelineRun: &tektonv1.PipelineRun{
				Status: tektonv1.PipelineRunStatus{
					Status: knativev1.Status{
						Conditions: knativev1.Conditions{
							{
								Type:    conditionSucceeded,
								Status:  corev1.ConditionFalse,
								Message: "TaskRun build-step failed: container exited with code 1",
							},
						},
					},
				},
			},
			want: "Build failed: TaskRun build-step failed: container exited with code 1",
		},
		{
			name: "returns fallback when no conditions",
			pipelineRun: &tektonv1.PipelineRun{
				Status: tektonv1.PipelineRunStatus{},
			},
			want: "Build failed",
		},
		{
			name: "returns fallback when Succeeded condition has empty message",
			pipelineRun: &tektonv1.PipelineRun{
				Status: tektonv1.PipelineRunStatus{
					Status: knativev1.Status{
						Conditions: knativev1.Conditions{
							{
								Type:   conditionSucceeded,
								Status: corev1.ConditionFalse,
							},
						},
					},
				},
			},
			want: "Build failed",
		},
		{
			name: "ignores non-Succeeded conditions",
			pipelineRun: &tektonv1.PipelineRun{
				Status: tektonv1.PipelineRunStatus{
					Status: knativev1.Status{
						Conditions: knativev1.Conditions{
							{
								Type:    "Ready",
								Status:  corev1.ConditionFalse,
								Message: "not ready",
							},
						},
					},
				},
			},
			want: "Build failed",
		},
		{
			name: "ignores Succeeded=True condition",
			pipelineRun: &tektonv1.PipelineRun{
				Status: tektonv1.PipelineRunStatus{
					Status: knativev1.Status{
						Conditions: knativev1.Conditions{
							{
								Type:    conditionSucceeded,
								Status:  corev1.ConditionTrue,
								Message: "All Tasks have completed executing",
							},
						},
					},
				},
			},
			want: "Build failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pipelineRunFailureMessage(tt.pipelineRun)
			if got != tt.want {
				t.Errorf("pipelineRunFailureMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTaskRunFailureMessage(t *testing.T) {
	tests := []struct {
		name     string
		taskRun  *tektonv1.TaskRun
		fallback string
		want     string
	}{
		{
			name: "returns condition message on failure",
			taskRun: &tektonv1.TaskRun{
				Status: tektonv1.TaskRunStatus{
					Status: knativev1.Status{
						Conditions: knativev1.Conditions{
							{
								Type:    conditionSucceeded,
								Status:  corev1.ConditionFalse,
								Message: "step flash failed: timeout waiting for device",
							},
						},
					},
				},
			},
			fallback: "Flash to device failed",
			want:     "Flash to device failed: step flash failed: timeout waiting for device",
		},
		{
			name: "returns fallback when no conditions",
			taskRun: &tektonv1.TaskRun{
				Status: tektonv1.TaskRunStatus{},
			},
			fallback: "Flash to device failed",
			want:     "Flash to device failed",
		},
		{
			name: "returns fallback when Succeeded condition has empty message",
			taskRun: &tektonv1.TaskRun{
				Status: tektonv1.TaskRunStatus{
					Status: knativev1.Status{
						Conditions: knativev1.Conditions{
							{
								Type:   conditionSucceeded,
								Status: corev1.ConditionFalse,
							},
						},
					},
				},
			},
			fallback: "Flash to device failed",
			want:     "Flash to device failed",
		},
		{
			name: "ignores Succeeded=True condition",
			taskRun: &tektonv1.TaskRun{
				Status: tektonv1.TaskRunStatus{
					Status: knativev1.Status{
						Conditions: knativev1.Conditions{
							{
								Type:    conditionSucceeded,
								Status:  corev1.ConditionTrue,
								Message: "All steps completed",
							},
						},
					},
				},
			},
			fallback: "Flash to device failed",
			want:     "Flash to device failed",
		},
		{
			name: "uses custom fallback message",
			taskRun: &tektonv1.TaskRun{
				Status: tektonv1.TaskRunStatus{},
			},
			fallback: "Custom operation failed",
			want:     "Custom operation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := taskRunFailureMessage(tt.taskRun, tt.fallback)
			if got != tt.want {
				t.Errorf("taskRunFailureMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

func newTestSchemeWithTekton() *runtime.Scheme {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))
	utilruntime.Must(tektonv1.AddToScheme(scheme))
	return scheme
}

func testTaskRun(name string, failed bool, message string) *tektonv1.TaskRun {
	now := metav1.Now()
	status := corev1.ConditionTrue
	if failed {
		status = corev1.ConditionFalse
	}
	return &tektonv1.TaskRun{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "test-ns"},
		Status: tektonv1.TaskRunStatus{
			Status: knativev1.Status{
				Conditions: knativev1.Conditions{{
					Type:    conditionSucceeded,
					Status:  status,
					Message: message,
				}},
			},
			TaskRunStatusFields: tektonv1.TaskRunStatusFields{
				CompletionTime: &now,
			},
		},
	}
}

func TestPipelineRunFailureDetail(t *testing.T) {
	const ns = "test-ns"

	tests := []struct {
		name        string
		pipelineRun *tektonv1.PipelineRun
		taskRuns    []runtime.Object
		wantPrefix  string
	}{
		{
			name: "build-image task failed",
			pipelineRun: &tektonv1.PipelineRun{
				ObjectMeta: metav1.ObjectMeta{Name: "pr-1", Namespace: ns},
				Status: tektonv1.PipelineRunStatus{
					PipelineRunStatusFields: tektonv1.PipelineRunStatusFields{
						ChildReferences: []tektonv1.ChildStatusReference{
							{Name: "pr-1-build-run", PipelineTaskName: tasks.PipelineTaskBuildImage},
							{Name: "pr-1-push-run", PipelineTaskName: "push-disk-artifact"},
						},
					},
				},
			},
			taskRuns: []runtime.Object{
				testTaskRun("pr-1-build-run", true, "step build exited with code 1"),
			},
			wantPrefix: "Image build failed: step build exited with code 1",
		},
		{
			name: "push-disk-artifact task failed",
			pipelineRun: &tektonv1.PipelineRun{
				ObjectMeta: metav1.ObjectMeta{Name: "pr-2", Namespace: ns},
				Status: tektonv1.PipelineRunStatus{
					PipelineRunStatusFields: tektonv1.PipelineRunStatusFields{
						ChildReferences: []tektonv1.ChildStatusReference{
							{Name: "pr-2-build-run", PipelineTaskName: tasks.PipelineTaskBuildImage},
							{Name: "pr-2-push-run", PipelineTaskName: "push-disk-artifact"},
						},
					},
				},
			},
			taskRuns: []runtime.Object{
				testTaskRun("pr-2-build-run", false, ""),
				testTaskRun("pr-2-push-run", true, "push to registry timed out"),
			},
			wantPrefix: "Disk image push failed: push to registry timed out",
		},
		{
			name: "flash-image task failed",
			pipelineRun: &tektonv1.PipelineRun{
				ObjectMeta: metav1.ObjectMeta{Name: "pr-3", Namespace: ns},
				Status: tektonv1.PipelineRunStatus{
					PipelineRunStatusFields: tektonv1.PipelineRunStatusFields{
						ChildReferences: []tektonv1.ChildStatusReference{
							{Name: "pr-3-build-run", PipelineTaskName: tasks.PipelineTaskBuildImage},
							{Name: "pr-3-push-run", PipelineTaskName: "push-disk-artifact"},
							{Name: "pr-3-flash-run", PipelineTaskName: "flash-image"},
						},
					},
				},
			},
			taskRuns: []runtime.Object{
				testTaskRun("pr-3-build-run", false, ""),
				testTaskRun("pr-3-push-run", false, ""),
				testTaskRun("pr-3-flash-run", true, "timeout waiting for device"),
			},
			wantPrefix: "Flash failed: timeout waiting for device",
		},
		{
			name: "unknown task name uses quoted fallback",
			pipelineRun: &tektonv1.PipelineRun{
				ObjectMeta: metav1.ObjectMeta{Name: "pr-4", Namespace: ns},
				Status: tektonv1.PipelineRunStatus{
					PipelineRunStatusFields: tektonv1.PipelineRunStatusFields{
						ChildReferences: []tektonv1.ChildStatusReference{
							{Name: "pr-4-custom-run", PipelineTaskName: "custom-step"},
						},
					},
				},
			},
			taskRuns: []runtime.Object{
				testTaskRun("pr-4-custom-run", true, "something went wrong"),
			},
			wantPrefix: `Task "custom-step" failed: something went wrong`,
		},
		{
			name: "no failed TaskRun found falls back to PipelineRun message",
			pipelineRun: &tektonv1.PipelineRun{
				ObjectMeta: metav1.ObjectMeta{Name: "pr-5", Namespace: ns},
				Status: tektonv1.PipelineRunStatus{
					Status: knativev1.Status{
						Conditions: knativev1.Conditions{{
							Type:    conditionSucceeded,
							Status:  corev1.ConditionFalse,
							Message: "Tasks Completed: 1 (Failed: 1, Cancelled 0), Skipped: 2",
						}},
					},
					PipelineRunStatusFields: tektonv1.PipelineRunStatusFields{
						ChildReferences: []tektonv1.ChildStatusReference{
							// TaskRun not in fake client — simulates missing/deleted pod
							{Name: "pr-5-gone-run", PipelineTaskName: tasks.PipelineTaskBuildImage},
						},
					},
				},
			},
			taskRuns:   nil,
			wantPrefix: "Build failed: Tasks Completed: 1 (Failed: 1, Cancelled 0), Skipped: 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newTestSchemeWithTekton()
			builder := fake.NewClientBuilder().WithScheme(scheme)
			for _, obj := range tt.taskRuns {
				builder = builder.WithRuntimeObjects(obj)
			}
			r := &ImageBuildReconciler{Client: builder.Build(), Scheme: scheme}

			got := r.pipelineRunFailureDetail(context.Background(), tt.pipelineRun)
			if got != tt.wantPrefix {
				t.Errorf("pipelineRunFailureDetail() = %q, want %q", got, tt.wantPrefix)
			}
		})
	}
}

func TestSafeDerivedName(t *testing.T) {
	tests := []struct {
		name       string
		baseName   string
		suffix     string
		wantMaxLen int
		wantSuffix string
	}{
		{
			name:       "short name no truncation",
			baseName:   "simple",
			suffix:     "-manifest",
			wantMaxLen: 63,
			wantSuffix: "-manifest",
		},
		{
			name:       "exact length boundary",
			baseName:   "exactly-fifty-four-chars-to-test-boundary-conditions",
			suffix:     "-manifest",
			wantMaxLen: 63,
			wantSuffix: "-manifest",
		},
		{
			name:       "long name needs truncation",
			baseName:   "this-is-a-very-long-build-name-that-will-definitely-exceed-limits",
			suffix:     "-manifest",
			wantMaxLen: 63,
			wantSuffix: "-manifest",
		},
		{
			name:       "long suffix",
			baseName:   "build-name",
			suffix:     "-upload-pod",
			wantMaxLen: 63,
			wantSuffix: "-upload-pod",
		},
		{
			name:       "very long name with short suffix",
			baseName:   "extremely-long-build-name-that-definitely-exceeds-kubernetes-dns-label-limits",
			suffix:     "-ws",
			wantMaxLen: 63,
			wantSuffix: "-ws",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeDerivedName(tt.baseName, tt.suffix)

			// Check length constraint
			if len(result) > tt.wantMaxLen {
				t.Errorf("safeDerivedName() result %q length %d exceeds max %d", result, len(result), tt.wantMaxLen)
			}

			// Check suffix is preserved
			if !strings.HasSuffix(result, tt.wantSuffix) {
				t.Errorf("safeDerivedName() result %q does not end with expected suffix %q", result, tt.wantSuffix)
			}

			// Check deterministic (same input gives same output)
			result2 := safeDerivedName(tt.baseName, tt.suffix)
			if result != result2 {
				t.Errorf("safeDerivedName() is not deterministic: %q != %q", result, result2)
			}
		})
	}

	// Test uniqueness: different base names that would truncate to same prefix should produce different results
	t.Run("hash provides uniqueness", func(t *testing.T) {
		longName1 := "very-long-name-with-same-prefix-but-different-suffix-one"
		longName2 := "very-long-name-with-same-prefix-but-different-suffix-two"
		suffix := "-manifest"

		result1 := safeDerivedName(longName1, suffix)
		result2 := safeDerivedName(longName2, suffix)

		if result1 == result2 {
			t.Errorf("safeDerivedName() produced same result for different inputs: %q", result1)
		}

		// Both should still be valid length and have correct suffix
		if len(result1) > 63 || len(result2) > 63 {
			t.Errorf("safeDerivedName() results exceed length: %q (%d), %q (%d)", result1, len(result1), result2, len(result2))
		}

		if !strings.HasSuffix(result1, suffix) || !strings.HasSuffix(result2, suffix) {
			t.Errorf("safeDerivedName() results don't have correct suffix: %q, %q", result1, result2)
		}
	})
}

func TestSetImageBuildConditions(t *testing.T) {
	tests := []struct {
		name            string
		phase           string
		message         string
		wantProgressing metav1.ConditionStatus
		wantReady       metav1.ConditionStatus
		wantReadyReason string
	}{
		{
			name:            "pending",
			phase:           "Pending",
			message:         "Waiting for resources",
			wantProgressing: metav1.ConditionTrue,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: "Pending",
		},
		{
			name:            "uploading",
			phase:           "Uploading",
			message:         "Uploading manifest",
			wantProgressing: metav1.ConditionTrue,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: "Uploading",
		},
		{
			name:            "building",
			phase:           "Building",
			message:         "Build started",
			wantProgressing: metav1.ConditionTrue,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: "Building",
		},
		{
			name:            "pushing",
			phase:           "Pushing",
			message:         "Pushing artifact",
			wantProgressing: metav1.ConditionTrue,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: "Pushing",
		},
		{
			name:            "flashing",
			phase:           "Flashing",
			message:         "Flashing to device",
			wantProgressing: metav1.ConditionTrue,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: "Flashing",
		},
		{
			name:            "completed",
			phase:           "Completed",
			message:         "Build completed successfully",
			wantProgressing: metav1.ConditionFalse,
			wantReady:       metav1.ConditionTrue,
			wantReadyReason: "BuildSucceeded",
		},
		{
			name:            "failed",
			phase:           "Failed",
			message:         "PipelineRun failed",
			wantProgressing: metav1.ConditionFalse,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: "Failed",
		},
		{
			name:            "cancelled",
			phase:           "Cancelled",
			message:         "Build cancelled by user",
			wantProgressing: metav1.ConditionFalse,
			wantReady:       metav1.ConditionFalse,
			wantReadyReason: "Cancelled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ib := &automotivev1alpha1.ImageBuild{}
			setImageBuildConditions(ib, tt.phase, tt.message)

			progressing := meta.FindStatusCondition(ib.Status.Conditions, automotivev1alpha1.ImageBuildConditionProgressing)
			if progressing == nil {
				t.Fatal("Progressing condition not set")
			}
			if progressing.Status != tt.wantProgressing {
				t.Errorf("Progressing status = %v, want %v", progressing.Status, tt.wantProgressing)
			}
			if progressing.Message != tt.message {
				t.Errorf("Progressing message = %q, want %q", progressing.Message, tt.message)
			}

			ready := meta.FindStatusCondition(ib.Status.Conditions, automotivev1alpha1.ImageBuildConditionReady)
			if ready == nil {
				t.Fatal("Ready condition not set")
			}
			if ready.Status != tt.wantReady {
				t.Errorf("Ready status = %v, want %v", ready.Status, tt.wantReady)
			}
			if ready.Reason != tt.wantReadyReason {
				t.Errorf("Ready reason = %q, want %q", ready.Reason, tt.wantReadyReason)
			}
			if ready.Message != tt.message {
				t.Errorf("Ready message = %q, want %q", ready.Message, tt.message)
			}
		})
	}
}

func TestSetImageBuildConditionsTransition(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{}

	setImageBuildConditions(ib, "Building", "Build started")
	ready := meta.FindStatusCondition(ib.Status.Conditions, automotivev1alpha1.ImageBuildConditionReady)
	if ready.Status != metav1.ConditionFalse {
		t.Fatalf("Ready should be False during Building, got %v", ready.Status)
	}

	setImageBuildConditions(ib, "Completed", "Build done")
	ready = meta.FindStatusCondition(ib.Status.Conditions, automotivev1alpha1.ImageBuildConditionReady)
	if ready.Status != metav1.ConditionTrue {
		t.Fatalf("Ready should be True after Completed, got %v", ready.Status)
	}
	progressing := meta.FindStatusCondition(ib.Status.Conditions, automotivev1alpha1.ImageBuildConditionProgressing)
	if progressing.Status != metav1.ConditionFalse {
		t.Fatalf("Progressing should be False after Completed, got %v", progressing.Status)
	}

	if len(ib.Status.Conditions) != 2 {
		t.Errorf("Expected 2 conditions after transitions, got %d", len(ib.Status.Conditions))
	}
}

func TestEnsureImageStreamOwnerRefNoMatch(t *testing.T) {
	testNS := "test-ns"
	testBuildName := "test-build"
	testStreamName := "test-stream"
	imageStreamURL := tasks.DefaultInternalRegistryURL + "/" + testNS + "/" + testStreamName + ":latest"
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))

	imageBuild := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      testBuildName,
			Namespace: testNS,
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			Export: &automotivev1alpha1.ExportSpec{
				Container:             imageStreamURL,
				UseServiceAccountAuth: true,
			},
		},
	}

	noMatchErr := &meta.NoKindMatchError{
		GroupKind: schema.GroupKind{Group: "image.openshift.io", Kind: "ImageStream"},
	}

	getCalled := false
	// Create a fake client that will return a NoMatch error for ImageStream lookups
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if obj.GetObjectKind().GroupVersionKind().Group == "image.openshift.io" &&
					obj.GetObjectKind().GroupVersionKind().Kind == "ImageStream" {
					getCalled = true
					return noMatchErr
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	reconciler := &ImageBuildReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}

	// ensureImageStreamOwnerRef should return nil when encountering a NotFound/NoMatch error
	// (which occurs when ImageStream is not found or the CRD is not available)
	err := reconciler.ensureImageStreamOwnerRef(context.Background(), imageBuild)
	if err != nil {
		t.Errorf("ensureImageStreamOwnerRef returned error: %v, want nil", err)
	}
	if !getCalled {
		t.Fatal("expected ImageStream lookup to be attempted")
	}
}

func TestResolveExportFormat(t *testing.T) {
	tests := []struct {
		name       string
		spec       automotivev1alpha1.ImageBuildSpec
		configMap  *corev1.ConfigMap
		wantFormat string
	}{
		{
			name: "user-specified format wins",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB:    &automotivev1alpha1.AIBSpec{Target: "ebbr"},
				Export: &automotivev1alpha1.ExportSpec{Format: "raw"},
			},
			wantFormat: "raw",
		},
		{
			name: "target-defaults ConfigMap provides format",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Target: "ebbr"},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "aib-target-defaults",
					Namespace: controllerutils.OperatorNamespace(),
				},
				Data: map[string]string{
					"target-defaults.yaml": "targets:\n  ebbr:\n    defaultFormat: simg\n  qemu:\n    defaultFormat: raw\n",
				},
			},
			wantFormat: "simg",
		},
		{
			name: "target not in ConfigMap falls back to qcow2",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Target: "unknown-board"},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "aib-target-defaults",
					Namespace: controllerutils.OperatorNamespace(),
				},
				Data: map[string]string{
					"target-defaults.yaml": "targets:\n  ebbr:\n    defaultFormat: simg\n",
				},
			},
			wantFormat: "qcow2",
		},
		{
			name: "no ConfigMap falls back to qcow2",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Target: "ebbr"},
			},
			wantFormat: "qcow2",
		},
		{
			name:       "no target falls back to qcow2",
			spec:       automotivev1alpha1.ImageBuildSpec{},
			wantFormat: "qcow2",
		},
		{
			name: "user-specified format overrides ConfigMap",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB:    &automotivev1alpha1.AIBSpec{Target: "ebbr"},
				Export: &automotivev1alpha1.ExportSpec{Format: "qcow2"},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "aib-target-defaults",
					Namespace: controllerutils.OperatorNamespace(),
				},
				Data: map[string]string{
					"target-defaults.yaml": "targets:\n  ebbr:\n    defaultFormat: simg\n",
				},
			},
			wantFormat: "qcow2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newTestSchemeWithTekton()
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.configMap != nil {
				builder = builder.WithObjects(tt.configMap)
			}
			r := &ImageBuildReconciler{Client: builder.Build(), Scheme: scheme}

			ib := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "test-ns"},
				Spec:       tt.spec,
			}

			got := r.resolveExportFormat(context.Background(), ib)
			if got != tt.wantFormat {
				t.Errorf("resolveExportFormat() = %q, want %q", got, tt.wantFormat)
			}
		})
	}
}

func TestResolveExtraArgs(t *testing.T) {
	tests := []struct {
		name      string
		spec      automotivev1alpha1.ImageBuildSpec
		configMap *corev1.ConfigMap
		wantArgs  []string
	}{
		{
			name: "user-specified extra args win",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{
					Target:       "ride4_sa8775p_sx",
					AIBExtraArgs: []string{"--custom-flag"},
				},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "aib-target-defaults",
					Namespace: controllerutils.OperatorNamespace(),
				},
				Data: map[string]string{
					"target-defaults.yaml": "targets:\n  ride4_sa8775p_sx:\n    extraArgs:\n      - --separate-partitions\n",
				},
			},
			wantArgs: []string{"--custom-flag"},
		},
		{
			name: "ConfigMap provides extra args",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Target: "ride4_sa8775p_sx"},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "aib-target-defaults",
					Namespace: controllerutils.OperatorNamespace(),
				},
				Data: map[string]string{
					"target-defaults.yaml": "targets:\n  ride4_sa8775p_sx:\n    extraArgs:\n      - --separate-partitions\n",
				},
			},
			wantArgs: []string{"--separate-partitions"},
		},
		{
			name: "target without extra args returns nil",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Target: "qemu"},
			},
			configMap: &corev1.ConfigMap{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "aib-target-defaults",
					Namespace: controllerutils.OperatorNamespace(),
				},
				Data: map[string]string{
					"target-defaults.yaml": "targets:\n  qemu:\n    defaultFormat: raw\n",
				},
			},
			wantArgs: nil,
		},
		{
			name: "no ConfigMap returns nil",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{Target: "ride4_sa8775p_sx"},
			},
			wantArgs: nil,
		},
		{
			name:     "no target returns nil",
			spec:     automotivev1alpha1.ImageBuildSpec{},
			wantArgs: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newTestSchemeWithTekton()
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.configMap != nil {
				builder = builder.WithObjects(tt.configMap)
			}
			r := &ImageBuildReconciler{Client: builder.Build(), Scheme: scheme}

			ib := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "test-ns"},
				Spec:       tt.spec,
			}

			got := r.resolveExtraArgs(context.Background(), ib)
			if len(got) != len(tt.wantArgs) {
				t.Errorf("resolveExtraArgs() = %v, want %v", got, tt.wantArgs)
				return
			}
			for i := range got {
				if got[i] != tt.wantArgs[i] {
					t.Errorf("resolveExtraArgs()[%d] = %q, want %q", i, got[i], tt.wantArgs[i])
				}
			}
		})
	}
}

func TestPushUsesPersistedExportFormat(t *testing.T) {
	tests := []struct {
		name            string
		statusFormat    string
		configMapFormat string
		wantUsedByPush  string
	}{
		{
			name:            "uses persisted format from status",
			statusFormat:    "simg",
			configMapFormat: "raw",
			wantUsedByPush:  "simg",
		},
		{
			name:            "falls back to resolve when status empty",
			statusFormat:    "",
			configMapFormat: "raw",
			wantUsedByPush:  "raw",
		},
		{
			name:            "falls back to qcow2 when both empty",
			statusFormat:    "",
			configMapFormat: "",
			wantUsedByPush:  "qcow2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scheme := newTestSchemeWithTekton()
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tt.configMapFormat != "" {
				builder = builder.WithObjects(&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "aib-target-defaults",
						Namespace: controllerutils.OperatorNamespace(),
					},
					Data: map[string]string{
						"target-defaults.yaml": "targets:\n  ebbr:\n    defaultFormat: " + tt.configMapFormat + "\n",
					},
				})
			}
			r := &ImageBuildReconciler{Client: builder.Build(), Scheme: scheme}

			ib := &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "test-ns"},
				Spec: automotivev1alpha1.ImageBuildSpec{
					AIB: &automotivev1alpha1.AIBSpec{Target: "ebbr"},
				},
				Status: automotivev1alpha1.ImageBuildStatus{
					ResolvedExportFormat: tt.statusFormat,
				},
			}

			got := ib.Status.ResolvedExportFormat
			if got == "" {
				got = r.resolveExportFormat(context.Background(), ib)
			}
			if got != tt.wantUsedByPush {
				t.Errorf("push format = %q, want %q", got, tt.wantUsedByPush)
			}
		})
	}
}

func TestOCIRepoVolumes(t *testing.T) {
	tests := []struct {
		name          string
		ociRepoImages []string
		wantImage     bool
	}{
		{
			name:          "no OCI repos — EmptyDir",
			ociRepoImages: nil,
			wantImage:     false,
		},
		{
			name:          "empty slice — EmptyDir",
			ociRepoImages: []string{},
			wantImage:     false,
		},
		{
			name:          "single OCI repo — ImageVolumeSource",
			ociRepoImages: []string{"quay.io/org/rpms:v1"},
			wantImage:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vols := ociRepoVolumes(tt.ociRepoImages)
			if len(vols) != 1 {
				t.Fatalf("volume count = %d, want 1", len(vols))
			}
			vol := vols[0]
			if vol.Name != tasks.OCIRepoVolumeName {
				t.Errorf("volume name = %q, want %q", vol.Name, tasks.OCIRepoVolumeName)
			}
			if tt.wantImage {
				if vol.Image == nil {
					t.Fatal("expected ImageVolumeSource, got nil")
				}
				if vol.Image.Reference != tt.ociRepoImages[0] {
					t.Errorf("Image.Reference = %q, want %q", vol.Image.Reference, tt.ociRepoImages[0])
				}
				if vol.Image.PullPolicy != corev1.PullAlways {
					t.Errorf("Image.PullPolicy = %q, want PullAlways", vol.Image.PullPolicy)
				}
			} else {
				if vol.EmptyDir == nil {
					t.Fatal("expected EmptyDir, got nil")
				}
				if vol.Image != nil {
					t.Error("should not have Image when EmptyDir is set")
				}
			}
		})
	}
}

func TestGetOCIRepoImages(t *testing.T) {
	tests := []struct {
		name string
		spec automotivev1alpha1.ImageBuildSpec
		want []string
	}{
		{
			name: "nil AIB returns nil",
			spec: automotivev1alpha1.ImageBuildSpec{AIB: nil},
			want: nil,
		},
		{
			name: "empty OCIRepoImages returns nil",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{
					Distro: "autosd",
					Target: "qemu",
				},
			},
			want: nil,
		},
		{
			name: "returns OCI repo images",
			spec: automotivev1alpha1.ImageBuildSpec{
				AIB: &automotivev1alpha1.AIBSpec{
					Distro:        "autosd",
					Target:        "qemu",
					OCIRepoImages: []string{"quay.io/org/rpms:v1", "quay.io/org/extra:v2"},
				},
			},
			want: []string{"quay.io/org/rpms:v1", "quay.io/org/extra:v2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.spec.GetOCIRepoImages()
			if len(got) != len(tt.want) {
				t.Fatalf("GetOCIRepoImages() len = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("GetOCIRepoImages()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func newTestReconciler(objs ...client.Object) *ImageBuildReconciler {
	scheme := newTestSchemeWithTekton()
	builder := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(objs...).
		WithStatusSubresource(objs...)
	return &ImageBuildReconciler{
		Client:   builder.Build(),
		Scheme:   scheme,
		Recorder: record.NewEventRecorderAdapter(record.NewFakeRecorder(100)),
	}
}

func TestHandleUploadingState_ClientSkipsUploadsWithoutHydrate(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "skip-uploads",
			Namespace:         "test-ns",
			CreationTimestamp: metav1.Now(),
			Annotations: map[string]string{
				labels.ClientSkipsUploads: labels.ValueTrue,
			},
		},
		Status: automotivev1alpha1.ImageBuildStatus{
			Phase:   "Uploading",
			Message: "Waiting for file uploads",
		},
	}
	r := newTestReconciler(ib)

	if _, err := r.handleUploadingState(context.Background(), ib); err != nil {
		t.Fatalf("handleUploadingState() error: %v", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "skip-uploads", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if fresh.Annotations[labels.UploadsComplete] != labels.ValueTrue {
		t.Errorf("uploads-complete = %q, want true", fresh.Annotations[labels.UploadsComplete])
	}
	if fresh.Status.Phase != phaseBuilding {
		t.Errorf("phase = %q, want %q", fresh.Status.Phase, phaseBuilding)
	}
}

func TestHandleUploadingState_HydrateUploadPodNotReady(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "hydrate-wait",
			Namespace:         "test-ns",
			CreationTimestamp: metav1.Now(),
			Annotations: map[string]string{
				labels.WorkspaceHydrate:   `[{"kind":"path","absPath":"/workspace/src/a","relPath":"src/a"}]`,
				labels.ClientSkipsUploads: labels.ValueTrue,
			},
		},
		Status: automotivev1alpha1.ImageBuildStatus{
			Phase:   "Uploading",
			Message: "Waiting for file uploads",
		},
		Spec: automotivev1alpha1.ImageBuildSpec{Workspace: "dev-ws"},
	}
	r := newTestReconciler(ib)
	r.RestConfig = &rest.Config{}

	result, err := r.handleUploadingState(context.Background(), ib)
	if err != nil {
		t.Fatalf("handleUploadingState() error: %v", err)
	}
	if result.RequeueAfter != 2*time.Second {
		t.Fatalf("RequeueAfter = %v, want 2s", result.RequeueAfter)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "hydrate-wait", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if fresh.Status.Phase != "Uploading" {
		t.Errorf("phase = %q, want Uploading", fresh.Status.Phase)
	}
	if fresh.Status.Message != "Waiting for upload pod" {
		t.Errorf("message = %q, want Waiting for upload pod", fresh.Status.Message)
	}
}

func newRunningUploadPod(buildName string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildName + "-upload",
			Namespace: "test-ns",
			Labels: map[string]string{
				labels.ImageBuildName: buildName,
				labels.Name:           "upload-pod",
			},
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "upload"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

func newHydrateBuild(name string) *automotivev1alpha1.ImageBuild {
	return &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:              name,
			Namespace:         "test-ns",
			CreationTimestamp: metav1.Now(),
			Annotations: map[string]string{
				labels.WorkspaceHydrate:   `[{"kind":"path","absPath":"/workspace/src/a","relPath":"src/a"}]`,
				labels.ClientSkipsUploads: labels.ValueTrue,
			},
		},
		Status: automotivev1alpha1.ImageBuildStatus{Phase: "Uploading"},
		Spec:   automotivev1alpha1.ImageBuildSpec{Workspace: "dev-ws"},
	}
}

// pollHydrate drives ensureWorkspaceHydrate until it settles (done or error) so
// tests can observe the background goroutine's result deterministically.
func pollHydrate(t *testing.T, r *ImageBuildReconciler, ib *automotivev1alpha1.ImageBuild) (bool, error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		done, err := r.ensureWorkspaceHydrate(context.Background(), ib)
		if done || err != nil {
			return done, err
		}
		if time.Now().After(deadline) {
			t.Fatal("hydrate did not settle in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// driveUploadingUntilSettled calls handleUploadingState until the background
// hydration finishes and a reconcile returns something other than the poll
// requeue (workspaceHydratePoll), i.e. the error was surfaced and classified.
func driveUploadingUntilSettled(t *testing.T, r *ImageBuildReconciler, ib *automotivev1alpha1.ImageBuild) ctrl.Result {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		result, err := r.handleUploadingState(context.Background(), ib)
		if err != nil {
			t.Fatalf("handleUploadingState() error: %v", err)
		}
		if result.RequeueAfter != workspaceHydratePoll {
			return result
		}
		if time.Now().After(deadline) {
			t.Fatal("hydrate did not settle in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestEnsureWorkspaceHydrate_AsyncCompletes verifies the copy runs off the
// reconcile path (goroutine) and, once finished, is recorded via the
// WorkspaceHydrateDone annotation so it is not repeated.
func TestEnsureWorkspaceHydrate_AsyncCompletes(t *testing.T) {
	ib := newHydrateBuild("hydrate-async")
	r := newTestReconciler(ib, newRunningUploadPod("hydrate-async"))
	r.RestConfig = &rest.Config{}

	var calls atomic.Int32
	r.hydrateFunc = func(context.Context, *rest.Config, client.Client, *automotivev1alpha1.ImageBuild) error {
		calls.Add(1)
		return nil
	}

	// First call must not block: it starts the goroutine and reports not-done.
	done, err := r.ensureWorkspaceHydrate(context.Background(), ib)
	if err != nil || done {
		t.Fatalf("first call = (%v, %v), want (false, nil)", done, err)
	}

	done, err = pollHydrate(t, r, ib)
	if err != nil {
		t.Fatalf("hydrate error: %v", err)
	}
	if !done {
		t.Fatal("hydrate never completed")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("hydrate ran %d times, want 1", got)
	}
	if ib.Annotations[labels.WorkspaceHydrateDone] != labels.ValueTrue {
		t.Fatalf("WorkspaceHydrateDone = %q, want true", ib.Annotations[labels.WorkspaceHydrateDone])
	}
	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "hydrate-async", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if fresh.Annotations[labels.WorkspaceHydrateDone] != labels.ValueTrue {
		t.Fatal("WorkspaceHydrateDone not persisted")
	}
}

// TestEnsureWorkspaceHydrate_InProgressDoesNotRelaunch confirms repeated
// reconciles while a copy is running return not-done without starting a second
// goroutine.
func TestEnsureWorkspaceHydrate_InProgressDoesNotRelaunch(t *testing.T) {
	ib := newHydrateBuild("hydrate-inflight")
	r := newTestReconciler(ib, newRunningUploadPod("hydrate-inflight"))
	r.RestConfig = &rest.Config{}

	started := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	r.hydrateFunc = func(context.Context, *rest.Config, client.Client, *automotivev1alpha1.ImageBuild) error {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return nil
	}
	t.Cleanup(func() { close(release) })

	// First call launches the goroutine; wait until it is actually running so the
	// relaunch assertion below is not racing the goroutine's own calls.Add(1).
	done, err := r.ensureWorkspaceHydrate(context.Background(), ib)
	if err != nil || done {
		t.Fatalf("first call = (%v, %v), want (false, nil)", done, err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("hydrate goroutine never started")
	}

	// Further reconciles while the copy is in flight must not relaunch it.
	for i := range 3 {
		done, err := r.ensureWorkspaceHydrate(context.Background(), ib)
		if err != nil || done {
			t.Fatalf("call %d = (%v, %v), want (false, nil)", i, done, err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("hydrate launched %d times while in progress, want 1", got)
	}
}

// TestEnsureWorkspaceHydrate_NoUploadPodDefers ensures we do not spawn a
// goroutine before the destination pod is ready.
func TestEnsureWorkspaceHydrate_NoUploadPodDefers(t *testing.T) {
	ib := newHydrateBuild("hydrate-nopod")
	r := newTestReconciler(ib)
	r.RestConfig = &rest.Config{}

	var calls atomic.Int32
	r.hydrateFunc = func(context.Context, *rest.Config, client.Client, *automotivev1alpha1.ImageBuild) error {
		calls.Add(1)
		return nil
	}

	done, err := r.ensureWorkspaceHydrate(context.Background(), ib)
	if done {
		t.Fatal("done = true, want false while upload pod missing")
	}
	if !errors.Is(err, buildapi.ErrUploadPodNotReady) {
		t.Fatalf("err = %v, want ErrUploadPodNotReady", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("hydrate ran %d times, want 0 (no goroutine before pod ready)", got)
	}
}

// TestEnsureWorkspaceHydrate_ErrorSurfacesAndClearsJob verifies a failed copy
// surfaces the error, does not mark hydration done, and clears its tracking
// entry so a later reconcile can retry.
func TestEnsureWorkspaceHydrate_ErrorSurfacesAndClearsJob(t *testing.T) {
	ib := newHydrateBuild("hydrate-err")
	r := newTestReconciler(ib, newRunningUploadPod("hydrate-err"))
	r.RestConfig = &rest.Config{}

	wantErr := errors.New("boom")
	r.hydrateFunc = func(context.Context, *rest.Config, client.Client, *automotivev1alpha1.ImageBuild) error {
		return wantErr
	}

	_, err := pollHydrate(t, r, ib)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if ib.Annotations[labels.WorkspaceHydrateDone] == labels.ValueTrue {
		t.Fatal("failed hydrate must not be marked done")
	}
	if _, ok := r.hydrating.Load("test-ns/hydrate-err"); ok {
		t.Fatal("failed hydrate job entry must be cleared for retry")
	}
}

func TestHandleUploadingState_HydrateDoneSelfCompletesUploads(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "hydrate-done",
			Namespace:         "test-ns",
			CreationTimestamp: metav1.Now(),
			Annotations: map[string]string{
				labels.WorkspaceHydrate:     `[{"kind":"path","absPath":"/workspace/src/a","relPath":"src/a"}]`,
				labels.WorkspaceHydrateDone: labels.ValueTrue,
				labels.ClientSkipsUploads:   labels.ValueTrue,
			},
		},
		Status: automotivev1alpha1.ImageBuildStatus{
			Phase:   "Uploading",
			Message: "Waiting for file uploads",
		},
	}
	r := newTestReconciler(ib)

	if _, err := r.handleUploadingState(context.Background(), ib); err != nil {
		t.Fatalf("handleUploadingState() error: %v", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "hydrate-done", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if fresh.Annotations[labels.UploadsComplete] != labels.ValueTrue {
		t.Errorf("uploads-complete = %q, want true", fresh.Annotations[labels.UploadsComplete])
	}
	if fresh.Status.Phase != phaseBuilding {
		t.Errorf("phase = %q, want %q", fresh.Status.Phase, phaseBuilding)
	}
}

func TestHandleUploadingState_HydratePermanentErrorFailsBuild(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "hydrate-bad",
			Namespace:         "test-ns",
			CreationTimestamp: metav1.Now(),
			Annotations: map[string]string{
				labels.WorkspaceHydrate: `{`,
			},
		},
		Status: automotivev1alpha1.ImageBuildStatus{Phase: "Uploading"},
	}
	// A running upload pod lets ensureWorkspaceHydrate launch the background copy;
	// the invalid annotation then produces a permanent error asynchronously.
	r := newTestReconciler(ib, newRunningUploadPod("hydrate-bad"))
	r.RestConfig = &rest.Config{}

	driveUploadingUntilSettled(t, r, ib)

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "hydrate-bad", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if fresh.Status.Phase != phaseFailed {
		t.Errorf("phase = %q, want %q", fresh.Status.Phase, phaseFailed)
	}
}

func TestHandleUploadingState_HydrateTransientErrorRequeues(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "hydrate-retry",
			Namespace:         "test-ns",
			CreationTimestamp: metav1.Now(),
			Annotations: map[string]string{
				labels.WorkspaceHydrate: `[{"kind":"path","absPath":"/workspace/src/a","relPath":"src/a"}]`,
			},
		},
		Spec:   automotivev1alpha1.ImageBuildSpec{Workspace: "dev-ws"},
		Status: automotivev1alpha1.ImageBuildStatus{Phase: "Uploading"},
	}
	ws := &automotivev1alpha1.Workspace{
		ObjectMeta: metav1.ObjectMeta{Name: "dev-ws", Namespace: "test-ns"},
		Status:     automotivev1alpha1.WorkspaceStatus{Phase: "Stopped"},
	}
	uploadPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "hydrate-retry-upload-pod",
			Namespace: "test-ns",
			Labels: map[string]string{
				labels.ImageBuildName: "hydrate-retry",
				labels.Name:           "upload-pod",
			},
		},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "fileserver"}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	r := newTestReconciler(ib, ws, uploadPod)
	r.RestConfig = &rest.Config{}

	// The workspace is Stopped, so the background copy returns a transient error;
	// a later reconcile surfaces it and schedules the retry requeue.
	result := driveUploadingUntilSettled(t, r, ib)
	if result.RequeueAfter != workspaceHydrateRetry {
		t.Fatalf("RequeueAfter = %v, want %v", result.RequeueAfter, workspaceHydrateRetry)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "hydrate-retry", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if fresh.Status.Phase == phaseFailed {
		t.Fatalf("transient hydrate error failed the build: %s", fresh.Status.Message)
	}
	if fresh.Annotations[labels.WorkspaceHydrateAttempts] != "1" {
		t.Errorf("attempts = %q, want 1", fresh.Annotations[labels.WorkspaceHydrateAttempts])
	}
}

func TestUpdateStatusSetsConditionsOnCompleted(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "test-ns"},
		Status:     automotivev1alpha1.ImageBuildStatus{Phase: phaseBuilding},
	}
	r := newTestReconciler(ib)

	if err := r.updateStatus(context.Background(), ib, phaseCompleted, "Build done"); err != nil {
		t.Fatalf("updateStatus() error: %v", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "test-build", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	ready := meta.FindStatusCondition(fresh.Status.Conditions, automotivev1alpha1.ImageBuildConditionReady)
	if ready == nil {
		t.Fatal("Ready condition not set")
	}
	if ready.Status != metav1.ConditionTrue {
		t.Errorf("Ready = %v, want True", ready.Status)
	}

	progressing := meta.FindStatusCondition(fresh.Status.Conditions, automotivev1alpha1.ImageBuildConditionProgressing)
	if progressing == nil {
		t.Fatal("Progressing condition not set")
	}
	if progressing.Status != metav1.ConditionFalse {
		t.Errorf("Progressing = %v, want False", progressing.Status)
	}
}

func TestUpdateStatusGuardsCancelledPhase(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "test-ns"},
		Status:     automotivev1alpha1.ImageBuildStatus{Phase: phaseCancelled, Message: "Cancelled by user"},
	}
	r := newTestReconciler(ib)

	if err := r.updateStatus(context.Background(), ib, phaseCompleted, "Build done"); err != nil {
		t.Fatalf("updateStatus() error: %v", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "test-build", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	if fresh.Status.Phase != phaseCancelled {
		t.Errorf("Phase = %q, want %q (guard should prevent overwrite)", fresh.Status.Phase, phaseCancelled)
	}
	if fresh.Status.Message != "Cancelled by user" {
		t.Errorf("Message = %q, want %q", fresh.Status.Message, "Cancelled by user")
	}
}

func TestUpdateStatusAppliesMutations(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "test-ns"},
		Status:     automotivev1alpha1.ImageBuildStatus{Phase: phaseBuilding},
	}
	r := newTestReconciler(ib)

	err := r.updateStatus(context.Background(), ib, phaseCompleted, "Build done", func(ib *automotivev1alpha1.ImageBuild) {
		ib.Status.AIBImageUsed = "quay.io/aib:v1"
		ib.Status.BuilderImageUsed = "quay.io/builder:v2"
		ib.Status.LeaseID = "lease-123"
	})
	if err != nil {
		t.Fatalf("updateStatus() error: %v", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "test-build", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	if fresh.Status.AIBImageUsed != "quay.io/aib:v1" {
		t.Errorf("AIBImageUsed = %q, want %q", fresh.Status.AIBImageUsed, "quay.io/aib:v1")
	}
	if fresh.Status.BuilderImageUsed != "quay.io/builder:v2" {
		t.Errorf("BuilderImageUsed = %q, want %q", fresh.Status.BuilderImageUsed, "quay.io/builder:v2")
	}
	if fresh.Status.LeaseID != "lease-123" {
		t.Errorf("LeaseID = %q, want %q", fresh.Status.LeaseID, "lease-123")
	}
	if fresh.Status.Phase != phaseCompleted {
		t.Errorf("Phase = %q, want %q", fresh.Status.Phase, phaseCompleted)
	}

	ready := meta.FindStatusCondition(fresh.Status.Conditions, automotivev1alpha1.ImageBuildConditionReady)
	if ready == nil || ready.Status != metav1.ConditionTrue {
		t.Error("Ready condition should be True after Completed with mutations")
	}
}

func TestUpdateStatusSetsCompletionTime(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "test-ns"},
		Status:     automotivev1alpha1.ImageBuildStatus{Phase: phaseBuilding},
	}
	r := newTestReconciler(ib)

	if err := r.updateStatus(context.Background(), ib, phaseCompleted, "Build done"); err != nil {
		t.Fatalf("updateStatus() error: %v", err)
	}

	fresh := &automotivev1alpha1.ImageBuild{}
	if err := r.Get(context.Background(), types.NamespacedName{Name: "test-build", Namespace: "test-ns"}, fresh); err != nil {
		t.Fatalf("Get() error: %v", err)
	}

	if fresh.Status.CompletionTime == nil {
		t.Error("CompletionTime should be set on terminal phase")
	}
}

func TestUpdateStatusSkipsLiveResultCollection(t *testing.T) {
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{Name: "test-build", Namespace: "test-ns"},
		Status: automotivev1alpha1.ImageBuildStatus{
			Phase: phaseBuilding, PipelineRunName: "pipeline",
		},
	}
	scheme := newTestSchemeWithTekton()
	collected := false
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ib).
		WithStatusSubresource(ib).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*tektonv1.PipelineRun); ok {
					collected = true
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).Build()
	r := &ImageBuildReconciler{Client: fakeClient, Scheme: scheme}

	if err := r.updateStatus(context.Background(), ib, phaseBuilding, "Building"); err != nil {
		t.Fatal(err)
	}
	if collected {
		t.Fatal("heartbeat collected PipelineRun results")
	}
}

func TestVerifiedBundlesCacheHitSkipsLookup(t *testing.T) {
	const ref = "registry.example.com/bundle@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	scheme := newTestSchemeWithTekton()
	getCalled := false
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*corev1.ConfigMap); ok && key.Name == "cosign-pub-key" {
					getCalled = true
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	r := &ImageBuildReconciler{
		Client: fakeClient,
		Scheme: scheme,
	}
	r.verifiedBundles.Store(ref, struct{}{})

	if _, ok := r.verifiedBundles.Load(ref); !ok {
		t.Fatal("expected cache hit for pre-stored digest ref")
	}
	if getCalled {
		t.Error("cache hit should not trigger cosign key lookup")
	}
}

func TestVerifiedBundlesCacheMissAndFailureNotCached(t *testing.T) {
	const ref = "registry.example.com/bundle@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

	r := &ImageBuildReconciler{}

	if _, ok := r.verifiedBundles.Load(ref); ok {
		t.Fatal("expected cache miss for unknown digest ref")
	}

	r.verifiedBundles.Store(ref, struct{}{})
	if _, ok := r.verifiedBundles.Load(ref); !ok {
		t.Fatal("expected cache hit after Store")
	}

	const failedRef = "registry.example.com/bundle@sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if _, ok := r.verifiedBundles.Load(failedRef); ok {
		t.Fatal("never-stored ref should not be in cache (simulates failed verification not being cached)")
	}
}

func TestVerifiedBundlesCacheKeyIsolation(t *testing.T) {
	r := &ImageBuildReconciler{}

	refA := "registry.example.com/bundle@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	refB := "registry.example.com/bundle@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	r.verifiedBundles.Store(refA, struct{}{})

	if _, ok := r.verifiedBundles.Load(refA); !ok {
		t.Error("refA should be cached")
	}
	if _, ok := r.verifiedBundles.Load(refB); ok {
		t.Error("refB should not be cached — different digest means different bundle")
	}
}

func TestCleanupTransientSecretsDeletesOwnedS3Secret(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))

	buildUID := types.UID("build-uid-123")
	s3SecretName := "my-s3-creds"

	imageBuild := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-build",
			Namespace: "default",
			UID:       buildUID,
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			Export: &automotivev1alpha1.ExportSpec{
				Disk: &automotivev1alpha1.DiskExport{
					S3: &automotivev1alpha1.S3Export{
						Bucket:            "bucket",
						CredentialsSecret: s3SecretName,
					},
				},
			},
		},
	}

	s3Secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s3SecretName,
			Namespace: "default",
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: automotivev1alpha1.GroupVersion.String(),
					Kind:       "ImageBuild",
					Name:       "test-build",
					UID:        buildUID,
					Controller: func() *bool { b := true; return &b }(),
				},
			},
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(s3Secret).
		Build()

	r := &ImageBuildReconciler{Client: fakeClient, Scheme: scheme}
	log := logr.Discard()

	err := r.cleanupTransientSecrets(context.Background(), imageBuild, log)
	if err != nil {
		t.Fatalf("cleanupTransientSecrets returned error: %v", err)
	}

	got := &corev1.Secret{}
	getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: s3SecretName, Namespace: "default"}, got)
	if getErr == nil {
		t.Error("expected S3 credentials secret to be deleted, but it still exists")
	}
}

func TestCleanupTransientSecretsPreservesUnownedS3Secret(t *testing.T) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))

	buildUID := types.UID("build-uid-123")
	s3SecretName := "user-s3-creds"

	imageBuild := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-build",
			Namespace: "default",
			UID:       buildUID,
		},
		Spec: automotivev1alpha1.ImageBuildSpec{
			Export: &automotivev1alpha1.ExportSpec{
				Disk: &automotivev1alpha1.DiskExport{
					S3: &automotivev1alpha1.S3Export{
						Bucket:            "bucket",
						CredentialsSecret: s3SecretName,
					},
				},
			},
		},
	}

	userSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      s3SecretName,
			Namespace: "default",
		},
	}

	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(userSecret).
		Build()

	r := &ImageBuildReconciler{Client: fakeClient, Scheme: scheme}
	log := logr.Discard()

	err := r.cleanupTransientSecrets(context.Background(), imageBuild, log)
	if err != nil {
		t.Fatalf("cleanupTransientSecrets returned error: %v", err)
	}

	got := &corev1.Secret{}
	getErr := fakeClient.Get(context.Background(), types.NamespacedName{Name: s3SecretName, Namespace: "default"}, got)
	if getErr != nil {
		t.Errorf("expected user-provided S3 secret to be preserved, but got error: %v", getErr)
	}
}

func TestS3Prefix(t *testing.T) {
	tests := []struct {
		name  string
		build *automotivev1alpha1.ImageBuild
		want  string
	}{
		{
			name: "uses explicit prefix",
			build: &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "my-build"},
				Spec: automotivev1alpha1.ImageBuildSpec{
					Export: &automotivev1alpha1.ExportSpec{
						Disk: &automotivev1alpha1.DiskExport{
							S3: &automotivev1alpha1.S3Export{
								Bucket: "bucket",
								Prefix: "custom/path",
							},
						},
					},
				},
			},
			want: "custom/path",
		},
		{
			name: "defaults to builds/<name> when prefix empty",
			build: &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "my-build"},
				Spec: automotivev1alpha1.ImageBuildSpec{
					Export: &automotivev1alpha1.ExportSpec{
						Disk: &automotivev1alpha1.DiskExport{
							S3: &automotivev1alpha1.S3Export{
								Bucket: "bucket",
							},
						},
					},
				},
			},
			want: "builds/my-build",
		},
		{
			name: "defaults to builds/<name> when no S3 export",
			build: &automotivev1alpha1.ImageBuild{
				ObjectMeta: metav1.ObjectMeta{Name: "my-build"},
				Spec:       automotivev1alpha1.ImageBuildSpec{},
			},
			want: "builds/my-build",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s3Prefix(tt.build)
			if got != tt.want {
				t.Errorf("s3Prefix() = %q, want %q", got, tt.want)
			}
		})
	}
}
