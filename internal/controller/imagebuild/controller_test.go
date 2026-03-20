package imagebuild

import (
	"context"
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	tektonv1 "github.com/tektoncd/pipeline/pkg/apis/pipeline/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	knativev1 "knative.dev/pkg/apis/duck/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
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
							{Name: "pr-1-build-run", PipelineTaskName: "build-image"},
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
							{Name: "pr-2-build-run", PipelineTaskName: "build-image"},
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
							{Name: "pr-3-build-run", PipelineTaskName: "build-image"},
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
							{Name: "pr-5-gone-run", PipelineTaskName: "build-image"},
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
