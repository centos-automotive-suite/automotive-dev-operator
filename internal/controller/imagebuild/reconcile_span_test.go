package imagebuild

import (
	"context"
	"fmt"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

func setupTestTracer(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	origTracer := ibTracer
	ibTracer = tp.Tracer("imagebuild-controller-test")
	t.Cleanup(func() { ibTracer = origTracer })

	return recorder
}

func newReconcilerWithClient(c client.Client) *ImageBuildReconciler {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(automotivev1alpha1.AddToScheme(scheme))
	return &ImageBuildReconciler{
		Client:   c,
		Scheme:   scheme,
		Log:      ctrl.Log.WithName("test"),
		Recorder: record.NewEventRecorderAdapter(record.NewFakeRecorder(10)),
	}
}

func TestReconcileSpan_GetError_RecordsSpanError(t *testing.T) {
	recorder := setupTestTracer(t)

	injectedErr := fmt.Errorf("simulated API server error")
	fakeClient := fake.NewClientBuilder().
		WithScheme(newTestSchemeWithTekton()).
		WithInterceptorFuncs(interceptor.Funcs{
			Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
				if _, ok := obj.(*automotivev1alpha1.ImageBuild); ok {
					return injectedErr
				}
				return c.Get(ctx, key, obj, opts...)
			},
		}).
		Build()

	r := newReconcilerWithClient(fakeClient)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-build", Namespace: "test-ns"},
	})
	if err == nil {
		t.Fatal("expected error from Reconcile, got nil")
	}

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}

	span := spans[0]
	if span.Status().Code != codes.Error {
		t.Errorf("span status = %v, want codes.Error; the Reconcile span should record errors from early returns", span.Status().Code)
	}
}

func TestReconcileSpan_UpdateTraceIDError_RecordsSpanError(t *testing.T) {
	recorder := setupTestTracer(t)

	scheme := newTestSchemeWithTekton()
	ib := &automotivev1alpha1.ImageBuild{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-build",
			Namespace: "test-ns",
		},
	}

	injectedErr := fmt.Errorf("simulated update conflict")
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ib).
		WithStatusSubresource(ib).
		WithInterceptorFuncs(interceptor.Funcs{
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.UpdateOption) error {
				if _, ok := obj.(*automotivev1alpha1.ImageBuild); ok {
					return injectedErr
				}
				return c.Update(ctx, obj, opts...)
			},
		}).
		Build()

	r := newReconcilerWithClient(fakeClient)
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: "test-build", Namespace: "test-ns"},
	})
	if err == nil {
		t.Fatal("expected error from Reconcile, got nil")
	}

	spans := recorder.Ended()
	if len(spans) == 0 {
		t.Fatal("no spans recorded")
	}

	reconcileSpan := spans[0]
	if reconcileSpan.Status().Code != codes.Error {
		t.Errorf("span status = %v, want codes.Error; the Reconcile span should record errors when trace-id update fails", reconcileSpan.Status().Code)
	}
}
