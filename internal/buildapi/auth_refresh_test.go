package buildapi

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

// newRefreshClient returns a client holding an OperatorConfig whose one JWT
// issuer takes its CA from Secret oidc-ca, and that Secret.
func newRefreshClient(t *testing.T, secret *corev1.Secret, funcs interceptor.Funcs) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := automotivev1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	config := &automotivev1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: "ado"},
		Spec: automotivev1alpha1.OperatorConfigSpec{BuildAPI: &automotivev1alpha1.BuildAPIConfig{
			Authentication: &automotivev1alpha1.AuthenticationConfig{JWT: []automotivev1alpha1.JWTAuthenticatorConfig{{
				Issuer: automotivev1alpha1.JWTIssuerConfig{
					URL:                        "https://issuer.example",
					CertificateAuthoritySecret: &automotivev1alpha1.SecretKeySelector{Name: "oidc-ca", Key: "ca.crt"},
				},
			}}},
		}},
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(config, secret).WithInterceptorFuncs(funcs).Build()
}

// A refresh that cannot read the OperatorConfig says so, rather than
// reporting a config that references no CAs.
func TestRefreshAuthConfigReportsAReadFailure(t *testing.T) {
	readErr := errors.New("apiserver unavailable")
	c := newRefreshClient(t, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "oidc-ca", Namespace: "ado"}}, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			if _, ok := obj.(*automotivev1alpha1.OperatorConfig); ok {
				return readErr
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	a := &APIServer{log: logr.Discard()}
	if _, err := a.refreshAuthConfig(c, "ado"); !errors.Is(err, readErr) {
		t.Fatalf("got error %v, want %v", err, readErr)
	}
}

// After a failed refresh the watcher keeps polling the CAs it had, marked
// unapplied, so fixing one still triggers a refresh.
func TestCARefsAfterRefresh(t *testing.T) {
	previous := []caRef{{namespace: "ado", name: "oidc-ca", version: "7"}}
	refreshed := []caRef{{namespace: "ado", name: "other-ca", version: "3"}}

	got := caRefsAfterRefresh(previous, refreshed, nil)
	if len(got) != 1 || got[0] != refreshed[0] {
		t.Errorf("after a successful refresh got %+v, want %+v", got, refreshed)
	}

	got = caRefsAfterRefresh(previous, nil, errors.New("read failed"))
	want := caRef{namespace: "ado", name: "oidc-ca", version: caVersionUnknown}
	if len(got) != 1 || got[0] != want {
		t.Errorf("after a failed refresh got %+v, want %+v", got, want)
	}
}

// A refresh records the CA versions it built from. If two overlapped, the
// older could finish last and install a config other than the one recorded,
// so they run one at a time.
func TestRefreshesDoNotOverlap(t *testing.T) {
	var configReads atomic.Int32
	firstInside := make(chan struct{})
	releaseFirst := make(chan struct{})
	var blocked atomic.Bool
	c := newRefreshClient(t, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-ca", Namespace: "ado"},
	}, interceptor.Funcs{
		Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
			switch obj.(type) {
			case *automotivev1alpha1.OperatorConfig:
				configReads.Add(1)
			case *corev1.Secret:
				// Hold the first refresh partway, after it read the config.
				if blocked.CompareAndSwap(false, true) {
					close(firstInside)
					<-releaseFirst
				}
			}
			return c.Get(ctx, key, obj, opts...)
		},
	})
	a := &APIServer{log: logr.Discard()}

	firstDone := make(chan struct{})
	go func() {
		_, _ = a.refreshAuthConfig(c, "ado")
		close(firstDone)
	}()
	<-firstInside

	secondDone := make(chan struct{})
	go func() {
		_, _ = a.refreshAuthConfig(c, "ado")
		close(secondDone)
	}()
	time.Sleep(100 * time.Millisecond)
	if n := configReads.Load(); n != 1 {
		t.Fatalf("a second refresh started while the first ran: %d OperatorConfig reads", n)
	}

	close(releaseFirst)
	for _, done := range []chan struct{}{firstDone, secondDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("refresh did not finish")
		}
	}
	if n := configReads.Load(); n != 2 {
		t.Fatalf("got %d OperatorConfig reads, want 2", n)
	}
}
