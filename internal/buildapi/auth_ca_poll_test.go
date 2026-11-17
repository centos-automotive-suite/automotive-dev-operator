package buildapi

import (
	"context"
	"testing"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const testPollInterval = 10 * time.Millisecond

func newCAPollClient(t *testing.T, objects ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

// startPoll runs pollCARef from ref's version as the refresh recorded it, and
// returns its event channel and a channel closed when it returns.
func startPoll(ctx context.Context, t *testing.T, c client.Client, ref caRef) (<-chan struct{}, <-chan struct{}) {
	t.Helper()
	version, err := caRefVersion(ctx, c, ref)
	if err != nil {
		t.Fatal(err)
	}
	ref.version = version
	a := &APIServer{log: logr.Discard()}
	eventCh := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		a.pollCARef(ctx, c, ref, testPollInterval, eventCh)
		close(done)
	}()
	return eventCh, done
}

func expectSignal(t *testing.T, eventCh <-chan struct{}) {
	t.Helper()
	select {
	case <-eventCh:
	case <-time.After(2 * time.Second):
		t.Fatal("no signal after the CA changed")
	}
}

func expectNoSignal(t *testing.T, eventCh <-chan struct{}) {
	t.Helper()
	select {
	case <-eventCh:
		t.Fatal("signalled before anything changed")
	case <-time.After(10 * testPollInterval):
	}
}

// The build API reads its OIDC issuers' CAs by name, so it notices a change
// by polling them rather than watching the namespace.
func TestPollCARef(t *testing.T) {
	meta := metav1.ObjectMeta{Name: "oidc-ca", Namespace: "ado"}

	cases := []struct {
		name   string
		ref    caRef
		object client.Object
		change func(context.Context, client.Client, client.Object) error
	}{
		{
			name:   "secret updated",
			ref:    caRef{namespace: "ado", name: "oidc-ca"},
			object: &corev1.Secret{ObjectMeta: meta, Data: map[string][]byte{"ca.crt": []byte("old")}},
			change: func(ctx context.Context, c client.Client, obj client.Object) error {
				obj.(*corev1.Secret).Data["ca.crt"] = []byte("new")
				return c.Update(ctx, obj)
			},
		},
		{
			name:   "configmap updated",
			ref:    caRef{namespace: "ado", name: "oidc-ca", isConfigMap: true},
			object: &corev1.ConfigMap{ObjectMeta: meta, Data: map[string]string{"ca.crt": "old"}},
			change: func(ctx context.Context, c client.Client, obj client.Object) error {
				obj.(*corev1.ConfigMap).Data["ca.crt"] = "new"
				return c.Update(ctx, obj)
			},
		},
		{
			name:   "secret deleted",
			ref:    caRef{namespace: "ado", name: "oidc-ca"},
			object: &corev1.Secret{ObjectMeta: meta},
			change: func(ctx context.Context, c client.Client, obj client.Object) error {
				return c.Delete(ctx, obj)
			},
		},
		{
			name:   "secret created",
			ref:    caRef{namespace: "ado", name: "oidc-ca"},
			object: nil,
			change: func(ctx context.Context, c client.Client, _ client.Object) error {
				return c.Create(ctx, &corev1.Secret{ObjectMeta: meta})
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var objects []client.Object
			if tc.object != nil {
				objects = append(objects, tc.object)
			}
			c := newCAPollClient(t, objects...)
			ctx := t.Context()

			eventCh, _ := startPoll(ctx, t, c, tc.ref)
			expectNoSignal(t, eventCh)

			if tc.object != nil {
				if err := c.Get(ctx, client.ObjectKeyFromObject(tc.object), tc.object); err != nil {
					t.Fatal(err)
				}
			}
			if err := tc.change(ctx, c, tc.object); err != nil {
				t.Fatal(err)
			}
			expectSignal(t, eventCh)
		})
	}
}

// A CA that changes after the refresh read it, but before the poller's first
// read, still differs from the version the active config was built from.
func TestPollCARefSignalsChangeBeforeFirstPoll(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "oidc-ca", Namespace: "ado"},
		Data:       map[string][]byte{"ca.crt": []byte("old")},
	}
	c := newCAPollClient(t, secret)
	ctx := t.Context()
	ref := caRef{namespace: "ado", name: "oidc-ca"}
	version, err := caRefVersion(ctx, c, ref)
	if err != nil {
		t.Fatal(err)
	}
	ref.version = version

	secret.Data["ca.crt"] = []byte("new")
	if err := c.Update(ctx, secret); err != nil {
		t.Fatal(err)
	}

	a := &APIServer{log: logr.Discard()}
	eventCh := make(chan struct{}, 1)
	go a.pollCARef(ctx, c, ref, testPollInterval, eventCh)
	expectSignal(t, eventCh)
}

func TestPollCARefStopsWhenCancelled(t *testing.T) {
	c := newCAPollClient(t, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "oidc-ca", Namespace: "ado"}})
	ctx, cancel := context.WithCancel(context.Background())
	eventCh, done := startPoll(ctx, t, c, caRef{namespace: "ado", name: "oidc-ca"})
	expectNoSignal(t, eventCh)

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("poller did not stop when its context ended")
	}
}
