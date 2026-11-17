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

// The build API reads its OIDC issuers' CAs by name, so it notices a change
// by polling them rather than watching the namespace.
func TestPollCARef(t *testing.T) {
	const interval = 10 * time.Millisecond
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
			scheme := runtime.NewScheme()
			if err := corev1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			builder := fake.NewClientBuilder().WithScheme(scheme)
			if tc.object != nil {
				builder = builder.WithObjects(tc.object)
			}
			c := builder.Build()
			a := &APIServer{log: logr.Discard()}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			eventCh := make(chan struct{}, 1)
			done := make(chan struct{})
			go func() {
				a.pollCARef(ctx, c, tc.ref, interval, eventCh)
				close(done)
			}()

			select {
			case <-eventCh:
				t.Fatal("signalled before anything changed")
			case <-time.After(10 * interval):
			}

			if tc.object != nil {
				if err := c.Get(ctx, client.ObjectKeyFromObject(tc.object), tc.object); err != nil {
					t.Fatal(err)
				}
			}
			if err := tc.change(ctx, c, tc.object); err != nil {
				t.Fatal(err)
			}
			select {
			case <-eventCh:
			case <-time.After(2 * time.Second):
				t.Fatal("no signal after the CA changed")
			}

			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("poller did not stop when its context ended")
			}
		})
	}
}
