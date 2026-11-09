package buildapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/gin-gonic/gin"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Registry tokens leave the cluster (API responses) or sit in Secrets, so
// they must belong to registry-only ServiceAccounts, never to ado-build. Only
// the build's own Secret may push; tokens handed to users only pull.
func TestRegistryTokensUseRegistryServiceAccounts(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS or run make test for token tests")
	}
	env := &envtest.Environment{}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Error(err)
		}
	})
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	const ns = "default"
	for _, name := range []string{
		automotivev1alpha1.BuildServiceAccountName,
		automotivev1alpha1.RegistryServiceAccountName,
		automotivev1alpha1.RegistryPullServiceAccountName,
	} {
		sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
		if _, err := cs.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	saUser := func(name string) string { return "system:serviceaccount:" + ns + ":" + name }

	t.Run("build registry secret", func(t *testing.T) {
		name, err := createInternalRegistrySecret(ctx, cfg, ns, "demo", 3600)
		if err != nil {
			t.Fatal(err)
		}
		secret, err := cs.CoreV1().Secrets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			t.Fatal(err)
		}
		token := registryTokenFromDockerConfig(t, secret)
		wantUser := saUser(automotivev1alpha1.RegistryServiceAccountName)
		if user, ok := reviewToken(t, cs, token); !ok || user != wantUser {
			t.Fatalf("token authenticates as %q (ok=%t), want %q", user, ok, wantUser)
		}

		// Bound to its Secret: the token dies with the build's transient secrets.
		if err := cs.CoreV1().Secrets(ns).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for {
			if _, ok := reviewToken(t, cs, token); !ok {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("token still valid after its Secret was deleted")
			}
			time.Sleep(200 * time.Millisecond)
		}
	})

	t.Run("canceled request removes its secret", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		// The client goes away right after the Secret is created.
		canceling := rest.CopyConfig(cfg)
		canceling.Wrap(func(rt http.RoundTripper) http.RoundTripper {
			return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				resp, err := rt.RoundTrip(r)
				if err != nil || r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/secrets") {
					return resp, err
				}
				body, err := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				resp.Body = io.NopCloser(bytes.NewReader(body))
				cancel()
				return resp, err
			})
		})
		if _, err := createInternalRegistrySecret(ctx, canceling, ns, "canceled", 3600); err == nil {
			t.Fatal("expected an error after the request was canceled")
		}
		_, err := cs.CoreV1().Secrets(ns).Get(t.Context(), "canceled-registry-auth", metav1.GetOptions{})
		if !k8serrors.IsNotFound(err) {
			t.Fatalf("secret left behind after a canceled request (a retry would hit AlreadyExists): %v", err)
		}
	})

	t.Run("token returned to users", func(t *testing.T) {
		a := newTestServer(t, func(d *apiDependencies) {
			d.getRESTConfigFromRequest = func(*gin.Context) (*rest.Config, error) { return cfg, nil }
		})
		token, _, err := a.mintRegistryToken(ctx, nil, ns, 3600)
		if err != nil {
			t.Fatal(err)
		}
		wantUser := saUser(automotivev1alpha1.RegistryPullServiceAccountName)
		if user, ok := reviewToken(t, cs, token); !ok || user != wantUser {
			t.Fatalf("token authenticates as %q (ok=%t), want %q", user, ok, wantUser)
		}
	})
}

// registryTokenFromDockerConfig extracts the SA token stored for the internal registry.
func registryTokenFromDockerConfig(t *testing.T, secret *corev1.Secret) string {
	t.Helper()
	var cfg struct {
		Auths map[string]struct {
			Auth string `json:"auth"`
		} `json:"auths"`
	}
	if err := json.Unmarshal(secret.Data[corev1.DockerConfigJsonKey], &cfg); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(cfg.Auths[defaultInternalRegistryURL].Auth)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := strings.CutPrefix(string(decoded), "serviceaccount:")
	if !ok {
		t.Fatalf("unexpected registry auth %q", decoded)
	}
	return token
}

// reviewToken reports who the API server authenticates token as.
func reviewToken(t *testing.T, cs kubernetes.Interface, token string) (string, bool) {
	t.Helper()
	review, err := cs.AuthenticationV1().TokenReviews().Create(t.Context(),
		&authnv1.TokenReview{Spec: authnv1.TokenReviewSpec{Token: token}}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return review.Status.User.Username, review.Status.Authenticated
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
