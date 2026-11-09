package operatorconfig

import (
	"os"
	"strings"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/labels"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Build pods report progress by patching an annotation on their own pod, which
// RBAC can only grant as patch on every pod in the namespace. The admission
// policy must narrow that to the progress annotation on the caller's own pod.
func TestBuildPodPatchPolicy(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS or run make test for admission policy tests")
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
	admin, err := client.New(cfg, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	const ns = "ado"
	buildSA := automotivev1alpha1.BuildServiceAccountName

	r := &OperatorConfigReconciler{}
	policy := r.buildBuildPodPatchPolicy(ns)
	for _, obj := range []client.Object{
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: buildSA, Namespace: ns}},
		// The grant build pods hold today (config/rbac/pipeline_pod_role.yaml).
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "pipeline-pod-annotator", Namespace: ns},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"patch"}}},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "pipeline-pod-annotator", Namespace: ns},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "pipeline-pod-annotator"},
			Subjects:   []rbacv1.Subject{{Kind: rbacv1.ServiceAccountKind, Name: buildSA, Namespace: ns}},
		},
		testPod(ns, "build-pod", nil),
		testPod(ns, "ado-build-api", map[string]string{"component": "build-api"}),
		policy,
		r.buildBuildPodPatchPolicyBinding(ns),
	} {
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatalf("creating %T %s: %v", obj, obj.GetName(), err)
		}
	}

	asBuildPod := impersonateBuildSA(t, cfg, ns, "build-pod")
	asUnboundToken := impersonateBuildSA(t, cfg, ns, "")
	progress := `{"metadata":{"annotations":{"` + labels.Progress + `":"Building image|3|5"}}}`

	// The policy is loaded asynchronously; wait until it denies a request.
	deadline := time.Now().Add(30 * time.Second)
	for patchPod(t, asBuildPod, ns, "ado-build-api", progress) == nil {
		if time.Now().After(deadline) {
			t.Fatal("admission policy never took effect")
		}
		time.Sleep(200 * time.Millisecond)
	}

	const (
		otherPod        = "may only update the pod its token was issued to"
		otherAnnotation = "may only change the " + labels.Progress + " annotation"
		fixedField      = "may not change a pod's spec, labels, owners or finalizers"
	)
	for _, tc := range []struct {
		name   string
		as     client.Client
		pod    string
		patch  string
		denied string // the policy message expected, empty if allowed
	}{
		{name: "own pod progress", as: asBuildPod, pod: "build-pod", patch: progress},
		// OpenShift's SCC admission re-selects the SCC on every update, as the
		// requester, and rewrites these annotations before policies run.
		{name: "own pod progress with SCC annotations rewritten", as: asBuildPod, pod: "build-pod",
			patch: `{"metadata":{"annotations":{"` + labels.Progress + `":"Building image|4|5",` +
				`"openshift.io/scc":"privileged","security.openshift.io/validated-scc-subject-type":"serviceaccount"}}}`},
		{name: "own pod other annotation", as: asBuildPod, pod: "build-pod",
			patch: `{"metadata":{"annotations":{"example.com/other":"x"}}}`, denied: otherAnnotation},
		{name: "own pod labels", as: asBuildPod, pod: "build-pod",
			patch: `{"metadata":{"labels":{"component":"build-api"}}}`, denied: fixedField},
		{name: "own pod image", as: asBuildPod, pod: "build-pod",
			patch: `{"spec":{"containers":[{"name":"step","image":"registry.example/evil"}]}}`, denied: fixedField},
		{name: "other pod progress", as: asBuildPod, pod: "ado-build-api", patch: progress, denied: otherPod},
		{name: "token not bound to a pod", as: asUnboundToken, pod: "build-pod", patch: progress, denied: otherPod},
		{name: "other users unaffected", as: admin, pod: "ado-build-api",
			patch: `{"metadata":{"labels":{"example.com/admin":"x"}}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := patchPod(t, tc.as, ns, tc.pod, tc.patch)
			if tc.denied == "" {
				if err != nil {
					t.Fatalf("patch denied: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), policy.Name) || !strings.Contains(err.Error(), tc.denied) {
				t.Fatalf("patch was not denied by %s with %q: %v", policy.Name, tc.denied, err)
			}
		})
	}
}

// testPod is an unscheduled pod running as the build SA.
func testPod(ns, name string, podLabels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: podLabels},
		Spec: corev1.PodSpec{
			ServiceAccountName: automotivev1alpha1.BuildServiceAccountName,
			Containers:         []corev1.Container{{Name: "step", Image: "registry.example/step"}},
		},
	}
}

// impersonateBuildSA acts as the build ServiceAccount. With a pod name it
// carries the identity of that pod's mounted token; without one it is a
// token minted through the TokenRequest API.
func impersonateBuildSA(t *testing.T, cfg *rest.Config, ns, pod string) client.Client {
	t.Helper()
	impersonated := rest.CopyConfig(cfg)
	impersonated.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + ns + ":" + automotivev1alpha1.BuildServiceAccountName,
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"},
	}
	if pod != "" {
		impersonated.Impersonate.Extra = map[string][]string{"authentication.kubernetes.io/pod-name": {pod}}
	}
	c, err := client.New(impersonated, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// patchPod sends a strategic merge patch, so a spec patch changes only the
// fields it names and the API server's own validation accepts it.
func patchPod(t *testing.T, c client.Client, ns, name, patch string) error {
	t.Helper()
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}}
	return c.Patch(t.Context(), pod, client.RawPatch(types.StrategicMergePatchType, []byte(patch)))
}
