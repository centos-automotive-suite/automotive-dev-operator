package operatorconfig

import (
	"os"
	"strings"
	"testing"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// The build controller and the build API may create pods and Tekton runs in
// the operator's namespace, and RBAC cannot limit which ServiceAccount those
// run as. The admission policy must keep them from starting one as the
// operator's.
func TestWorkloadAccountsPolicy(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("set KUBEBUILDER_ASSETS or run make test for admission policy tests")
	}
	env := &envtest.Environment{CRDs: []*apiextensionsv1.CustomResourceDefinition{
		openCRD("tekton.dev", "v1", "TaskRun", "taskruns"),
		openCRD("tekton.dev", "v1", "PipelineRun", "pipelineruns"),
		openCRD("shipwright.io", "v1beta1", "BuildRun", "buildruns"),
	}}
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
	const ns = workloadTestNamespace
	controllerSA := automotivev1alpha1.BuildControllerServiceAccountName

	r := &OperatorConfigReconciler{}
	policy := r.buildWorkloadAccountsPolicy(ns)
	objects := []client.Object{&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}}
	buildAPISA := automotivev1alpha1.BuildAPIServiceAccountName
	for _, sa := range []string{controllerSA, buildAPISA, "ado-operator", automotivev1alpha1.BuildServiceAccountName, workspaceServiceAccountName} {
		objects = append(objects, &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa, Namespace: ns}})
	}
	objects = append(objects,
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "workloads", Namespace: ns},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"pods", "secrets"}, Verbs: []string{"create"}},
				{APIGroups: []string{"tekton.dev"}, Resources: []string{"taskruns", "pipelineruns"}, Verbs: []string{"create"}},
				{APIGroups: []string{"shipwright.io"}, Resources: []string{"buildruns"}, Verbs: []string{"create"}},
			},
		},
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "workloads", Namespace: ns},
			RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "workloads"},
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.ServiceAccountKind, Name: controllerSA, Namespace: ns},
				{Kind: rbacv1.ServiceAccountKind, Name: buildAPISA, Namespace: ns},
			},
		},
		policy,
		r.buildWorkloadAccountsPolicyBinding(ns),
	)
	for _, obj := range objects {
		if err := admin.Create(ctx, obj); err != nil {
			t.Fatalf("creating %T %s: %v", obj, obj.GetName(), err)
		}
	}

	asController := impersonateSA(t, cfg, ns, controllerSA)
	asBuildAPI := impersonateSA(t, cfg, ns, buildAPISA)
	pod := func(sa string) client.Object {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "pod-", Namespace: ns},
			Spec: corev1.PodSpec{
				ServiceAccountName: sa,
				Containers:         []corev1.Container{{Name: "step", Image: "registry.example/step"}},
			},
		}
	}

	// The policy is loaded asynchronously; wait until it denies a request.
	// Other errors may be transient, so only a denial naming it ends the wait.
	policyName := workloadAccountsPolicyName(ns)
	deadline := time.Now().Add(30 * time.Second)
	for {
		err := asController.Create(ctx, pod("ado-operator"))
		if err != nil && strings.Contains(err.Error(), policyName) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("admission policy never took effect, last result: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}

	for _, tc := range []struct {
		name    string
		as      client.Client
		obj     client.Object
		allowed bool
	}{
		{name: "build pod", as: asController, obj: pod(automotivev1alpha1.BuildServiceAccountName), allowed: true},
		{name: "workspace pod", as: asController, obj: pod(workspaceServiceAccountName), allowed: true},
		{name: "operator pod", as: asController, obj: pod("ado-operator")},
		{name: "own identity pod", as: asController, obj: pod(controllerSA)},
		{name: "build TaskRun", as: asController, allowed: true,
			obj: run("tekton.dev/v1", "TaskRun", map[string]any{"serviceAccountName": automotivev1alpha1.BuildServiceAccountName})},
		{name: "TaskRun with Tekton's default", as: asController, allowed: true,
			obj: run("tekton.dev/v1", "TaskRun", map[string]any{})},
		{name: "operator TaskRun", as: asController,
			obj: run("tekton.dev/v1", "TaskRun", map[string]any{"serviceAccountName": "ado-operator"})},
		{name: "build PipelineRun", as: asController, allowed: true,
			obj: run("tekton.dev/v1", "PipelineRun", map[string]any{
				"taskRunTemplate": map[string]any{"serviceAccountName": automotivev1alpha1.BuildServiceAccountName},
			})},
		{name: "PipelineRun with an operator task", as: asController,
			obj: run("tekton.dev/v1", "PipelineRun", map[string]any{
				"taskRunTemplate": map[string]any{"serviceAccountName": automotivev1alpha1.BuildServiceAccountName},
				"taskRunSpecs":    []any{map[string]any{"pipelineTaskName": "build", "serviceAccountName": "ado-operator"}},
			})},
		{name: "build BuildRun", as: asController, allowed: true,
			obj: run("shipwright.io/v1beta1", "BuildRun", map[string]any{"serviceAccount": automotivev1alpha1.BuildServiceAccountName})},
		{name: "operator BuildRun", as: asController,
			obj: run("shipwright.io/v1beta1", "BuildRun", map[string]any{"serviceAccount": "ado-operator"})},
		{name: "build API flash TaskRun", as: asBuildAPI, allowed: true,
			obj: run("tekton.dev/v1", "TaskRun", map[string]any{"serviceAccountName": automotivev1alpha1.BuildServiceAccountName})},
		// Kubernetes fills a Secret of this type with a token for the
		// ServiceAccount it names.
		{name: "operator token Secret", as: asController, obj: tokenSecret("ado-operator")},
		{name: "build token Secret", as: asBuildAPI, obj: tokenSecret(automotivev1alpha1.BuildServiceAccountName)},
		{name: "opaque Secret", as: asBuildAPI, allowed: true, obj: &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{GenerateName: "secret-", Namespace: ns},
			StringData: map[string]string{"token": "x"},
		}},
		{name: "build API operator TaskRun", as: asBuildAPI,
			obj: run("tekton.dev/v1", "TaskRun", map[string]any{"serviceAccountName": "ado-operator"})},
		{name: "other users unaffected", as: admin, obj: pod("ado-operator"), allowed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.as.Create(ctx, tc.obj)
			if tc.allowed {
				if err != nil {
					t.Fatalf("create denied: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), policy.Name) {
				t.Fatalf("create was not denied by %s: %v", policy.Name, err)
			}
		})
	}
}

// openCRD defines a namespaced kind that accepts any spec, standing in for
// the Tekton and Shipwright CRDs.
func openCRD(group, version, kind, plural string) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{Name: plural + "." + group},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: group,
			Scope: apiextensionsv1.NamespaceScoped,
			Names: apiextensionsv1.CustomResourceDefinitionNames{Kind: kind, Plural: plural},
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Name: version, Served: true, Storage: true,
				Schema: &apiextensionsv1.CustomResourceValidation{OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
					Type:                   "object",
					XPreserveUnknownFields: new(true),
				}},
			}},
		},
	}
}

func tokenSecret(sa string) client.Object {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "token-", Namespace: workloadTestNamespace,
			Annotations: map[string]string{corev1.ServiceAccountNameKey: sa},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}
}

// workloadTestNamespace is the operator's namespace in the workload policy test.
const workloadTestNamespace = "ado"

func run(apiVersion, kind string, spec map[string]any) client.Object {
	obj := &unstructured.Unstructured{Object: map[string]any{"spec": spec}}
	obj.SetAPIVersion(apiVersion)
	obj.SetKind(kind)
	obj.SetNamespace(workloadTestNamespace)
	obj.SetGenerateName("run-")
	return obj
}

func impersonateSA(t *testing.T, cfg *rest.Config, ns, sa string) client.Client {
	t.Helper()
	impersonated := rest.CopyConfig(cfg)
	impersonated.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:" + ns + ":" + sa,
		Groups:   []string{"system:serviceaccounts", "system:serviceaccounts:" + ns, "system:authenticated"},
	}
	c, err := client.New(impersonated, client.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
