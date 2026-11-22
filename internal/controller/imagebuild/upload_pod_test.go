package imagebuild

import (
	"context"
	"slices"
	"strconv"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	controllerutils "github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent/agentconn"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8slabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func uploadTestBuild() *automotivev1alpha1.ImageBuild {
	return &automotivev1alpha1.ImageBuild{
		TypeMeta:   metav1.TypeMeta{APIVersion: automotivev1alpha1.GroupVersion.String(), Kind: "ImageBuild"},
		ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "test-ns", UID: "build-uid"},
	}
}

func getObject(t *testing.T, r *ImageBuildReconciler, name string, obj client.Object) {
	t.Helper()
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: "test-ns", Name: name}, obj); err != nil {
		t.Fatalf("getting %s: %v", name, err)
	}
}

// The upload pod runs the workspace agent, which callers reach through a
// Service with a serving certificate, with a token only the build holds, and
// which bounds uploads as the build API's limits say.
func TestCreateUploadPodRunsTheAgent(t *testing.T) {
	ib := uploadTestBuild()
	config := &automotivev1alpha1.OperatorConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "config", Namespace: controllerutils.OperatorNamespace()},
		Spec: automotivev1alpha1.OperatorConfigSpec{BuildAPI: &automotivev1alpha1.BuildAPIConfig{
			MaxTotalUploadSize: 3 << 30, MaxUploadFileSize: 1 << 30,
		}},
	}
	r := newTestReconciler(ib, config)
	if err := r.createUploadPod(context.Background(), ib); err != nil {
		t.Fatal(err)
	}

	pod := &corev1.Pod{}
	getObject(t, r, safeDerivedName("b", "-upload-pod"), pod)
	agent := pod.Spec.Containers[0]
	if agent.Image != automotivev1alpha1.DefaultOperatorImage {
		t.Errorf("image = %q, want the operator image", agent.Image)
	}
	for _, args := range [][]string{
		{"/workspace-agent", "serve"},
		{"--workdir", "/workspace/shared"},
		{"--max-upload", strconv.Itoa(3 << 30)},
		{"--max-file", strconv.Itoa(1 << 30)},
		{"--build-uploads"},
	} {
		if !containsRun(agent.Command, args) {
			t.Errorf("command %q lacks %q", agent.Command, args)
		}
	}
	probe := agent.ReadinessProbe
	if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Scheme != corev1.URISchemeHTTPS || probe.HTTPGet.Port.IntValue() != workspaceagent.APIPort {
		t.Errorf("readiness probe = %+v, want the agent's HTTPS health check", probe)
	}

	secret := &corev1.Secret{}
	getObject(t, r, workspaceagent.UploadTokenSecretName("b"), secret)
	if len(secret.Data[workspaceagent.TokenKey]) == 0 || !metav1.IsControlledBy(secret, ib) {
		t.Errorf("token secret = %+v, want a token the build owns", secret)
	}
	service := &corev1.Service{}
	getObject(t, r, workspaceagent.UploadServiceName("b"), service)
	if service.Annotations[agentconn.ServingCertAnn] != workspaceagent.UploadTLSSecretName("b") || !metav1.IsControlledBy(service, ib) {
		t.Errorf("service = %+v, want a serving certificate, owned by the build", service.ObjectMeta)
	}
	if !k8slabels.SelectorFromSet(service.Spec.Selector).Matches(k8slabels.Set(pod.Labels)) {
		t.Errorf("service selector %v misses the pod's labels %v", service.Spec.Selector, pod.Labels)
	}
	var mounted []string
	for _, volume := range pod.Spec.Volumes {
		if volume.Secret != nil {
			mounted = append(mounted, volume.Secret.SecretName)
		}
	}
	for _, name := range []string{workspaceagent.UploadTokenSecretName("b"), workspaceagent.UploadTLSSecretName("b")} {
		if !slices.Contains(mounted, name) {
			t.Errorf("the pod doesn't mount %s", name)
		}
	}
	// The agent never calls the API, and a token for any account in the
	// namespace can pull other users' images from the registry.
	if automount := pod.Spec.AutomountServiceAccountToken; automount == nil || *automount {
		t.Errorf("automountServiceAccountToken = %v, want false", automount)
	}
	bundle := &corev1.ConfigMap{}
	getObject(t, r, agentconn.CABundleConfigMap, bundle)
	if bundle.Annotations[agentconn.InjectCABundleAnn] != "true" {
		t.Errorf("CA bundle annotations = %v", bundle.Annotations)
	}
}

// containsRun reports whether want appears in args as a contiguous run.
func containsRun(args, want []string) bool {
	for i := range args {
		if slices.Equal(args[i:min(i+len(want), len(args))], want) {
			return true
		}
	}
	return false
}

// Someone who could create the token would know it, and someone who could
// create the Service could send the uploads elsewhere, so the build uses
// neither unless it owns them.
func TestCreateUploadPodRefusesAccessTheBuildDoesNotOwn(t *testing.T) {
	for name, planted := range map[string]client.Object{
		"token": &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: workspaceagent.UploadTokenSecretName("b"), Namespace: "test-ns"},
			Data:       map[string][]byte{workspaceagent.TokenKey: []byte("known")},
		},
		"service": &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: workspaceagent.UploadServiceName("b"), Namespace: "test-ns"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "elsewhere"}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			ib := uploadTestBuild()
			r := newTestReconciler(ib, planted)
			if err := r.createUploadPod(context.Background(), ib); err == nil {
				t.Fatal("the build took a planted " + name)
			}
			pods := &corev1.PodList{}
			if err := r.List(context.Background(), pods, client.InNamespace("test-ns")); err != nil {
				t.Fatal(err)
			}
			if len(pods.Items) != 0 {
				t.Errorf("an upload pod was created with a planted %s", name)
			}
		})
	}
}

// Uploads are done once the build starts, so their agent's access goes with
// the pod.
func TestShutdownUploadPodRemovesTheAgentsAccess(t *testing.T) {
	ib := uploadTestBuild()
	r := newTestReconciler(ib)
	if err := r.createUploadPod(context.Background(), ib); err != nil {
		t.Fatal(err)
	}
	if err := r.shutdownUploadPod(context.Background(), ib); err != nil {
		t.Fatal(err)
	}
	for name, obj := range map[string]client.Object{
		safeDerivedName("b", "-upload-pod"):       &corev1.Pod{},
		workspaceagent.UploadTokenSecretName("b"): &corev1.Secret{},
		workspaceagent.UploadServiceName("b"):     &corev1.Service{},
	} {
		if err := r.Get(context.Background(), types.NamespacedName{Namespace: "test-ns", Name: name}, obj); err == nil {
			t.Errorf("%s is still there", name)
		}
	}
}
