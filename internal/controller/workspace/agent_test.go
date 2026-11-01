package workspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"slices"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func TestReconcileCreatesAgentServiceAndToken(t *testing.T) {
	ws, pvc, _ := runningWorkspace("agent-ws", "default")
	r, fc := newTestReconciler(ws, pvc)
	ctx := context.Background()
	request := ctrl.Request{NamespacedName: types.NamespacedName{Name: ws.Name, Namespace: ws.Namespace}}
	if _, err := r.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}

	service := &corev1.Service{}
	if err := fc.Get(ctx, types.NamespacedName{Name: "workspace-agent-ws-agent", Namespace: "default"}, service); err != nil {
		t.Fatalf("agent service: %v", err)
	}
	if service.Annotations[servingCertAnn] != workspaceagent.TLSSecretName(ws.Name) {
		t.Errorf("service annotations = %v, want a serving certificate in %s", service.Annotations, workspaceagent.TLSSecretName(ws.Name))
	}
	if len(service.Spec.Ports) != 1 || service.Spec.Ports[0].Port != workspaceagent.APIPort ||
		!maps.Equal(service.Spec.Selector, map[string]string{agentPodLabel: service.Name}) {
		t.Errorf("service spec = %+v, want port %d selecting the workspace pod", service.Spec, workspaceagent.APIPort)
	}

	secret := &corev1.Secret{}
	key := types.NamespacedName{Name: workspaceagent.TokenSecretName(ws.Name), Namespace: "default"}
	if err := fc.Get(ctx, key, secret); err != nil {
		t.Fatalf("agent token: %v", err)
	}
	token := string(secret.Data[workspaceagent.TokenKey])
	if len(token) < 40 {
		t.Errorf("token = %q, want 32 random bytes", token)
	}
	if !metav1.IsControlledBy(secret, ws) || !metav1.IsControlledBy(service, ws) {
		t.Error("agent service and token are not owned by the workspace")
	}

	if _, err := r.Reconcile(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := fc.Get(ctx, key, secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data[workspaceagent.TokenKey]) != token {
		t.Error("a second reconcile replaced the token of a running agent")
	}
}

func TestBuildPodAddsAgent(t *testing.T) {
	r := &Reconciler{AgentImage: "quay.io/example/operator:v1"}
	config := &automotivev1alpha1.OperatorConfig{Spec: automotivev1alpha1.OperatorConfigSpec{
		Workspaces: &automotivev1alpha1.WorkspacesConfig{ToolchainImage: "quay.io/example/toolchain:v1"},
	}}
	for _, tt := range []struct {
		image     string
		startHook bool
	}{
		{image: "", startHook: false}, // the toolchain entrypoint starts the agent
		{image: "quay.io/example/custom:v1", startHook: true},
	} {
		ws := &automotivev1alpha1.Workspace{
			ObjectMeta: metav1.ObjectMeta{Name: "agent-ws", Namespace: "default"},
			Spec:       automotivev1alpha1.WorkspaceSpec{Image: tt.image},
		}
		pod := r.buildPod(ws, config)
		if pod.Labels[agentPodLabel] != workspaceagent.ServiceName(ws.Name) {
			t.Errorf("image %q: labels = %v, want the agent Service to select this pod alone", tt.image, pod.Labels)
		}
		if pod.Spec.RestartPolicy != corev1.RestartPolicyAlways {
			t.Errorf("image %q: restart policy = %q, want Always so a failed agent restarts only the container", tt.image, pod.Spec.RestartPolicy)
		}
		i := slices.IndexFunc(pod.Spec.InitContainers, func(c corev1.Container) bool { return c.Name == "agent-install" })
		if i < 0 || pod.Spec.InitContainers[i].Image != r.AgentImage {
			t.Errorf("image %q: init containers = %+v, want agent-install from %s", tt.image, pod.Spec.InitContainers, r.AgentImage)
		}
		container := pod.Spec.Containers[0]
		mounted := map[string]bool{}
		for _, m := range container.VolumeMounts {
			mounted[m.MountPath] = m.ReadOnly
		}
		for _, path := range []string{workspaceagent.InstallDir, workspaceagent.TokenDir, workspaceagent.TLSDir} {
			if readOnly, ok := mounted[path]; !ok || !readOnly {
				t.Errorf("image %q: %s is not mounted read-only", tt.image, path)
			}
		}
		probe := container.ReadinessProbe
		if probe == nil || probe.HTTPGet == nil || probe.HTTPGet.Scheme != corev1.URISchemeHTTPS ||
			probe.HTTPGet.Port.IntValue() != workspaceagent.APIPort || container.LivenessProbe == nil {
			t.Errorf("image %q: probes = %+v, want HTTPS /healthz on the agent port", tt.image, probe)
		}
		hasHook := container.Lifecycle != nil && container.Lifecycle.PostStart != nil &&
			slices.Equal(container.Lifecycle.PostStart.Exec.Command, []string{workspaceagent.Binary, "start"})
		if hasHook != tt.startHook {
			t.Errorf("image %q: postStart hook = %v, want %v", tt.image, hasHook, tt.startHook)
		}
	}
}

func TestAgentServiceNameIsADNSLabel(t *testing.T) {
	long := "a-very-long-workspace-name-that-does-not-fit-in-a-dns-label-at-all"
	for _, name := range []string{long, "dotted.name"} {
		got := workspaceagent.ServiceName(name)
		if len(got) > 63 || got != workspaceagent.ServiceName(name) {
			t.Errorf("ServiceName(%q) = %q, want a stable DNS label", name, got)
		}
		// Workspaces share a namespace: another user must not be able to
		// take this name by naming a workspace after the digest.
		sum := sha256.Sum256([]byte(name))
		if digest := hex.EncodeToString(sum[:8]); workspaceagent.ServiceName(digest) == got {
			t.Errorf("workspace %q takes the agent Service of %q", digest, name)
		}
	}
}

func TestAgentAccessRefusesAnotherWorkspacesObjects(t *testing.T) {
	ws, pvc, _ := runningWorkspace("agent-ws", "default")
	ws.UID = "mine"
	other := &automotivev1alpha1.Workspace{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "default", UID: "theirs"}}
	taken := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: workspaceagent.TokenSecretName(ws.Name), Namespace: "default"},
		Data:       map[string][]byte{workspaceagent.TokenKey: []byte("their token")},
	}
	r, _ := newTestReconciler(ws, pvc, other)
	if err := controllerutil.SetControllerReference(other, taken, r.Scheme); err != nil {
		t.Fatal(err)
	}
	if err := r.Create(context.Background(), taken); err != nil {
		t.Fatal(err)
	}
	if err := r.ensureAgentAccess(context.Background(), ws); err == nil {
		t.Fatal("the workspace adopted another workspace's agent token")
	}
}
