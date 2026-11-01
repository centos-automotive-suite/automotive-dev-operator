package workspace

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

const (
	agentVolume      = "ado-agent"
	agentTokenVolume = "ado-agent-token"
	agentTLSVolume   = "ado-agent-tls"
	// servingCertAnn asks OpenShift's service CA to issue a certificate for
	// the Service into the named Secret, and to rotate it.
	servingCertAnn = "service.beta.openshift.io/serving-cert-secret-name"
	// agentPodLabel selects a workspace's pod for its agent Service. Its
	// value is the Service name, which is unique per workspace, unlike the
	// workspace name label, which is truncated to 63 characters.
	agentPodLabel = "automotive.sdv.cloud.redhat.com/workspace-agent"
	// maxWorkspaceRestarts is how many times in a row the workspace container
	// may restart, after a failed agent liveness probe or an exiting
	// entrypoint, without becoming ready before the workspace is marked Failed.
	maxWorkspaceRestarts = 3
	// readyRestartsAnn holds the workspace container's restart count when the
	// controller last saw the pod Ready.
	readyRestartsAnn = "automotive.sdv.cloud.redhat.com/ready-restart-count"
)

// ensureAgentAccess creates what the build API needs to reach a workspace's
// agent: a Service with a serving certificate, and a Secret with the bearer
// token. Both belong to the workspace and are never replaced, so a running
// agent keeps its token.
func (r *Reconciler) ensureAgentAccess(ctx context.Context, ws *automotivev1alpha1.Workspace) error {
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:        workspaceagent.ServiceName(ws.Name),
			Namespace:   ws.Namespace,
			Labels:      agentLabels(ws),
			Annotations: map[string]string{servingCertAnn: workspaceagent.TLSSecretName(ws.Name)},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{agentPodLabel: workspaceagent.ServiceName(ws.Name)},
			Ports: []corev1.ServicePort{{
				Name:       "agent",
				Port:       workspaceagent.APIPort,
				TargetPort: intstr.FromInt32(workspaceagent.APIPort),
				Protocol:   corev1.ProtocolTCP,
			}},
		},
	}
	if err := r.createOwned(ctx, ws, service); err != nil {
		return fmt.Errorf("creating agent service: %w", err)
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      workspaceagent.TokenSecretName(ws.Name),
			Namespace: ws.Namespace,
			Labels:    agentLabels(ws),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{workspaceagent.TokenKey: []byte(base64.RawURLEncoding.EncodeToString(token))},
	}
	if err := r.createOwned(ctx, ws, secret); err != nil {
		return fmt.Errorf("creating agent token: %w", err)
	}
	return nil
}

func (r *Reconciler) createOwned(ctx context.Context, ws *automotivev1alpha1.Workspace, obj client.Object) error {
	if err := r.Get(ctx, client.ObjectKeyFromObject(obj), obj); err == nil {
		// Never adopt another workspace's token or Service, including one a
		// deleted workspace of the same name left for garbage collection.
		if ws != nil && !metav1.IsControlledBy(obj, ws) {
			return fmt.Errorf("%s already exists and belongs to another workspace", obj.GetName())
		}
		return nil
	} else if !k8serrors.IsNotFound(err) {
		return err
	}
	if err := controllerutil.SetControllerReference(ws, obj, r.Scheme); err != nil {
		return err
	}
	return client.IgnoreAlreadyExists(r.Create(ctx, obj))
}

func agentLabels(ws *automotivev1alpha1.Workspace) map[string]string {
	return map[string]string{
		"app.kubernetes.io/managed-by":        "automotive-dev-operator",
		"app.kubernetes.io/component":         "workspace-agent",
		automotivev1alpha1.LabelWorkspaceName: controllerutils.SanitizeLabelValue(ws.Name),
	}
}

// agentImage is the operator image, which ships the agent binary.
func (r *Reconciler) agentImage(operatorConfig *automotivev1alpha1.OperatorConfig) string {
	if r.AgentImage != "" {
		return r.AgentImage
	}
	var images *automotivev1alpha1.ImagesConfig
	if operatorConfig != nil {
		images = operatorConfig.Spec.GetImages()
	}
	return images.GetOperatorImage()
}

// agentPodSpec adds the agent to a workspace pod: an init container copies the
// binary from the operator image into an emptyDir, the workspace container
// mounts it with the token and serving certificate, and probes on the agent
// gate readiness. startHook is set for images whose entrypoint doesn't start
// the agent itself.
func agentPodSpec(spec *corev1.PodSpec, ws *automotivev1alpha1.Workspace, image string, startHook bool) {
	spec.Volumes = append(spec.Volumes,
		corev1.Volume{Name: agentVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}},
		corev1.Volume{Name: agentTokenVolume, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName: workspaceagent.TokenSecretName(ws.Name), DefaultMode: ptr.To[int32](0o400),
		}}},
		corev1.Volume{Name: agentTLSVolume, VolumeSource: corev1.VolumeSource{Secret: &corev1.SecretVolumeSource{
			SecretName: workspaceagent.TLSSecretName(ws.Name), DefaultMode: ptr.To[int32](0o400),
		}}},
	)
	spec.InitContainers = append(spec.InitContainers, corev1.Container{
		Name:         "agent-install",
		Image:        image,
		Command:      []string{"cp", "/workspace-agent", workspaceagent.Binary},
		VolumeMounts: []corev1.VolumeMount{{Name: agentVolume, MountPath: workspaceagent.InstallDir}},
		SecurityContext: &corev1.SecurityContext{
			AllowPrivilegeEscalation: new(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		},
	})

	container := &spec.Containers[0]
	container.VolumeMounts = append(container.VolumeMounts,
		corev1.VolumeMount{Name: agentVolume, MountPath: workspaceagent.InstallDir, ReadOnly: true},
		corev1.VolumeMount{Name: agentTokenVolume, MountPath: workspaceagent.TokenDir, ReadOnly: true},
		corev1.VolumeMount{Name: agentTLSVolume, MountPath: workspaceagent.TLSDir, ReadOnly: true},
	)
	container.Ports = append(container.Ports,
		corev1.ContainerPort{Name: "agent", ContainerPort: workspaceagent.APIPort, Protocol: corev1.ProtocolTCP},
		corev1.ContainerPort{Name: "files", ContainerPort: workspaceagent.FilesPort, Protocol: corev1.ProtocolTCP},
	)
	healthz := func(period, failures int32) *corev1.Probe {
		return &corev1.Probe{
			ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{
				Path: "/healthz", Port: intstr.FromInt32(workspaceagent.APIPort), Scheme: corev1.URISchemeHTTPS,
			}},
			PeriodSeconds:    period,
			FailureThreshold: failures,
			TimeoutSeconds:   2,
		}
	}
	// The entrypoint may take a while to set up the workspace before it
	// starts the agent; give it two minutes.
	container.StartupProbe = healthz(2, 60)
	container.ReadinessProbe = healthz(5, 3)
	container.LivenessProbe = healthz(10, 3)
	if startHook {
		container.Lifecycle = &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{
			Exec: &corev1.ExecAction{Command: []string{workspaceagent.Binary, "start"}},
		}}
	}
}
