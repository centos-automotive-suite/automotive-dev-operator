package workspace

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"maps"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/controller/controllerutils"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/workspaceagent/agentconn"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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
// token, both owned by the workspace. The token is never replaced, so a
// running agent keeps it. The Service's selector and ports, and the
// namespace's agent NetworkPolicy, are kept at the operator's definitions.
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
	err := ensureOwned(ctx, r, ws, service, func(existing *corev1.Service) bool {
		if maps.Equal(existing.Spec.Selector, service.Spec.Selector) &&
			equality.Semantic.DeepEqual(existing.Spec.Ports, service.Spec.Ports) {
			return false
		}
		// Only these two: the API server fills in the rest of the spec.
		existing.Spec.Selector = service.Spec.Selector
		existing.Spec.Ports = service.Spec.Ports
		return true
	})
	if err != nil {
		return fmt.Errorf("agent service: %w", err)
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
	if err := ensureOwned(ctx, r, ws, secret, nil); err != nil {
		return fmt.Errorf("creating agent token: %w", err)
	}

	// Shared by every workspace in the namespace, so owned by none of them.
	bundle := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{
		Name:        agentconn.CABundleConfigMap,
		Namespace:   ws.Namespace,
		Labels:      map[string]string{"app.kubernetes.io/managed-by": "automotive-dev-operator"},
		Annotations: map[string]string{agentconn.InjectCABundleAnn: "true"},
	}}
	if err := ensureOwned(ctx, r, nil, bundle, nil); err != nil {
		return fmt.Errorf("creating service CA bundle: %w", err)
	}
	policy := agentNetworkPolicy(ws.Namespace)
	err = ensureOwned(ctx, r, nil, policy, func(existing *networkingv1.NetworkPolicy) bool {
		if equality.Semantic.DeepEqual(existing.Spec, policy.Spec) {
			return false
		}
		existing.Spec = policy.Spec
		return true
	})
	if err != nil {
		return fmt.Errorf("workspace network policy: %w", err)
	}
	return nil
}

// agentNetworkPolicy admits only the agent's ports into workspace pods: the
// API from the build API and the workspace controller, and the file server
// from image build pods, which Tekton labels with their ImageBuild. The
// policy can't tell one user's builds from another's, which is why file URLs
// carry a per-build grant.
func agentNetworkPolicy(namespace string) *networkingv1.NetworkPolicy {
	tcp := corev1.ProtocolTCP
	port := func(p int32) []networkingv1.NetworkPolicyPort {
		return []networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: new(intstr.FromInt32(p))}}
	}
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-workspace-agents",
			Namespace: namespace,
			Labels:    map[string]string{"app.kubernetes.io/managed-by": "automotive-dev-operator"},
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{
				"app.kubernetes.io/managed-by": "automotive-dev-operator",
				"app.kubernetes.io/component":  "workspace",
			}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					Ports: port(workspaceagent.APIPort),
					From: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{{
							Key:      "app.kubernetes.io/component",
							Operator: metav1.LabelSelectorOpIn,
							Values:   []string{"build-api", "build-controller"},
						}},
					}}, {PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{
						"control-plane": "operator",
					}}}},
				},
				{
					Ports: port(workspaceagent.FilesPort),
					From: []networkingv1.NetworkPolicyPeer{{PodSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{{
							Key:      "automotive.sdv.cloud.redhat.com/imagebuild-name",
							Operator: metav1.LabelSelectorOpExists,
						}},
					}}},
				},
			},
		},
	}
}

// ensureOwned creates obj, owned by ws when ws is not nil. When obj already
// exists, update copies the fields the operator manages into it and reports
// whether any changed; with a nil update the existing object is kept as is.
func ensureOwned[T any, P interface {
	*T
	client.Object
}](ctx context.Context, r *Reconciler, ws *automotivev1alpha1.Workspace, obj P, update func(existing P) bool) error {
	existing := P(new(T))
	err := r.Get(ctx, client.ObjectKeyFromObject(obj), existing)
	if k8serrors.IsNotFound(err) {
		if ws != nil {
			if err := controllerutil.SetControllerReference(ws, obj, r.Scheme); err != nil {
				return err
			}
		}
		return client.IgnoreAlreadyExists(r.Create(ctx, obj))
	}
	if err != nil {
		return err
	}
	// Never adopt another workspace's token or Service, including one a
	// deleted workspace of the same name left for garbage collection.
	if ws != nil && !metav1.IsControlledBy(existing, ws) {
		return fmt.Errorf("%s already exists and belongs to another workspace", obj.GetName())
	}
	if update == nil || !update(existing) {
		return nil
	}
	return r.Update(ctx, existing)
}

// isWorkspaceActive asks the workspace's agent whether live runs, terminals
// or exec'd processes keep it from auto-pausing.
func (r *Reconciler) isWorkspaceActive(ctx context.Context, ws *automotivev1alpha1.Workspace) (bool, error) {
	connect := r.connectAgent
	if connect == nil {
		connect = func(ctx context.Context, ws *automotivev1alpha1.Workspace) (*workspaceagent.Client, error) {
			reader := r.AgentReader
			if reader == nil {
				reader = r.Client
			}
			return agentconn.Connect(ctx, reader, ws)
		}
	}
	agent, err := connect(ctx, ws)
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	activity, err := agent.Activity(ctx)
	if err != nil {
		return false, fmt.Errorf("checking workspace activity: %w", err)
	}
	return activity.Active, nil
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
