package operatorconfig

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/golang-jwt/jwt/v5"
	routev1 "github.com/openshift/api/route/v1"
	securityv1 "github.com/openshift/api/security/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
)

const (
	buildControllerName         = "ado-build-controller"
	pipelineSCCBindingName      = "ado-build-privileged"
	sccPrivilegedRoleName       = "ado-build-privileged"
	workspaceServiceAccountName = "ado-workspace"
	workspaceSCCName            = "ado-workspace-scc"
)

// getOperatorImage returns the operator image from env var, then config, then default constant
func getOperatorImage(images *automotivev1alpha1.ImagesConfig) string {
	if img := os.Getenv("OPERATOR_IMAGE"); img != "" {
		return img
	}
	return images.GetOperatorImage()
}

// buildBuildAPIContainers builds the container list for build-API deployment, conditionally including oauth-proxy
func (r *OperatorConfigReconciler) buildBuildAPIContainers(namespace string, isOpenShift bool, config *automotivev1alpha1.OperatorConfig) []corev1.Container {
	buildAPIEnv := []corev1.EnvVar{
		{
			Name:  "BUILD_API_NAMESPACE",
			Value: namespace,
		},
		{
			Name: "INTERNAL_JWT_ISSUER",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: internalJWTSecretName,
					},
					Key: "issuer",
				},
			},
		},
		{
			Name: "INTERNAL_JWT_AUDIENCE",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: internalJWTSecretName,
					},
					Key: "audience",
				},
			},
		},
		{
			Name: "INTERNAL_JWT_KEY",
			ValueFrom: &corev1.EnvVarSource{
				SecretKeyRef: &corev1.SecretKeySelector{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: internalJWTSecretName,
					},
					Key: "signing-key",
				},
			},
		},
	}
	images := config.Spec.GetImages()
	var resourcesCfg *automotivev1alpha1.BuildAPIResourcesConfig
	if config.Spec.BuildAPI != nil {
		resourcesCfg = config.Spec.BuildAPI.Resources
	}
	containers := []corev1.Container{
		{
			Name:      "build-api",
			Image:     getOperatorImage(images),
			Command:   []string{"/build-api"},
			Resources: resourcesCfg.GetBuildAPIResources(),
			Env:       buildAPIEnv,
			Ports: []corev1.ContainerPort{
				{
					Name:          "http",
					ContainerPort: 8080,
					Protocol:      corev1.ProtocolTCP,
				},
			},
			LivenessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/v1/healthz",
						Port: intstr.FromInt(8080),
					},
				},
				InitialDelaySeconds: 15,
				PeriodSeconds:       20,
				TimeoutSeconds:      5,
				FailureThreshold:    3,
			},
			ReadinessProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/v1/healthz",
						Port: intstr.FromInt(8080),
					},
				},
				InitialDelaySeconds: 5,
				PeriodSeconds:       10,
				TimeoutSeconds:      3,
				FailureThreshold:    3,
			},
			StartupProbe: &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					HTTPGet: &corev1.HTTPGetAction{
						Path: "/v1/healthz",
						Port: intstr.FromInt(8080),
					},
				},
				InitialDelaySeconds: 10,
				PeriodSeconds:       5,
				TimeoutSeconds:      3,
				FailureThreshold:    30, // Allow up to 150s for startup
			},
			// No volume mounts needed - Build API reads directly from OperatorConfig CRD
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptr.To(false),
			},
		},
	}

	// Only add oauth-proxy on OpenShift
	if isOpenShift {
		containers = append(containers, corev1.Container{
			Name:  "oauth-proxy",
			Image: images.GetOAuthProxyImage(),
			Args: []string{
				"--provider=openshift",
				"--https-address=",
				"--http-address=:8081",
				"--upstream=http://localhost:8080",
				"--openshift-service-account=ado-operator",
				"--cookie-secret=$(COOKIE_SECRET)",
				"--cookie-secure=false",
				"--pass-access-token=true",
				"--pass-user-bearer-token=true",
				"--pass-user-headers=true",
				"--request-logging=true",
				"--skip-auth-regex=^/healthz",
				"--skip-auth-regex=^/v1/",
				"--skip-auth-regex=/v1/",
				"--email-domain=*",
				"--skip-provider-button=true",
				"--upstream-timeout=0",
			},
			Env: []corev1.EnvVar{
				{
					Name: "COOKIE_SECRET",
					ValueFrom: &corev1.EnvVarSource{
						SecretKeyRef: &corev1.SecretKeySelector{
							LocalObjectReference: corev1.LocalObjectReference{
								Name: "ado-build-api-oauth-proxy",
							},
							Key: "cookie-secret",
						},
					},
				},
			},
			Ports: []corev1.ContainerPort{
				{
					Name:          "proxy-http",
					ContainerPort: 8081,
					Protocol:      corev1.ProtocolTCP,
				},
			},
			Resources: resourcesCfg.GetOAuthProxyResources(),
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptr.To(false),
			},
		})
	}

	return containers
}

func (r *OperatorConfigReconciler) buildBuildAPIDeployment(namespace string, isOpenShift bool, config *automotivev1alpha1.OperatorConfig) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":      "automotive-dev-operator",
					"app.kubernetes.io/component": "build-api",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":      "automotive-dev-operator",
						"app.kubernetes.io/component": "build-api",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "ado-operator",
					InitContainers: []corev1.Container{
						{
							Name:    "init-secrets",
							Image:   getOperatorImage(config.Spec.GetImages()),
							Command: []string{"/init-secrets"},
							Env: []corev1.EnvVar{
								{
									Name: "POD_NAMESPACE",
									ValueFrom: &corev1.EnvVarSource{
										FieldRef: &corev1.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: ptr.To(false),
							},
						},
					},
					Containers: r.buildBuildAPIContainers(namespace, isOpenShift, config),
					// No volumes needed - Build API reads directly from OperatorConfig CRD
				},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildAPIService(namespace string, isOpenShift bool) *corev1.Service {
	// Always expose port 8080 (direct access to build-api)
	ports := []corev1.ServicePort{
		{
			Name:       "http",
			Port:       8080,
			TargetPort: intstr.FromInt(8080),
			Protocol:   corev1.ProtocolTCP,
		},
	}

	// On OpenShift, also expose port 8081 (oauth-proxy)
	if isOpenShift {
		ports = append(ports, corev1.ServicePort{
			Name:       "proxy",
			Port:       8081,
			TargetPort: intstr.FromInt(8081),
			Protocol:   corev1.ProtocolTCP,
		})
	}

	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
			},
			Ports: ports,
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildAPIRoute(namespace string, config *automotivev1alpha1.OperatorConfig) *routev1.Route {
	// Derive route timeout from the longest configured timeout + buffer.
	// Must cover uploads, build log streaming, and workspace exec sessions.
	routeTimeoutMinutes := int32(15)
	if config.Spec.ContainerBuilds != nil && config.Spec.ContainerBuilds.UploadTimeoutMinutes > 0 {
		if t := config.Spec.ContainerBuilds.UploadTimeoutMinutes + 2; t > routeTimeoutMinutes {
			routeTimeoutMinutes = t
		}
	}
	if config.Spec.OSBuilds != nil {
		if config.Spec.OSBuilds.UploadTimeoutMinutes > 0 {
			if t := config.Spec.OSBuilds.UploadTimeoutMinutes + 2; t > routeTimeoutMinutes {
				routeTimeoutMinutes = t
			}
		}
		if t := config.Spec.OSBuilds.GetBuildTimeoutMinutes() + 5; t > routeTimeoutMinutes {
			routeTimeoutMinutes = t
		}
	}

	return &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
			Annotations: map[string]string{
				"haproxy.router.openshift.io/timeout": fmt.Sprintf("%dm", routeTimeoutMinutes),
			},
		},
		Spec: routev1.RouteSpec{
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: "ado-build-api",
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromString("http"),
			},
			TLS: &routev1.TLSConfig{
				Termination:                   routev1.TLSTerminationEdge,
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
			},
			WildcardPolicy: routev1.WildcardPolicyNone,
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildAPIIngress(namespace string) *networkingv1.Ingress {
	pathTypePrefix := networkingv1.PathTypePrefix
	ingressClassName := "nginx"

	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
			Annotations: map[string]string{
				"nginx.ingress.kubernetes.io/backend-protocol": "HTTP",
				"nginx.ingress.kubernetes.io/ssl-redirect":     "false",
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: &ingressClassName,
			Rules: []networkingv1.IngressRule{
				{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path:     "/",
									PathType: &pathTypePrefix,
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: "ado-build-api",
											Port: networkingv1.ServiceBackendPort{
												// Use port name "http" - matches the service definition on all platforms
												Name: "http",
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildOAuthSecret(name, namespace string) *corev1.Secret {
	// Generate a random 32-byte cookie secret for AES-256
	cookieSecret := make([]byte, 32)
	if _, err := rand.Read(cookieSecret); err != nil {
		// Fallback to a static secret if random generation fails
		// This should never happen in practice
		cookieSecret = []byte("fallback-secret-change-me-32bit")
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":    "automotive-dev-operator",
				"app.kubernetes.io/part-of": "automotive-dev-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"cookie-secret": []byte(base64.StdEncoding.EncodeToString(cookieSecret)[:32]),
		},
	}
}

func (r *OperatorConfigReconciler) buildInternalJWTSecret(name, namespace string) (*corev1.Secret, error) {
	signingKey, err := generateRandomToken(32)
	if err != nil {
		return nil, err
	}

	issuer := "ado-build-api"
	audience := "ado-build-api"
	expiresAt := time.Now().Add(365 * 24 * time.Hour)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   "internal",
		Audience:  jwt.ClaimStrings{audience},
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
		NotBefore: jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
	})
	signedToken, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return nil, fmt.Errorf("failed to sign internal JWT: %w", err)
	}

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Type: corev1.SecretTypeOpaque,
		StringData: map[string]string{
			"signing-key": signingKey,
			"token":       signedToken,
			"issuer":      issuer,
			"audience":    audience,
			"expires-at":  expiresAt.Format(time.RFC3339),
		},
	}, nil
}

func generateRandomToken(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i := range bytes {
		bytes[i] = charset[int(bytes[i])%len(charset)]
	}
	return string(bytes), nil
}

func (r *OperatorConfigReconciler) buildBuildControllerDeployment(namespace string, config *automotivev1alpha1.OperatorConfig) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildControllerName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-controller",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":      "automotive-dev-operator",
					"app.kubernetes.io/component": "build-controller",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app.kubernetes.io/name":      "automotive-dev-operator",
						"app.kubernetes.io/component": "build-controller",
					},
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: buildControllerName,
					SecurityContext: &corev1.PodSecurityContext{
						RunAsNonRoot: ptr.To(true),
					},
					Containers: []corev1.Container{
						{
							Name:    "manager",
							Image:   getOperatorImage(config.Spec.GetImages()),
							Command: []string{"/manager"},
							Args: []string{
								"--mode=build",
								"--leader-elect",
								"--health-probe-bind-address=:8081",
								"--metrics-bind-address=:8443",
							},
							Env: []corev1.EnvVar{
								{
									Name:  "OPERATOR_IMAGE",
									Value: getOperatorImage(config.Spec.GetImages()),
								},
								{
									Name:  "WATCH_NAMESPACE",
									Value: namespace,
								},
							},
							Ports: []corev1.ContainerPort{
								{
									Name:          "health",
									ContainerPort: 8081,
									Protocol:      corev1.ProtocolTCP,
								},
								{
									Name:          "https",
									ContainerPort: 8443,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							LivenessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/healthz",
										Port: intstr.FromInt(8081),
									},
								},
								InitialDelaySeconds: 15,
								PeriodSeconds:       20,
							},
							ReadinessProbe: &corev1.Probe{
								ProbeHandler: corev1.ProbeHandler{
									HTTPGet: &corev1.HTTPGetAction{
										Path: "/readyz",
										Port: intstr.FromInt(8081),
									},
								},
								InitialDelaySeconds: 5,
								PeriodSeconds:       10,
							},
							Resources: func() corev1.ResourceRequirements {
								var resourcesCfg *automotivev1alpha1.BuildAPIResourcesConfig
								if config.Spec.BuildAPI != nil {
									resourcesCfg = config.Spec.BuildAPI.Resources
								}
								return resourcesCfg.GetBuildControllerResources()
							}(),
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: ptr.To(false),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildControllerServiceAccount(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildControllerName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-controller",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildControllerClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: buildControllerName,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-controller",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Rules: []rbacv1.PolicyRule{
			// ImageBuild controller RBAC
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"imagebuilds"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"imagebuilds/status"},
				Verbs:     []string{"get", "update", "patch"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"imagebuilds/finalizers"},
				Verbs:     []string{"update"},
			},
			// Image controller RBAC
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"images"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"images/status"},
				Verbs:     []string{"get", "update", "patch"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"images/finalizers"},
				Verbs:     []string{"update"},
			},
			// CatalogImage controller RBAC
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"catalogimages"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"catalogimages/status"},
				Verbs:     []string{"get", "update", "patch"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"catalogimages/finalizers"},
				Verbs:     []string{"update"},
			},
			// Workspace controller RBAC
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"workspaces"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"workspaces/status"},
				Verbs:     []string{"get", "update", "patch"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"workspaces/finalizers"},
				Verbs:     []string{"update"},
			},
			// Read-only access to OperatorConfig (for build config)
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"operatorconfigs"},
				Verbs:     []string{"get", "list", "watch"},
			},
			// Core resources needed by ImageBuild controller
			{
				APIGroups: []string{""},
				Resources: []string{"namespaces"},
				Verbs:     []string{"get", "list", "watch", "create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"persistentvolumeclaims"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"secrets"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"serviceaccounts/token"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/exec"},
				Verbs:     []string{"create"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"pods/log"},
				Verbs:     []string{"get"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"services"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
			// OpenShift-specific
			{
				APIGroups: []string{"image.openshift.io"},
				Resources: []string{"imagestreams"},
				Verbs:     []string{"get", "create"},
			},
			{
				APIGroups: []string{"route.openshift.io"},
				Resources: []string{"routes"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			// Tekton resources
			{
				APIGroups: []string{"tekton.dev"},
				Resources: []string{"tasks", "pipelines", "pipelineruns", "taskruns"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			// ContainerBuild controller RBAC
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"containerbuilds"},
				Verbs:     []string{"get", "list", "watch"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"containerbuilds/status"},
				Verbs:     []string{"get", "update", "patch"},
			},
			{
				APIGroups: []string{"automotive.sdv.cloud.redhat.com"},
				Resources: []string{"containerbuilds/finalizers"},
				Verbs:     []string{"update"},
			},
			// Shipwright resources (used by ContainerBuild controller)
			{
				APIGroups: []string{"shipwright.io"},
				Resources: []string{"builds", "buildruns"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildControllerClusterRoleBinding(namespace string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: buildControllerName,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-controller",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     buildControllerName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      buildControllerName,
				Namespace: namespace,
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildControllerLeaderElectionRole(namespace string) *rbacv1.Role {
	return &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildControllerName + "-leader-election",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-controller",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{"coordination.k8s.io"},
				Resources: []string{"leases"},
				Verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			},
			{
				APIGroups: []string{""},
				Resources: []string{"events"},
				Verbs:     []string{"create", "patch"},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildControllerLeaderElectionRoleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      buildControllerName + "-leader-election",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-controller",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "Role",
			Name:     buildControllerName + "-leader-election",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      buildControllerName,
				Namespace: namespace,
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildWorkspaceServiceAccount(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      workspaceServiceAccountName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "workspace",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildWorkspaceSCCClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: workspaceServiceAccountName + "-privileged",
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "workspace",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				ResourceNames: []string{workspaceSCCName},
				Verbs:         []string{"use"},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildWorkspaceSCCRoleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      workspaceServiceAccountName + "-privileged",
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "workspace",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     workspaceServiceAccountName + "-privileged",
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      workspaceServiceAccountName,
				Namespace: namespace,
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildServiceAccount(namespace string) *corev1.ServiceAccount {
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      automotivev1alpha1.BuildServiceAccountName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildSCCClusterRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: sccPrivilegedRoleName,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{"security.openshift.io"},
				Resources:     []string{"securitycontextconstraints"},
				ResourceNames: []string{"privileged", "pipelines-scc"},
				Verbs:         []string{"use"},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildSCCRoleBinding(namespace string) *rbacv1.RoleBinding {
	return &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      pipelineSCCBindingName,
			Namespace: namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     sccPrivilegedRoleName,
		},
		Subjects: []rbacv1.Subject{
			{
				Kind:      "ServiceAccount",
				Name:      automotivev1alpha1.BuildServiceAccountName,
				Namespace: namespace,
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildWorkspaceSCC() *securityv1.SecurityContextConstraints {
	return &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{
			Name: workspaceSCCName,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "workspace",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		AllowHostDirVolumePlugin: false,
		AllowHostIPC:             false,
		AllowHostNetwork:         false,
		AllowHostPID:             false,
		AllowHostPorts:           false,
		AllowPrivilegeEscalation: ptr.To(true),
		AllowPrivilegedContainer: false,
		AllowedCapabilities:      []corev1.Capability{"SETUID", "SETGID", "SYS_ADMIN", "DAC_OVERRIDE", "CHOWN", "FOWNER"},
		FSGroup: securityv1.FSGroupStrategyOptions{
			Type:   securityv1.FSGroupStrategyMustRunAs,
			Ranges: []securityv1.IDRange{{Min: 0, Max: 65534}},
		},
		RunAsUser: securityv1.RunAsUserStrategyOptions{
			Type: securityv1.RunAsUserStrategyRunAsAny,
		},
		SELinuxContext: securityv1.SELinuxContextStrategyOptions{
			Type: securityv1.SELinuxStrategyMustRunAs,
			SELinuxOptions: &corev1.SELinuxOptions{
				Type: "container_engine_t",
			},
		},
		SeccompProfiles: []string{"*"},
		SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
			Type:   securityv1.SupplementalGroupsStrategyMustRunAs,
			Ranges: []securityv1.IDRange{{Min: 0, Max: 65534}},
		},
		UserNamespaceLevel: securityv1.NamespaceLevelRequirePod,
		Volumes: []securityv1.FSType{
			securityv1.FSTypeConfigMap,
			securityv1.FSTypeCSI,
			securityv1.FSTypeDownwardAPI,
			securityv1.FSTypeEmptyDir,
			securityv1.FSTypeEphemeral,
			securityv1.FSProjected,
			securityv1.FSTypePersistentVolumeClaim,
			securityv1.FSTypeSecret,
		},
	}
}

// buildWorkspaceSCCPrivileged creates a privileged SCC for clusters that don't
// support user namespaces (OCP < 4.19). This allows nested podman/buildah.
func (r *OperatorConfigReconciler) buildWorkspaceSCCPrivileged() *securityv1.SecurityContextConstraints {
	return &securityv1.SecurityContextConstraints{
		ObjectMeta: metav1.ObjectMeta{
			Name: workspaceSCCName,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "workspace",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		AllowHostDirVolumePlugin: false,
		AllowHostIPC:             false,
		AllowHostNetwork:         false,
		AllowHostPID:             false,
		AllowHostPorts:           false,
		AllowPrivilegeEscalation: ptr.To(true),
		AllowPrivilegedContainer: true,
		AllowedCapabilities:      []corev1.Capability{"*"},
		FSGroup: securityv1.FSGroupStrategyOptions{
			Type: securityv1.FSGroupStrategyRunAsAny,
		},
		RunAsUser: securityv1.RunAsUserStrategyOptions{
			Type: securityv1.RunAsUserStrategyRunAsAny,
		},
		SELinuxContext: securityv1.SELinuxContextStrategyOptions{
			Type: securityv1.SELinuxStrategyMustRunAs,
			SELinuxOptions: &corev1.SELinuxOptions{
				Type: "container_engine_t",
			},
		},
		SeccompProfiles: []string{"*"},
		SupplementalGroups: securityv1.SupplementalGroupsStrategyOptions{
			Type: securityv1.SupplementalGroupsStrategyRunAsAny,
		},
		Volumes: []securityv1.FSType{
			securityv1.FSTypeAll,
		},
	}
}
