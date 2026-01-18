package operatorconfig

import (
	"crypto/rand"
	"encoding/base64"
	"os"

	routev1 "github.com/openshift/api/route/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	defaultOperatorImage = "quay.io/rh-sdv-cloud/automotive-dev-operator:latest"
)

// getOperatorImage returns the operator image from env var or default
func getOperatorImage() string {
	if img := os.Getenv("OPERATOR_IMAGE"); img != "" {
		return img
	}
	return defaultOperatorImage
}

// buildBuildAPIContainers builds the container list for build-API deployment, conditionally including oauth-proxy
func (r *OperatorConfigReconciler) buildBuildAPIContainers(isOpenShift bool) []corev1.Container {
	containers := []corev1.Container{
		{
			Name:            "build-api",
			Image:           getOperatorImage(),
			ImagePullPolicy: corev1.PullIfNotPresent,
			Command:         []string{"/build-api"},
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("50m"),
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("200m"),
					corev1.ResourceMemory: resource.MustParse("512Mi"),
				},
			},
			Env: []corev1.EnvVar{
				{
					Name: "BUILD_API_NAMESPACE",
					ValueFrom: &corev1.EnvVarSource{
						FieldRef: &corev1.ObjectFieldSelector{
							FieldPath: "metadata.namespace",
						},
					},
				},
			},
			Ports: []corev1.ContainerPort{
				{
					Name:          "http",
					ContainerPort: 8080,
					Protocol:      corev1.ProtocolTCP,
				},
			},
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: boolPtr(false),
			},
		},
	}

	// Only add oauth-proxy on OpenShift
	if isOpenShift {
		containers = append(containers, corev1.Container{
			Name:            "oauth-proxy",
			Image:           "registry.redhat.io/openshift4/ose-oauth-proxy:latest",
			ImagePullPolicy: corev1.PullIfNotPresent,
			Args: []string{
				"--provider=openshift",
				"--https-address=",
				"--http-address=:8081",
				"--upstream=http://localhost:8080",
				"--openshift-service-account=ado-controller-manager",
				"--cookie-secret=$(COOKIE_SECRET)",
				"--cookie-secure=false",
				"--pass-access-token=true",
				"--pass-user-headers=true",
				"--request-logging=true",
				"--skip-auth-regex=^/healthz",
				"--skip-auth-regex=^/v1/",
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
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("10m"),
					corev1.ResourceMemory: resource.MustParse("32Mi"),
				},
				Limits: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("100m"),
					corev1.ResourceMemory: resource.MustParse("128Mi"),
				},
			},
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: boolPtr(false),
			},
		})
	}

	return containers
}

func (r *OperatorConfigReconciler) buildBuildAPIDeployment(isOpenShift bool) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api",
			Namespace: operatorNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: int32Ptr(1),
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
					ServiceAccountName: "ado-controller-manager",
					InitContainers: []corev1.Container{
						{
							Name:            "init-secrets",
							Image:           getOperatorImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"/init-secrets"},
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
								AllowPrivilegeEscalation: boolPtr(false),
							},
						},
					},
					Containers: r.buildBuildAPIContainers(isOpenShift),
				},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildAPIService(isOpenShift bool) *corev1.Service {
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
			Namespace: operatorNamespace,
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

func (r *OperatorConfigReconciler) buildBuildAPIRoute() *routev1.Route {
	return &routev1.Route{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api",
			Namespace: operatorNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Spec: routev1.RouteSpec{
			To: routev1.RouteTargetReference{
				Kind: "Service",
				Name: "ado-build-api",
			},
			Port: &routev1.RoutePort{
				TargetPort: intstr.FromString("proxy"),
			},
			TLS: &routev1.TLSConfig{
				Termination:                   routev1.TLSTerminationEdge,
				InsecureEdgeTerminationPolicy: routev1.InsecureEdgeTerminationPolicyRedirect,
			},
			WildcardPolicy: routev1.WildcardPolicyNone,
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildAPIIngress() *networkingv1.Ingress {
	pathTypePrefix := networkingv1.PathTypePrefix
	ingressClassName := "nginx"

	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api",
			Namespace: operatorNamespace,
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

func (r *OperatorConfigReconciler) buildOAuthSecret(name string) *corev1.Secret {
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
			Namespace: operatorNamespace,
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

func boolPtr(b bool) *bool {
	return &b
}

func int32Ptr(i int32) *int32 {
	return &i
}

func int64Ptr(i int64) *int64 {
	return &i
}
