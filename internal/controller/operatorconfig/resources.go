package operatorconfig

import (
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
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

func (r *OperatorConfigReconciler) buildBuildAPIDeployment() *appsv1.Deployment {
	labels := map[string]string{
		"app.kubernetes.io/name":      "automotive-dev-operator",
		"app.kubernetes.io/component": "build-api",
		"app.kubernetes.io/part-of":   "automotive-dev-operator",
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api",
			Namespace: operatorNamespace,
			Labels:    labels,
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
					Labels: labels,
				},
				Spec: corev1.PodSpec{
					ServiceAccountName: "ado-controller-manager",
					Containers: []corev1.Container{
						{
							Name:            "build-api",
							Image:           getOperatorImage(),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"/build-api"},
							Ports: []corev1.ContainerPort{
								{
									Name:          "http",
									ContainerPort: 8080,
									Protocol:      corev1.ProtocolTCP,
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
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: boolPtr(false),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								RunAsNonRoot: boolPtr(true),
							},
						},
						{
							Name:  "https-proxy",
							Image: "registry.access.redhat.com/ubi9/nginx-120:latest",
							Ports: []corev1.ContainerPort{
								{
									Name:          "https",
									ContainerPort: 8443,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "serving-cert",
									MountPath: "/var/serving-cert",
									ReadOnly:  true,
								},
								{
									Name:      "nginx-conf",
									MountPath: "/etc/nginx/nginx.conf",
									SubPath:   "nginx.conf",
									ReadOnly:  true,
								},
							},
							Resources: corev1.ResourceRequirements{
								Requests: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("25m"),
									corev1.ResourceMemory: resource.MustParse("32Mi"),
								},
								Limits: corev1.ResourceList{
									corev1.ResourceCPU:    resource.MustParse("100m"),
									corev1.ResourceMemory: resource.MustParse("128Mi"),
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: boolPtr(false),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								RunAsNonRoot: boolPtr(true),
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "serving-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName: "ado-build-api-cert",
								},
							},
						},
						{
							Name: "nginx-conf",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "ado-build-api-nginx-config",
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

func (r *OperatorConfigReconciler) buildBuildAPIService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api",
			Namespace: operatorNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
			Annotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": "ado-build-api-cert",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       8080,
					TargetPort: intstr.FromInt(8080),
					Protocol:   corev1.ProtocolTCP,
				},
				{
					Name:       "https",
					Port:       8443,
					TargetPort: intstr.FromInt(8443),
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildBuildAPINginxConfigMap() *corev1.ConfigMap {
	nginxConf := `error_log /dev/stdout info;
events {
    worker_connections 1024;
}
http {
    access_log /dev/stdout;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    keepalive_timeout 65;

    upstream build_api {
        server localhost:8080;
    }

    server {
        listen 8443 ssl;
        ssl_certificate /var/serving-cert/tls.crt;
        ssl_certificate_key /var/serving-cert/tls.key;

        location / {
            proxy_pass http://build_api;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;

            # Forward auth headers
            proxy_set_header Authorization $http_authorization;
            proxy_set_header X-Forwarded-Access-Token $http_x_forwarded_access_token;

            # Handle WebSocket connections for logs
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
`

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ado-build-api-nginx-config",
			Namespace: operatorNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "automotive-dev-operator",
				"app.kubernetes.io/component": "build-api",
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
			},
		},
		Data: map[string]string{
			"nginx.conf": nginxConf,
		},
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func int32Ptr(i int32) *int32 {
	return &i
}
