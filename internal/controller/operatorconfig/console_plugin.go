package operatorconfig

import (
	"context"
	"fmt"
	"os"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

const (
	consolePluginName        = "automotive-dev-console-plugin"
	consolePluginServiceName = "automotive-dev-console-plugin"
	consolePluginPort        = 9443
)

var consolePluginGVK = schema.GroupVersionKind{
	Group:   "console.openshift.io",
	Version: "v1",
	Kind:    "ConsolePlugin",
}

// getConsolePluginImage returns the console plugin image from config, env var, or default
func getConsolePluginImage(config *automotivev1alpha1.OperatorConfig) string {
	// Check config first
	if config.Spec.ConsolePlugin != nil && config.Spec.ConsolePlugin.Image != "" {
		return config.Spec.ConsolePlugin.Image
	}
	// Check environment variable (set by CSV)
	envImage := os.Getenv("CONSOLE_PLUGIN_IMAGE")
	if envImage != "" {
		return envImage
	}
	// Use internal registry as default for cluster deployments
	return "image-registry.openshift-image-registry.svc:5000/automotive-dev-operator-system/automotive-dev-console-plugin:latest"
}

func (r *OperatorConfigReconciler) deployConsolePlugin(ctx context.Context, config *automotivev1alpha1.OperatorConfig) error {
	r.Log.Info("Starting ConsolePlugin deployment")

	// Create/update nginx ConfigMap
	r.Log.Info("Creating/updating console plugin nginx configmap")
	configMap := r.buildConsolePluginNginxConfigMap()
	if err := r.createOrUpdate(ctx, configMap, config); err != nil {
		r.Log.Error(err, "Failed to create/update console plugin nginx configmap")
		return fmt.Errorf("failed to create/update console plugin nginx configmap: %w", err)
	}
	r.Log.Info("Console plugin nginx configmap created/updated successfully")

	// Create/update deployment
	r.Log.Info("Creating/updating console plugin deployment")
	deployment := r.buildConsolePluginDeployment(config)
	if err := r.createOrUpdate(ctx, deployment, config); err != nil {
		r.Log.Error(err, "Failed to create/update console plugin deployment")
		return fmt.Errorf("failed to create/update console plugin deployment: %w", err)
	}
	r.Log.Info("Console plugin deployment created/updated successfully")

	// Create/update service
	r.Log.Info("Creating/updating console plugin service")
	service := r.buildConsolePluginService()
	if err := r.createOrUpdate(ctx, service, config); err != nil {
		r.Log.Error(err, "Failed to create/update console plugin service")
		return fmt.Errorf("failed to create/update console plugin service: %w", err)
	}
	r.Log.Info("Console plugin service created/updated successfully")

	// Create/update ConsolePlugin CR (using unstructured)
	r.Log.Info("Creating/updating ConsolePlugin CR")
	if err := r.ensureConsolePluginCR(ctx); err != nil {
		r.Log.Error(err, "Failed to create/update ConsolePlugin CR")
		return fmt.Errorf("failed to create/update ConsolePlugin CR: %w", err)
	}
	r.Log.Info("ConsolePlugin CR created/updated successfully")

	r.Log.Info("Console plugin deployment completed successfully")
	return nil
}

func (r *OperatorConfigReconciler) cleanupConsolePlugin(ctx context.Context) error {
	r.Log.Info("Cleaning up console plugin resources")

	// Delete ConsolePlugin CR (cluster-scoped)
	consolePlugin := &unstructured.Unstructured{}
	consolePlugin.SetGroupVersionKind(consolePluginGVK)
	consolePlugin.SetName(consolePluginName)
	if err := r.Delete(ctx, consolePlugin); err != nil && !errors.IsNotFound(err) {
		// Ignore "no matches for kind" errors (CRD doesn't exist) and forbidden errors
		// (RBAC not set up yet or resource never created)
		if !isConsolePluginCRDMissing(err) && !errors.IsForbidden(err) {
			return fmt.Errorf("failed to delete ConsolePlugin CR: %w", err)
		}
		if isConsolePluginCRDMissing(err) {
			r.Log.Info("ConsolePlugin CRD not available, skipping CR deletion")
		} else if errors.IsForbidden(err) {
			r.Log.Info("ConsolePlugin deletion forbidden (RBAC not configured or resource doesn't exist), skipping")
		}
	} else {
		r.Log.Info("ConsolePlugin CR deleted")
	}

	// Delete deployment
	deployment := &appsv1.Deployment{}
	deployment.Name = consolePluginName
	deployment.Namespace = operatorNamespace
	if err := r.Delete(ctx, deployment); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete console plugin deployment: %w", err)
	}
	r.Log.Info("Console plugin deployment deleted")

	// Delete service
	service := &corev1.Service{}
	service.Name = consolePluginServiceName
	service.Namespace = operatorNamespace
	if err := r.Delete(ctx, service); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete console plugin service: %w", err)
	}
	r.Log.Info("Console plugin service deleted")

	// Delete nginx configmap
	configMap := &corev1.ConfigMap{}
	configMap.Name = consolePluginName
	configMap.Namespace = operatorNamespace
	if err := r.Delete(ctx, configMap); err != nil && !errors.IsNotFound(err) {
		return fmt.Errorf("failed to delete console plugin nginx configmap: %w", err)
	}
	r.Log.Info("Console plugin nginx configmap deleted")

	r.Log.Info("Console plugin cleanup completed successfully")
	return nil
}

func isConsolePluginCRDMissing(err error) bool {
	if err == nil {
		return false
	}
	errMsg := err.Error()
	return errMsg == "no matches for kind \"ConsolePlugin\" in version \"console.openshift.io/v1\""
}

func (r *OperatorConfigReconciler) buildConsolePluginDeployment(config *automotivev1alpha1.OperatorConfig) *appsv1.Deployment {
	replicas := int32(1)
	labels := map[string]string{
		"app.kubernetes.io/name":      consolePluginName,
		"app.kubernetes.io/part-of":   "automotive-dev-operator",
		"app.kubernetes.io/component": "console-plugin",
	}

	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      consolePluginName,
			Namespace: operatorNamespace,
			Labels:    labels,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app.kubernetes.io/name":    consolePluginName,
					"app.kubernetes.io/part-of": "automotive-dev-operator",
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
							Name:            "console-plugin",
							Image:           getConsolePluginImage(config),
							ImagePullPolicy: corev1.PullIfNotPresent,
							Ports: []corev1.ContainerPort{
								{
									ContainerPort: consolePluginPort,
									Protocol:      corev1.ProtocolTCP,
								},
							},
							SecurityContext: &corev1.SecurityContext{
								AllowPrivilegeEscalation: boolPtr(false),
								Capabilities: &corev1.Capabilities{
									Drop: []corev1.Capability{"ALL"},
								},
								RunAsNonRoot: boolPtr(true),
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "plugin-serving-cert",
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
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "plugin-serving-cert",
							VolumeSource: corev1.VolumeSource{
								Secret: &corev1.SecretVolumeSource{
									SecretName:  consolePluginName + "-cert",
									DefaultMode: int32Ptr(420),
								},
							},
						},
						{
							Name: "nginx-conf",
							VolumeSource: corev1.VolumeSource{
								ConfigMap: &corev1.ConfigMapVolumeSource{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: consolePluginName,
									},
									DefaultMode: int32Ptr(420),
								},
							},
						},
					},
				},
			},
		},
	}
}

func (r *OperatorConfigReconciler) buildConsolePluginService() *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      consolePluginServiceName,
			Namespace: operatorNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      consolePluginName,
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
				"app.kubernetes.io/component": "console-plugin",
			},
			Annotations: map[string]string{
				"service.beta.openshift.io/serving-cert-secret-name": consolePluginName + "-cert",
			},
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app.kubernetes.io/name":    consolePluginName,
				"app.kubernetes.io/part-of": "automotive-dev-operator",
			},
			Ports: []corev1.ServicePort{
				{
					Name:       "https",
					Port:       consolePluginPort,
					Protocol:   corev1.ProtocolTCP,
					TargetPort: intstr.FromInt(consolePluginPort),
				},
			},
		},
	}
}

func (r *OperatorConfigReconciler) ensureConsolePluginCR(ctx context.Context) error {
	consolePlugin := &unstructured.Unstructured{}
	consolePlugin.SetGroupVersionKind(consolePluginGVK)
	consolePlugin.SetName(consolePluginName)

	// Check if it exists
	existing := &unstructured.Unstructured{}
	existing.SetGroupVersionKind(consolePluginGVK)
	err := r.Get(ctx, client.ObjectKey{Name: consolePluginName}, existing)

	if err != nil {
		if errors.IsNotFound(err) {
			// Create new ConsolePlugin
			return r.createConsolePluginCR(ctx)
		}
		if isConsolePluginCRDMissing(err) {
			r.Log.Info("ConsolePlugin CRD not available (not running on OpenShift?), skipping CR creation")
			return nil
		}
		return err
	}

	// Update existing - set resource version and update
	consolePlugin.SetResourceVersion(existing.GetResourceVersion())
	r.setConsolePluginSpec(consolePlugin)
	return r.Update(ctx, consolePlugin)
}

func (r *OperatorConfigReconciler) createConsolePluginCR(ctx context.Context) error {
	consolePlugin := &unstructured.Unstructured{}
	consolePlugin.SetGroupVersionKind(consolePluginGVK)
	consolePlugin.SetName(consolePluginName)
	r.setConsolePluginSpec(consolePlugin)

	return r.Create(ctx, consolePlugin)
}

func (r *OperatorConfigReconciler) setConsolePluginSpec(consolePlugin *unstructured.Unstructured) {
	// Set spec following the ConsolePlugin schema
	spec := map[string]interface{}{
		"displayName": "Automotive",
		"backend": map[string]interface{}{
			"type": "Service",
			"service": map[string]interface{}{
				"name":      consolePluginServiceName,
				"namespace": operatorNamespace,
				"port":      int64(consolePluginPort),
				"basePath":  "/",
			},
		},
		"proxy": []interface{}{
			map[string]interface{}{
				"alias": "build-api",
				"endpoint": map[string]interface{}{
					"type": "Service",
					"service": map[string]interface{}{
						"name":      "ado-build-api",
						"namespace": operatorNamespace,
						"port":      int64(8443),
					},
				},
				"authorization": "UserToken",
			},
		},
	}

	consolePlugin.Object["spec"] = spec
}

func (r *OperatorConfigReconciler) buildConsolePluginNginxConfigMap() *corev1.ConfigMap {
	// nginx.conf for serving the console plugin
	nginxConf := `error_log /dev/stdout info;
events {
    worker_connections 1024;
}
http {
    access_log /dev/stdout;
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    keepalive_timeout 65;
    server {
        listen 9443 ssl;
        ssl_certificate /var/serving-cert/tls.crt;
        ssl_certificate_key /var/serving-cert/tls.key;
        root /usr/share/nginx/html;
        location / {
            add_header Cache-Control "no-cache, no-store, must-revalidate";
            add_header Pragma "no-cache";
            add_header Expires "0";
        }
        location /locales/ {
            add_header Cache-Control "no-cache, no-store, must-revalidate";
        }
        location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
            add_header Cache-Control "public, max-age=31536000, immutable";
            expires 1y;
        }
    }
}`

	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      consolePluginName,
			Namespace: operatorNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      consolePluginName,
				"app.kubernetes.io/part-of":   "automotive-dev-operator",
				"app.kubernetes.io/component": "console-plugin",
			},
		},
		Data: map[string]string{
			"nginx.conf": nginxConf,
		},
	}
}
