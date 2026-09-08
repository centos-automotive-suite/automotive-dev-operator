package v1alpha1

// OutboundPolicyConfig allows administrators to grant access to intentional internal destinations.
type OutboundPolicyConfig struct {
	// AllowedHostnames are exact hostnames, not URL prefixes or wildcard patterns.
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MaxLength=253
	// +kubebuilder:validation:items:Pattern=`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*\.?$`
	// +optional
	AllowedHostnames []string `json:"allowedHostnames,omitempty"`
	// +kubebuilder:validation:MaxItems=128
	// +kubebuilder:validation:items:MaxLength=64
	// +kubebuilder:validation:items:Format=cidr
	// +optional
	AllowedCIDRs []string `json:"allowedCIDRs,omitempty"`
	// TrustedCAConfigMap names a same-namespace ConfigMap containing ca-bundle.crt.
	// +kubebuilder:validation:MaxLength=253
	// +optional
	TrustedCAConfigMap string `json:"trustedCAConfigMap,omitempty"`
}

// WebhookNotificationsConfig configures outbound terminal event delivery.
type WebhookNotificationsConfig struct {
	// +optional
	OutboundPolicy *OutboundPolicyConfig `json:"outboundPolicy,omitempty"`
	// AllowHTTP is only intended for development receivers.
	// +optional
	AllowHTTP bool `json:"allowHTTP,omitempty"`
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=120
	// +optional
	TimeoutSeconds int32 `json:"timeoutSeconds,omitempty"`
	// +kubebuilder:default=8
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=1000
	// +optional
	MaxAttempts int32 `json:"maxAttempts,omitempty"`
	// +kubebuilder:default=86400
	// +kubebuilder:validation:Minimum=60
	// +kubebuilder:validation:Maximum=604800
	// +optional
	DeliveryWindowSeconds int32 `json:"deliveryWindowSeconds,omitempty"`
}
