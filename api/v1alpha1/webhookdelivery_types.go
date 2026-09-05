package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// DeliverySubject identifies an operation in the delivery's own namespace by UID.
// +kubebuilder:validation:XValidation:rule="(self.kind == 'ImageBuild' && self.apiVersion == 'automotive.sdv.cloud.redhat.com/v1alpha1') || (self.kind == 'TaskRun' && self.apiVersion == 'tekton.dev/v1')",message="subject must be an ImageBuild or a Tekton v1 TaskRun"
type DeliverySubject struct {
	// +kubebuilder:validation:Enum=automotive.sdv.cloud.redhat.com/v1alpha1;tekton.dev/v1
	APIVersion string `json:"apiVersion"`
	// +kubebuilder:validation:Enum=ImageBuild;TaskRun
	Kind string `json:"kind"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Type=string
	UID types.UID `json:"uid"`
}

// WebhookDeliverySpec contains internal references only; endpoint and key belong in the Secret.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="delivery intent is immutable"
type WebhookDeliverySpec struct {
	Subject DeliverySubject `json:"subject"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	CallbackSecretRef string `json:"callbackSecretRef"`
}

// WebhookEventSnapshot freezes the exact JSON bytes that are signed on every attempt.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="event snapshot is immutable"
type WebhookEventSnapshot struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	ID string `json:"id"`
	// +kubebuilder:validation:Enum=build.terminal;flash.terminal
	Type string      `json:"type"`
	Time metav1.Time `json:"time"`
	// Body is base64-encoded in Kubernetes JSON, preserving exact payload bytes.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=349528
	Body []byte `json:"body"`
}

// WebhookDeliveryStatus stores a bounded snapshot and the latest attempt, not an unbounded history.
// +kubebuilder:validation:XValidation:rule="!has(oldSelf.snapshot) || has(self.snapshot)",message="event snapshot cannot be removed"
type WebhookDeliveryStatus struct {
	NotificationStatus `json:",inline"`
	// +optional
	Snapshot *WebhookEventSnapshot `json:"snapshot,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced

// WebhookDelivery is internal durable notification state, not a public trigger API.
type WebhookDelivery struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              WebhookDeliverySpec `json:"spec"`
	// +optional
	Status WebhookDeliveryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// WebhookDeliveryList contains WebhookDelivery objects.
type WebhookDeliveryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []WebhookDelivery `json:"items"`
}

func init() { SchemeBuilder.Register(&WebhookDelivery{}, &WebhookDeliveryList{}) }
