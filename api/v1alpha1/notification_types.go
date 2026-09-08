package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ArtifactStatus describes an output actually published by a build stage.
type ArtifactStatus struct {
	// +kubebuilder:validation:Enum=container;disk;s3
	Kind string `json:"kind"`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	URL string `json:"url"`
	// Digest is the OCI digest or a checksum of uploaded bytes, never an S3 ETag.
	// +kubebuilder:validation:Pattern=`^sha256:[a-f0-9]{64}$`
	// +optional
	Digest string `json:"digest,omitempty"`
}

// FlashOutcomeStatus excludes device credentials and command configuration.
type FlashOutcomeStatus struct {
	Enabled bool `json:"enabled"`
	// +kubebuilder:validation:Enum=NotStarted;Running;Succeeded;Failed;Cancelled
	State string `json:"state"`
	// +kubebuilder:validation:MaxLength=253
	// +optional
	LeaseID string `json:"leaseId,omitempty"`
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	Message string `json:"message,omitempty"`
}

// BuildTerminalResult remains unchanged when the display phase later becomes Expired.
// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="terminal result is immutable"
type BuildTerminalResult struct {
	// +kubebuilder:validation:Enum=Completed;Failed;Cancelled
	Phase string `json:"phase"`
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message"`
	// +optional
	StartedAt   *metav1.Time `json:"startedAt,omitempty"`
	CompletedAt metav1.Time  `json:"completedAt"`
	// +kubebuilder:validation:MaxItems=64
	// +optional
	Artifacts []ArtifactStatus `json:"artifacts,omitempty"`
	// +optional
	Flash *FlashOutcomeStatus `json:"flash,omitempty"`
}

// DeliveryState describes notification delivery independently of the operation outcome.
// +kubebuilder:validation:Enum=Pending;Delivering;Delivered;Failed
type DeliveryState string

const (
	DeliveryPending    DeliveryState = "Pending"
	DeliveryDelivering DeliveryState = "Delivering"
	DeliveryDelivered  DeliveryState = "Delivered"
	DeliveryFailed     DeliveryState = "Failed"
)

// NotificationStatus is safe to return through an operation API.
type NotificationStatus struct {
	State DeliveryState `json:"state"`
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=1000
	Attempts int32 `json:"attempts"`
	// +optional
	LastAttemptTime *metav1.Time `json:"lastAttemptTime,omitempty"`
	// +optional
	NextAttemptTime *metav1.Time `json:"nextAttemptTime,omitempty"`
	// +kubebuilder:validation:Minimum=100
	// +kubebuilder:validation:Maximum=599
	// +optional
	LastHTTPStatus int32 `json:"lastHttpStatus,omitempty"`
	// LastError is a sanitized diagnostic, never a raw HTTP error or response body.
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	LastError string `json:"lastError,omitempty"`
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`
}
