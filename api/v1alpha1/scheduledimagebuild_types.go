/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ConcurrencyPolicy describes how the schedule treats overlapping builds.
// +kubebuilder:validation:Enum=Allow;Forbid;Replace
type ConcurrencyPolicy string

// ConcurrencyPolicy values.
const (
	AllowConcurrent   ConcurrencyPolicy = "Allow"
	ForbidConcurrent  ConcurrencyPolicy = "Forbid"
	ReplaceConcurrent ConcurrencyPolicy = "Replace"
)

// ScheduledImageBuildSpec defines the desired state of ScheduledImageBuild
// +kubebuilder:validation:XValidation:rule="!has(self.matrix) || !has(self.matrix.distros) || size(self.matrix.distros) == 0 || has(self.imageBuildTemplate.spec.aib)",message="matrix distros requires aib in imageBuildTemplate"
// +kubebuilder:validation:XValidation:rule="!has(self.matrix) || !has(self.matrix.targets) || size(self.matrix.targets) == 0 || has(self.imageBuildTemplate.spec.aib)",message="matrix targets requires aib in imageBuildTemplate"
type ScheduledImageBuildSpec struct {
	// Schedule is a cron expression defining when builds should run (5-field standard format).
	// Examples: "0 2 * * *" (daily at 2am), "0 */6 * * *" (every 6 hours)
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=9
	// +kubebuilder:validation:Pattern=`^([-0-9*/,]+\s+){4}[-0-9*/,]+$`
	Schedule string `json:"schedule"`

	// Suspend tells the controller to suspend subsequent executions.
	// Existing running builds will not be affected.
	// +optional
	Suspend *bool `json:"suspend,omitempty"`

	// ConcurrencyPolicy specifies how to treat concurrent builds.
	// +kubebuilder:default=Forbid
	// +optional
	ConcurrencyPolicy ConcurrencyPolicy `json:"concurrencyPolicy,omitempty"`

	// StartingDeadlineSeconds is the deadline in seconds for starting a build
	// if it misses its scheduled time. Missed builds beyond this window are skipped.
	// +kubebuilder:validation:Minimum=0
	// +optional
	StartingDeadlineSeconds *int64 `json:"startingDeadlineSeconds,omitempty"`

	// SuccessfulBuildsHistoryLimit is the number of successful finished builds to retain.
	// +kubebuilder:default=3
	// +kubebuilder:validation:Minimum=0
	// +optional
	SuccessfulBuildsHistoryLimit *int32 `json:"successfulBuildsHistoryLimit,omitempty"`

	// FailedBuildsHistoryLimit is the number of failed finished builds to retain.
	// +kubebuilder:default=1
	// +kubebuilder:validation:Minimum=0
	// +optional
	FailedBuildsHistoryLimit *int32 `json:"failedBuildsHistoryLimit,omitempty"`

	// ImageBuildTemplate is the template for creating ImageBuild CRs.
	// +kubebuilder:validation:Required
	ImageBuildTemplate ImageBuildTemplateSpec `json:"imageBuildTemplate"`

	// Matrix defines a build matrix that creates multiple ImageBuilds per schedule tick.
	// Each tick creates one ImageBuild for each combination of the specified dimensions,
	// overriding the corresponding fields in the imageBuildTemplate.
	// +optional
	Matrix *BuildMatrix `json:"matrix,omitempty"`

	// PublishToCatalog configures automatic publishing of completed builds to the catalog.
	// +optional
	PublishToCatalog *PublishToCatalogSpec `json:"publishToCatalog,omitempty"`
}

// ImageBuildTemplateSpec describes the ImageBuild that will be created on each schedule tick.
type ImageBuildTemplateSpec struct {
	// Metadata contains labels and annotations to apply to created ImageBuilds.
	// +optional
	Metadata ScheduledBuildMetadata `json:"metadata,omitempty"`

	// Spec is the ImageBuildSpec used as the template for child ImageBuilds.
	// +kubebuilder:validation:Required
	Spec ImageBuildSpec `json:"spec"`
}

// ScheduledBuildMetadata contains metadata to apply to child ImageBuilds.
type ScheduledBuildMetadata struct {
	// Labels to set on created ImageBuilds.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`

	// Annotations to set on created ImageBuilds.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// BuildMatrix defines multiple configurations to build on each schedule tick.
// Each dimension list overrides the corresponding scalar field in the template spec.
// The cross-product of all dimensions determines how many ImageBuilds are created per tick.
type BuildMatrix struct {
	// Architectures lists target architectures to build for.
	// Each value overrides imageBuildTemplate.spec.architecture.
	// +optional
	// +kubebuilder:validation:MaxItems=4
	Architectures []string `json:"architectures,omitempty"`

	// Distros lists distributions to build for.
	// Each value overrides imageBuildTemplate.spec.aib.distro.
	// +optional
	// +kubebuilder:validation:MaxItems=4
	Distros []string `json:"distros,omitempty"`

	// Targets lists hardware targets to build for.
	// Each value overrides imageBuildTemplate.spec.aib.target.
	// +optional
	// +kubebuilder:validation:MaxItems=4
	Targets []string `json:"targets,omitempty"`
}

// PublishToCatalogSpec configures automatic catalog publishing for completed builds.
type PublishToCatalogSpec struct {
	// Enabled controls whether completed builds are automatically published to the catalog.
	Enabled bool `json:"enabled"`

	// Tags are category tags to apply to the CatalogImage.
	// +optional
	Tags []string `json:"tags,omitempty"`

	// AuthSecretRef references a secret containing registry credentials
	// for verifying the published image.
	// +optional
	AuthSecretRef *AuthSecretReference `json:"authSecretRef,omitempty"`
}

// ScheduledImageBuildPhase represents the current state of the schedule.
// +kubebuilder:validation:Enum=Active;Suspended
type ScheduledImageBuildPhase string

// ScheduledImageBuildPhase values.
const (
	ScheduledImageBuildPhaseActive    ScheduledImageBuildPhase = "Active"
	ScheduledImageBuildPhaseSuspended ScheduledImageBuildPhase = "Suspended"
)

// ScheduledImageBuildStatus defines the observed state of ScheduledImageBuild
type ScheduledImageBuildStatus struct {
	// ObservedGeneration is the most recent generation observed by the controller.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Phase represents the current state of the schedule.
	// +optional
	Phase ScheduledImageBuildPhase `json:"phase,omitempty"`

	// LastScheduleTime is when the last build was created.
	// +optional
	LastScheduleTime *metav1.Time `json:"lastScheduleTime,omitempty"`

	// LastSuccessfulTime is when the last build completed successfully.
	// +optional
	LastSuccessfulTime *metav1.Time `json:"lastSuccessfulTime,omitempty"`

	// LastFailedTime is when the last build failed.
	// +optional
	LastFailedTime *metav1.Time `json:"lastFailedTime,omitempty"`

	// Active is a list of currently running ImageBuild references.
	// +optional
	Active []corev1.ObjectReference `json:"active,omitempty"`

	// Conditions represent the latest available observations.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Schedule",type=string,JSONPath=`.spec.schedule`,priority=0
// +kubebuilder:printcolumn:name="Suspend",type=boolean,JSONPath=`.spec.suspend`,priority=0
// +kubebuilder:printcolumn:name="Last Schedule",type=date,JSONPath=`.status.lastScheduleTime`,priority=0
// +kubebuilder:printcolumn:name="Last Success",type=date,JSONPath=`.status.lastSuccessfulTime`,priority=0
// +kubebuilder:printcolumn:name="Last Failure",type=date,JSONPath=`.status.lastFailedTime`,priority=0
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`,priority=0

// ScheduledImageBuild defines a cron schedule for creating ImageBuild CRs
// with optional automatic publishing to the catalog.
type ScheduledImageBuild struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ScheduledImageBuildSpec   `json:"spec,omitempty"`
	Status ScheduledImageBuildStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ScheduledImageBuildList contains a list of ScheduledImageBuild
type ScheduledImageBuildList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ScheduledImageBuild `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ScheduledImageBuild{}, &ScheduledImageBuildList{})
}
