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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ContainerBuildSpec defines the desired state of ContainerBuild
type ContainerBuildSpec struct {
	// Containerfile is the path to the Containerfile/Dockerfile within the build context.
	// Defaults to "Containerfile".
	// +optional
	Containerfile string `json:"containerfile,omitempty"`

	// Strategy is the Shipwright build strategy name to use (e.g. "buildah").
	// Defaults to "buildah".
	// +optional
	Strategy string `json:"strategy,omitempty"`

	// StrategyKind is the kind of the strategy: ClusterBuildStrategy or BuildStrategy.
	// Defaults to "ClusterBuildStrategy".
	// +optional
	StrategyKind string `json:"strategyKind,omitempty"`

	// Output is the target image reference to push the built image to (required).
	// For example: "quay.io/myorg/myimage:tag"
	Output string `json:"output"`

	// PushSecretRef is the name of a kubernetes.io/dockerconfigjson secret
	// for authenticating to the output registry.
	// +optional
	PushSecretRef string `json:"pushSecretRef,omitempty"`

	// Architecture is the target CPU architecture for the build.
	// +optional
	Architecture string `json:"architecture,omitempty"`

	// BuildArgs are --build-arg values passed to the container build.
	// +optional
	BuildArgs map[string]string `json:"buildArgs,omitempty"`

	// Timeout is the maximum build duration in minutes. Defaults to 30.
	// +optional
	Timeout int32 `json:"timeout,omitempty"`

	// UseServiceAccountAuth indicates the build should authenticate to the registry
	// using a service account token (e.g. for the OpenShift internal registry).
	// +optional
	UseServiceAccountAuth bool `json:"useServiceAccountAuth,omitempty"`

	// TTL is the time-to-live for this build. After this duration past its
	// completion, the build transitions to the Expired phase and its
	// BuildRun is cleaned up. The ContainerBuild CR itself is preserved.
	// In-progress builds never expire.
	// Uses Go duration format (e.g. "24h", "72h", "168h").
	// Empty uses the OperatorConfig default. Set to "0" to disable expiry.
	// +optional
	TTL string `json:"ttl,omitempty"`
}

// ContainerBuildStatus defines the observed state of ContainerBuild
type ContainerBuildStatus struct {
	// Phase is the current lifecycle phase of the container build.
	// One of: Pending, Uploading, Building, Completed, Failed, Expired.
	Phase string `json:"phase,omitempty"`

	// BuildRunName is the name of the Shipwright BuildRun created for this build.
	BuildRunName string `json:"buildRunName,omitempty"`

	// Message provides human-readable details about the current phase.
	Message string `json:"message,omitempty"`

	// StartTime is when the build started.
	// +optional
	StartTime *metav1.Time `json:"startTime,omitempty"`

	// CompletionTime is when the build finished.
	// +optional
	CompletionTime *metav1.Time `json:"completionTime,omitempty"`

	// ImageDigest is the digest of the built and pushed image.
	ImageDigest string `json:"imageDigest,omitempty"`

	// ExpiresAt is when this build will transition to the Expired phase
	// and have its BuildRun cleaned up. The ContainerBuild CR itself is
	// preserved. Nil if expiry is disabled (TTL "0" or no-expire annotation).
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`

	// PreviousPhase is the phase the build was in before transitioning to Expired.
	// +optional
	PreviousPhase string `json:"previousPhase,omitempty"`

	// Conditions represent the latest available observations of the build's state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`
// +kubebuilder:printcolumn:name="Output",type=string,JSONPath=`.spec.output`
// +kubebuilder:printcolumn:name="Expires",type=date,JSONPath=`.status.expiresAt`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// ContainerBuild is the Schema for the containerbuilds API
type ContainerBuild struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ContainerBuildSpec   `json:"spec,omitempty"`
	Status ContainerBuildStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ContainerBuildList contains a list of ContainerBuild
type ContainerBuildList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ContainerBuild `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ContainerBuild{}, &ContainerBuildList{})
}

// GetContainerfile returns the Containerfile path, defaulting to "Containerfile".
func (s *ContainerBuildSpec) GetContainerfile() string {
	if s.Containerfile == "" {
		return "Containerfile"
	}
	return s.Containerfile
}

// GetStrategy returns the strategy name, defaulting to "buildah".
func (s *ContainerBuildSpec) GetStrategy() string {
	if s.Strategy == "" {
		return "buildah"
	}
	return s.Strategy
}

// GetStrategyKind returns the strategy kind, defaulting to "ClusterBuildStrategy".
func (s *ContainerBuildSpec) GetStrategyKind() string {
	if s.StrategyKind == "" {
		return "ClusterBuildStrategy"
	}
	return s.StrategyKind
}

// GetArchitecture returns the target architecture, defaulting to "amd64".
func (s *ContainerBuildSpec) GetArchitecture() string {
	if s.Architecture == "" {
		return "amd64"
	}
	return s.Architecture
}

// GetTTL returns the per-build TTL string, or empty if not set.
func (s *ContainerBuildSpec) GetTTL() string {
	return s.TTL
}

// GetTimeout returns the timeout in minutes, defaulting to 30.
func (s *ContainerBuildSpec) GetTimeout() int32 {
	if s.Timeout <= 0 {
		return 30
	}
	return s.Timeout
}
