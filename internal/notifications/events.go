// Package notifications defines the public terminal event contract, independent of delivery execution.
package notifications

import (
	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	APIVersion      = "notifications.caib.dev/v1alpha1"
	BuildTerminal   = "build.terminal"
	FlashTerminal   = "flash.terminal"
	MaxPayloadBytes = 256 * 1024
)

// TerminalEvent contains exactly one subject, selected by Type.
type TerminalEvent struct {
	APIVersion string      `json:"apiVersion"`
	ID         string      `json:"id"`
	Type       string      `json:"type"`
	Time       metav1.Time `json:"time"`
	Build      *BuildEvent `json:"build,omitempty"`
	Flash      *FlashEvent `json:"flash,omitempty"`
}

// BuildEvent projects the immutable terminal result without internal references or credentials.
type BuildEvent struct {
	Name                                   string `json:"name"`
	ExternalID                             string `json:"externalId,omitempty"`
	TraceID                                string `json:"traceId,omitempty"`
	automotivev1alpha1.BuildTerminalResult `json:",inline"`
}

// FlashEvent describes a standalone flash; embedded flashing uses BuildEvent.Flash.
type FlashEvent struct {
	Name        string       `json:"name"`
	Phase       string       `json:"phase"`
	Message     string       `json:"message"`
	ExternalID  string       `json:"externalId,omitempty"`
	TraceID     string       `json:"traceId,omitempty"`
	ImageRef    string       `json:"imageRef"`
	LeaseID     string       `json:"leaseId,omitempty"`
	StartedAt   *metav1.Time `json:"startedAt,omitempty"`
	CompletedAt metav1.Time  `json:"completedAt"`
}
