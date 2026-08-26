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

// Package catalogimage provides event recording and audit logging for CatalogImage resources.
package catalogimage

import (
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"
	"sigs.k8s.io/controller-runtime/pkg/client"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
)

// AuditEventType represents the type of catalog audit event
type AuditEventType string

const (
	// AuditEventPublished indicates an image was published to the catalog
	AuditEventPublished AuditEventType = "Published"
	// AuditEventVerified indicates an image was verified in the registry
	AuditEventVerified AuditEventType = "Verified"
	// AuditEventUnavailable indicates an image became unavailable
	AuditEventUnavailable AuditEventType = "Unavailable"
	// AuditEventRemoved indicates an image was removed from the catalog
	AuditEventRemoved AuditEventType = "Removed"
	// AuditEventAccessError indicates an access error occurred
	AuditEventAccessError AuditEventType = "AccessError"
)

// AuditRecorder records audit events for CatalogImages
type AuditRecorder struct {
	recorder events.EventRecorder
	scheme   *runtime.Scheme
}

// NewAuditRecorder creates a new AuditRecorder
func NewAuditRecorder(recorder events.EventRecorder, scheme *runtime.Scheme) *AuditRecorder {
	return &AuditRecorder{
		recorder: recorder,
		scheme:   scheme,
	}
}

// RecordPublished records that an image was published to the catalog
func (a *AuditRecorder) RecordPublished(
	_ context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
	source string,
) {
	a.recorder.Eventf(catalogImage, nil, corev1.EventTypeNormal, string(AuditEventPublished), string(AuditEventPublished),
		"Image published to catalog from %s", source)
}

// RecordVerified records that an image was verified in the registry
func (a *AuditRecorder) RecordVerified(_ context.Context, catalogImage *automotivev1alpha1.CatalogImage) {
	a.recorder.Eventf(catalogImage, nil, corev1.EventTypeNormal, string(AuditEventVerified), string(AuditEventVerified),
		"Image verified and accessible in registry")
}

// RecordUnavailable records that an image became unavailable
func (a *AuditRecorder) RecordUnavailable(
	_ context.Context,
	catalogImage *automotivev1alpha1.CatalogImage,
	reason string,
) {
	a.recorder.Eventf(catalogImage, nil, corev1.EventTypeWarning, string(AuditEventUnavailable), string(AuditEventUnavailable),
		"Image became unavailable: %s", reason)
}

// RecordRemoved records that an image was removed from the catalog
func (a *AuditRecorder) RecordRemoved(_ context.Context, catalogImage *automotivev1alpha1.CatalogImage) {
	a.recorder.Eventf(catalogImage, nil, corev1.EventTypeNormal, string(AuditEventRemoved), string(AuditEventRemoved),
		"Image removed from catalog")
}

// RecordAccessError records that an access error occurred
func (a *AuditRecorder) RecordAccessError(_ context.Context, catalogImage *automotivev1alpha1.CatalogImage, err error) {
	a.recorder.Eventf(catalogImage, nil, corev1.EventTypeWarning, string(AuditEventAccessError), string(AuditEventAccessError),
		"Registry access error: %v", err)
}

// CatalogImageLister provides methods to list CatalogImages efficiently
//
//nolint:revive // Name intentionally includes resource type for clarity
type CatalogImageLister struct {
	client client.Client
}

// NewCatalogImageLister creates a new CatalogImageLister
func NewCatalogImageLister(client client.Client) *CatalogImageLister {
	return &CatalogImageLister{client: client}
}

// ListByPhase lists CatalogImages by phase using the field index
func (l *CatalogImageLister) ListByPhase(
	ctx context.Context,
	namespace string,
	phase automotivev1alpha1.CatalogImagePhase,
) (*automotivev1alpha1.CatalogImageList, error) {
	list := &automotivev1alpha1.CatalogImageList{}
	opts := []client.ListOption{
		client.MatchingFields{"status.phase": string(phase)},
	}
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	if err := l.client.List(ctx, list, opts...); err != nil {
		return nil, err
	}
	return list, nil
}

// ListByRegistryURL lists CatalogImages by registry URL using the field index
func (l *CatalogImageLister) ListByRegistryURL(
	ctx context.Context,
	namespace, registryURL string,
) (*automotivev1alpha1.CatalogImageList, error) {
	list := &automotivev1alpha1.CatalogImageList{}
	opts := []client.ListOption{
		client.MatchingFields{"spec.registryUrl": registryURL},
	}
	if namespace != "" {
		opts = append(opts, client.InNamespace(namespace))
	}
	if err := l.client.List(ctx, list, opts...); err != nil {
		return nil, err
	}
	return list, nil
}

// ListAvailable lists all Available CatalogImages
func (l *CatalogImageLister) ListAvailable(
	ctx context.Context,
	namespace string,
) (*automotivev1alpha1.CatalogImageList, error) {
	return l.ListByPhase(ctx, namespace, automotivev1alpha1.CatalogImagePhaseAvailable)
}

// ExistsByRegistryURL checks if a CatalogImage exists with the given registry URL
func (l *CatalogImageLister) ExistsByRegistryURL(ctx context.Context, namespace, registryURL string) (bool, error) {
	list, err := l.ListByRegistryURL(ctx, namespace, registryURL)
	if err != nil {
		return false, err
	}
	return len(list.Items) > 0, nil
}
