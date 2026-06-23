package flashcmd

import (
	"fmt"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/oci"
)

func TestResolveTargetFromAnnotations_Found(t *testing.T) {
	targetKey := oci.Get().AnnotationKey("target")
	target := ""
	h := NewHandler(Options{
		Target: &target,
		AnnotationReader: func(_ string) (map[string]string, error) {
			return map[string]string{targetKey: "rcar_s4"}, nil
		},
	})

	got := h.resolveTargetFromAnnotations("quay.io/test/image:v1")
	if got != "rcar_s4" {
		t.Errorf("expected rcar_s4, got %q", got)
	}
}

func TestResolveTargetFromAnnotations_NotPresent(t *testing.T) {
	target := ""
	h := NewHandler(Options{
		Target: &target,
		AnnotationReader: func(_ string) (map[string]string, error) {
			return map[string]string{}, nil
		},
	})

	got := h.resolveTargetFromAnnotations("quay.io/test/image:v1")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestResolveTargetFromAnnotations_FetchError(t *testing.T) {
	target := ""
	h := NewHandler(Options{
		Target: &target,
		AnnotationReader: func(_ string) (map[string]string, error) {
			return nil, fmt.Errorf("network error")
		},
	})

	got := h.resolveTargetFromAnnotations("quay.io/test/image:v1")
	if got != "" {
		t.Errorf("expected empty string on error, got %q", got)
	}
}

func TestResolveTargetFromAnnotations_PassesImageRef(t *testing.T) {
	target := ""
	var receivedRef string
	h := NewHandler(Options{
		Target: &target,
		AnnotationReader: func(imageRef string) (map[string]string, error) {
			receivedRef = imageRef
			return map[string]string{}, nil
		},
	})

	h.resolveTargetFromAnnotations("quay.io/org/specific:tag")
	if receivedRef != "quay.io/org/specific:tag" {
		t.Errorf("expected imageRef passed through, got %q", receivedRef)
	}
}
