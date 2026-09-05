package notifications

import (
	"strings"
	"testing"
)

func TestLifecycleNamesAreStableAndBounded(t *testing.T) {
	longName := strings.Repeat("a", 63)
	secretName := CallbackSecretName(SubjectImageBuild, longName, "uid-a")
	if len(secretName) > 63 || secretName != CallbackSecretName(SubjectImageBuild, longName, "uid-a") {
		t.Fatalf("invalid callback secret name %q", secretName)
	}
	if secretName == CallbackSecretName(SubjectImageBuild, strings.Repeat("a", 62)+"b", "uid-a") {
		t.Fatal("truncated callback secret names collided")
	}
	if secretName == CallbackSecretName(SubjectTaskRun, longName, "uid-a") ||
		secretName == CallbackSecretName(SubjectImageBuild, longName, "uid-b") {
		t.Fatal("callback secret identity ignored kind or operation identity")
	}
	deliveryName := DeliveryName(strings.Repeat("u", 128))
	if len(deliveryName) > 63 || deliveryName != DeliveryName(strings.Repeat("u", 128)) {
		t.Fatalf("invalid delivery name %q", deliveryName)
	}
	eventID := EventID(strings.Repeat("u", 128))
	if len(eventID) > 128 || eventID != EventID(strings.Repeat("u", 128)) {
		t.Fatalf("invalid event ID %q", eventID)
	}
}
