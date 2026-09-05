package notifications

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

const (
	AnnotationCallbackInitializing = "automotive.sdv.cloud.redhat.com/callback-initializing"
	AnnotationCallbackSecretRef    = "automotive.sdv.cloud.redhat.com/callback-secret-ref"
	AnnotationCallbackSubjectKind  = "automotive.sdv.cloud.redhat.com/callback-subject-kind"
	AnnotationCallbackSubjectName  = "automotive.sdv.cloud.redhat.com/callback-subject-name"
	AnnotationCallbackSubjectUID   = "automotive.sdv.cloud.redhat.com/callback-subject-uid"
	AnnotationExternalID           = "automotive.sdv.cloud.redhat.com/external-id"

	LabelCallbackSecret = "automotive.sdv.cloud.redhat.com/callback-secret"

	CallbackURLKey  = "url"
	CallbackHMACKey = "hmac-key"

	SubjectImageBuild = "ImageBuild"
	SubjectTaskRun    = "TaskRun"
)

// CallbackSecretName binds credential storage to a kind and operation-specific identity.
func CallbackSecretName(subjectKind, subjectName, identity string) string {
	digest := sha256.Sum256([]byte(subjectKind + "\x00" + subjectName + "\x00" + identity))
	return boundedName(strings.ToLower(subjectKind)+"-"+subjectName, fmt.Sprintf("-%x-callback", digest[:4]))
}

// DeliveryName is keyed by subject UID so a replacement cannot reuse an old event.
func DeliveryName(subjectUID string) string {
	return boundedName("webhook-"+subjectUID, "")
}

// EventID is stable across retries and bounded independently of UID length.
func EventID(subjectUID string) string {
	digest := sha256.Sum256([]byte(subjectUID))
	return fmt.Sprintf("event-%x", digest[:])
}

func boundedName(base, suffix string) string {
	if len(base)+len(suffix) <= 63 {
		return base + suffix
	}
	hash := sha256.Sum256([]byte(base))
	hashText := fmt.Sprintf("%x", hash[:4])
	return base[:63-len(suffix)-len(hashText)-1] + "-" + hashText + suffix
}
