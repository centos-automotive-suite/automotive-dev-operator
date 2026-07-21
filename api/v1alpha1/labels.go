package v1alpha1

// Observability label and annotation keys.
// LabelDistro, LabelTarget, LabelArchitecture are defined in catalogimage_types.go.
const (
	LabelBuildMode               = "automotive.sdv.cloud.redhat.com/build-mode"
	LabelTraceID                 = "automotive.sdv.cloud.redhat.com/trace-id"
	LabelImageBuildName          = "automotive.sdv.cloud.redhat.com/imagebuild-name"
	LabelTaskType                = "automotive.sdv.cloud.redhat.com/task-type"
	LabelWorkspaceName           = "automotive.sdv.cloud.redhat.com/workspace-name"
	LabelScheduledImageBuildName = "automotive.sdv.cloud.redhat.com/scheduledimagebuild-name"
	LabelOwner                   = "automotive.sdv.cloud.redhat.com/owner"

	AnnotationTraceID       = "automotive.sdv.cloud.redhat.com/trace-id"
	AnnotationRequestedBy   = "automotive.sdv.cloud.redhat.com/requested-by"
	AnnotationTaskBundleRef = "automotive.sdv.cloud.redhat.com/task-bundle-ref"
)
