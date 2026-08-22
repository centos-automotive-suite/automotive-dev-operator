// Package labels defines shared label and annotation constants used across
// the buildapi and controller packages.
package labels

// RequestedBy and related constants are annotation/label keys in the
// automotive.sdv.cloud.redhat.com domain.
const (
	RequestedBy          = "automotive.sdv.cloud.redhat.com/requested-by"
	Transient            = "automotive.sdv.cloud.redhat.com/transient"
	ResourceType         = "automotive.sdv.cloud.redhat.com/resource-type"
	BuildName            = "automotive.sdv.cloud.redhat.com/build-name"
	ImageBuildName       = "automotive.sdv.cloud.redhat.com/imagebuild-name"
	ImageReseal          = "automotive.sdv.cloud.redhat.com/imagereseal"
	Workspace            = "automotive.sdv.cloud.redhat.com/workspace"
	UploadsComplete      = "automotive.sdv.cloud.redhat.com/uploads-complete"
	WorkspaceHydrate     = "automotive.sdv.cloud.redhat.com/workspace-hydrate"
	WorkspaceHydrateDone = "automotive.sdv.cloud.redhat.com/workspace-hydrate-done"
	AwaitClientUploads   = "automotive.sdv.cloud.redhat.com/await-client-uploads"
	ClientSkipsUploads   = "automotive.sdv.cloud.redhat.com/client-skips-uploads"
	FlashTaskRun         = "automotive.sdv.cloud.redhat.com/flash-taskrun"
	Progress             = "automotive.sdv.cloud.redhat.com/progress"
	Username             = "automotive.sdv.cloud.redhat.com/username"
	TaskType             = "automotive.sdv.cloud.redhat.com/task-type"
	ContainerBuild       = "automotive.sdv.cloud.redhat.com/containerbuild"
	ImageRef             = "automotive.sdv.cloud.redhat.com/image-ref"
	Distro               = "automotive.sdv.cloud.redhat.com/distro"
	Target               = "automotive.sdv.cloud.redhat.com/target"
	Architecture         = "automotive.sdv.cloud.redhat.com/architecture"
)

// ManagedBy and related constants are standard Kubernetes label keys.
const (
	ManagedBy = "app.kubernetes.io/managed-by"
	PartOf    = "app.kubernetes.io/part-of"
	CreatedBy = "app.kubernetes.io/created-by"
	Component = "app.kubernetes.io/component"
	Name      = "app.kubernetes.io/name"
)

// ValueTrue and related constants are common label values.
const (
	ValueTrue            = "true"
	ValueBuildAPI        = "build-api"
	ValueAutomotiveDev   = "automotive-dev"
	ValueBuildAPICreator = "automotive-dev-build-api"
	ValueOperator        = "automotive-dev-operator"
)
