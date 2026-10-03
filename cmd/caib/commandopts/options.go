// Package commandopts holds shared CLI command state.
package commandopts

// Connection holds connection settings shared by commands.
type Connection struct {
	ServerURL       string
	AuthToken       string
	InsecureSkipTLS bool
}

// Output holds output settings shared by commands.
type Output struct {
	Format     string
	Wait       bool
	FollowLogs bool
	Timeout    int
	Dir        string
}

// Callback holds callback settings shared by commands.
type Callback struct {
	ExternalID string
	URL        string
	SecretFile string
}

// Registry holds registry settings shared by commands.
type Registry struct {
	ContainerPush             string
	ExportOCI                 string
	AuthFile                  string
	UseInternalRegistry       bool
	InternalRegistryImageName string
	InternalRegistryTag       string
}

// S3 holds s3 settings shared by commands.
type S3 struct {
	Bucket            string
	Prefix            string
	Region            string
	Endpoint          string
	AccessKeyID       string
	SecretAccessKey   string
	CredentialsSecret string
	Insecure          bool
}

// Flash holds flash settings shared by commands.
type Flash struct {
	AfterBuild        bool
	JumpstarterClient string
	Name              string
	ExporterSelector  string
	LeaseDuration     string
	LeaseName         string
	Cmd               string
	LeaseTags         []string
}

// Sealed holds sealed settings shared by commands.
type Sealed struct {
	BuilderImage      string
	Architecture      string
	KeySecret         string
	KeyPasswordSecret string
	KeyFile           string
	KeyPassword       string
	InputRef          string
	OutputRef         string
	SignedRef         string
}

// Build holds build settings shared by commands.
type Build struct {
	Manifest               string
	Name                   string
	Distro                 string
	Target                 string
	Architecture           string
	ExportFormat           string
	Mode                   string
	AutomotiveImageBuilder string
	StorageClass           string
	CustomDefs             []string
	DefineFiles            []string
	AIBExtraArgs           []string
	GitURL                 string
	GitRef                 string
	GitSecret              string
	GitLockfile            string
	Lockfile               string
	RootPassword           string
	ExtraRepos             []string
	LocalRepo              string
	Workspace              string
	CompressionAlgo        string
	BuildDiskImage         bool
	DiskFormat             string
	BuilderImage           string
	ContainerRef           string
	RebuildBuilder         bool
	BuilderCachePolicy     string
	SecureBuild            bool
	Reproducible           bool
	TaskBundleRef          string
	RestoreSourcesRef      string
	TTL                    string
}
