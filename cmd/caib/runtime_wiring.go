package main

import (
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/buildcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/downloadcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/flashcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/image"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/querycmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/sealedcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/tokencmd"
)

type runtimeState struct {
	ServerURL              *string
	Manifest               *string
	BuildName              *string
	ShowOutputFormat       *string
	Distro                 *string
	Target                 *string
	Architecture           *string
	ExportFormat           *string
	Mode                   *string
	AutomotiveImageBuilder *string
	StorageClass           *string
	OutputDir              *string
	Timeout                *int
	WaitForBuild           *bool
	CustomDefs             *[]string
	AIBExtraArgs           *[]string
	ExtraRepos             *[]string
	Workspace              *string
	FollowLogs             *bool
	CompressionAlgo        *string
	AuthToken              *string

	ContainerPush    *string
	BuildDiskImage   *bool
	DiskFormat       *string
	ExportOCI        *string
	BuilderImage     *string
	RegistryAuthFile *string
	ContainerRef     *string
	RebuildBuilder   *bool

	FlashAfterBuild   *bool
	JumpstarterClient *string
	FlashName         *string
	ExporterSelector  *string
	LeaseDuration     *string
	LeaseName         *string
	FlashCmd          *string

	UseInternalRegistry       *bool
	InternalRegistryImageName *string
	InternalRegistryTag       *string

	SecureBuild *bool

	InsecureSkipTLS *bool

	SealedBuilderImage      *string
	SealedArchitecture      *string
	SealedKeySecret         *string
	SealedKeyPasswordSecret *string
	SealedKeyFile           *string
	SealedKeyPassword       *string
	SealedInputRef          *string
	SealedOutputRef         *string
	SealedSignedRef         *string
}

func newRuntimeState() runtimeState {
	return runtimeState{
		ServerURL:              &serverURL,
		Manifest:               &manifest,
		BuildName:              &buildName,
		ShowOutputFormat:       &showOutputFormat,
		Distro:                 &distro,
		Target:                 &target,
		Architecture:           &architecture,
		ExportFormat:           &exportFormat,
		Mode:                   &mode,
		AutomotiveImageBuilder: &automotiveImageBuilder,
		StorageClass:           &storageClass,
		OutputDir:              &outputDir,
		Timeout:                &timeout,
		WaitForBuild:           &waitForBuild,
		CustomDefs:             &customDefs,
		AIBExtraArgs:           &aibExtraArgs,
		ExtraRepos:             &extraRepos,
		Workspace:              &workspaceName,
		FollowLogs:             &followLogs,
		CompressionAlgo:        &compressionAlgo,
		AuthToken:              &authToken,

		ContainerPush:    &containerPush,
		BuildDiskImage:   &buildDiskImage,
		DiskFormat:       &diskFormat,
		ExportOCI:        &exportOCI,
		BuilderImage:     &builderImage,
		RegistryAuthFile: &registryAuthFile,
		ContainerRef:     &containerRef,
		RebuildBuilder:   &rebuildBuilder,

		FlashAfterBuild:   &flashAfterBuild,
		JumpstarterClient: &jumpstarterClient,
		FlashName:         &flashName,
		ExporterSelector:  &exporterSelector,
		LeaseDuration:     &leaseDuration,
		LeaseName:         &leaseName,
		FlashCmd:          &flashCmdOverride,

		UseInternalRegistry:       &useInternalRegistry,
		InternalRegistryImageName: &internalRegistryImageName,
		InternalRegistryTag:       &internalRegistryTag,

		SecureBuild: &secureBuild,

		InsecureSkipTLS: &insecureSkipTLS,

		SealedBuilderImage:      &sealedBuilderImage,
		SealedArchitecture:      &sealedArchitecture,
		SealedKeySecret:         &sealedKeySecret,
		SealedKeyPasswordSecret: &sealedKeyPasswordSecret,
		SealedKeyFile:           &sealedKeyFile,
		SealedKeyPassword:       &sealedKeyPassword,
		SealedInputRef:          &sealedInputRef,
		SealedOutputRef:         &sealedOutputRef,
		SealedSignedRef:         &sealedSignedRef,
	}
}

type handlerSet struct {
	build    *buildcmd.Handler
	query    *querycmd.Handler
	download *downloadcmd.Handler
	flash    *flashcmd.Handler
	sealed   *sealedcmd.Handler
	token    *tokencmd.Handler
}

func (s runtimeState) newHandlers() handlerSet {
	return handlerSet{
		build: buildcmd.NewHandler(buildcmd.Options{
			ServerURL:                 s.ServerURL,
			Manifest:                  s.Manifest,
			BuildName:                 s.BuildName,
			Distro:                    s.Distro,
			Target:                    s.Target,
			Architecture:              s.Architecture,
			ExportFormat:              s.ExportFormat,
			Mode:                      s.Mode,
			AutomotiveImageBuilder:    s.AutomotiveImageBuilder,
			StorageClass:              s.StorageClass,
			OutputDir:                 s.OutputDir,
			Timeout:                   s.Timeout,
			WaitForBuild:              s.WaitForBuild,
			CustomDefs:                s.CustomDefs,
			AIBExtraArgs:              s.AIBExtraArgs,
			ExtraRepos:                s.ExtraRepos,
			Workspace:                 s.Workspace,
			FollowLogs:                s.FollowLogs,
			CompressionAlgo:           s.CompressionAlgo,
			AuthToken:                 s.AuthToken,
			ContainerPush:             s.ContainerPush,
			BuildDiskImage:            s.BuildDiskImage,
			DiskFormat:                s.DiskFormat,
			ExportOCI:                 s.ExportOCI,
			BuilderImage:              s.BuilderImage,
			RegistryAuthFile:          s.RegistryAuthFile,
			ContainerRef:              s.ContainerRef,
			RebuildBuilder:            s.RebuildBuilder,
			FlashAfterBuild:           s.FlashAfterBuild,
			JumpstarterClient:         s.JumpstarterClient,
			LeaseDuration:             s.LeaseDuration,
			LeaseName:                 s.LeaseName,
			FlashCmd:                  s.FlashCmd,
			ExporterSelector:          s.ExporterSelector,
			UseInternalRegistry:       s.UseInternalRegistry,
			InternalRegistryImageName: s.InternalRegistryImageName,
			InternalRegistryTag:       s.InternalRegistryTag,
			SecureBuild:               s.SecureBuild,
			InsecureSkipTLS:           s.InsecureSkipTLS,
			HandleError:               handleError,
		}),
		query: querycmd.NewHandler(querycmd.Options{
			ServerURL:        s.ServerURL,
			AuthToken:        s.AuthToken,
			ShowOutputFormat: s.ShowOutputFormat,
			InsecureSkipTLS:  s.InsecureSkipTLS,
			HandleError:      handleError,
		}),
		download: downloadcmd.NewHandler(downloadcmd.Options{
			ServerURL:       s.ServerURL,
			AuthToken:       s.AuthToken,
			OutputDir:       s.OutputDir,
			InsecureSkipTLS: s.InsecureSkipTLS,
			HandleError:     handleError,
		}),
		flash: flashcmd.NewHandler(flashcmd.Options{
			ServerURL:         s.ServerURL,
			AuthToken:         s.AuthToken,
			JumpstarterClient: s.JumpstarterClient,
			FlashName:         s.FlashName,
			Target:            s.Target,
			ExporterSelector:  s.ExporterSelector,
			LeaseDuration:     s.LeaseDuration,
			LeaseName:         s.LeaseName,
			FlashCmd:          s.FlashCmd,
			WaitForBuild:      s.WaitForBuild,
			FollowLogs:        s.FollowLogs,
			InsecureSkipTLS:   s.InsecureSkipTLS,
			RegistryAuthFile:  s.RegistryAuthFile,
			HandleError:       handleError,
		}),
		sealed: sealedcmd.NewHandler(sealedcmd.Options{
			ServerURL:               s.ServerURL,
			AuthToken:               s.AuthToken,
			AutomotiveImageBuilder:  s.AutomotiveImageBuilder,
			SealedBuilderImage:      s.SealedBuilderImage,
			SealedArchitecture:      s.SealedArchitecture,
			AIBExtraArgs:            s.AIBExtraArgs,
			WaitForBuild:            s.WaitForBuild,
			FollowLogs:              s.FollowLogs,
			Timeout:                 s.Timeout,
			SealedKeySecret:         s.SealedKeySecret,
			SealedKeyPasswordSecret: s.SealedKeyPasswordSecret,
			SealedKeyFile:           s.SealedKeyFile,
			SealedKeyPassword:       s.SealedKeyPassword,
			SealedInputRef:          s.SealedInputRef,
			SealedOutputRef:         s.SealedOutputRef,
			SealedSignedRef:         s.SealedSignedRef,
			RegistryAuthFile:        s.RegistryAuthFile,
			InsecureSkipTLS:         s.InsecureSkipTLS,
			HandleError:             handleError,
		}),
		token: tokencmd.NewHandler(tokencmd.Options{
			ServerURL:       s.ServerURL,
			AuthToken:       s.AuthToken,
			InsecureSkipTLS: s.InsecureSkipTLS,
			HandleError:     handleError,
		}),
	}
}

func (s runtimeState) imageOptions(h handlerSet) image.Options {
	return image.Options{
		RunBuild:             h.build.RunBuild,
		RunDisk:              h.build.RunDisk,
		RunBuildDev:          h.build.RunBuildDev,
		RunList:              h.query.RunList,
		RunShow:              h.query.RunShow,
		RunDownload:          h.download.RunDownload,
		RunLogs:              h.build.RunLogs,
		RunFlash:             h.flash.RunFlash,
		RunPrepareReseal:     h.sealed.RunPrepareReseal,
		RunReseal:            h.sealed.RunReseal,
		RunExtractForSigning: h.sealed.RunExtractForSigning,
		RunInjectSigned:      h.sealed.RunInjectSigned,
		RunToken:             h.token.RunToken,
		RunDelete:            h.build.RunDelete,
		GetDefaultArch:       getDefaultArch,

		ServerURL:              s.ServerURL,
		AuthToken:              s.AuthToken,
		BuildName:              s.BuildName,
		ShowOutputFormat:       s.ShowOutputFormat,
		Distro:                 s.Distro,
		Target:                 s.Target,
		Architecture:           s.Architecture,
		ExportFormat:           s.ExportFormat,
		Mode:                   s.Mode,
		AutomotiveImageBuilder: s.AutomotiveImageBuilder,
		StorageClass:           s.StorageClass,
		OutputDir:              s.OutputDir,
		Timeout:                s.Timeout,
		WaitForBuild:           s.WaitForBuild,
		CustomDefs:             s.CustomDefs,
		AIBExtraArgs:           s.AIBExtraArgs,
		ExtraRepos:             s.ExtraRepos,
		Workspace:              s.Workspace,
		FollowLogs:             s.FollowLogs,
		CompressionAlgo:        s.CompressionAlgo,
		ContainerPush:          s.ContainerPush,
		BuildDiskImage:         s.BuildDiskImage,
		DiskFormat:             s.DiskFormat,
		ExportOCI:              s.ExportOCI,
		BuilderImage:           s.BuilderImage,
		RegistryAuthFile:       s.RegistryAuthFile,
		RebuildBuilder:         s.RebuildBuilder,

		FlashAfterBuild:   s.FlashAfterBuild,
		JumpstarterClient: s.JumpstarterClient,
		FlashName:         s.FlashName,
		ExporterSelector:  s.ExporterSelector,
		LeaseDuration:     s.LeaseDuration,
		LeaseName:         s.LeaseName,
		FlashCmd:          s.FlashCmd,

		UseInternalRegistry:       s.UseInternalRegistry,
		InternalRegistryImageName: s.InternalRegistryImageName,
		InternalRegistryTag:       s.InternalRegistryTag,

		SecureBuild: s.SecureBuild,

		SealedBuilderImage:      s.SealedBuilderImage,
		SealedArchitecture:      s.SealedArchitecture,
		SealedKeySecret:         s.SealedKeySecret,
		SealedKeyPasswordSecret: s.SealedKeyPasswordSecret,
		SealedKeyFile:           s.SealedKeyFile,
		SealedKeyPassword:       s.SealedKeyPassword,
		SealedInputRef:          s.SealedInputRef,
		SealedOutputRef:         s.SealedOutputRef,
		SealedSignedRef:         s.SealedSignedRef,
	}
}
