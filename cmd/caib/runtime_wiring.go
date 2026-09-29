package main

import (
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/buildcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/commandopts"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/downloadcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/flashcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/image"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/inspectcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/querycmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/sealedcmd"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/tokencmd"
)

type runtimeState struct {
	Quiet      bool
	Connection commandopts.Connection
	Output     commandopts.Output
	Callback   commandopts.Callback
	Registry   commandopts.Registry
	S3         commandopts.S3
	Flash      commandopts.Flash
	Sealed     commandopts.Sealed
	Build      commandopts.Build
}

func newRuntimeState() *runtimeState { return &runtimeState{} }

type handlerSet struct {
	build    *buildcmd.Handler
	query    *querycmd.Handler
	download *downloadcmd.Handler
	flash    *flashcmd.Handler
	sealed   *sealedcmd.Handler
	token    *tokencmd.Handler
	inspect  *inspectcmd.Handler
}

func (s *runtimeState) newHandlers() handlerSet {
	return handlerSet{
		build:    buildcmd.NewHandler(buildcmd.Options{Connection: &s.Connection, Output: &s.Output, Callback: &s.Callback, Registry: &s.Registry, S3: &s.S3, Flash: &s.Flash, Build: &s.Build, HandleError: handleError}),
		query:    querycmd.NewHandler(querycmd.Options{Connection: &s.Connection, Output: &s.Output, HandleError: handleError}),
		download: downloadcmd.NewHandler(downloadcmd.Options{Connection: &s.Connection, Output: &s.Output, HandleError: handleError}),
		flash:    flashcmd.NewHandler(flashcmd.Options{Connection: &s.Connection, Output: &s.Output, Callback: &s.Callback, Flash: &s.Flash, Registry: &s.Registry, Build: &s.Build, HandleError: handleError}),
		sealed:   sealedcmd.NewHandler(sealedcmd.Options{Connection: &s.Connection, Output: &s.Output, Sealed: &s.Sealed, Registry: &s.Registry, Build: &s.Build, HandleError: handleError}),
		token:    tokencmd.NewHandler(tokencmd.Options{Connection: &s.Connection, Output: &s.Output, HandleError: handleError}),
		inspect:  inspectcmd.NewHandler(inspectcmd.Options{Connection: &s.Connection, Output: &s.Output, Registry: &s.Registry, HandleError: handleError}),
	}
}

func (s *runtimeState) imageOptions(h handlerSet) image.Options {
	return image.Options{
		RunBuild:             h.build.RunBuild,
		RunResolve:           h.build.RunResolve,
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
		RunCancel:            h.build.RunCancel,
		RunInspect:           h.inspect.RunInspect,
		GetDefaultArch:       getDefaultArch,
		Connection:           &s.Connection,
		Output:               &s.Output,
		Callback:             &s.Callback,
		Registry:             &s.Registry,
		S3:                   &s.S3,
		Flash:                &s.Flash,
		Sealed:               &s.Sealed,
		Build:                &s.Build,
	}
}
