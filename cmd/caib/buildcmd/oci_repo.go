package buildcmd

import (
	"context"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/clilog"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/registryauth"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

var pinOCIRepoImageFn = registryauth.PinImage

func (h *Handler) pinOCIRepoImages(ctx context.Context, req *buildcontract.BuildRequest) {
	for i, ref := range req.OCIRepoImages {
		pinned, err := pinOCIRepoImageFn(ctx, ref, h.opts.Registry.AuthFile)
		if err != nil {
			clilog.Warnf("Could not pin OCI repository image %q: %v; submitting the reference unchanged\n", ref, err)
			continue
		}
		req.OCIRepoImages[i] = pinned
	}
}
