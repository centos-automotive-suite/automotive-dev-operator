package buildcmd

import (
	"fmt"
	"strings"

	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"github.com/fatih/color"
)

func replaceFlashImagePlaceholders(cmd, imageURI string) string {
	cmd = strings.ReplaceAll(cmd, "{image_uri}", imageURI)
	cmd = strings.ReplaceAll(cmd, "{artifact_url}", imageURI)
	cmd = strings.ReplaceAll(cmd, "${IMAGE}", imageURI)
	cmd = strings.ReplaceAll(cmd, "${IMAGE_REF}", imageURI)
	return cmd
}

func hasUnresolvedFlashImagePlaceholder(cmd string) bool {
	placeholders := []string{
		"{image_uri}",
		"{artifact_url}",
		"${IMAGE}",
		"${IMAGE_REF}",
	}
	for _, placeholder := range placeholders {
		if strings.Contains(cmd, placeholder) {
			return true
		}
	}
	return false
}

// displayFlashInstructions shows flash instructions when flash is not executed or fails.
func (h *Handler) displayFlashInstructions(st *buildapitypes.BuildResponse, isFailure bool) {
	if st.Jumpstarter == nil || !st.Jumpstarter.Available {
		return
	}
	if st.Jumpstarter.ExporterSelector == "" && st.Jumpstarter.FlashCmd == "" {
		return
	}
	// Don't show jumpstarter instructions if user requested a local download.
	if *h.opts.OutputDir != "" {
		return
	}

	colorsSupported := h.supportsColorOutput()
	var commandColor, infoColor func(...any) string
	var commandPrefix string

	if isFailure {
		if colorsSupported {
			commandColor = color.New(color.FgHiYellow, color.Bold).SprintFunc()
			infoColor = color.New(color.FgHiWhite).SprintFunc()
		} else {
			commandColor = func(a ...any) string { return fmt.Sprint(a...) }
			infoColor = func(a ...any) string { return fmt.Sprint(a...) }
			commandPrefix = ">> "
		}
	} else {
		if colorsSupported {
			commandColor = color.New(color.FgHiGreen, color.Bold).SprintFunc()
			infoColor = color.New(color.FgHiYellow).SprintFunc()
		} else {
			commandColor = func(a ...any) string { return fmt.Sprint(a...) }
			infoColor = func(a ...any) string { return fmt.Sprint(a...) }
			commandPrefix = ">> "
		}
	}

	if isFailure {
		fmt.Printf("%s\n", infoColor("Flash failed, but you can flash manually using Jumpstarter:"))
	} else {
		fmt.Printf("%s\n", infoColor("Jumpstarter is available for flashing:"))
	}

	if st.Jumpstarter.ExporterSelector != "" {
		fmt.Printf("  %s %s\n", infoColor("Exporter selector:"), st.Jumpstarter.ExporterSelector)
	}

	if st.Jumpstarter.FlashCmd != "" {
		flashCmd := st.Jumpstarter.FlashCmd
		imageURI := st.DiskImage
		if imageURI == "" {
			imageURI = st.ContainerImage
		}
		if imageURI != "" {
			flashCmd = replaceFlashImagePlaceholders(flashCmd, imageURI)
		}

		if hasUnresolvedFlashImagePlaceholder(flashCmd) {
			fmt.Printf("  %s\n", infoColor("Flash command template:"))
			fmt.Printf("    %s%s\n", commandPrefix, commandColor(replaceFlashImagePlaceholders(flashCmd, "<image-uri>")))
			fmt.Printf("  %s\n", infoColor("No pushed disk image URI is available for this build."))
			fmt.Printf("  %s\n", infoColor("Use --push-disk <registry/repo:tag> or --internal-registry to produce a flashable URI."))
			return
		}

		fmt.Printf("  %s\n", infoColor("Flash command:"))
		fmt.Printf("    %s%s\n", commandPrefix, commandColor(flashCmd))
	}
}

func (h *Handler) handleFlashError(err error, st *buildapitypes.BuildResponse) {
	if *h.opts.FlashAfterBuild && st != nil {
		h.displayFlashInstructions(st, true)
	}
	h.handleError(err)
}
