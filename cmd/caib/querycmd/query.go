// Package querycmd provides handlers for image list/show commands.
package querycmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	common "github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/common"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const outputFormatTable = "table"

// Options wires query handlers to caller-owned state and helper callbacks.
type Options struct {
	ServerURL       *string
	AuthToken       *string
	OutputFormat    *string
	InsecureSkipTLS *bool

	HandleError func(error)
}

// Handler implements list/show command run functions.
type Handler struct {
	opts Options
}

// NewHandler creates a query handler.
func NewHandler(opts Options) *Handler {
	return &Handler{opts: opts}
}

func (h *Handler) handleError(err error) {
	if h.opts.HandleError != nil {
		h.opts.HandleError(err)
		return
	}
	panic(err)
}

// resolveOutputFormat normalises and validates the configured output format.
// It returns the canonical lowercase format string or an error for unsupported values.
func (h *Handler) resolveOutputFormat() (string, error) {
	format := outputFormatTable
	if h.opts.OutputFormat != nil && strings.TrimSpace(*h.opts.OutputFormat) != "" {
		format = strings.ToLower(strings.TrimSpace(*h.opts.OutputFormat))
	}

	switch format {
	case outputFormatTable, "json", "yaml", "yml":
		return format, nil
	default:
		return "", fmt.Errorf("invalid output format %q (supported: table, json, yaml)", format)
	}
}

// RunList handles `caib image list`.
func (h *Handler) RunList(_ *cobra.Command, _ []string) {
	format, err := h.resolveOutputFormat()
	if err != nil {
		h.handleError(err)
		return
	}

	ctx := context.Background()
	if h.opts.ServerURL == nil || strings.TrimSpace(*h.opts.ServerURL) == "" {
		h.handleError(fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')"))
		return
	}
	if h.opts.InsecureSkipTLS == nil {
		h.handleError(fmt.Errorf("internal error: --insecure option is not configured"))
		return
	}

	serverURL := strings.TrimSpace(*h.opts.ServerURL)
	insecureSkipTLS := *h.opts.InsecureSkipTLS

	var items []buildapitypes.BuildListItem
	err = common.ExecuteWithReauth(serverURL, h.opts.AuthToken, insecureSkipTLS, func(api *buildapiclient.Client) error {
		var listErr error
		items, listErr = api.ListBuilds(ctx)
		return listErr
	})
	if err != nil {
		h.handleError(fmt.Errorf("error listing ImageBuilds: %w", err))
		return
	}

	h.renderList(format, items)
}

// renderList formats and prints a list of builds according to the configured output format.
func (h *Handler) renderList(format string, items []buildapitypes.BuildListItem) {
	if items == nil {
		items = []buildapitypes.BuildListItem{}
	}
	h.renderFormatted(format, items, func() error {
		if len(items) == 0 {
			fmt.Println("No ImageBuilds found")
			return nil
		}
		return printBuildList(items)
	})
}

// RunShow handles `caib image show`.
func (h *Handler) RunShow(_ *cobra.Command, args []string) {
	format, err := h.resolveOutputFormat()
	if err != nil {
		h.handleError(err)
		return
	}

	ctx := context.Background()
	showBuildName := args[0]

	if h.opts.ServerURL == nil || strings.TrimSpace(*h.opts.ServerURL) == "" {
		h.handleError(fmt.Errorf("server URL required (use --server, CAIB_SERVER, run 'caib login <server-url>' or 'jmp login <endpoint>')"))
		return
	}
	if h.opts.InsecureSkipTLS == nil {
		h.handleError(fmt.Errorf("internal error: --insecure option is not configured"))
		return
	}
	serverURL := strings.TrimSpace(*h.opts.ServerURL)
	insecureSkipTLS := *h.opts.InsecureSkipTLS

	var st *buildapitypes.BuildResponse
	err = common.ExecuteWithReauth(serverURL, h.opts.AuthToken, insecureSkipTLS, func(api *buildapiclient.Client) error {
		var getErr error
		st, getErr = api.GetBuild(ctx, showBuildName)
		return getErr
	})
	if err != nil {
		h.handleError(fmt.Errorf("error getting ImageBuild %s: %w", showBuildName, err))
		return
	}

	// Backward-compatible fallback for older API servers that do not yet include response parameters.
	if st.Parameters == nil {
		fallbackErr := common.ExecuteWithReauth(serverURL, h.opts.AuthToken, insecureSkipTLS, func(api *buildapiclient.Client) error {
			tpl, tplErr := api.GetBuildTemplate(ctx, showBuildName)
			if tplErr != nil {
				return tplErr
			}
			st.Parameters = buildParametersFromTemplate(tpl)
			return nil
		})
		if fallbackErr != nil {
			fmt.Fprintf(
				os.Stderr,
				"Warning: failed to fetch build template for %s from %s: %v\n",
				showBuildName,
				serverURL,
				fallbackErr,
			)
		}
	}

	h.renderShow(format, st)
}

// renderShow formats and prints a single build response according to the configured output format.
func (h *Handler) renderShow(format string, st *buildapitypes.BuildResponse) {
	h.renderFormatted(format, st, func() error { return printBuildDetails(st) })
}

// renderFormatted outputs data in the given format, using tablePrinter for table output.
func (h *Handler) renderFormatted(format string, data any, tablePrinter func() error) {
	switch format {
	case "json":
		out, marshalErr := json.MarshalIndent(data, "", "  ")
		if marshalErr != nil {
			h.handleError(fmt.Errorf("error rendering JSON output: %w", marshalErr))
			return
		}
		fmt.Println(string(out))
	case "yaml", "yml":
		out, marshalErr := yaml.Marshal(data)
		if marshalErr != nil {
			h.handleError(fmt.Errorf("error rendering YAML output: %w", marshalErr))
			return
		}
		fmt.Print(string(out))
	case outputFormatTable:
		if err := tablePrinter(); err != nil {
			h.handleError(fmt.Errorf("error writing table output: %w", err))
		}
	default:
		h.handleError(fmt.Errorf("invalid output format %q (supported: table, json, yaml)", format))
	}
}

func buildParametersFromTemplate(tpl *buildapitypes.BuildTemplateResponse) *buildapitypes.BuildParameters {
	if tpl == nil {
		return nil
	}

	params := &buildapitypes.BuildParameters{
		Architecture:           string(tpl.Architecture),
		Distro:                 string(tpl.Distro),
		Target:                 string(tpl.Target),
		Mode:                   string(tpl.Mode),
		ExportFormat:           string(tpl.ExportFormat),
		Compression:            tpl.Compression,
		StorageClass:           tpl.StorageClass,
		AutomotiveImageBuilder: tpl.AutomotiveImageBuilder,
		BuilderImage:           tpl.BuilderImage,
		ContainerRef:           tpl.ContainerRef,
		BuildDiskImage:         tpl.BuildDiskImage,
		FlashEnabled:           tpl.FlashEnabled,
		FlashLeaseDuration:     tpl.FlashLeaseDuration,
		UseServiceAccountAuth:  tpl.UseInternalRegistry,
	}

	if strings.TrimSpace(params.Architecture) == "" &&
		strings.TrimSpace(params.Distro) == "" &&
		strings.TrimSpace(params.Target) == "" &&
		strings.TrimSpace(params.Mode) == "" &&
		strings.TrimSpace(params.ExportFormat) == "" &&
		strings.TrimSpace(params.Compression) == "" &&
		strings.TrimSpace(params.StorageClass) == "" &&
		strings.TrimSpace(params.AutomotiveImageBuilder) == "" &&
		strings.TrimSpace(params.BuilderImage) == "" &&
		strings.TrimSpace(params.ContainerRef) == "" &&
		strings.TrimSpace(params.FlashLeaseDuration) == "" &&
		!params.BuildDiskImage &&
		!params.FlashEnabled &&
		!params.UseServiceAccountAuth {
		return nil
	}

	return params
}

func printBuildList(items []buildapitypes.BuildListItem) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	if _, err := fmt.Fprintln(w, "NAME\tSTATUS\tAGE\tREQUESTED BY\tARTIFACT"); err != nil {
		return err
	}
	for _, it := range items {
		artifact := it.DiskImage
		if artifact == "" {
			artifact = it.ContainerImage
		}
		if _, err := fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\n",
			it.Name,
			it.Phase,
			formatAge(it.CreatedAt),
			it.RequestedBy,
			artifact,
		); err != nil {
			return err
		}
	}
	return w.Flush()
}

func printBuildDetails(st *buildapitypes.BuildResponse) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	rows := [][2]string{
		{"Name", st.Name},
		{"Phase", st.Phase},
		{"Message", st.Message},
		{"Requested By", valueOrDash(st.RequestedBy)},
		{"Start Time", valueOrDash(st.StartTime)},
		{"Completion Time", valueOrDash(st.CompletionTime)},
		{"Container Image", valueOrDash(st.ContainerImage)},
		{"Disk Image", valueOrDash(st.DiskImage)},
		{"Warning", valueOrDash(st.Warning)},
	}

	if st.Parameters != nil {
		rows = append(rows,
			[2]string{"Architecture", valueOrDash(st.Parameters.Architecture)},
			[2]string{"Distro", valueOrDash(st.Parameters.Distro)},
			[2]string{"Target", valueOrDash(st.Parameters.Target)},
			[2]string{"Mode", valueOrDash(st.Parameters.Mode)},
			[2]string{"Export Format", valueOrDash(st.Parameters.ExportFormat)},
			[2]string{"Compression", valueOrDash(st.Parameters.Compression)},
			[2]string{"Storage Class", valueOrDash(st.Parameters.StorageClass)},
			[2]string{"AIB Image", valueOrDash(st.Parameters.AutomotiveImageBuilder)},
			[2]string{"Builder Image", valueOrDash(st.Parameters.BuilderImage)},
		)
	}

	if st.Jumpstarter != nil {
		rows = append(rows,
			[2]string{"Jumpstarter Available", fmt.Sprintf("%t", st.Jumpstarter.Available)},
			[2]string{"Jumpstarter Exporter", valueOrDash(st.Jumpstarter.ExporterSelector)},
			[2]string{"Jumpstarter Flash Cmd", valueOrDash(st.Jumpstarter.FlashCmd)},
			[2]string{"Jumpstarter Lease ID", valueOrDash(st.Jumpstarter.LeaseID)},
		)
	}

	for _, row := range rows {
		if _, err := fmt.Fprintf(w, "%s\t%s\n", row[0], row[1]); err != nil {
			return err
		}
	}
	return w.Flush()
}

func valueOrDash(v string) string {
	if strings.TrimSpace(v) == "" {
		return "-"
	}
	return v
}

func formatAge(rfcTime string) string {
	t, err := time.Parse(time.RFC3339, rfcTime)
	if err != nil {
		return rfcTime
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}
