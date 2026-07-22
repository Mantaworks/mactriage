package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/present"
	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/Mantaworks/mactriage/internal/reportutil"
	"github.com/Mantaworks/mactriage/internal/support"
	"github.com/atotto/clipboard"
	"github.com/spf13/cobra"
)

func (a *application) shareCommand() *cobra.Command {
	var copyRequested bool
	cmd := &cobra.Command{
		Use:   "share <report.json|application>",
		Short: "Create a sanitized Markdown support report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := a.shareReport(cmd, args[0])
			if err != nil {
				return err
			}
			r = a.redactReport(r)
			markdown := support.MarkdownSummary(r)
			if a.opts.output != "" {
				if err := present.WriteAtomic(a.opts.output, 0o600, func(w io.Writer) error {
					_, writeErr := io.WriteString(w, markdown)
					return writeErr
				}); err != nil {
					return err
				}
			}
			value := struct {
				SchemaVersion string `json:"schema_version"`
				Type          string `json:"type"`
				Markdown      string `json:"markdown"`
				CopyAvailable bool   `json:"copy_available"`
			}{report.SchemaVersion, "share", markdown, copyRequested}
			if a.opts.json {
				if err := json.NewEncoder(a.config.Out).Encode(value); err != nil {
					return err
				}
			} else {
				fmt.Fprint(a.config.Out, markdown)
			}
			if copyRequested && !a.opts.json && a.canPrompt() {
				approved, err := present.Confirm("Copy this sanitized report?", "The Markdown preview above will be written to the macOS clipboard. Nothing will be uploaded. Default: No.", a.opts.accessible)
				if err != nil {
					return err
				}
				if approved {
					if err := clipboard.WriteAll(markdown); err != nil {
						return fmt.Errorf("copy report: %w", err)
					}
					fmt.Fprintln(a.config.Err, "Sanitized report copied. Nothing was uploaded.")
				}
			}
			a.setExit(cmd, 0)
			return nil
		},
	}
	cmd.Flags().BoolVar(&copyRequested, "copy", false, "offer to copy the preview to the clipboard")
	return cmd
}

func (a *application) shareReport(cmd *cobra.Command, target string) (report.Report, error) {
	if info, err := os.Stat(target); err == nil && !info.IsDir() {
		r, loadErr := reportutil.Load(target)
		if loadErr != nil {
			return report.Report{}, fmt.Errorf("read report: %w", loadErr)
		}
		return r, nil
	}
	if strings.HasSuffix(strings.ToLower(target), ".json") {
		return report.Report{}, fmt.Errorf("report file was not found: %s", target)
	}
	r, _, err := a.collectDiagnosis(cmd.Context(), target, macos.DiagnoseOptions{NoLaunch: true})
	return r, err
}
