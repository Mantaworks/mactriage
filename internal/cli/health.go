package cli

import (
	"fmt"

	"github.com/Mantaworks/mactriage/internal/action"
	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/spf13/cobra"
)

func (a *application) storageCommand() *cobra.Command {
	var details, fix bool
	cmd := &cobra.Command{Use: "storage", Short: "Explain startup-disk capacity by safe aggregate category", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if details && !a.opts.json {
			fmt.Fprintln(a.config.Err, "mactriage will measure standard folders and report aggregate category sizes only. It will not list or delete files.")
			fmt.Fprintln(a.config.Err)
		}
		r, err := (macos.StorageInspector{Runner: a.runner}).Inspect(cmd.Context(), details)
		if err != nil {
			return err
		}
		r = diagnosis.Analyze(r)
		if err := a.renderReport(r); err != nil {
			return err
		}
		if fix && a.canPrompt() && !a.opts.json {
			rechecked, actionErr := a.offerReportActions(cmd.Context(), "startup disk", r, func(action.RecheckMode) (*report.Report, error) {
				updated, inspectErr := (macos.StorageInspector{Runner: a.runner}).Inspect(cmd.Context(), details)
				if inspectErr != nil {
					return nil, inspectErr
				}
				updated = diagnosis.Analyze(updated)
				if renderErr := a.renderReport(updated); renderErr != nil {
					return nil, renderErr
				}
				return &updated, nil
			})
			if actionErr != nil {
				return actionErr
			}
			if rechecked != nil {
				r = *rechecked
			}
		}
		a.setReportExit(cmd, r)
		return nil
	}}
	cmd.Flags().BoolVar(&details, "details", false, "measure aggregate sizes for standard storage categories")
	cmd.Flags().BoolVar(&fix, "fix", false, "offer an eligible safe follow-through action")
	return cmd
}

func (a *application) startupCommand() *cobra.Command {
	var fix bool
	cmd := &cobra.Command{Use: "startup", Short: "List sanitized Login Items and launch-agent identifiers", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		r, err := (macos.Doctor{Runner: a.runner}).Inspect(cmd.Context(), macos.DoctorOptions{Only: []string{"startup"}})
		if err != nil {
			return err
		}
		r.Command, r.Target = "startup", "this Mac"
		r = diagnosis.Analyze(r)
		if err := a.renderReport(r); err != nil {
			return err
		}
		if fix && a.canPrompt() && !a.opts.json {
			rechecked, actionErr := a.offerReportActions(cmd.Context(), "startup items", r, func(action.RecheckMode) (*report.Report, error) {
				updated, inspectErr := (macos.Doctor{Runner: a.runner}).Inspect(cmd.Context(), macos.DoctorOptions{Only: []string{"startup"}})
				if inspectErr != nil {
					return nil, inspectErr
				}
				updated.Command, updated.Target = "startup", "this Mac"
				updated = diagnosis.Analyze(updated)
				if renderErr := a.renderReport(updated); renderErr != nil {
					return nil, renderErr
				}
				return &updated, nil
			})
			if actionErr != nil {
				return actionErr
			}
			if rechecked != nil {
				r = *rechecked
			}
		}
		a.setReportExit(cmd, r)
		return nil
	}}
	cmd.Flags().BoolVar(&fix, "fix", false, "offer an eligible safe follow-through action")
	return cmd
}
