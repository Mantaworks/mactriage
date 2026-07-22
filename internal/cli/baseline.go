package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Mantaworks/mactriage/internal/baseline"
	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/present"
	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/Mantaworks/mactriage/internal/reportutil"
	"github.com/spf13/cobra"
)

func (a *application) baselineCommand() *cobra.Command {
	root := &cobra.Command{Use: "baseline", Short: "Save and compare private Mac health snapshots"}
	root.AddCommand(a.baselineSaveCommand(), a.baselineListCommand(), a.baselineCompareCommand(), a.baselineDeleteCommand())
	return root
}

func (a *application) baselineStore() baseline.Store {
	return baseline.Store{Dir: a.config.BaselineDir}
}

func (a *application) baselineSaveCommand() *cobra.Command {
	var only, skip []string
	cmd := &cobra.Command{
		Use:   "save [name]",
		Short: "Save a private sanitized doctor baseline",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := time.Now().Format("20060102-150405")
			if len(args) == 1 {
				name = args[0]
			}
			r, err := (macos.Doctor{Runner: a.runner}).Inspect(cmd.Context(), macos.DoctorOptions{Only: only, Skip: skip})
			if err != nil {
				return err
			}
			r = diagnosis.Analyze(r)
			r = a.redactReport(r)
			path, err := a.baselineStore().Save(name, r)
			if err != nil {
				return err
			}
			value := struct {
				Type   string        `json:"type"`
				Name   string        `json:"name"`
				Path   string        `json:"path"`
				Report report.Report `json:"report"`
			}{"baseline_saved", name, path, r}
			if err := a.writeManagementResult(value, func(w io.Writer) { fmt.Fprintf(w, "Saved private baseline %q to %s\n", name, path) }); err != nil {
				return err
			}
			a.setReportExit(cmd, r)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&only, "only", nil, "run only selected doctor checks")
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "skip selected doctor checks")
	return cmd
}

func (a *application) baselineListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List saved health baselines",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := a.baselineStore().List()
			if err != nil {
				return err
			}
			value := struct {
				Type      string           `json:"type"`
				Baselines []baseline.Entry `json:"baselines"`
			}{"baseline_list", entries}
			if err := a.writeManagementResult(value, func(w io.Writer) {
				if len(entries) == 0 {
					fmt.Fprintln(w, "No baselines saved.")
					return
				}
				fmt.Fprintln(w, "Saved baselines")
				for _, entry := range entries {
					fmt.Fprintf(w, "  %s  %s\n", entry.Name, entry.GeneratedAt.Local().Format(time.RFC822))
				}
			}); err != nil {
				return err
			}
			a.setExit(cmd, 0)
			return nil
		},
	}
}

func (a *application) baselineCompareCommand() *cobra.Command {
	var only, skip []string
	cmd := &cobra.Command{
		Use:   "compare <baseline> [other-baseline]",
		Short: "Compare a baseline with another baseline or this Mac now",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			before, err := a.baselineStore().Load(args[0])
			if err != nil {
				return fmt.Errorf("load baseline %q: %w", args[0], err)
			}
			var after report.Report
			if len(args) == 2 {
				after, err = a.baselineStore().Load(args[1])
			} else {
				after, err = (macos.Doctor{Runner: a.runner}).Inspect(cmd.Context(), macos.DoctorOptions{Only: only, Skip: skip})
				after = diagnosis.Analyze(after)
			}
			if err != nil {
				return err
			}
			before, after = a.redactReport(before), a.redactReport(after)
			comparison := reportutil.Compare(before, after)
			if a.opts.output != "" {
				if err := present.WriteAtomic(a.opts.output, 0o600, func(w io.Writer) error { return json.NewEncoder(w).Encode(comparison) }); err != nil {
					return err
				}
			}
			if a.opts.json {
				if err := json.NewEncoder(a.config.Out).Encode(comparison); err != nil {
					return err
				}
			} else {
				a.renderComparison(comparison)
			}
			a.setExit(cmd, 0)
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&only, "only", nil, "run only selected doctor checks for the current comparison")
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "skip selected doctor checks for the current comparison")
	return cmd
}

func (a *application) baselineDeleteCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete one saved baseline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				if a.opts.json || !a.canPrompt() {
					return errors.New("baseline delete requires --yes when noninteractive")
				}
				approved, err := present.Confirm("Delete baseline "+args[0]+"?", "This removes only the selected mactriage baseline file. Default: No.", a.opts.accessible)
				if err != nil {
					return err
				}
				if !approved {
					fmt.Fprintln(a.config.Err, "No changes made.")
					a.setExit(cmd, 0)
					return nil
				}
			}
			if err := a.baselineStore().Delete(args[0]); err != nil {
				return err
			}
			value := struct {
				Deleted string `json:"deleted"`
			}{args[0]}
			if err := a.writeManagementResult(value, func(w io.Writer) { fmt.Fprintf(w, "Deleted baseline %q.\n", args[0]) }); err != nil {
				return err
			}
			a.setExit(cmd, 0)
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm deletion without an interactive prompt")
	return cmd
}

func (a *application) writeManagementResult(value any, human func(io.Writer)) error {
	if a.opts.output != "" {
		if err := present.WriteAtomic(a.opts.output, 0o600, func(w io.Writer) error { return json.NewEncoder(w).Encode(value) }); err != nil {
			return err
		}
	}
	if a.opts.json {
		return json.NewEncoder(a.config.Out).Encode(value)
	}
	human(a.config.Out)
	return nil
}
