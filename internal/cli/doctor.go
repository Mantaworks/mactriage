package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Mantaworks/mactriage/internal/action"
	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/knowledge"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/present"
	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/spf13/cobra"
)

func (a *application) doctorCommand() *cobra.Command {
	var severity string
	var only, skip []string
	var fix bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Run a guided whole-Mac health check",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			minimum, err := parseSeverity(severity)
			if err != nil {
				return err
			}
			collect := func(emit func(present.ProgressEvent)) (report.Report, error) {
				doctor := macos.Doctor{Runner: a.runner, Emit: func(event macos.ProgressEvent) {
					emit(present.ProgressEvent{ID: event.ID, Label: event.Label, Status: event.Status, Duration: event.Duration})
				}}
				r, inspectErr := doctor.Inspect(cmd.Context(), macos.DoctorOptions{Only: only, Skip: skip})
				if inspectErr != nil {
					return report.Report{}, inspectErr
				}
				return filterSeverity(diagnosis.Analyze(r), minimum), nil
			}
			if !a.opts.json {
				fmt.Fprintln(a.config.Err, "mactriage will run bounded, read-only checks across this Mac. It will not delete files, change settings, or install updates.")
				fmt.Fprintln(a.config.Err)
			}
			var r report.Report
			switch {
			case a.opts.json:
				r, err = collect(func(present.ProgressEvent) {})
			case a.animate():
				r, err = present.RunProgress(cmd.Context(), a.config.Err, a.color(), collect)
			default:
				r, err = present.PlainProgress(a.config.Err, collect)
			}
			if err != nil {
				return err
			}
			if err := a.renderReport(r); err != nil {
				return err
			}
			if fix && a.canPrompt() && !a.opts.json {
				rechecked, actionErr := a.offerReportActions(cmd.Context(), "this Mac", r, func(_ action.RecheckMode) (*report.Report, error) {
					updated, updateErr := collect(func(present.ProgressEvent) {})
					if updateErr != nil {
						return nil, updateErr
					}
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
			a.setExit(cmd, r.ExitCode())
			return nil
		},
	}
	cmd.Flags().StringVar(&severity, "severity", "info", "minimum finding severity: info, warning, error, or critical")
	cmd.Flags().StringSliceVar(&only, "only", nil, "run only these checks: "+strings.Join(macos.DoctorChecks, ","))
	cmd.Flags().StringSliceVar(&skip, "skip", nil, "skip these checks: "+strings.Join(macos.DoctorChecks, ","))
	cmd.Flags().BoolVar(&fix, "fix", false, "interactively offer eligible safe actions (each still requires confirmation)")
	return cmd
}

func parseSeverity(value string) (report.Severity, error) {
	severity := report.Severity(strings.ToLower(strings.TrimSpace(value)))
	switch severity {
	case report.Info, report.Warning, report.Error, report.Critical:
		return severity, nil
	default:
		return "", errors.New("--severity must be info, warning, error, or critical")
	}
}

func filterSeverity(r report.Report, minimum report.Severity) report.Report {
	weight := map[report.Severity]int{report.Info: 0, report.Warning: 1, report.Error: 2, report.Critical: 3}
	filtered := r.Findings[:0]
	for _, finding := range r.Findings {
		if weight[finding.Severity] >= weight[minimum] {
			filtered = append(filtered, finding)
		}
	}
	r.Findings = filtered
	visible := make(map[string]bool, len(filtered))
	for _, finding := range filtered {
		visible[finding.Code] = true
	}
	actions := r.Actions[:0]
	for _, available := range r.Actions {
		if available.ID == action.OpenSoftwareUpdate && !visible[knowledge.CodeDoctorUpdatesAvailable] {
			continue
		}
		actions = append(actions, available)
	}
	r.Actions = actions
	return r
}
