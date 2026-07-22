package cli

import (
	"fmt"
	"time"

	"github.com/Mantaworks/mactriage/internal/action"
	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/spf13/cobra"
)

func (a *application) permissionsCommand() *cobra.Command {
	var lookback time.Duration
	cmd := &cobra.Command{
		Use:   "permissions <application>",
		Short: "Explain macOS privacy permission denials",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if lookback < time.Minute || lookback > 24*time.Hour {
				return fmt.Errorf("--lookback must be between 1m and 24h")
			}
			resolver := macos.Resolver{Runner: a.runner}
			apps, err := resolver.Resolve(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			selected, err := a.chooseApp(apps)
			if err != nil {
				return err
			}
			if !a.opts.json {
				fmt.Fprintf(a.config.Err, "mactriage will inspect declared entitlements and the last %s of bounded privacy logs. It will not read or modify the TCC database.\n\n", lookback)
			}
			inspector := macos.PermissionInspector{Runner: a.runner}
			r, err := inspector.Inspect(cmd.Context(), selected, lookback)
			if err != nil {
				return err
			}
			r = diagnosis.Analyze(r)
			if err := a.renderReport(r); err != nil {
				return err
			}
			if a.canPrompt() && !a.opts.json {
				rechecked, actionErr := a.offerReportActions(cmd.Context(), selected.Path, r, func(_ action.RecheckMode) (*report.Report, error) {
					updated, inspectErr := inspector.Inspect(cmd.Context(), selected, lookback)
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
		},
	}
	cmd.Flags().DurationVar(&lookback, "lookback", 10*time.Minute, "privacy-log lookback window")
	return cmd
}
