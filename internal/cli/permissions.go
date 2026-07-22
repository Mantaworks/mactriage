package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/Mantaworks/mactriage/internal/action"
	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/present"
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
			if a.canPrompt() && !a.opts.json && hasAction(r, action.OpenSecurity) {
				spec, _ := action.Lookup(action.OpenSecurity, selected.Path)
				description := spec.Definition.Description + "\nCommand: " + strings.Join(spec.Definition.Command, " ") + "\nDefault: No."
				approved, confirmErr := present.Confirm(spec.Definition.Title+"?", description, a.opts.accessible)
				if confirmErr != nil {
					return confirmErr
				}
				if approved {
					if _, err := (action.Executor{Runner: a.runner}).Execute(cmd.Context(), action.OpenSecurity, selected.Path); err != nil {
						return err
					}
					fmt.Fprintln(a.config.Err, "Privacy & Security opened. No permission was changed. Rechecking evidence…")
					r, err = inspector.Inspect(cmd.Context(), selected, lookback)
					if err != nil {
						return err
					}
					r = diagnosis.Analyze(r)
					if err := a.renderReport(r); err != nil {
						return err
					}
				}
			}
			a.setExit(cmd, r.ExitCode())
			return nil
		},
	}
	cmd.Flags().DurationVar(&lookback, "lookback", 10*time.Minute, "privacy-log lookback window")
	return cmd
}

func hasAction(r report.Report, id report.ActionID) bool {
	for _, available := range r.Actions {
		if available.ID == id {
			return true
		}
	}
	return false
}
