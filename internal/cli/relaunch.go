package cli

import (
	"errors"
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

func (a *application) relaunchCommand() *cobra.Command {
	var observe time.Duration
	cmd := &cobra.Command{
		Use:   "relaunch <application>",
		Short: "Safely relaunch an application and verify recovery",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if observe < time.Second || observe > 30*time.Second {
				return errors.New("--observe must be between 1s and 30s")
			}
			apps, err := (macos.Resolver{Runner: a.runner}).Resolve(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			selected, err := a.chooseApp(apps)
			if err != nil {
				return err
			}
			processName := selected.Executable
			if processName == "" {
				processName = strings.TrimSuffix(selected.Name, ".app")
			}
			executor := action.Executor{Runner: a.runner}
			pids, err := executor.AppPIDs(cmd.Context(), processName)
			if err != nil {
				return fmt.Errorf("inspect running application processes: %w", err)
			}
			r := report.New("relaunch", selected.Path)
			r.Evidence = append(r.Evidence, report.Evidence{ID: report.EvidenceRelaunch, Status: report.StatusOK, Summary: fmt.Sprintf("Found %d running application processes", len(pids)), Data: report.RelaunchData{ProcessName: processName, PIDs: pids}})
			definition, _ := action.Definition(action.RelaunchApp, selected.Path)
			r.Actions = append(r.Actions, definition)
			if err := a.renderReport(r); err != nil {
				return err
			}
			if a.opts.json || !a.canPrompt() {
				a.setExit(cmd, 0)
				return nil
			}
			description := fmt.Sprintf("Running PIDs: %v\nThis can discard unsaved work. mactriage will send SIGTERM, wait, reopen the app, and observe it for %s. Default: No.", pids, observe)
			approved, err := present.Confirm("Gracefully relaunch "+selected.Name+"?", description, a.opts.accessible)
			if err != nil {
				return err
			}
			if !approved {
				fmt.Fprintln(a.config.Err, "No changes made.")
				a.setExit(cmd, 0)
				return nil
			}
			outcome, relaunchErr := executor.RelaunchApp(cmd.Context(), selected.Path, processName, pids, false, observe)
			if errors.Is(relaunchErr, action.ErrProcessStillRunning) {
				force, confirmErr := present.Confirm("Force the application to quit?", "SIGTERM did not stop the app. SIGKILL can discard unsaved work and prevents normal cleanup. mactriage will reopen and verify the app afterward. Default: No.", a.opts.accessible)
				if confirmErr != nil {
					return confirmErr
				}
				if !force {
					fmt.Fprintln(a.config.Err, "The app was not force-quit. No relaunch was attempted.")
					a.setExit(cmd, 0)
					return nil
				}
				outcome, relaunchErr = executor.RelaunchApp(cmd.Context(), selected.Path, processName, pids, true, observe)
			}
			r.Actions = nil
			status, summary := report.StatusOK, "Application relaunched and remained running"
			if relaunchErr != nil {
				status, summary = report.StatusFailed, "Application relaunch could not be verified"
			}
			r.Evidence = []report.Evidence{{ID: report.EvidenceRelaunch, Status: status, Summary: summary, Error: errorText(relaunchErr), Data: report.RelaunchData{ProcessName: processName, PIDs: outcome.OldPIDs, NewPIDs: outcome.NewPIDs, Forced: outcome.Forced, Survived: outcome.Survived}}}
			r = diagnosis.Analyze(r)
			if err := a.renderReport(r); err != nil {
				return err
			}
			a.setReportExit(cmd, r)
			return nil
		},
	}
	cmd.Flags().DurationVar(&observe, "observe", 3*time.Second, "how long the relaunched app must remain running")
	return cmd
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
