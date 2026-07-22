package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/present"
	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/spf13/cobra"
)

func (a *application) scanCommand() *cobra.Command {
	var limit, workers int
	cmd := &cobra.Command{
		Use:   "scan [directory]",
		Short: "Check installed applications for compatibility and integrity problems",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 1 || limit > 5000 {
				return fmt.Errorf("--limit must be between 1 and 5000")
			}
			if workers < 1 || workers > 16 {
				return fmt.Errorf("--workers must be between 1 and 16")
			}
			var roots []string
			if len(args) == 1 {
				roots = []string{args[0]}
			}
			scanner := macos.AppScanner{Runner: a.runner}
			work := func(emit func(present.ProgressEvent)) (report.Report, error) {
				started := time.Now()
				emit(present.ProgressEvent{ID: "scan", Label: "Inspect application bundles", Status: "running"})
				r, err := scanner.Scan(cmd.Context(), roots, limit, workers)
				status := string(report.StatusOK)
				if err != nil {
					status = string(report.StatusFailed)
				}
				emit(present.ProgressEvent{ID: "scan", Label: "Inspect application bundles", Status: status, Duration: time.Since(started)})
				return diagnosis.Analyze(r), err
			}
			var r report.Report
			var err error
			switch {
			case a.opts.json:
				r, err = work(func(present.ProgressEvent) {})
			case a.animate():
				r, err = present.RunProgress(cmd.Context(), a.config.Err, a.color(), work)
			default:
				r, err = present.PlainProgress(a.config.Err, work)
			}
			if err != nil {
				return err
			}
			if err := a.renderReport(r); err != nil {
				return err
			}
			if !a.opts.json {
				renderScannedApps(a.config.Out, r)
			}
			a.setExit(cmd, r.ExitCode())
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 250, "maximum applications to inspect")
	cmd.Flags().IntVar(&workers, "workers", 6, "concurrent application inspections")
	return cmd
}

func renderScannedApps(out interface{ Write([]byte) (int, error) }, r report.Report) {
	for _, evidence := range r.Evidence {
		data, ok := evidence.Data.(report.ScanData)
		if !ok {
			continue
		}
		problemCount := 0
		for _, app := range data.Apps {
			if len(app.Issues) > 0 {
				problemCount++
			}
		}
		if problemCount == 0 {
			fmt.Fprintf(out, "\nChecked applications\n  %d inspected · no compatibility or integrity problems found\n", len(data.Apps))
			return
		}
		fmt.Fprintf(out, "\nApplications needing attention (%d)\n", problemCount)
		for _, app := range data.Apps {
			if len(app.Issues) == 0 {
				continue
			}
			fmt.Fprintf(out, "  %s\n    %s\n    %s\n", app.Name, app.Path, strings.Join(app.Issues, ", "))
		}
		return
	}
}
