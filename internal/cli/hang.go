package cli

import (
	"fmt"

	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/spf13/cobra"
)

func (a *application) hangCommand() *cobra.Command {
	var cpuThreshold float64
	var memoryThresholdMiB uint64
	var sampleOutput string
	cmd := &cobra.Command{
		Use:   "hang <process-or-pid>",
		Short: "Inspect a frozen, slow, or resource-heavy application",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cpuThreshold <= 0 || cpuThreshold > 10000 {
				return fmt.Errorf("--cpu-threshold must be greater than 0 and no more than 10000")
			}
			if memoryThresholdMiB == 0 {
				return fmt.Errorf("--memory-threshold-mib must be greater than 0")
			}
			if !a.opts.json {
				fmt.Fprintln(a.config.Err, "mactriage will inspect the running process without stopping or modifying it.")
				if sampleOutput == "" {
					fmt.Fprintln(a.config.Err, "No raw process sample will be collected; use --sample-output to request one explicitly.")
					fmt.Fprintln(a.config.Err)
				}
			}
			inspector := macos.ProcessInspector{Runner: a.runner}
			r, err := inspector.Inspect(cmd.Context(), args[0], macos.ProcessThresholds{CPUPercent: cpuThreshold, MemoryBytes: memoryThresholdMiB << 20})
			if err != nil {
				return err
			}
			r = diagnosis.Analyze(r)
			if sampleOutput != "" {
				pid := processPID(r)
				if pid == 0 {
					return fmt.Errorf("could not determine process PID for sampling")
				}
				if !a.opts.json {
					fmt.Fprintf(a.config.Err, "Collecting Apple's three-second process sample into %s. Stack data can contain private paths and symbols.\n", sampleOutput)
				}
				if err := inspector.Sample(cmd.Context(), pid, sampleOutput); err != nil {
					return err
				}
			}
			if err := a.renderReport(r); err != nil {
				return err
			}
			a.setExit(cmd, r.ExitCode())
			return nil
		},
	}
	cmd.Flags().Float64Var(&cpuThreshold, "cpu-threshold", 80, "warn at this process CPU percentage")
	cmd.Flags().Uint64Var(&memoryThresholdMiB, "memory-threshold-mib", 4096, "warn at this resident-memory size in MiB")
	cmd.Flags().StringVar(&sampleOutput, "sample-output", "", "explicitly collect a private raw Apple process sample at PATH")
	return cmd
}

func processPID(r report.Report) int {
	for _, evidence := range r.Evidence {
		if data, ok := evidence.Data.(report.ProcessData); ok {
			return data.PID
		}
	}
	return 0
}
