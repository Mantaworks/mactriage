package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Mantaworks/mactriage/internal/knowledge"
	"github.com/Mantaworks/mactriage/internal/present"
	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/Mantaworks/mactriage/internal/reportutil"
	"github.com/Mantaworks/mactriage/internal/support"
	"github.com/spf13/cobra"
)

func (a *application) explainCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "explain <finding-code>",
		Short: "Explain a diagnostic code in plain language",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			entry, ok := knowledge.Lookup(args[0])
			if !ok {
				return fmt.Errorf("unknown diagnostic code %q", args[0])
			}
			if a.opts.output != "" {
				if err := present.WriteAtomic(a.opts.output, 0o600, func(w io.Writer) error { return json.NewEncoder(w).Encode(entry) }); err != nil {
					return err
				}
			}
			if a.opts.json {
				if err := json.NewEncoder(a.config.Out).Encode(entry); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(a.config.Out, "%s\nCode: %s\n\nWhat it means\n  %s\n\nWhat to do\n  %s\n\nWhat mactriage will not do\n  %s\n", entry.Title, entry.Code, entry.Meaning, entry.Next, entry.Safety)
			}
			a.setExit(cmd, 0)
			return nil
		},
	}
}

func (a *application) summarizeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "summarize <report.json>",
		Short: "Create a help-desk-ready Markdown summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := reportutil.Load(args[0])
			if err != nil {
				return fmt.Errorf("read report: %w", err)
			}
			r = a.redactReport(r)
			markdown := support.MarkdownSummary(r)
			value := struct {
				SchemaVersion string `json:"schema_version"`
				Type          string `json:"type"`
				Markdown      string `json:"markdown"`
			}{report.SchemaVersion, "summary", markdown}
			if a.opts.output != "" {
				if err := present.WriteAtomic(a.opts.output, 0o600, func(w io.Writer) error {
					if a.opts.json {
						return json.NewEncoder(w).Encode(value)
					}
					_, err := io.WriteString(w, markdown)
					return err
				}); err != nil {
					return err
				}
			}
			if a.opts.json {
				if err := json.NewEncoder(a.config.Out).Encode(value); err != nil {
					return err
				}
			} else {
				fmt.Fprint(a.config.Out, markdown)
			}
			a.setExit(cmd, 0)
			return nil
		},
	}
}

func (a *application) compareCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "compare <before.json> <after.json>",
		Short: "Compare two mactriage reports",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			before, err := reportutil.Load(args[0])
			if err != nil {
				return fmt.Errorf("read before report: %w", err)
			}
			after, err := reportutil.Load(args[1])
			if err != nil {
				return fmt.Errorf("read after report: %w", err)
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
}

func (a *application) renderComparison(comparison reportutil.Comparison) {
	fmt.Fprintln(a.config.Out, "mactriage comparison")
	printCodes := func(label string, codes []string) {
		fmt.Fprintf(a.config.Out, "\n%s (%d)\n", label, len(codes))
		if len(codes) == 0 {
			fmt.Fprintln(a.config.Out, "  None")
			return
		}
		fmt.Fprintln(a.config.Out, "  "+strings.Join(codes, "\n  "))
	}
	printCodes("Resolved findings", comparison.Resolved)
	printCodes("New findings", comparison.Added)
	printCodes("Unchanged findings", comparison.Unchanged)
	if len(comparison.EvidenceChanges) > 0 {
		fmt.Fprintln(a.config.Out, "\nEvidence changes")
		for _, change := range comparison.EvidenceChanges {
			fmt.Fprintf(a.config.Out, "  %s: %s → %s\n", change.ID, change.Before, change.After)
		}
	}
	if len(comparison.MetricChanges) > 0 {
		fmt.Fprintln(a.config.Out, "\nHealth metric changes")
		for _, change := range comparison.MetricChanges {
			fmt.Fprintf(a.config.Out, "  %s: %.1f → %.1f %s\n", change.Metric, change.Before, change.After, change.Unit)
		}
	}
	if len(comparison.NewIntelOnly) > 0 {
		fmt.Fprintln(a.config.Out, "\nNew Intel-only applications")
		fmt.Fprintln(a.config.Out, "  "+strings.Join(comparison.NewIntelOnly, "\n  "))
	}
}
