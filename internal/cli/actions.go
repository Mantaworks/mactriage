package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Mantaworks/mactriage/internal/action"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/present"
	"github.com/Mantaworks/mactriage/internal/report"
)

func (a *application) offerActions(ctx context.Context, selected macos.App, opts macos.DiagnoseOptions, r report.Report) (*report.Report, error) {
	for _, available := range r.Actions {
		description := available.Description
		if len(available.Command) > 0 {
			description += "\nCommand: " + strings.Join(available.Command, " ")
		}
		approved, err := present.Confirm(available.Title+"?", description+"\nDefault: No.", a.opts.accessible)
		if err != nil {
			return nil, err
		}
		if !approved {
			continue
		}
		spec, ok := action.Lookup(available.ID, selected.Path)
		if !ok {
			return nil, fmt.Errorf("action %q is not allowlisted", available.ID)
		}
		if available.RequiresRoot && os.Geteuid() != 0 {
			if len(available.Command) < 2 || available.Command[0] != "mactriage" {
				return nil, fmt.Errorf("action %q cannot be elevated safely", available.ID)
			}
			code, err := a.runSudo(ctx, available.Command[1:])
			if err != nil || code != 0 {
				return nil, fmt.Errorf("action %q exited with code %d: %w", available.ID, code, err)
			}
		} else if spec.Executable {
			if _, err := (action.Executor{Runner: a.runner}).Execute(ctx, available.ID, selected.Path); err != nil {
				return nil, err
			}
		}
		if spec.Completion != "" {
			fmt.Fprintln(a.config.Err, "\n"+spec.Completion)
		}
		switch spec.Recheck {
		case action.RecheckPassive:
			opts.NoLaunch = true
		case action.RecheckLaunch:
			opts.NoLaunch = false
		default:
			continue
		}
		return a.recheckAndRender(ctx, selected.Path, opts)
	}
	return nil, nil
}

func (a *application) recheckAndRender(ctx context.Context, target string, opts macos.DiagnoseOptions) (*report.Report, error) {
	rechecked, _, err := a.collectDiagnosis(ctx, target, opts)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := a.renderReport(rechecked); err != nil {
		return nil, err
	}
	return &rechecked, nil
}
