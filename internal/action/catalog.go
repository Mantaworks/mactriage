package action

import (
	"context"
	"fmt"

	"github.com/Mantaworks/mactriage/internal/report"
)

const (
	RepairSyspolicyd   report.ActionID = "repair.syspolicyd"
	OpenSecurity       report.ActionID = "open.security"
	LaunchRosetta      report.ActionID = "launch.rosetta_prompt"
	RetryLaunch        report.ActionID = "retry.launch"
	OpenSoftwareUpdate report.ActionID = "open.software_update"
	RelaunchApp        report.ActionID = "relaunch.app"
)

type RecheckMode int

const (
	RecheckNone RecheckMode = iota
	RecheckPassive
	RecheckLaunch
)

type Spec struct {
	Definition report.Action
	Recheck    RecheckMode
	Completion string
	Executable bool
	run        func(Executor, context.Context, string) (Outcome, error)
}

func Lookup(id report.ActionID, target string) (Spec, bool) {
	switch id {
	case RepairSyspolicyd:
		return Spec{
			Definition: report.Action{ID: id, Title: "Restart syspolicyd", Description: "Terminate the confirmed wedged policy daemon, verify launchd starts a new process, then rerun the affected checks.", Command: []string{"mactriage", "repair", "syspolicyd", "--yes"}, RequiresRoot: true, Available: true},
			Recheck:    RecheckLaunch, Completion: "Repair completed. Rechecking the application…", Executable: true,
			run: func(e Executor, ctx context.Context, _ string) (Outcome, error) {
				result, err := e.RestartSyspolicyd(ctx)
				return Outcome{Restart: &result}, err
			},
		}, true
	case OpenSecurity:
		return Spec{
			Definition: report.Action{ID: id, Title: "Open Privacy & Security", Description: "Open the macOS settings pane, verify System Settings started, then rerun the policy check without changing its decision.", Command: []string{"open", "x-apple.systempreferences:com.apple.preference.security?General"}, Available: true},
			Recheck:    RecheckPassive, Completion: "Privacy & Security is open and verified. mactriage has not changed the policy decision. Rechecking policy evidence…", Executable: true,
			run: func(e Executor, ctx context.Context, _ string) (Outcome, error) {
				return Outcome{}, e.openSecurity(ctx)
			},
		}, true
	case LaunchRosetta:
		return Spec{
			Definition: report.Action{ID: id, Title: "Launch and install Rosetta if needed", Description: "Open the Intel application so macOS can present Apple's supported Rosetta installation prompt, then rerun launch checks.", Command: []string{"open", target}, Available: true},
			Recheck:    RecheckLaunch, Completion: "The app was launched. If Rosetta is missing, macOS will present Apple's installation prompt. Rechecking launch evidence…", Executable: true,
			run: func(e Executor, ctx context.Context, target string) (Outcome, error) {
				return Outcome{}, e.launchRosetta(ctx, target)
			},
		}, true
	case RetryLaunch:
		return Spec{
			Definition: report.Action{ID: id, Title: "Retry diagnosis and launch", Description: "Repeat the affected checks, launch the application once, and observe the result.", Command: []string{"mactriage", "diagnose", target}, Available: true},
			Recheck:    RecheckLaunch, Completion: "Retrying the affected checks and launch…",
		}, true
	case OpenSoftwareUpdate:
		return Spec{
			Definition: report.Action{ID: id, Title: "Open Software Update", Description: "Open the macOS Software Update pane so you can review available updates. mactriage will not install anything.", Command: []string{"open", "/System/Library/PreferencePanes/SoftwareUpdate.prefPane"}, Available: true},
			Recheck:    RecheckPassive, Completion: "Software Update opened. No update was installed. Rechecking availability…", Executable: true,
			run: func(e Executor, ctx context.Context, _ string) (Outcome, error) {
				return Outcome{}, e.openSoftwareUpdate(ctx)
			},
		}, true
	case RelaunchApp:
		return Spec{
			Definition: report.Action{ID: id, Title: "Gracefully relaunch application", Description: "Warn about unsaved work, request graceful termination, reopen the application, and verify it remains running. Force termination requires a separate confirmation.", Command: []string{"mactriage", "relaunch", target}, Available: true},
		}, true
	default:
		return Spec{}, false
	}
}

func Definition(id report.ActionID, target string) (report.Action, bool) {
	spec, ok := Lookup(id, target)
	if !ok {
		return report.Action{}, false
	}
	return spec.Definition, true
}

func (e Executor) Execute(ctx context.Context, id report.ActionID, target string) (Outcome, error) {
	spec, ok := Lookup(id, target)
	if !ok || spec.run == nil {
		return Outcome{}, fmt.Errorf("action %q is not executable", id)
	}
	if e.Runner == nil {
		return Outcome{}, fmt.Errorf("action executor requires a command runner")
	}
	return spec.run(e, ctx, target)
}
