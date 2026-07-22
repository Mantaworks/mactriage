package action_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/action"
	"github.com/Mantaworks/mactriage/internal/platform"
)

func TestRestartSyspolicydRequiresRoot(t *testing.T) {
	executor := action.Executor{Runner: &sequenceRunner{}, EUID: func() int { return 501 }}
	_, err := executor.RestartSyspolicyd(context.Background())
	if !errors.Is(err, action.ErrNeedsElevation) {
		t.Fatalf("error = %v, want ErrNeedsElevation", err)
	}
}

func TestRestartSyspolicydVerifiesNewPID(t *testing.T) {
	runner := &sequenceRunner{results: []platform.Result{
		{Stdout: "497\n", ExitCode: 0},
		{ExitCode: 0},
		{Stdout: "812\n", ExitCode: 0},
	}}
	executor := action.Executor{Runner: runner, EUID: func() int { return 0 }}
	result, err := executor.RestartSyspolicyd(context.Background())
	if err != nil {
		t.Fatalf("RestartSyspolicyd returned error: %v", err)
	}
	if result.OldPID != 497 || result.NewPID != 812 || !result.Restarted {
		t.Fatalf("unexpected restart result: %#v", result)
	}
}

func TestOpenSecurityActionVerifiesSystemSettings(t *testing.T) {
	runner := &sequenceRunner{results: []platform.Result{{}, {Stdout: "99\n"}}}
	_, err := (action.Executor{Runner: runner, PollInterval: time.Millisecond}).Execute(context.Background(), action.OpenSecurity, "")
	if err != nil || runner.calls != 2 {
		t.Fatalf("Execute calls=%d error=%v", runner.calls, err)
	}
}

func TestOpenSoftwareUpdateActionVerifiesSystemSettings(t *testing.T) {
	runner := &sequenceRunner{results: []platform.Result{{}, {Stdout: "99\n"}}}
	_, err := (action.Executor{Runner: runner, PollInterval: time.Millisecond}).Execute(context.Background(), action.OpenSoftwareUpdate, "this Mac")
	if err != nil || runner.calls != 2 {
		t.Fatalf("Execute calls=%d error=%v", runner.calls, err)
	}
}

func TestActionCatalogContainsPermissionAndFollowup(t *testing.T) {
	definition, ok := action.Definition(action.RepairSyspolicyd, "/Applications/Example.app")
	if !ok || !definition.RequiresRoot || len(definition.Command) == 0 || !strings.Contains(definition.Description, "rerun") {
		t.Fatalf("incomplete action definition: %#v", definition)
	}
}

func TestRelaunchAppTerminatesLaunchesAndVerifiesSurvival(t *testing.T) {
	runner := &sequenceRunner{results: []platform.Result{
		{Stdout: "10\n11\n"},
		{},
		{ExitCode: 1, Err: errors.New("not running")},
		{},
		{Stdout: "99\n"},
		{Stdout: "99\n"},
	}}
	executor := action.Executor{Runner: runner, PollInterval: time.Millisecond, TerminateTimeout: 10 * time.Millisecond}
	result, err := executor.RelaunchApp(context.Background(), "/Applications/Example.app", "Example", false, time.Millisecond)
	if err != nil {
		t.Fatalf("RelaunchApp returned error: %v", err)
	}
	if len(result.OldPIDs) != 2 || len(result.NewPIDs) != 1 || result.NewPIDs[0] != 99 || !result.Survived || result.Forced {
		t.Fatalf("unexpected relaunch result: %#v", result)
	}
}

type sequenceRunner struct {
	results []platform.Result
	calls   int
}

func (r *sequenceRunner) Run(context.Context, string, ...string) platform.Result {
	if r.calls >= len(r.results) {
		return platform.Result{ExitCode: 1, Err: errors.New("unexpected call")}
	}
	result := r.results[r.calls]
	r.calls++
	return result
}
