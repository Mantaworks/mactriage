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
		{},
		{Stdout: "99\n"},
		{Stdout: "99\n"},
		{},
		{Stdout: "99\n100\n"},
		{Stdout: "99\n100\n"},
	}}
	executor := action.Executor{Runner: runner, PollInterval: time.Millisecond, TerminateTimeout: 10 * time.Millisecond}
	result, err := executor.RelaunchApp(context.Background(), "/Applications/Example.app", "Example", []int{10, 11}, false, time.Millisecond)
	if err != nil {
		t.Fatalf("RelaunchApp returned error: %v", err)
	}
	if len(result.OldPIDs) != 2 || len(result.NewPIDs) != 1 || result.NewPIDs[0] != 100 || !result.Survived || result.Forced {
		t.Fatalf("unexpected relaunch result: %#v", result)
	}
	if len(runner.commands) == 0 || runner.commands[0] != "/bin/kill -TERM 10 11" {
		t.Fatalf("unapproved PID was signaled: %#v", runner.commands)
	}
}

func TestForcedRelaunchSignalsOnlyStillRunningApprovedPIDs(t *testing.T) {
	runner := &sequenceRunner{results: []platform.Result{
		{Stdout: "11\n99\n"},
		{},
		{Stdout: "99\n"},
		{Stdout: "99\n"},
		{},
		{Stdout: "99\n100\n"},
		{Stdout: "99\n100\n"},
	}}
	executor := action.Executor{Runner: runner, PollInterval: time.Millisecond, TerminateTimeout: 10 * time.Millisecond}
	result, err := executor.RelaunchApp(context.Background(), "/Applications/Example.app", "Example", []int{10, 11}, true, time.Millisecond)
	if err != nil || !result.Forced || !result.Survived {
		t.Fatalf("result=%#v error=%v", result, err)
	}
	if len(runner.commands) < 2 || runner.commands[1] != "/bin/kill -KILL 11" {
		t.Fatalf("force signal escaped approved live set: %#v", runner.commands)
	}
}

type sequenceRunner struct {
	results  []platform.Result
	calls    int
	commands []string
}

func (r *sequenceRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	r.commands = append(r.commands, path+" "+strings.Join(args, " "))
	if r.calls >= len(r.results) {
		return platform.Result{ExitCode: 1, Err: errors.New("unexpected call")}
	}
	result := r.results[r.calls]
	r.calls++
	return result
}
