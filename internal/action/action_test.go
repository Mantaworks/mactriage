package action_test

import (
	"context"
	"errors"
	"testing"

	"github.com/upsidedly/mactriage/internal/action"
	"github.com/upsidedly/mactriage/internal/platform"
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
