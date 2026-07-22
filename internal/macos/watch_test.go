package macos_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/upsidedly/mactriage/internal/macos"
	"github.com/upsidedly/mactriage/internal/platform"
)

func TestWatcherEmitsNumericDescriptorSample(t *testing.T) {
	runner := watchRunner{}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	watcher := macos.Watcher{Runner: runner, Now: func() time.Time {
		clock = clock.Add(10 * time.Second)
		return clock
	}}
	var events []macos.WatchEvent
	err := watcher.Run(context.Background(), macos.WatchOptions{Target: "example", Interval: time.Millisecond, Window: time.Minute, WarnGrowth: 150, Duration: time.Second}, func(event macos.WatchEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(events) != 1 || events[0].DescriptorCount != 2 || events[0].PID != 42 {
		t.Fatalf("unexpected events: %#v", events)
	}
}

type watchRunner struct{}

func (watchRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/pgrep":
		return platform.Result{Stdout: "42\n"}
	case "/usr/sbin/lsof":
		return platform.Result{Stdout: strings.Join([]string{"p42", "cexample", "fcwd", "f0", "tCHR", "f9u", "tREG"}, "\x00") + "\x00"}
	case "/usr/bin/log":
		return platform.Result{Stdout: ""}
	default:
		return platform.Result{Err: errors.New("unexpected command: " + path)}
	}
}
