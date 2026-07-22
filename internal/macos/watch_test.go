package macos_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
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
	if len(events) != 1 || events[0].DescriptorCount != 2 || events[0].PID != 42 || events[0].CPUPercent != 42.5 || events[0].RSSBytes != 256*1024*1024 || events[0].Threads != 2 || events[0].SocketCount != 1 || events[0].MemoryFreePercent != 37 {
		t.Fatalf("unexpected events: %#v", events)
	}
}

func TestWatcherSurvivesNamedProcessPIDChange(t *testing.T) {
	runner := &restartWatchRunner{}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	watcher := macos.Watcher{Runner: runner, Now: func() time.Time {
		clock = clock.Add(time.Second)
		return clock
	}}
	var events []macos.WatchEvent
	err := watcher.Run(context.Background(), macos.WatchOptions{Target: "example", Interval: time.Millisecond, Window: time.Minute, WarnGrowth: 10, Duration: 5 * time.Second}, func(event macos.WatchEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	foundRestart := false
	for _, event := range events {
		foundRestart = foundRestart || event.Type == "restart" && event.PID == 43
	}
	if !foundRestart {
		t.Fatalf("missing restart event: %#v", events)
	}
}

func TestWatcherWarnsOnRepeatedRestartLoop(t *testing.T) {
	runner := &loopingWatchRunner{}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	watcher := macos.Watcher{Runner: runner, Now: func() time.Time {
		clock = clock.Add(time.Second)
		return clock
	}}
	var events []macos.WatchEvent
	err := watcher.Run(context.Background(), macos.WatchOptions{Target: "example", Interval: time.Millisecond, Window: time.Minute, Duration: 8 * time.Second}, func(event macos.WatchEvent) error {
		events = append(events, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		if event.Type == "restart" && event.Severity == "warning" && event.RestartCount >= 3 {
			found = true
		}
	}
	if !found {
		t.Fatalf("restart-loop warning missing: %#v", events)
	}
}

func TestWatcherFallsBackWhenLiveLogStreamFails(t *testing.T) {
	runner := &failingStreamRunner{}
	watcher := macos.Watcher{Runner: runner}
	err := watcher.Run(context.Background(), macos.WatchOptions{Target: "42", Interval: 5 * time.Millisecond, Window: time.Second, WarnGrowth: 10, Duration: 30 * time.Millisecond}, func(macos.WatchEvent) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if runner.logShowCalls == 0 {
		t.Fatal("watcher did not fall back to bounded log queries")
	}
}

func TestWatcherReturnsPersistentDescriptorPermissionFailure(t *testing.T) {
	runner := permissionWatchRunner{}
	err := (macos.Watcher{Runner: runner}).Run(context.Background(), macos.WatchOptions{Target: "example", Interval: time.Millisecond, Window: time.Second, Duration: time.Second}, func(macos.WatchEvent) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "permission") {
		t.Fatalf("error=%v, want persistent permission failure", err)
	}
}

func TestWatcherReturnsFixedPIDDescriptorFailure(t *testing.T) {
	err := (macos.Watcher{Runner: permissionWatchRunner{}}).Run(context.Background(), macos.WatchOptions{Target: "42", Interval: time.Millisecond, Window: time.Second, Duration: time.Second}, func(macos.WatchEvent) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "fixed PID") {
		t.Fatalf("error=%v, want fixed-PID descriptor failure", err)
	}
}

func TestWatcherBoundsMissingNamedProcessRetries(t *testing.T) {
	runner := &missingWatchRunner{}
	err := (macos.Watcher{Runner: runner}).Run(context.Background(), macos.WatchOptions{Target: "missing", Interval: time.Millisecond, Window: time.Second}, func(macos.WatchEvent) error { return nil })
	if err == nil || runner.calls != 4 {
		t.Fatalf("error=%v calls=%d, want bounded retries", err, runner.calls)
	}
}

func TestWatcherReturnsInterruption(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (macos.Watcher{Runner: watchRunner{}}).Run(ctx, macos.WatchOptions{Target: "example", Interval: time.Millisecond, Window: time.Second, Duration: time.Second}, func(macos.WatchEvent) error { return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
}

type watchRunner struct{}

func (watchRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/pgrep":
		return platform.Result{Stdout: "42\n"}
	case "/usr/sbin/lsof":
		return platform.Result{Stdout: strings.Join([]string{"p42", "cexample", "fcwd", "f0", "tIPv4", "f9u", "tREG"}, "\x00") + "\x00"}
	case "/bin/ps":
		if len(args) > 0 && args[0] == "-M" {
			return platform.Result{Stdout: "USER PID COMMAND\nuser 42 example\nuser 42 example\n"}
		}
		return platform.Result{Stdout: "42.5 262144 8\n"}
	case "/usr/bin/memory_pressure":
		return platform.Result{Stdout: "System-wide memory free percentage: 37%\n"}
	case "/usr/bin/log":
		return platform.Result{Stdout: ""}
	default:
		return platform.Result{Err: errors.New("unexpected command: " + path)}
	}
}

type restartWatchRunner struct {
	pgrepCalls int
	lsofCalls  int
}

type loopingWatchRunner struct{ pid int }

func (r *loopingWatchRunner) Run(_ context.Context, path string, _ ...string) platform.Result {
	switch path {
	case "/usr/bin/pgrep":
		r.pid++
		return platform.Result{Stdout: fmt.Sprintf("%d\n", 40+r.pid)}
	case "/usr/sbin/lsof":
		return platform.Result{Stdout: "p42\x00f0\x00tREG\x00"}
	case "/usr/bin/log":
		return platform.Result{}
	default:
		return platform.Result{Err: errors.New("unavailable")}
	}
}

func (r *restartWatchRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/pgrep":
		r.pgrepCalls++
		if r.pgrepCalls == 1 {
			return platform.Result{Stdout: "42\n"}
		}
		return platform.Result{Stdout: "43\n"}
	case "/usr/sbin/lsof":
		r.lsofCalls++
		if r.lsofCalls == 1 {
			return platform.Result{Err: errors.New("process exited during sample")}
		}
		return platform.Result{Stdout: "p42\x00f0\x00tCHR\x00"}
	case "/usr/bin/log":
		return platform.Result{}
	case "/bin/launchctl":
		return platform.Result{Stdout: "NOFILE = { soft = 256, hard = 10240 }"}
	case "/usr/sbin/sysctl":
		return platform.Result{Stdout: "kern.num_files: 100\nkern.maxfiles: 10000\n"}
	default:
		return platform.Result{Err: errors.New("unexpected command")}
	}
}

type failingStreamRunner struct{ logShowCalls int }

func (r *failingStreamRunner) StreamLines(context.Context, string, func([]byte) error, ...string) error {
	return errors.New("stream unavailable")
}

type permissionWatchRunner struct{}

func (permissionWatchRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/pgrep":
		return platform.Result{Stdout: "42\n"}
	case "/usr/sbin/lsof":
		return platform.Result{Err: errors.New("permission denied")}
	default:
		return platform.Result{}
	}
}

type missingWatchRunner struct{ calls int }

func (r *missingWatchRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	if path == "/usr/bin/pgrep" {
		r.calls++
		return platform.Result{Err: errors.New("not found")}
	}
	return platform.Result{}
}

func (r *failingStreamRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/sbin/lsof":
		return platform.Result{Stdout: "p42\x00f0\x00tCHR\x00"}
	case "/usr/bin/log":
		r.logShowCalls++
		return platform.Result{}
	case "/bin/launchctl":
		return platform.Result{Stdout: "NOFILE = { soft = 256, hard = 10240 }"}
	case "/usr/sbin/sysctl":
		return platform.Result{Stdout: "kern.num_files: 100\nkern.maxfiles: 10000\n"}
	default:
		return platform.Result{Err: errors.New("unexpected command")}
	}
}
