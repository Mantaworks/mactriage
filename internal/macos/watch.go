package macos

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/upsidedly/mactriage/internal/platform"
	"github.com/upsidedly/mactriage/internal/report"
)

type WatchOptions struct {
	Target       string
	Interval     time.Duration
	Window       time.Duration
	WarnGrowth   int
	Duration     time.Duration
	IncludePaths bool
}

type WatchEvent struct {
	SchemaVersion   string          `json:"schema_version"`
	Type            string          `json:"type"`
	Timestamp       time.Time       `json:"timestamp"`
	Target          string          `json:"target"`
	PID             int             `json:"pid,omitempty"`
	DescriptorCount int             `json:"descriptor_count,omitempty"`
	Growth          int             `json:"growth,omitempty"`
	WindowSeconds   int             `json:"window_seconds,omitempty"`
	Severity        report.Severity `json:"severity"`
	Message         string          `json:"message"`
	ByType          map[string]int  `json:"by_type,omitempty"`
	ByPath          map[string]int  `json:"by_path,omitempty"`
}

type Watcher struct {
	Runner platform.Runner
	Now    func() time.Time
}

func (w Watcher) Run(ctx context.Context, opts WatchOptions, emit func(WatchEvent) error) error {
	if w.Runner == nil {
		return errors.New("watcher requires a command runner")
	}
	if emit == nil {
		return errors.New("watcher requires an event sink")
	}
	if opts.Target == "" {
		opts.Target = "syspolicyd"
	}
	if opts.Interval <= 0 {
		opts.Interval = 5 * time.Second
	}
	if opts.Window <= 0 {
		opts.Window = 60 * time.Second
	}
	if opts.WarnGrowth <= 0 {
		opts.WarnGrowth = 150
	}
	now := w.Now
	if now == nil {
		now = time.Now
	}
	type point struct {
		at    time.Time
		count int
	}
	var samples []point
	lastPID := 0
	started := now()
	for {
		pid, err := w.resolvePID(ctx, opts.Target)
		stamp := now().UTC()
		if err != nil {
			if emitErr := emit(WatchEvent{SchemaVersion: report.SchemaVersion, Type: "error", Timestamp: stamp, Target: opts.Target, Severity: report.Error, Message: err.Error()}); emitErr != nil {
				return emitErr
			}
		} else {
			if lastPID != 0 && lastPID != pid {
				if err := emit(WatchEvent{SchemaVersion: report.SchemaVersion, Type: "restart", Timestamp: stamp, Target: opts.Target, PID: pid, Severity: report.Info, Message: fmt.Sprintf("process restarted (PID %d → %d)", lastPID, pid)}); err != nil {
					return err
				}
				samples = nil
			}
			lastPID = pid
			result := w.Runner.Run(ctx, "/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(pid), "-F0pcftn")
			if result.Err != nil {
				return fmt.Errorf("enumerate descriptors for %s (PID %d): %w", opts.Target, pid, result.Err)
			}
			sample := ParseLSOF([]byte(result.Stdout))
			cutoff := stamp.Add(-opts.Window)
			kept := samples[:0]
			for _, existing := range samples {
				if !existing.at.Before(cutoff) {
					kept = append(kept, existing)
				}
			}
			samples = append(kept, point{at: stamp, count: sample.Count})
			growth := 0
			if len(samples) > 1 {
				growth = sample.Count - samples[0].count
			}
			severity, message := report.Info, "descriptor sample collected"
			if growth >= opts.WarnGrowth {
				severity, message = report.Warning, fmt.Sprintf("descriptor count increased by %d within %s", growth, opts.Window)
			}
			paths := map[string]int(nil)
			if opts.IncludePaths {
				paths = sample.ByPath
			}
			logs := w.recentLogs(ctx, pid, opts.Interval)
			if logs.EMFILE > 0 {
				severity, message = report.Critical, "EMFILE detected in correlated unified logs"
			} else if logs.ENFILE > 0 {
				severity, message = report.Critical, "ENFILE detected in correlated unified logs"
			}
			if err := emit(WatchEvent{SchemaVersion: report.SchemaVersion, Type: "sample", Timestamp: stamp, Target: opts.Target, PID: pid, DescriptorCount: sample.Count, Growth: growth, WindowSeconds: int(opts.Window.Seconds()), Severity: severity, Message: message, ByType: sample.ByType, ByPath: paths}); err != nil {
				return err
			}
		}
		if opts.Duration > 0 && now().Sub(started) >= opts.Duration {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(opts.Interval):
		}
	}
}

func (w Watcher) resolvePID(ctx context.Context, target string) (int, error) {
	if pid, err := strconv.Atoi(target); err == nil && pid > 0 {
		return pid, nil
	}
	result := w.Runner.Run(ctx, "/usr/bin/pgrep", "-x", target)
	if result.Err != nil || strings.TrimSpace(result.Stdout) == "" {
		return 0, fmt.Errorf("process %q was not found", target)
	}
	pid, err := strconv.Atoi(strings.Fields(result.Stdout)[0])
	if err != nil {
		return 0, fmt.Errorf("invalid PID returned for %q", target)
	}
	return pid, nil
}

func (w Watcher) recentLogs(ctx context.Context, pid int, interval time.Duration) LogSummary {
	last := fmt.Sprintf("%.0fs", interval.Seconds()+1)
	predicate := fmt.Sprintf("processID == %d", pid)
	result := w.Runner.Run(ctx, "/usr/bin/log", "show", "--last", last, "--style", "ndjson", "--predicate", predicate)
	if result.Err != nil {
		return LogSummary{}
	}
	return ParseLogEvents([]byte(result.Stdout))
}
