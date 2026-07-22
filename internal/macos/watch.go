package macos

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

type WatchOptions struct {
	Target       string
	Interval     time.Duration
	Window       time.Duration
	WarnGrowth   int
	Duration     time.Duration
	IncludePaths bool
	Thresholds   diagnosis.ResourceThresholds
}

type WatchEvent struct {
	SchemaVersion     string          `json:"schema_version"`
	Type              string          `json:"type"`
	Timestamp         time.Time       `json:"timestamp"`
	Target            string          `json:"target"`
	PID               int             `json:"pid,omitempty"`
	DescriptorCount   int             `json:"descriptor_count,omitempty"`
	Growth            int             `json:"growth,omitempty"`
	GrowthRate        float64         `json:"growth_per_second,omitempty"`
	WindowSeconds     int             `json:"window_seconds,omitempty"`
	Severity          report.Severity `json:"severity"`
	Message           string          `json:"message"`
	ByType            map[string]int  `json:"by_type,omitempty"`
	ByPath            map[string]int  `json:"by_path,omitempty"`
	CPUPercent        float64         `json:"cpu_percent,omitempty"`
	RSSBytes          uint64          `json:"rss_bytes,omitempty"`
	Threads           int             `json:"threads,omitempty"`
	SocketCount       int             `json:"socket_count,omitempty"`
	DiskReadBytes     uint64          `json:"disk_read_bytes,omitempty"`
	DiskWriteBytes    uint64          `json:"disk_write_bytes,omitempty"`
	MemoryFreePercent float64         `json:"memory_free_percent,omitempty"`
	RestartCount      int             `json:"restart_count,omitempty"`
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
	if opts.Thresholds.CPUPercent <= 0 {
		opts.Thresholds.CPUPercent = 80
	}
	if opts.Thresholds.MemoryBytes == 0 {
		opts.Thresholds.MemoryBytes = 4 << 30
	}
	if opts.Thresholds.Threads <= 0 {
		opts.Thresholds.Threads = 500
	}
	if opts.Thresholds.Sockets <= 0 {
		opts.Thresholds.Sockets = 1000
	}
	if opts.Thresholds.MinMemoryFree <= 0 {
		opts.Thresholds.MinMemoryFree = 10
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
	var restartTimes []time.Time
	lastPID := 0
	lsofRetries := 0
	resolveRetries := 0
	started := now()
	streamCtx, stopStream := context.WithCancel(ctx)
	defer stopStream()
	var logMu sync.Mutex
	var pendingLogs LogSummary
	streamFailed := false
	streaming := false
	if streamer, ok := w.Runner.(platform.LineStreamer); ok {
		streaming = true
		predicate := fmt.Sprintf("process == %q", opts.Target)
		if _, err := strconv.Atoi(opts.Target); err == nil {
			predicate = fmt.Sprintf("processID == %s", opts.Target)
		}
		go func() {
			err := streamer.StreamLines(streamCtx, "/usr/bin/log", func(line []byte) error {
				summary := ParseLogEvents(append(line, '\n'))
				logMu.Lock()
				pendingLogs.EMFILE += summary.EMFILE
				pendingLogs.ENFILE += summary.ENFILE
				logMu.Unlock()
				return nil
			}, "stream", "--style", "ndjson", "--predicate", predicate)
			if err != nil && streamCtx.Err() == nil {
				logMu.Lock()
				streamFailed = true
				logMu.Unlock()
			}
		}()
	}
	for {
		pid, err := w.resolvePID(ctx, opts.Target)
		stamp := now().UTC()
		if err != nil {
			resolveRetries++
			if _, numericErr := strconv.Atoi(opts.Target); numericErr == nil || resolveRetries > 3 {
				return err
			}
			if emitErr := emit(WatchEvent{SchemaVersion: report.SchemaVersion, Type: "error", Timestamp: stamp, Target: opts.Target, Severity: report.Error, Message: err.Error()}); emitErr != nil {
				return emitErr
			}
		} else {
			resolveRetries = 0
			if lastPID != 0 && lastPID != pid {
				cutoff := stamp.Add(-opts.Window)
				kept := restartTimes[:0]
				for _, previous := range restartTimes {
					if !previous.Before(cutoff) {
						kept = append(kept, previous)
					}
				}
				restartTimes = append(kept, stamp)
				severity, message := diagnosis.ClassifyRestart(len(restartTimes), opts.Window)
				message += fmt.Sprintf(" (PID %d → %d)", lastPID, pid)
				if err := emit(WatchEvent{SchemaVersion: report.SchemaVersion, Type: "restart", Timestamp: stamp, Target: opts.Target, PID: pid, Severity: severity, Message: message, RestartCount: len(restartTimes)}); err != nil {
					return err
				}
				samples = nil
			}
			lastPID = pid
			result := w.Runner.Run(ctx, "/usr/sbin/lsof", "-nP", "-a", "-p", strconv.Itoa(pid), "-F0pcftn")
			if result.Err != nil {
				if _, numericErr := strconv.Atoi(opts.Target); numericErr == nil {
					return fmt.Errorf("enumerate descriptors for fixed PID %d: %w", pid, result.Err)
				}
				replacement, resolveErr := w.resolvePID(ctx, opts.Target)
				switch {
				case resolveErr == nil && replacement != pid:
					lsofRetries = 0
				case resolveErr != nil && lsofRetries < 3:
					lsofRetries++
				default:
					return fmt.Errorf("enumerate descriptors for %s (PID %d): %w", opts.Target, pid, result.Err)
				}
				if emitErr := emit(WatchEvent{SchemaVersion: report.SchemaVersion, Type: "error", Timestamp: stamp, Target: opts.Target, PID: pid, Severity: report.Warning, Message: fmt.Sprintf("process changed during descriptor sample for PID %d; retrying", pid)}); emitErr != nil {
					return emitErr
				}
			} else {
				lsofRetries = 0
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
				growthRate := 0.0
				if len(samples) > 1 {
					growth = sample.Count - samples[0].count
					seconds := stamp.Sub(samples[0].at).Seconds()
					if seconds > 0 {
						growthRate = float64(growth) / seconds
					}
				}
				paths := map[string]int(nil)
				if opts.IncludePaths {
					paths = sample.ByPath
				}
				logs := LogSummary{}
				if streaming {
					logMu.Lock()
					logs = pendingLogs
					pendingLogs = LogSummary{}
					failed := streamFailed
					logMu.Unlock()
					if failed {
						logs = w.recentLogs(ctx, pid, opts.Interval)
					}
				} else {
					logs = w.recentLogs(ctx, pid, opts.Interval)
				}
				processPressure, globalPressure := w.pressure(ctx, pid, sample.Count)
				resources := w.resources(ctx, pid)
				resources.Sockets = socketCount(sample.ByType)
				resources.MemoryFreePercent = w.memoryFreePercent(ctx)
				severity, message := diagnosis.ClassifyWatch(diagnosis.WatchFacts{Growth: growth, GrowthRate: growthRate, WarnGrowth: opts.WarnGrowth, Window: opts.Window, EMFILE: logs.EMFILE, ENFILE: logs.ENFILE, ProcessPressure: processPressure, GlobalPressure: globalPressure, Resources: resources, Thresholds: opts.Thresholds})
				if err := emit(WatchEvent{SchemaVersion: report.SchemaVersion, Type: "sample", Timestamp: stamp, Target: opts.Target, PID: pid, DescriptorCount: sample.Count, Growth: growth, GrowthRate: growthRate, WindowSeconds: int(opts.Window.Seconds()), Severity: severity, Message: message, ByType: sample.ByType, ByPath: paths, CPUPercent: resources.CPUPercent, RSSBytes: resources.RSSBytes, Threads: resources.Threads, SocketCount: resources.Sockets, MemoryFreePercent: resources.MemoryFreePercent}); err != nil {
					return err
				}
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

func (w Watcher) resources(ctx context.Context, pid int) diagnosis.ResourceSample {
	result := w.Runner.Run(ctx, "/bin/ps", "-p", strconv.Itoa(pid), "-o", "%cpu=", "-o", "rss=")
	if result.Err != nil {
		return diagnosis.ResourceSample{}
	}
	fields := strings.Fields(result.Stdout)
	if len(fields) < 2 {
		return diagnosis.ResourceSample{}
	}
	cpu, _ := strconv.ParseFloat(strings.ReplaceAll(fields[0], ",", "."), 64)
	rssKB, _ := strconv.ParseUint(fields[1], 10, 64)
	threads := (ProcessInspector{Runner: w.Runner}).threadCount(ctx, pid)
	return diagnosis.ResourceSample{CPUPercent: cpu, RSSBytes: rssKB * 1024, Threads: threads}
}

func (w Watcher) memoryFreePercent(ctx context.Context) float64 {
	result := w.Runner.Run(ctx, "/usr/bin/memory_pressure", "-Q")
	if result.Err != nil {
		return 0
	}
	const marker = "System-wide memory free percentage:"
	for _, line := range strings.Split(result.Stdout+"\n"+result.Stderr, "\n") {
		if index := strings.Index(line, marker); index >= 0 {
			value := strings.TrimSpace(strings.TrimSuffix(line[index+len(marker):], "%"))
			percent, _ := strconv.ParseFloat(value, 64)
			return percent
		}
	}
	return 0
}

func socketCount(types map[string]int) int {
	count := 0
	for kind, value := range types {
		lower := strings.ToLower(kind)
		if strings.HasPrefix(lower, "ipv") || lower == "unix" {
			count += value
		}
	}
	return count
}

func (w Watcher) pressure(ctx context.Context, pid, descriptorCount int) (process, global bool) {
	if result := w.Runner.Run(ctx, "/bin/launchctl", "procinfo", strconv.Itoa(pid)); result.Err == nil {
		if soft, _, ok := ParseNOFILELimit(result.Stdout); ok && soft > 0 {
			process = float64(descriptorCount) >= float64(soft)*0.8
		}
	}
	result := w.Runner.Run(ctx, "/usr/sbin/sysctl", "kern.num_files", "kern.maxfiles")
	if result.Err != nil {
		return process, false
	}
	values := map[string]uint64{}
	for _, line := range strings.Split(result.Stdout, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		if value, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64); err == nil {
			values[strings.TrimSpace(parts[0])] = value
		}
	}
	used, maximum := values["kern.num_files"], values["kern.maxfiles"]
	return process, used > 0 && maximum > 0 && float64(used) >= float64(maximum)*0.9
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
