package macos

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

type ProcessThresholds struct {
	CPUPercent  float64
	MemoryBytes uint64
}

type ProcessInspector struct {
	Runner platform.Runner
}

func (p ProcessInspector) Inspect(ctx context.Context, target string, thresholds ProcessThresholds) (report.Report, error) {
	if p.Runner == nil {
		return report.Report{}, errors.New("process inspector requires a command runner")
	}
	if thresholds.CPUPercent <= 0 {
		thresholds.CPUPercent = 80
	}
	if thresholds.MemoryBytes == 0 {
		thresholds.MemoryBytes = 4 << 30
	}
	pid, err := p.resolvePID(ctx, target)
	if err != nil {
		return report.Report{}, err
	}
	result := p.Runner.Run(ctx, "/bin/ps", "-p", strconv.Itoa(pid), "-o", "pid=", "-o", "%cpu=", "-o", "rss=", "-o", "state=", "-o", "etime=", "-o", "comm=")
	if result.TimedOut {
		return report.Report{}, errors.New("process inspection timed out")
	}
	if result.Err != nil {
		return report.Report{}, fmt.Errorf("inspect process %d: %w", pid, result.Err)
	}
	data, err := parseProcessSnapshot(result.Stdout, thresholds)
	if err != nil {
		return report.Report{}, err
	}
	data.Threads = p.threadCount(ctx, pid)
	r := report.New("hang", target)
	r.Host = (Collector{Runner: p.Runner}).host(ctx)
	r.Evidence = append(r.Evidence, report.Evidence{ID: report.EvidenceProcess, Status: report.StatusOK, Summary: fmt.Sprintf("Inspected process %d", data.PID), Data: data})
	return r, nil
}

func (p ProcessInspector) Sample(ctx context.Context, pid int, path string) error {
	if p.Runner == nil {
		return errors.New("process inspector requires a command runner")
	}
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".mactriage-sample-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		os.Remove(tempPath)
		return err
	}
	defer os.Remove(tempPath)
	result := p.Runner.Run(ctx, "/usr/bin/sample", strconv.Itoa(pid), "3", "1", "-file", tempPath)
	if result.TimedOut {
		return errors.New("process sample timed out")
	}
	if result.Err != nil {
		return fmt.Errorf("sample process %d: %w", pid, result.Err)
	}
	if err := os.Chmod(tempPath, 0o600); err != nil {
		return err
	}
	return os.Rename(tempPath, path)
}

func (p ProcessInspector) resolvePID(ctx context.Context, target string) (int, error) {
	if pid, err := strconv.Atoi(target); err == nil && pid > 0 {
		return pid, nil
	}
	result := p.Runner.Run(ctx, "/usr/bin/pgrep", "-ix", target)
	if result.Err != nil || strings.TrimSpace(result.Stdout) == "" {
		return 0, fmt.Errorf("running process %q was not found", target)
	}
	first := strings.Fields(result.Stdout)[0]
	pid, err := strconv.Atoi(first)
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("invalid PID returned for %q", target)
	}
	return pid, nil
}

func parseProcessSnapshot(text string, thresholds ProcessThresholds) (report.ProcessData, error) {
	fields := strings.Fields(strings.TrimSpace(text))
	if len(fields) < 6 {
		return report.ProcessData{}, errors.New("process metrics were incomplete")
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return report.ProcessData{}, errors.New("process metrics contained an invalid PID")
	}
	cpu, err := strconv.ParseFloat(strings.ReplaceAll(fields[1], ",", "."), 64)
	if err != nil {
		return report.ProcessData{}, errors.New("process metrics contained invalid CPU usage")
	}
	rssKB, err := strconv.ParseUint(fields[2], 10, 64)
	if err != nil {
		return report.ProcessData{}, errors.New("process metrics contained invalid memory usage")
	}
	return report.ProcessData{PID: pid, Name: strings.Join(fields[5:], " "), CPUPercent: cpu, RSSBytes: rssKB * 1024, State: fields[3], Elapsed: fields[4], CPUThreshold: thresholds.CPUPercent, MemoryThreshold: thresholds.MemoryBytes}, nil
}

func (p ProcessInspector) threadCount(ctx context.Context, pid int) int {
	result := p.Runner.Run(ctx, "/bin/ps", "-M", "-p", strconv.Itoa(pid))
	if result.Err != nil {
		return 0
	}
	lines := 0
	for _, line := range strings.Split(result.Stdout, "\n") {
		if strings.TrimSpace(line) != "" {
			lines++
		}
	}
	if lines <= 1 {
		return 0
	}
	return lines - 1
}
