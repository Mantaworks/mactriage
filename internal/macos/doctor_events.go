package macos

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/Mantaworks/mactriage/internal/report"
)

func (d Doctor) crashes(ctx context.Context) report.Evidence {
	dirs := []string{filepath.Join(os.Getenv("HOME"), "Library", "Logs", "DiagnosticReports"), "/Library/Logs/DiagnosticReports"}
	count := 0
	available := false
	for _, dir := range dirs {
		result := d.Runner.Run(ctx, "/usr/bin/find", dir, "-maxdepth", "1", "-type", "f", "-mtime", "-1", "(", "-name", "*.ips", "-o", "-name", "*.crash", ")", "-print")
		if result.Err == nil {
			available = true
			count += len(nonemptyLines(result.Stdout))
		}
	}
	if !available {
		return unavailable(report.EvidenceRecentCrashes, "Recent crash-report count is unavailable")
	}
	return report.Evidence{ID: report.EvidenceRecentCrashes, Status: report.StatusOK, Summary: fmt.Sprintf("Found %d crash reports created in the last day", count), Data: report.RecentCrashesData{Count: count}}
}

func (d Doctor) restarts(ctx context.Context) report.Evidence {
	result := d.Runner.Run(ctx, "/usr/bin/log", "show", "--last", "10m", "--style", "ndjson", "--predicate", `(process == "launchd" OR subsystem CONTAINS[c] "runningboard") AND (eventMessage CONTAINS[c] "exited" OR eventMessage CONTAINS[c] "terminated")`)
	if result.TimedOut {
		return timedOut(report.EvidenceRestartLoops, "Recent restart-log check timed out")
	}
	if result.Err != nil {
		return unavailable(report.EvidenceRestartLoops, "Recent restart logs are unavailable")
	}
	counts := map[string]int{}
	for _, line := range nonemptyLines(result.Stdout) {
		var event struct {
			Message string `json:"eventMessage"`
		}
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		match := regexp.MustCompile(`(?i)(?:service|process)\s+([a-z0-9_.-]+)\s+(?:exited|terminated)`).FindStringSubmatch(event.Message)
		if len(match) == 2 {
			counts[match[1]]++
		}
	}
	var processes []report.ProcessRestartObservation
	for name, count := range counts {
		processes = append(processes, report.ProcessRestartObservation{Name: name, Count: count})
	}
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].Count == processes[j].Count {
			return processes[i].Name < processes[j].Name
		}
		return processes[i].Count > processes[j].Count
	})
	return report.Evidence{ID: report.EvidenceRestartLoops, Status: report.StatusOK, Summary: fmt.Sprintf("Observed exit events for %d named processes", len(processes)), Data: report.RestartLoopsData{Processes: processes}}
}
