package macos

import (
	"context"
	"strings"

	"github.com/Mantaworks/mactriage/internal/report"
)

func (d Doctor) descriptors(ctx context.Context) report.Evidence {
	return (Collector{Runner: d.Runner}).limits(ctx)
}

func (d Doctor) services(ctx context.Context) report.Evidence {
	names := []string{"syspolicyd", "trustd", "launchservicesd", "runningboardd"}
	data := report.ServicesData{Running: make(map[string]bool, len(names)), Statuses: make(map[string]report.Status, len(names))}
	status := report.StatusOK
	for _, name := range names {
		result := d.Runner.Run(ctx, "/usr/bin/pgrep", "-x", name)
		switch {
		case result.TimedOut:
			data.Statuses[name] = report.StatusTimedOut
			status = report.StatusPartial
		case result.Err != nil && result.ExitCode != 1:
			data.Statuses[name] = report.StatusUnavailable
			status = report.StatusPartial
		default:
			data.Statuses[name] = report.StatusOK
			data.Running[name] = strings.TrimSpace(result.Stdout) != ""
		}
	}
	return report.Evidence{ID: report.EvidenceServices, Status: status, Summary: "Collected process-presence facts for core macOS application and security services", Data: data}
}

func (d Doctor) updates(ctx context.Context) report.Evidence {
	result := d.Runner.Run(ctx, "/usr/sbin/softwareupdate", "-l", "--no-scan")
	if result.TimedOut {
		return timedOut(report.EvidenceUpdates, "Software Update check timed out")
	}
	if result.Err != nil {
		return unavailable(report.EvidenceUpdates, "Software Update availability could not be checked")
	}
	text := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	available := !strings.Contains(text, "no new software available") && (strings.Contains(text, "label:") || strings.Contains(text, "recommended:"))
	return report.Evidence{ID: report.EvidenceUpdates, Status: report.StatusOK, Summary: "Cached Software Update availability checked without starting a new scan", Data: report.UpdatesData{Available: available, Cached: true}}
}
