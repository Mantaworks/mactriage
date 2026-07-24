package macos

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Mantaworks/mactriage/internal/report"
)

func (d Doctor) startup(ctx context.Context) report.Evidence {
	background := d.Runner.Run(ctx, "/usr/bin/sfltool", "dumpbtm")
	if background.TimedOut {
		return timedOut(report.EvidenceStartupItems, "Login and background item count timed out")
	}
	if background.Err == nil {
		count := len(regexp.MustCompile(`(?im)^\s*UUID\s*:`).FindAllString(background.Stdout, -1))
		items := parseStartupItems(background.Stdout)
		return report.Evidence{ID: report.EvidenceStartupItems, Status: report.StatusOK, Summary: fmt.Sprintf("Counted %d registered login and background items", count), Data: report.StartupItemsData{Count: count, Source: "background-task-management", Items: items}}
	}
	dirs := []string{filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"}
	count := 0
	var items []report.StartupItem
	available := false
	for _, dir := range dirs {
		result := d.Runner.Run(ctx, "/bin/ls", "-1", dir)
		if result.Err != nil {
			continue
		}
		available = true
		for _, line := range nonemptyLines(result.Stdout) {
			if strings.HasSuffix(strings.ToLower(line), ".plist") {
				count++
				if len(items) < 100 {
					items = append(items, report.StartupItem{Identifier: strings.TrimSuffix(line, filepath.Ext(line))})
				}
			}
		}
	}
	if !available {
		return unavailable(report.EvidenceStartupItems, "Startup agent count is unavailable")
	}
	return report.Evidence{ID: report.EvidenceStartupItems, Status: report.StatusPartial, Summary: fmt.Sprintf("Counted %d launch agents and daemons; registered Login Items were unavailable", count), Data: report.StartupItemsData{Count: count, Source: "launch-agent-fallback", Items: items}}
}

func parseStartupItems(output string) []report.StartupItem {
	var items []report.StartupItem
	var current report.StartupItem
	flush := func() {
		if current.Name != "" || current.Identifier != "" {
			items = append(items, current)
			current = report.StartupItem{}
		}
	}
	for _, line := range nonemptyLines(output) {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := strings.ToLower(strings.TrimSpace(parts[0])), strings.TrimSpace(parts[1])
		switch key {
		case "name":
			flush()
			current.Name = value
		case "identifier", "bundle identifier":
			current.Identifier = value
		case "team identifier":
			current.TeamID = value
		}
		if len(items) >= 100 {
			break
		}
	}
	flush()
	if len(items) > 100 {
		items = items[:100]
	}
	return items
}
