package macos

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

type HealthInspector struct {
	Runner platform.Runner
	Now    func() time.Time
}

func (h HealthInspector) Battery(ctx context.Context) report.Evidence {
	batt := h.Runner.Run(ctx, "/usr/bin/pmset", "-g", "batt")
	if batt.TimedOut {
		return timedOut(report.EvidenceBattery, "Battery check timed out")
	}
	if batt.Err != nil {
		return unavailable(report.EvidenceBattery, "Battery health is unavailable")
	}
	if strings.Contains(strings.ToLower(batt.Stdout), "no batteries") {
		return report.Evidence{ID: report.EvidenceBattery, Status: report.StatusSkipped, Summary: "This Mac has no internal battery", Data: report.BatteryData{Present: false}}
	}
	data := report.BatteryData{Present: true, Percent: firstInt(batt.Stdout, `([0-9]{1,3})%`)}
	lower := strings.ToLower(batt.Stdout)
	data.Charging = strings.Contains(lower, "charging") && !strings.Contains(lower, "not charging")
	ioreg := h.Runner.Run(ctx, "/usr/sbin/ioreg", "-rn", "AppleSmartBattery", "-d", "1")
	status := report.StatusOK
	if ioreg.Err == nil {
		data.CycleCount = plistInt(ioreg.Stdout, "CycleCount")
		max := plistInt(ioreg.Stdout, "AppleRawMaxCapacity")
		if max == 0 {
			max = plistInt(ioreg.Stdout, "MaxCapacity")
		}
		design := plistInt(ioreg.Stdout, "DesignCapacity")
		if max > 0 && design > 0 {
			data.HealthPercent = roundOne(float64(max) * 100 / float64(design))
		}
		data.Condition = plistString(ioreg.Stdout, "BatteryHealth")
		if data.Condition == "" {
			data.Condition = plistString(ioreg.Stdout, "Condition")
		}
	} else {
		status = report.StatusPartial
	}
	return report.Evidence{ID: report.EvidenceBattery, Status: status, Summary: fmt.Sprintf("Battery is at %d%% with %.1f%% estimated health", data.Percent, data.HealthPercent), Data: data}
}

func (h HealthInspector) Thermal(ctx context.Context) report.Evidence {
	result := h.Runner.Run(ctx, "/usr/bin/pmset", "-g", "therm")
	if result.TimedOut {
		return timedOut(report.EvidenceThermal, "Thermal check timed out")
	}
	if result.Err != nil {
		return unavailable(report.EvidenceThermal, "Thermal state is unavailable")
	}
	lower := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	data := report.ThermalData{
		CPUSpeedLimit:   firstInt(result.Stdout, `(?m)CPU_Speed_Limit\s*=\s*([0-9]+)`),
		SchedulerLimit:  firstInt(result.Stdout, `(?m)Scheduler_Limit\s*=\s*([0-9]+)`),
		CPUAvailable:    firstInt(result.Stdout, `(?m)CPU_Available\s*=\s*([0-9]+)`),
		WarningRecorded: !strings.Contains(lower, "no thermal warning") && strings.Contains(lower, "thermal"),
	}
	return report.Evidence{ID: report.EvidenceThermal, Status: report.StatusOK, Summary: "Collected macOS thermal-limit facts", Data: data}
}

func (h HealthInspector) Backup(ctx context.Context) report.Evidence {
	destinations := h.Runner.Run(ctx, "/usr/bin/tmutil", "destinationinfo")
	if destinations.TimedOut {
		return timedOut(report.EvidenceBackup, "Time Machine check timed out")
	}
	if destinations.Err != nil {
		if strings.Contains(strings.ToLower(destinations.Stdout+destinations.Stderr), "no destinations") || destinations.ExitCode == 1 {
			return report.Evidence{ID: report.EvidenceBackup, Status: report.StatusSkipped, Summary: "Time Machine has no configured destination", Data: report.BackupData{}}
		}
		return unavailable(report.EvidenceBackup, "Time Machine configuration is unavailable")
	}
	data := report.BackupData{Configured: true, DestinationCount: strings.Count(destinations.Stdout, "Name")}
	latest := h.Runner.Run(ctx, "/usr/bin/tmutil", "latestbackup")
	status := report.StatusOK
	if latest.Err == nil {
		match := regexp.MustCompile(`([0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{6})`).FindStringSubmatch(latest.Stdout)
		if len(match) == 2 {
			if stamp, err := time.ParseInLocation("2006-01-02-150405", match[1], time.Local); err == nil {
				now := time.Now
				if h.Now != nil {
					now = h.Now
				}
				data.HasBackup = true
				data.LatestAgeHours = roundOne(now().Sub(stamp).Hours())
			}
		}
	} else {
		status = report.StatusPartial
	}
	return report.Evidence{ID: report.EvidenceBackup, Status: status, Summary: "Collected Time Machine configuration and latest-backup age", Data: data}
}

func firstInt(value, pattern string) int {
	match := regexp.MustCompile(pattern).FindStringSubmatch(value)
	if len(match) != 2 {
		return 0
	}
	parsed, _ := strconv.Atoi(match[1])
	return parsed
}

func plistInt(value, key string) int {
	return firstInt(value, `(?m)"`+regexp.QuoteMeta(key)+`"\s*=\s*([0-9]+)`)
}

func plistString(value, key string) string {
	match := regexp.MustCompile(`(?m)"` + regexp.QuoteMeta(key) + `"\s*=\s*"([^"]+)"`).FindStringSubmatch(value)
	if len(match) == 2 {
		return match[1]
	}
	return ""
}
