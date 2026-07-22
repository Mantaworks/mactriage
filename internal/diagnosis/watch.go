package diagnosis

import (
	"fmt"
	"strings"
	"time"

	"github.com/Mantaworks/mactriage/internal/report"
)

type WatchFacts struct {
	Growth          int
	GrowthRate      float64
	WarnGrowth      int
	Window          time.Duration
	EMFILE          int
	ENFILE          int
	ProcessPressure bool
	GlobalPressure  bool
	Resources       ResourceSample
	Thresholds      ResourceThresholds
}

type ResourceThresholds struct {
	CPUPercent    float64
	MemoryBytes   uint64
	Threads       int
	Sockets       int
	MinMemoryFree float64
}

type ResourceSample struct {
	CPUPercent        float64
	RSSBytes          uint64
	Threads           int
	Sockets           int
	MemoryFreePercent float64
}

func ClassifyWatch(facts WatchFacts) (report.Severity, string) {
	if facts.EMFILE > 0 && facts.ProcessPressure {
		return report.Critical, "EMFILE detected with descriptor measurements"
	}
	if facts.ENFILE > 0 && facts.GlobalPressure {
		return report.Critical, "ENFILE detected with descriptor measurements"
	}
	if facts.EMFILE > 0 || facts.ENFILE > 0 {
		return report.Warning, "explicit descriptor error observed without corroborating pressure"
	}
	if facts.Growth >= facts.WarnGrowth {
		return report.Warning, fmt.Sprintf("descriptor count increased by %d within %s (%.1f/s)", facts.Growth, facts.Window, facts.GrowthRate)
	}
	var pressure []string
	if facts.Thresholds.CPUPercent > 0 && facts.Resources.CPUPercent >= facts.Thresholds.CPUPercent {
		pressure = append(pressure, fmt.Sprintf("CPU %.1f%%", facts.Resources.CPUPercent))
	}
	if facts.Thresholds.MemoryBytes > 0 && facts.Resources.RSSBytes >= facts.Thresholds.MemoryBytes {
		pressure = append(pressure, fmt.Sprintf("memory %d MiB", facts.Resources.RSSBytes>>20))
	}
	if facts.Thresholds.Threads > 0 && facts.Resources.Threads >= facts.Thresholds.Threads {
		pressure = append(pressure, fmt.Sprintf("threads %d", facts.Resources.Threads))
	}
	if facts.Thresholds.Sockets > 0 && facts.Resources.Sockets >= facts.Thresholds.Sockets {
		pressure = append(pressure, fmt.Sprintf("sockets %d", facts.Resources.Sockets))
	}
	if facts.Thresholds.MinMemoryFree > 0 && facts.Resources.MemoryFreePercent > 0 && facts.Resources.MemoryFreePercent <= facts.Thresholds.MinMemoryFree {
		pressure = append(pressure, fmt.Sprintf("system memory %.0f%% free", facts.Resources.MemoryFreePercent))
	}
	if len(pressure) > 0 {
		return report.Warning, "resource threshold reached: " + strings.Join(pressure, ", ")
	}
	return report.Info, "descriptor sample collected"
}

func ClassifyRestart(count int, window time.Duration) (report.Severity, string) {
	if count >= 3 {
		return report.Warning, fmt.Sprintf("process restart loop detected: %d restarts within %s", count, window)
	}
	return report.Info, "process restarted"
}
