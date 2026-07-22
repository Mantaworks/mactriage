package diagnosis

import (
	"fmt"
	"strings"
	"time"

	"github.com/Mantaworks/mactriage/internal/report"
)

type WatchFacts struct {
	Growth               int
	GrowthRate           float64
	WarnGrowth           int
	Window               time.Duration
	EMFILE               int
	ENFILE               int
	ProcessPressure      bool
	GlobalPressure       bool
	CPUPercent           float64
	CPUThreshold         float64
	RSSBytes             uint64
	MemoryThreshold      uint64
	Threads              int
	ThreadsThreshold     int
	Sockets              int
	SocketsThreshold     int
	MemoryFreePercent    float64
	MinMemoryFreePercent float64
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
	if facts.CPUThreshold > 0 && facts.CPUPercent >= facts.CPUThreshold {
		pressure = append(pressure, fmt.Sprintf("CPU %.1f%%", facts.CPUPercent))
	}
	if facts.MemoryThreshold > 0 && facts.RSSBytes >= facts.MemoryThreshold {
		pressure = append(pressure, fmt.Sprintf("memory %d MiB", facts.RSSBytes>>20))
	}
	if facts.ThreadsThreshold > 0 && facts.Threads >= facts.ThreadsThreshold {
		pressure = append(pressure, fmt.Sprintf("threads %d", facts.Threads))
	}
	if facts.SocketsThreshold > 0 && facts.Sockets >= facts.SocketsThreshold {
		pressure = append(pressure, fmt.Sprintf("sockets %d", facts.Sockets))
	}
	if facts.MinMemoryFreePercent > 0 && facts.MemoryFreePercent > 0 && facts.MemoryFreePercent <= facts.MinMemoryFreePercent {
		pressure = append(pressure, fmt.Sprintf("system memory %.0f%% free", facts.MemoryFreePercent))
	}
	if len(pressure) > 0 {
		return report.Warning, "resource threshold reached: " + strings.Join(pressure, ", ")
	}
	return report.Info, "descriptor sample collected"
}
