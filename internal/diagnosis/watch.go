package diagnosis

import (
	"fmt"
	"time"

	"github.com/upsidedly/mactriage/internal/report"
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
	return report.Info, "descriptor sample collected"
}
