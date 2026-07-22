package diagnosis_test

import (
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestClassifyWatchRequiresMeasurementToNameErrnoCondition(t *testing.T) {
	severity, _ := diagnosis.ClassifyWatch(diagnosis.WatchFacts{EMFILE: 1})
	if severity == report.Critical {
		t.Fatal("uncorroborated errno text must not become a critical diagnosis")
	}
	severity, _ = diagnosis.ClassifyWatch(diagnosis.WatchFacts{EMFILE: 1, ProcessPressure: true})
	if severity != report.Critical {
		t.Fatalf("severity=%s, want critical", severity)
	}
}

func TestClassifyWatchReportsGrowthRate(t *testing.T) {
	severity, message := diagnosis.ClassifyWatch(diagnosis.WatchFacts{Growth: 200, GrowthRate: 10, WarnGrowth: 150, Window: 20 * time.Second})
	if severity != report.Warning || message == "" {
		t.Fatalf("severity=%s message=%q", severity, message)
	}
}

func TestClassifyWatchReportsBroaderResourcePressure(t *testing.T) {
	severity, message := diagnosis.ClassifyWatch(diagnosis.WatchFacts{CPUPercent: 95, CPUThreshold: 80, MemoryFreePercent: 5, MinMemoryFreePercent: 10})
	if severity != report.Warning || message == "" {
		t.Fatalf("severity=%s message=%q", severity, message)
	}
}
