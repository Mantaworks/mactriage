package report_test

import (
	"testing"

	"github.com/Mantaworks/mactriage/internal/report"
)

func TestReportExitCodeReflectsUserFacingOutcome(t *testing.T) {
	tests := []struct {
		name string
		r    report.Report
		want int
	}{
		{name: "healthy", r: report.Report{Completeness: report.Complete}, want: 0},
		{name: "warning only", r: report.Report{Completeness: report.Complete, Findings: []report.Finding{{Severity: report.Warning}}}, want: 0},
		{name: "diagnosed error", r: report.Report{Completeness: report.Complete, Findings: []report.Finding{{Severity: report.Error}}}, want: 1},
		{name: "diagnosed critical", r: report.Report{Completeness: report.Complete, Findings: []report.Finding{{Severity: report.Critical}}}, want: 1},
		{name: "inconclusive", r: report.Report{Completeness: report.Partial}, want: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.ExitCode(); got != tt.want {
				t.Fatalf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNewSetsStableSchemaDefaults(t *testing.T) {
	r := report.New("diagnose", "Discord")
	if r.SchemaVersion != "1" {
		t.Fatalf("SchemaVersion = %q, want 1", r.SchemaVersion)
	}
	if r.Completeness != report.Complete {
		t.Fatalf("Completeness = %q, want complete", r.Completeness)
	}
	if r.GeneratedAt.IsZero() {
		t.Fatal("GeneratedAt must be populated")
	}
}
