package reportutil_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/Mantaworks/mactriage/internal/reportutil"
)

func TestCompareReportsTracksFindingAndEvidenceChanges(t *testing.T) {
	before := report.New("diagnose", "Example")
	before.Findings = []report.Finding{{Code: "old.problem", Severity: report.Error}, {Code: "same.problem", Severity: report.Warning}}
	before.Evidence = []report.Evidence{{ID: report.EvidenceSignature, Status: report.StatusFailed}}
	after := report.New("diagnose", "Example")
	after.Findings = []report.Finding{{Code: "same.problem", Severity: report.Warning}, {Code: "new.problem", Severity: report.Error}}
	after.Evidence = []report.Evidence{{ID: report.EvidenceSignature, Status: report.StatusOK}}
	comparison := reportutil.Compare(before, after)
	if !reflect.DeepEqual(comparison.Added, []string{"new.problem"}) || !reflect.DeepEqual(comparison.Resolved, []string{"old.problem"}) || !reflect.DeepEqual(comparison.Unchanged, []string{"same.problem"}) {
		t.Fatalf("unexpected comparison: %#v", comparison)
	}
	if len(comparison.EvidenceChanges) != 1 || comparison.EvidenceChanges[0].Before != report.StatusFailed || comparison.EvidenceChanges[0].After != report.StatusOK {
		t.Fatalf("unexpected evidence changes: %#v", comparison.EvidenceChanges)
	}
}

func TestLoadReadsSanitizedReportWithoutConcreteEvidencePayloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	contents := `{"schema_version":"1","command":"diagnose","target":"Example","host":{},"completeness":"complete","evidence":[{"id":"bundle","status":"ok","summary":"readable","data":{"path":"/Applications/Example.app"}}],"findings":[],"actions":[]}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := reportutil.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Target != "Example" || len(loaded.Evidence) != 1 || loaded.Evidence[0].Status != report.StatusOK {
		t.Fatalf("loaded=%#v", loaded)
	}
}

func TestCompareReportsHealthMetricsAndNewIntelOnlyApps(t *testing.T) {
	before := report.New("doctor", "this Mac")
	before.Host.Arch = "arm64"
	before.Evidence = []report.Evidence{
		{ID: report.EvidenceStorage, Status: report.StatusOK, Data: report.StorageData{AvailablePercent: 40}},
		{ID: report.EvidenceMemory, Status: report.StatusOK, Data: report.MemoryData{SwapUsedBytes: 1 << 30}},
		{ID: report.EvidenceScan, Status: report.StatusOK, Data: report.ScanData{Apps: []report.ScannedApp{{Name: "Example", Architectures: []string{"arm64"}}}}},
	}
	after := report.New("doctor", "this Mac")
	after.Host.Arch = "arm64"
	after.Evidence = []report.Evidence{
		{ID: report.EvidenceStorage, Status: report.StatusOK, Data: report.StorageData{AvailablePercent: 20}},
		{ID: report.EvidenceMemory, Status: report.StatusOK, Data: report.MemoryData{SwapUsedBytes: 3 << 30}},
		{ID: report.EvidenceScan, Status: report.StatusOK, Data: report.ScanData{Apps: []report.ScannedApp{{Name: "Example", Architectures: []string{"x86_64"}}}}},
	}

	comparison := reportutil.Compare(before, after)
	if len(comparison.MetricChanges) < 2 || len(comparison.NewIntelOnly) != 1 || comparison.NewIntelOnly[0] != "Example" {
		t.Fatalf("comparison=%#v", comparison)
	}
}
