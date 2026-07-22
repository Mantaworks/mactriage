package diagnosis_test

import (
	"testing"

	"github.com/upsidedly/mactriage/internal/diagnosis"
	"github.com/upsidedly/mactriage/internal/report"
)

func TestAnalyzeIdentifiesPerProcessDescriptorExhaustion(t *testing.T) {
	r := report.New("diagnose", "Discord")
	r.Evidence = []report.Evidence{
		{ID: "logs", Status: report.StatusOK, Data: map[string]any{"emfile": float64(3), "sec_static_code": float64(2)}},
		{ID: "limits", Status: report.StatusOK, Data: map[string]any{"global_used": float64(9423), "global_max": float64(184320)}},
		{ID: "launch", Status: report.StatusOK, Data: map[string]any{"spawned": true, "survived": false, "terminated": true}},
	}

	got := diagnosis.Analyze(r)
	assertFinding(t, got, "policy.emfile", report.Critical)
	if len(got.Actions) == 0 || got.Actions[0].ID != "repair.syspolicyd" {
		t.Fatalf("expected syspolicyd repair action, got %#v", got.Actions)
	}
}

func TestAnalyzeKeepsSystemWideExhaustionDistinct(t *testing.T) {
	r := report.New("system", "")
	r.Evidence = []report.Evidence{{ID: "logs", Status: report.StatusOK, Data: map[string]any{"enfile": float64(1)}}}
	got := diagnosis.Analyze(r)
	assertFinding(t, got, "system.enfile", report.Critical)
	for _, action := range got.Actions {
		if action.ID == "repair.syspolicyd" {
			t.Fatal("system-wide exhaustion must not recommend restarting syspolicyd")
		}
	}
}

func TestAnalyzeReportsInvalidSignatureAndGatekeeperReview(t *testing.T) {
	r := report.New("diagnose", "Example")
	r.Evidence = []report.Evidence{
		{ID: "signature", Status: report.StatusFailed, Data: map[string]any{"valid": false, "reason": "invalid"}},
		{ID: "gatekeeper", Status: report.StatusFailed, Data: map[string]any{"accepted": false, "reason": "rejected"}},
	}
	got := diagnosis.Analyze(r)
	assertFinding(t, got, "signature.invalid", report.Error)
	assertFinding(t, got, "gatekeeper.rejected", report.Error)
	for _, action := range got.Actions {
		if action.ID == "open.security" {
			t.Fatal("invalid signatures must not recommend bypassing Gatekeeper")
		}
	}
}

func TestAnalyzeReportsBundleCompatibilityAndCrashEvidence(t *testing.T) {
	r := report.New("diagnose", "Example")
	r.Evidence = []report.Evidence{
		{ID: "bundle", Status: report.StatusFailed, Data: map[string]any{"executable_present": false, "os_supported": false}},
		{ID: "quarantine", Status: report.StatusOK, Data: map[string]any{"present": true}},
		{ID: "crash", Status: report.StatusOK, Data: map[string]any{"count": float64(1)}},
	}
	got := diagnosis.Analyze(r)
	assertFinding(t, got, "bundle.executable_missing", report.Error)
	assertFinding(t, got, "os.unsupported", report.Error)
	assertFinding(t, got, "quarantine.present", report.Info)
	assertFinding(t, got, "crash.detected", report.Error)
}

func assertFinding(t *testing.T, r report.Report, code string, severity report.Severity) {
	t.Helper()
	for _, finding := range r.Findings {
		if finding.Code == code {
			if finding.Severity != severity {
				t.Fatalf("finding %s severity = %s, want %s", code, finding.Severity, severity)
			}
			return
		}
	}
	t.Fatalf("finding %s not present: %#v", code, r.Findings)
}
