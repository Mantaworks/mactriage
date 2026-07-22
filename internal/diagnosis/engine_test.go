package diagnosis_test

import (
	"testing"

	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestAnalyzeIdentifiesPerProcessDescriptorExhaustion(t *testing.T) {
	r := report.New("diagnose", "Discord")
	r.Evidence = []report.Evidence{
		{ID: "logs", Status: report.StatusOK, Data: report.LogsData{EMFILE: 3, SyspolicydEMFILE: 3, SyspolicydSecStaticCode: 2, SyspolicydWedgeSequence: 1}},
		{ID: "limits", Status: report.StatusOK, Data: report.LimitsData{GlobalUsed: 9423, GlobalMax: 184320}},
		{ID: "descriptors", Status: report.StatusOK, Data: report.DescriptorData{Process: "syspolicyd", Count: 240, ProcessSoft: 256}},
		{ID: "launch", Status: report.StatusOK, Data: report.LaunchData{Spawned: boolPointer(true), Terminated: true}},
	}

	got := diagnosis.Analyze(r)
	assertFinding(t, got, "policy.emfile", report.Critical)
	if len(got.Actions) == 0 || got.Actions[0].ID != "repair.syspolicyd" {
		t.Fatalf("expected syspolicyd repair action, got %#v", got.Actions)
	}
}

func TestAnalyzeKeepsSystemWideExhaustionDistinct(t *testing.T) {
	r := report.New("system", "")
	r.Evidence = []report.Evidence{
		{ID: "logs", Status: report.StatusOK, Data: report.LogsData{ENFILE: 1}},
		{ID: "limits", Status: report.StatusOK, Data: report.LimitsData{GlobalUsed: 184000, GlobalMax: 184320}},
	}
	got := diagnosis.Analyze(r)
	assertFinding(t, got, "system.enfile", report.Critical)
	for _, action := range got.Actions {
		if action.ID == "repair.syspolicyd" {
			t.Fatal("system-wide exhaustion must not recommend restarting syspolicyd")
		}
	}
}

func TestAnalyzeDoesNotAuthorizeRepairFromUnrelatedLogEvents(t *testing.T) {
	r := report.New("diagnose", "Example")
	r.Evidence = []report.Evidence{
		{ID: "logs", Status: report.StatusOK, Data: report.LogsData{EMFILE: 1, SecStaticCode: 1, SyspolicydSecStaticCode: 1}},
		{ID: "limits", Status: report.StatusOK, Data: report.LimitsData{}},
		{ID: "descriptors", Status: report.StatusOK, Data: report.DescriptorData{Process: "syspolicyd", Count: 256, ProcessSoft: 256}},
	}
	got := diagnosis.Analyze(r)
	for _, available := range got.Actions {
		if available.ID == "repair.syspolicyd" {
			t.Fatal("unrelated EMFILE evidence must not authorize syspolicyd restart")
		}
	}
}

func TestAnalyzeDeterminesRosettaFromHostHardware(t *testing.T) {
	r := report.New("diagnose", "Example")
	r.Host.Arch = "arm64"
	r.Evidence = []report.Evidence{{ID: "architecture", Status: report.StatusOK, Data: report.ArchitectureData{Architectures: []string{"x86_64"}}}}
	got := diagnosis.Analyze(r)
	assertFinding(t, got, "architecture.rosetta_required", report.Warning)
}

func TestAnalyzeReportsInvalidSignatureAndGatekeeperReview(t *testing.T) {
	r := report.New("diagnose", "Example")
	r.Evidence = []report.Evidence{
		{ID: "signature", Status: report.StatusFailed, Data: report.SignatureData{Valid: false, Reason: "invalid"}},
		{ID: "gatekeeper", Status: report.StatusFailed, Data: report.GatekeeperData{Accepted: false, Reason: "rejected"}},
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
		{ID: "bundle", Status: report.StatusFailed, Data: report.BundleData{OSSupported: boolPointer(false)}},
		{ID: "quarantine", Status: report.StatusOK, Data: report.QuarantineData{Present: true}},
		{ID: "crash", Status: report.StatusOK, Data: report.CrashData{Count: 1}},
	}
	got := diagnosis.Analyze(r)
	assertFinding(t, got, "bundle.executable_missing", report.Error)
	assertFinding(t, got, "os.unsupported", report.Error)
	assertFinding(t, got, "quarantine.present", report.Info)
	assertFinding(t, got, "crash.detected", report.Error)
}

func TestAnalyzeLogRuleMatrix(t *testing.T) {
	tests := []struct {
		name     string
		data     report.LogsData
		code     string
		severity report.Severity
	}{
		{"xprotect", report.LogsData{XProtect: 1}, "xprotect.blocked", report.Critical},
		{"launch services", report.LogsData{LaunchServices: 1}, "launchservices.failure", report.Error},
		{"missing library", report.LogsData{MissingLibrary: 1}, "dependency.missing", report.Error},
		{"signature", report.LogsData{SignatureErrors: 1}, "signature.runtime_invalid", report.Error},
		{"notarization", report.LogsData{NotarizationErrors: 1}, "notarization.failed", report.Error},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := report.New("diagnose", "Example")
			r.Evidence = []report.Evidence{{ID: "logs", Status: report.StatusOK, Data: test.data}}
			got := diagnosis.Analyze(r)
			assertFinding(t, got, test.code, test.severity)
		})
	}
}

func TestAnalyzeResolutionAndRepairFailures(t *testing.T) {
	missing := report.New("diagnose", "Missing")
	missing.Evidence = []report.Evidence{{ID: "bundle", Status: report.StatusFailed, Data: report.ResolutionData{ResolveCode: "app.not_found"}}}
	assertFinding(t, diagnosis.Analyze(missing), "app.not_found", report.Error)

	repair := report.New("repair", "syspolicyd")
	repair.Evidence = []report.Evidence{{ID: "restart", Status: report.StatusFailed, Error: "permission denied"}}
	assertFinding(t, diagnosis.Analyze(repair), "repair.failed", report.Error)
}

func TestAnalyzePartialEvidenceReturnsInconclusiveExit(t *testing.T) {
	r := report.New("diagnose", "Example")
	r.Evidence = []report.Evidence{{ID: "logs", Status: report.StatusPartial}}
	got := diagnosis.Analyze(r)
	if got.Completeness != report.Partial || got.ExitCode() != 3 {
		t.Fatalf("completeness=%s exit=%d", got.Completeness, got.ExitCode())
	}
}

func TestAnalyzeDoctorRanksEverydayHealthProblems(t *testing.T) {
	r := report.New("doctor", "this Mac")
	r.Evidence = []report.Evidence{
		{ID: report.EvidenceStorage, Status: report.StatusOK, Data: report.StorageData{AvailablePercent: 5}},
		{ID: report.EvidenceMemory, Status: report.StatusOK, Data: report.MemoryData{FreePercent: 4, SwapUsedBytes: 6 << 30}},
		{ID: report.EvidenceCPU, Status: report.StatusOK, Data: report.CPUData{LogicalCores: 4, LoadOne: 9, HighestPercent: 97, HighestProcess: "Example", ProcessStates: map[string]int{"D": 1}}},
		{ID: report.EvidenceServices, Status: report.StatusOK, Data: report.ServicesData{Running: map[string]bool{"syspolicyd": false, "trustd": true}}},
		{ID: report.EvidenceUpdates, Status: report.StatusOK, Data: report.UpdatesData{Available: true}},
		{ID: report.EvidenceRecentCrashes, Status: report.StatusOK, Data: report.RecentCrashesData{Count: 12}},
		{ID: report.EvidenceStartupItems, Status: report.StatusOK, Data: report.StartupItemsData{Count: 120}},
		{ID: report.EvidenceRestartLoops, Status: report.StatusOK, Data: report.RestartLoopsData{Processes: []report.ProcessRestartObservation{{Name: "com.example.Helper", Count: 4}}}},
		{ID: report.EvidenceLimits, Status: report.StatusOK, Data: report.LimitsData{GlobalUsed: 900, GlobalMax: 1000}},
	}

	got := diagnosis.Analyze(r)
	for _, expected := range []struct {
		code     string
		severity report.Severity
	}{
		{"doctor.storage_low", report.Error},
		{"doctor.memory_pressure", report.Warning},
		{"doctor.cpu_pressure", report.Warning},
		{"doctor.process_stalled", report.Warning},
		{"doctor.service_missing", report.Error},
		{"doctor.updates_available", report.Info},
		{"doctor.crash_volume", report.Warning},
		{"doctor.startup_items_high", report.Warning},
		{"doctor.restart_loop", report.Warning},
		{"doctor.descriptor_pressure", report.Warning},
	} {
		assertFinding(t, got, expected.code, expected.severity)
	}
	if len(got.Actions) == 0 || got.Actions[0].ID != "open.software_update" {
		t.Fatalf("expected Software Update action: %#v", got.Actions)
	}
}

func TestAnalyzeNetworkDistinguishesConnectivityAndConfiguration(t *testing.T) {
	r := report.New("network", "example.com")
	r.Evidence = []report.Evidence{{ID: report.EvidenceNetwork, Status: report.StatusOK, Data: report.NetworkData{
		Host: "example.com", DNSStatus: report.StatusOK, RouteStatus: report.StatusOK, ProxyStatus: report.StatusOK, VPNStatus: report.StatusOK, HTTPSStatus: report.StatusOK, ListenersStatus: report.StatusOK,
		DefaultRoute: true, HTTPSReachable: true, TLSValid: false, ProxyConfigured: true, VPNInterfaces: []string{"utun3"},
	}}}
	got := diagnosis.Analyze(r)
	assertFinding(t, got, "network.dns_failed", report.Error)
	assertFinding(t, got, "network.tls_invalid", report.Error)
	assertFinding(t, got, "network.proxy_detected", report.Info)
	assertFinding(t, got, "network.vpn_detected", report.Info)
}

func TestAnalyzeNetworkDoesNotDiagnoseUnavailableProbes(t *testing.T) {
	r := report.New("network", "example.com")
	r.Evidence = []report.Evidence{{ID: report.EvidenceNetwork, Status: report.StatusPartial, Data: report.NetworkData{
		Host: "example.com", DNSStatus: report.StatusUnavailable, RouteStatus: report.StatusUnavailable, HTTPSStatus: report.StatusTimedOut,
	}}}
	got := diagnosis.Analyze(r)
	if len(got.Findings) != 0 || got.Completeness != report.Partial || got.ExitCode() != 3 {
		t.Fatalf("unavailable probes became diagnoses: %#v", got)
	}
}

func TestAnalyzeRestartRequiresRepeatedObservations(t *testing.T) {
	r := report.New("doctor", "this Mac")
	r.Evidence = []report.Evidence{{ID: report.EvidenceRestartLoops, Status: report.StatusOK, Data: report.RestartLoopsData{Processes: []report.ProcessRestartObservation{{Name: "Example", Count: 2}}}}}
	got := diagnosis.Analyze(r)
	for _, finding := range got.Findings {
		if finding.Code == "doctor.restart_loop" {
			t.Fatalf("two exit observations classified as a restart loop: %#v", got.Findings)
		}
	}
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

func boolPointer(value bool) *bool { return &value }
