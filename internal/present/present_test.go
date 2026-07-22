package present_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mantaworks/mactriage/internal/present"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestJSONContainsStableSchemaAndNoANSI(t *testing.T) {
	r := report.New("diagnose", "/Applications/Example.app")
	r.Findings = append(r.Findings, report.Finding{Code: "signature.invalid", Severity: report.Error, Title: "Invalid", Explanation: "Failed", Confidence: "high"})
	var out bytes.Buffer
	if err := present.JSON(&out, r); err != nil {
		t.Fatalf("JSON returned error: %v", err)
	}
	text := out.String()
	if !strings.Contains(text, `"schema_version": "1"`) {
		t.Fatalf("schema missing from %s", text)
	}
	if strings.Contains(text, "\x1b[") {
		t.Fatalf("JSON contains ANSI: %q", text)
	}
}

func TestHumanPlainUsesTextSeverityLabels(t *testing.T) {
	r := report.New("diagnose", "Example")
	r.Findings = append(r.Findings, report.Finding{Code: "launch.terminated", Severity: report.Error, Title: "Terminated", Explanation: "Stopped", Confidence: "high"})
	var out bytes.Buffer
	present.Human(&out, r, present.Style{Color: false})
	if !strings.Contains(out.String(), "ERROR") || strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("unexpected plain output: %q", out.String())
	}
}

func TestHumanDoesNotCallPartialEvidenceHealthy(t *testing.T) {
	r := report.New("permissions", "Example")
	r.Completeness = report.Partial
	var out bytes.Buffer
	present.Human(&out, r, present.Style{Color: false})
	if !strings.Contains(out.String(), "INCONCLUSIVE") || strings.Contains(out.String(), "No diagnostic problems") {
		t.Fatalf("partial report rendered as healthy: %q", out.String())
	}
}

func TestHumanRendersNarrowAndWideWithoutLosingSeverity(t *testing.T) {
	r := report.New("diagnose", "Example")
	r.Findings = []report.Finding{{Code: "test", Severity: report.Warning, Title: "A warning", Explanation: strings.Repeat("evidence ", 20)}}
	for _, width := range []int{40, 120} {
		var out bytes.Buffer
		present.Human(&out, r, present.Style{Width: width})
		if !strings.Contains(out.String(), "WARNING") || strings.Contains(out.String(), "\x1b[") {
			t.Fatalf("width=%d output=%q", width, out.String())
		}
	}
}

func TestNDJSONNeverContainsANSI(t *testing.T) {
	var out bytes.Buffer
	if err := present.NDJSON(&out, map[string]string{"severity": "critical", "message": "plain"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "\x1b[") || strings.Count(out.String(), "\n") != 1 {
		t.Fatalf("invalid NDJSON: %q", out.String())
	}
}

func TestWriteAtomicUsesPrivateMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	if err := present.WriteAtomic(path, 0o600, func(w io.Writer) error {
		_, err := io.WriteString(w, "{}\n")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o, want 0600", info.Mode().Perm())
	}
}

func TestHumanDoctorRendererShowsReadableHealthSnapshot(t *testing.T) {
	r := report.New("doctor", "this Mac")
	r.Evidence = []report.Evidence{
		{ID: report.EvidenceStorage, Status: report.StatusOK, Data: report.StorageData{AvailablePercent: 42}},
		{ID: report.EvidenceMemory, Status: report.StatusOK, Data: report.MemoryData{FreePercent: 31, SwapUsedBytes: 512 << 20}},
		{ID: report.EvidenceCPU, Status: report.StatusOK, Data: report.CPUData{LoadOne: 2.5, LogicalCores: 8}},
		{ID: report.EvidenceNetwork, Status: report.StatusOK, Data: report.NetworkData{DNSStatus: report.StatusOK, HTTPSStatus: report.StatusOK, DNSResolved: true, HTTPSReachable: true, TLSValid: true}},
	}
	var out bytes.Buffer
	present.Human(&out, r, present.Style{Width: 80})
	for _, want := range []string{"Health snapshot", "Disk", "Memory", "CPU", "Network"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("doctor output missing %q: %s", want, out.String())
		}
	}
}

func TestHumanDoctorRendererShowsUnavailableNetworkFactsAsUnknown(t *testing.T) {
	r := report.New("doctor", "this Mac")
	r.Completeness = report.Partial
	r.Evidence = []report.Evidence{{ID: report.EvidenceNetwork, Status: report.StatusPartial, Data: report.NetworkData{
		DNSStatus: report.StatusUnavailable, HTTPSStatus: report.StatusTimedOut,
	}}}
	var out bytes.Buffer
	present.Human(&out, r, present.Style{})
	if strings.Count(out.String(), "unknown") != 3 || strings.Contains(out.String(), "not resolved") {
		t.Fatalf("unavailable network facts were rendered as measurements: %q", out.String())
	}
}
