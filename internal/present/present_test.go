package present_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/upsidedly/mactriage/internal/present"
	"github.com/upsidedly/mactriage/internal/report"
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
