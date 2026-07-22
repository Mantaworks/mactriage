package support_test

import (
	"archive/zip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Mantaworks/mactriage/internal/report"
	"github.com/Mantaworks/mactriage/internal/support"
)

func TestWriteBundleContainsOnlySanitizedDeclaredFiles(t *testing.T) {
	r := report.New("diagnose", "/Applications/Example.app")
	r.Findings = append(r.Findings, report.Finding{Code: "gatekeeper.rejected", Severity: report.Error, Title: "Gatekeeper rejected the application", Explanation: "Policy denied launch.", Confidence: report.ConfidenceHigh})
	path := filepath.Join(t.TempDir(), "support.zip")
	manifest, err := support.WriteBundle(path, r)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := manifest.Files, []string{"manifest.json", "report.json", "summary.txt"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("files=%v want=%v", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o want=0600", info.Mode().Perm())
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var names []string
	for _, file := range reader.File {
		names = append(names, file.Name)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, manifest.Files) {
		t.Fatalf("archive files=%v manifest=%v", names, manifest.Files)
	}
}

func TestMarkdownSummaryRedactsHomeAndControlCharacters(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	r := report.New("doctor", filepath.Join(home, "Applications", "Private.app")+"\x00")
	r.Findings = append(r.Findings, report.Finding{Code: "doctor.storage_low", Severity: report.Warning, Title: "Low disk", Explanation: "Needs attention\x1b[31m", Confidence: report.ConfidenceHigh})
	markdown := support.MarkdownSummary(r)
	if strings.Contains(markdown, home) || strings.Contains(markdown, "\x00") || strings.Contains(markdown, "\x1b") || !strings.Contains(markdown, "~/Applications/Private.app") {
		t.Fatalf("summary was not sanitized: %q", markdown)
	}
}
