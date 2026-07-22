package macos_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestScanFindsIntelOnlyAndInvalidSignatureApplications(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"Good.app", "Bad.app"} {
		if err := os.MkdirAll(filepath.Join(root, name, "Contents", "MacOS"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name, "Contents", "MacOS", "App"), []byte("binary"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r, err := (macos.AppScanner{Runner: scanRunner{}}).Scan(context.Background(), []string{root}, 20, 2)
	if err != nil {
		t.Fatal(err)
	}
	r = diagnosis.Analyze(r)
	data, ok := r.Evidence[0].Data.(report.ScanData)
	if !ok || len(data.Apps) != 2 {
		t.Fatalf("scan data=%#v", r.Evidence)
	}
	codes := map[string]bool{}
	for _, finding := range r.Findings {
		codes[finding.Code] = true
	}
	if !codes["scan.signature_invalid"] || !codes["scan.intel_only"] {
		t.Fatalf("findings=%#v", r.Findings)
	}
}

func TestScanDoesNotCallOperationalCodesignFailureInvalid(t *testing.T) {
	root := t.TempDir()
	appPath := filepath.Join(root, "Example.app")
	if err := os.MkdirAll(filepath.Join(appPath, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appPath, "Contents", "MacOS", "App"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := (macos.AppScanner{Runner: unavailableSignatureRunner{}}).Scan(context.Background(), []string{root}, 10, 1)
	if err != nil {
		t.Fatal(err)
	}
	r = diagnosis.Analyze(r)
	if r.Completeness != report.Partial {
		t.Fatalf("completeness=%s", r.Completeness)
	}
	for _, finding := range r.Findings {
		if finding.Code == "scan.signature_invalid" {
			t.Fatalf("operational failure became invalid signature: %#v", r.Findings)
		}
	}
}

type unavailableSignatureRunner struct{ scanRunner }

func (unavailableSignatureRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	if path == "/usr/bin/codesign" {
		return platform.Result{ExitCode: -1, Err: errors.New("codesign unavailable")}
	}
	return (scanRunner{}).Run(ctx, path, args...)
}

type scanRunner struct{}

func (scanRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/plutil":
		bundle := filepath.Base(filepath.Dir(filepath.Dir(args[len(args)-1])))
		return platform.Result{Stdout: `{"CFBundleName":"` + bundle[:len(bundle)-4] + `","CFBundleIdentifier":"com.example.` + bundle + `","CFBundleExecutable":"App","CFBundleShortVersionString":"1.0","LSMinimumSystemVersion":"13.0"}`}
	case "/usr/bin/codesign":
		if len(args) > 0 && filepath.Base(args[len(args)-1]) == "Bad.app" {
			return platform.Result{Err: errors.New("invalid signature"), Stderr: "invalid signature"}
		}
		return platform.Result{}
	case "/usr/bin/lipo":
		return platform.Result{Stdout: "x86_64\n"}
	case "/usr/bin/uname":
		return platform.Result{Stdout: "arm64\n"}
	case "/usr/bin/sw_vers":
		return platform.Result{Stdout: "14.5\n"}
	case "/usr/sbin/sysctl":
		return platform.Result{Stdout: "1\n"}
	default:
		return platform.Result{}
	}
}
