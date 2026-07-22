package macos_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/upsidedly/mactriage/internal/macos"
	"github.com/upsidedly/mactriage/internal/platform"
	"github.com/upsidedly/mactriage/internal/report"
)

func TestCollectorUsesTypedPlatformEvidenceWithoutDiagnosing(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "Fixture.app", "Contents", "MacOS", "Fixture")
	if err := os.MkdirAll(filepath.Dir(executable), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := collectorRunner{executable: executable}
	app := macos.App{Path: filepath.Join(root, "Fixture.app"), Name: "Fixture", BundleID: "dev.fixture", Executable: "Fixture", ExecutablePath: executable, MinimumOS: "13.0"}
	r, err := (macos.Collector{Runner: runner}).Collect(context.Background(), app, macos.DiagnoseOptions{NoLaunch: true})
	if err != nil {
		t.Fatal(err)
	}
	if r.Host.Arch != "amd64" || r.Host.OSVersion != "14.5" {
		t.Fatalf("unexpected host: %#v", r.Host)
	}
	arch := evidenceByID(t, r, "architecture")
	if _, ok := arch.Data.(report.ArchitectureData); !ok {
		t.Fatalf("architecture evidence is not typed: %#v", arch.Data)
	}
	deps := evidenceByID(t, r, "dependencies")
	if data, ok := deps.Data.(report.DependencyData); !ok || data.MissingCount != 1 {
		t.Fatalf("missing dependency evidence: %#v", deps.Data)
	}
	bundle := evidenceByID(t, r, "bundle")
	if data, ok := bundle.Data.(report.BundleData); !ok || data.OSSupported == nil || !*data.OSSupported {
		t.Fatalf("minimum-version evidence: %#v", bundle.Data)
	}
}

func TestCollectorMarksPermissionFailureAndTimeoutAsIncompleteEvidence(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "Fixture.app", "Contents", "MacOS", "Fixture")
	if err := os.MkdirAll(filepath.Dir(executable), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	app := macos.App{Path: filepath.Join(root, "Fixture.app"), Name: "Fixture", Executable: "Fixture", ExecutablePath: executable}
	runner := collectorRunner{executable: executable, xattrError: "permission denied", codesignTimeout: true}
	r, err := (macos.Collector{Runner: runner}).Collect(context.Background(), app, macos.DiagnoseOptions{NoLaunch: true})
	if err != nil {
		t.Fatal(err)
	}
	if evidenceByID(t, r, report.EvidenceQuarantine).Status != report.StatusUnavailable {
		t.Fatalf("quarantine permission failure was not unavailable: %#v", evidenceByID(t, r, report.EvidenceQuarantine))
	}
	if evidenceByID(t, r, report.EvidenceSignature).Status != report.StatusTimedOut {
		t.Fatalf("signature timeout was not preserved: %#v", evidenceByID(t, r, report.EvidenceSignature))
	}
}

func TestCollectorLaunchLifecycleFixtures(t *testing.T) {
	for _, mode := range []string{"survives", "terminates", "spawn_fails"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			executable := filepath.Join(root, "Fixture.app", "Contents", "MacOS", "Fixture")
			if err := os.MkdirAll(filepath.Dir(executable), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(executable, []byte("fixture"), 0o755); err != nil {
				t.Fatal(err)
			}
			app := macos.App{Path: filepath.Join(root, "Fixture.app"), Name: "Fixture", Executable: "Fixture", ExecutablePath: executable}
			runner := &lifecycleRunner{collectorRunner: collectorRunner{executable: executable}, mode: mode}
			r, err := (macos.Collector{Runner: runner}).Collect(context.Background(), app, macos.DiagnoseOptions{Observe: 350 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			launch, ok := evidenceByID(t, r, report.EvidenceLaunch).Data.(report.LaunchData)
			if !ok {
				t.Fatalf("launch evidence is not typed: %#v", evidenceByID(t, r, report.EvidenceLaunch).Data)
			}
			switch mode {
			case "survives":
				if launch.Spawned == nil || !*launch.Spawned || !launch.Survived {
					t.Fatalf("unexpected surviving launch: %#v", launch)
				}
			case "terminates":
				if launch.Spawned == nil || !*launch.Spawned || !launch.Terminated || launch.ExitSignal != "unknown" {
					t.Fatalf("unexpected terminated launch: %#v", launch)
				}
			case "spawn_fails":
				if launch.Spawned == nil || *launch.Spawned {
					t.Fatalf("unexpected failed launch: %#v", launch)
				}
			}
		})
	}
}

func evidenceByID(t *testing.T, r report.Report, id report.EvidenceID) report.Evidence {
	t.Helper()
	for _, evidence := range r.Evidence {
		if evidence.ID == id {
			return evidence
		}
	}
	t.Fatalf("missing evidence %q", id)
	return report.Evidence{}
}

type collectorRunner struct {
	executable      string
	xattrError      string
	codesignTimeout bool
}

type lifecycleRunner struct {
	collectorRunner
	mode    string
	opened  bool
	psCalls int
}

func (r *lifecycleRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/open":
		if r.mode == "spawn_fails" {
			return platform.Result{Err: errors.New("launch rejected")}
		}
		r.opened = true
		return platform.Result{}
	case "/bin/ps":
		if !r.opened {
			return platform.Result{}
		}
		r.psCalls++
		if r.mode == "terminates" && r.psCalls > 1 {
			return platform.Result{}
		}
		return platform.Result{Stdout: "42 " + r.executable + "\n"}
	default:
		return r.collectorRunner.Run(ctx, path, args...)
	}
}

func (r collectorRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/uname":
		return platform.Result{Stdout: "x86_64\n"}
	case "/usr/bin/sw_vers":
		if len(args) > 0 && args[0] == "-productVersion" {
			return platform.Result{Stdout: "14.5\n"}
		}
		return platform.Result{Stdout: "23F79\n"}
	case "/usr/sbin/sysctl":
		if len(args) > 0 && args[0] == "-n" {
			return platform.Result{Stdout: "0\n"}
		}
		return platform.Result{Stdout: "kern.num_files: 100\nkern.maxfiles: 10000\nkern.maxfilesperproc: 2048\n"}
	case "/usr/bin/codesign":
		if r.codesignTimeout {
			return platform.Result{Err: context.DeadlineExceeded, TimedOut: true}
		}
		return platform.Result{}
	case "/usr/sbin/spctl":
		return platform.Result{}
	case "/usr/bin/xattr":
		message := r.xattrError
		if message == "" {
			message = "attribute not found"
		}
		return platform.Result{Err: errors.New(message), Stderr: message}
	case "/usr/bin/lipo":
		return platform.Result{Stdout: "x86_64\n"}
	case "/usr/bin/otool":
		if len(args) > 0 && args[0] == "-L" {
			return platform.Result{Stdout: r.executable + ":\n\t@rpath/Missing.dylib (compatibility version 1.0.0, current version 1.0.0)\n"}
		}
		return platform.Result{Stdout: "Load command 1\n          cmd LC_RPATH\n      cmdsize 40\n         path @executable_path/../Frameworks (offset 12)\n"}
	case "/bin/launchctl":
		return platform.Result{Stdout: "maxfiles 256 unlimited\n"}
	case "/usr/bin/log":
		return platform.Result{}
	default:
		return platform.Result{Err: errors.New("unexpected command: " + path), TimedOut: path == "/usr/bin/false", Duration: time.Millisecond}
	}
}
