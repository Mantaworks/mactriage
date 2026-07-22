package macos_test

import (
	"context"
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
)

func TestPermissionInspectionReportsOnlyExplicitCorrelatedDenials(t *testing.T) {
	app := macos.App{Name: "Example", BundleID: "com.example.App", Path: "/Applications/Example.app"}
	r, err := (macos.PermissionInspector{Runner: permissionRunner{}}).Inspect(context.Background(), app, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r = diagnosis.Analyze(r)
	if len(r.Findings) != 1 || r.Findings[0].Code != "permission.denied" {
		t.Fatalf("findings=%#v", r.Findings)
	}
	if len(r.Actions) != 1 || r.Actions[0].ID != "open.security" {
		t.Fatalf("actions=%#v", r.Actions)
	}
}

type permissionRunner struct{}

func (permissionRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/codesign":
		return platform.Result{Stderr: `<plist><dict><key>com.apple.security.device.camera</key><true/></dict></plist>`}
	case "/usr/bin/log":
		return platform.Result{Stdout: "{\"process\":\"tccd\",\"eventMessage\":\"Denying camera access to com.example.App\"}\n{\"process\":\"tccd\",\"eventMessage\":\"Denying microphone access to com.other.App\"}\n"}
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
