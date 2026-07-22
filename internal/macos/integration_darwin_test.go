//go:build darwin && integration

package macos_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestIntegrationSystemUtilitiesExist(t *testing.T) {
	for _, path := range []string{"/usr/bin/codesign", "/usr/sbin/spctl", "/usr/bin/xattr", "/usr/bin/lipo", "/usr/bin/otool", "/usr/bin/log", "/usr/sbin/lsof", "/usr/bin/sample", "/usr/bin/pgrep", "/usr/bin/memory_pressure", "/bin/ps"} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("required system utility %s: %v", path, err)
		}
	}
}

func TestIntegrationProcessInspector(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	runner := platform.ExecRunner{Timeout: 10 * time.Second, MaxOutput: 1 << 20}
	r, err := (macos.ProcessInspector{Runner: runner}).Inspect(ctx, strconv.Itoa(os.Getpid()), macos.ProcessThresholds{})
	if err != nil {
		t.Fatalf("inspect current process: %v", err)
	}
	data, ok := r.Evidence[0].Data.(report.ProcessData)
	if !ok || data.PID != os.Getpid() || data.RSSBytes == 0 || data.Name == "" {
		t.Fatalf("incomplete process metrics: %#v", r.Evidence)
	}
}

func TestIntegrationScanOneSystemApplication(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	runner := platform.ExecRunner{Timeout: 15 * time.Second, MaxOutput: 2 << 20}
	r, err := (macos.AppScanner{Runner: runner}).Scan(ctx, []string{"/System/Applications/Calculator.app"}, 1, 1)
	if err != nil {
		t.Fatalf("scan Calculator: %v", err)
	}
	data, ok := r.Evidence[0].Data.(report.ScanData)
	if !ok || len(data.Apps) != 1 || data.Apps[0].Name == "" {
		t.Fatalf("incomplete scan data: %#v", r.Evidence)
	}
}

func TestIntegrationPassiveSystemAppDiagnosis(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	runner := platform.ExecRunner{Timeout: 15 * time.Second, MaxOutput: 4 << 20}
	apps, err := (macos.Resolver{Runner: runner}).Resolve(ctx, "/System/Applications/Calculator.app")
	if err != nil || len(apps) != 1 {
		t.Fatalf("resolve Calculator: apps=%d error=%v", len(apps), err)
	}
	r, err := (macos.Collector{Runner: runner}).Collect(ctx, apps[0], macos.DiagnoseOptions{NoLaunch: true})
	if err != nil {
		t.Fatalf("passive diagnosis: %v", err)
	}
	if r.Target == "" || len(r.Evidence) < 8 {
		t.Fatalf("incomplete integration report: target=%q evidence=%d", r.Target, len(r.Evidence))
	}
}
