//go:build darwin && integration

package macos_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
)

func TestIntegrationSystemUtilitiesExist(t *testing.T) {
	for _, path := range []string{"/usr/bin/codesign", "/usr/sbin/spctl", "/usr/bin/xattr", "/usr/bin/lipo", "/usr/bin/otool", "/usr/bin/log", "/usr/sbin/lsof"} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("required system utility %s: %v", path, err)
		}
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
