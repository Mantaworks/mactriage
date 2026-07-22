package macos_test

import (
	"context"
	"testing"

	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestInspectProcessProducesHighCPUFindingFromPublicReport(t *testing.T) {
	runner := processRunner{}
	r, err := (macos.ProcessInspector{Runner: runner}).Inspect(context.Background(), "Example", macos.ProcessThresholds{CPUPercent: 80, MemoryBytes: 4 << 30})
	if err != nil {
		t.Fatal(err)
	}
	r = diagnosis.Analyze(r)
	data, ok := r.Evidence[0].Data.(report.ProcessData)
	if !ok || data.Threads != 2 {
		t.Fatalf("process data=%#v", r.Evidence)
	}
	found := false
	for _, finding := range r.Findings {
		if finding.Code == "resource.cpu_high" {
			found = true
		}
	}
	if !found {
		t.Fatalf("high CPU finding missing: %#v", r.Findings)
	}
}

type processRunner struct{}

func (processRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/pgrep":
		return platform.Result{Stdout: "4242\n"}
	case "/bin/ps":
		if len(args) > 0 && args[0] == "-M" {
			return platform.Result{Stdout: "USER PID COMMAND\nuser 4242 Example\nuser 4242 Example\n"}
		}
		return platform.Result{Stdout: "4242 94.5 204800 S 01:02 /Applications/Example.app/Contents/MacOS/Example\n"}
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
