package platform_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/upsidedly/mactriage/internal/platform"
)

func TestExecRunnerRequiresAbsoluteExecutable(t *testing.T) {
	r := platform.ExecRunner{Timeout: time.Second, MaxOutput: 1024}
	result := r.Run(context.Background(), "printf", "hello")
	if result.Err == nil || !strings.Contains(result.Err.Error(), "absolute") {
		t.Fatalf("Run error = %v, want absolute-path error", result.Err)
	}
}

func TestExecRunnerCapturesStructuredResult(t *testing.T) {
	r := platform.ExecRunner{Timeout: time.Second, MaxOutput: 1024}
	result := r.Run(context.Background(), "/usr/bin/printf", "hello")
	if result.Err != nil {
		t.Fatalf("Run returned error: %v", result.Err)
	}
	if result.Stdout != "hello" || result.ExitCode != 0 || result.TimedOut {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestExecRunnerBoundsOutput(t *testing.T) {
	r := platform.ExecRunner{Timeout: time.Second, MaxOutput: 4}
	result := r.Run(context.Background(), "/usr/bin/printf", "abcdefgh")
	if result.Stdout != "abcd" || !result.Truncated {
		t.Fatalf("unexpected bounded output: %#v", result)
	}
}
