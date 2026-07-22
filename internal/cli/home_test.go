package cli

import (
	"reflect"
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/present"
)

func TestGuidedSelectionPreservesGlobalFlags(t *testing.T) {
	opts := options{output: "report.json", verbose: true, plain: true, accessible: true, color: "never", animation: "never", timeout: 30 * time.Second}
	got := homeArgs(opts, present.HomeChoice{Task: "diagnose", Target: "Example"})
	want := []string{"--output", "report.json", "--verbose", "--plain", "--accessible", "--color", "never", "--animation", "never", "--timeout", "30s", "diagnose", "Example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%v want=%v", got, want)
	}
}

func TestGuidedBaselineComparisonDispatchesNestedCommand(t *testing.T) {
	got := homeArgs(options{color: "auto", animation: "auto", timeout: 15 * time.Second}, present.HomeChoice{Task: "baseline-compare", Target: "healthy"})
	want := []string{"--color", "auto", "--animation", "auto", "--timeout", "15s", "baseline", "compare", "healthy"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args=%v want=%v", got, want)
	}
}
