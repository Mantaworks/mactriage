package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/upsidedly/mactriage/internal/cli"
	"github.com/upsidedly/mactriage/internal/platform"
)

func TestHelpExposesApprovedCommandSurface(t *testing.T) {
	var out, errOut bytes.Buffer
	app := cli.New(cli.Config{Out: &out, Err: &errOut, Version: "test"})
	app.SetArgs([]string{"--help"})
	if err := app.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext returned error: %v", err)
	}
	help := out.String()
	for _, command := range []string{"diagnose", "system", "watch", "repair", "completion", "version"} {
		if !strings.Contains(help, command) {
			t.Fatalf("help missing %q:\n%s", command, help)
		}
	}
}

func TestJSONRepairNeverMutates(t *testing.T) {
	var out, errOut bytes.Buffer
	runner := &countingRunner{}
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: runner}, []string{"--json", "repair", "syspolicyd", "--yes"})
	if code != 2 || runner.calls != 0 {
		t.Fatalf("code=%d calls=%d stdout=%q stderr=%q", code, runner.calls, out.String(), errOut.String())
	}
}

func TestTerminalModesKeepRedirectedAndAccessibleOutputStatic(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	for _, args := range [][]string{{"system"}, {"--accessible", "--animation", "always", "system"}, {"--plain", "system"}} {
		var out, errOut bytes.Buffer
		code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, args)
		if code != 0 || strings.Contains(out.String()+errOut.String(), "\x1b[") {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
}

func TestColorAlwaysExplicitlyOverridesNOColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, []string{"--color", "always", "system"})
	if code != 0 || !strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestCancelledDiagnosticCommandsExit130(t *testing.T) {
	for _, args := range [][]string{{"system"}, {"diagnose", "/definitely/not/real.app", "--no-launch"}} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var out, errOut bytes.Buffer
		code := cli.Execute(ctx, cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, args)
		if code != 130 {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
	}
}

type countingRunner struct{ calls int }

func (r *countingRunner) Run(context.Context, string, ...string) platform.Result {
	r.calls++
	return platform.Result{}
}

type systemRunner struct{}

func (systemRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/uname":
		return platform.Result{Stdout: "arm64\n"}
	case "/usr/bin/sw_vers":
		return platform.Result{Stdout: "14.5\n"}
	case "/usr/sbin/sysctl":
		if len(args) > 0 && args[0] == "-n" {
			return platform.Result{Stdout: "1\n"}
		}
		return platform.Result{Stdout: "kern.num_files: 100\nkern.maxfiles: 10000\nkern.maxfilesperproc: 2048\n"}
	case "/bin/launchctl":
		return platform.Result{Stdout: "maxfiles 256 unlimited\n"}
	case "/usr/bin/log":
		return platform.Result{}
	default:
		return platform.Result{}
	}
}

func TestInvalidPresentationModeIsRejected(t *testing.T) {
	var out, errOut bytes.Buffer
	app := cli.New(cli.Config{Out: &out, Err: &errOut})
	app.SetArgs([]string{"--color", "sparkly", "version"})
	if err := app.ExecuteContext(context.Background()); err == nil {
		t.Fatal("expected invalid color mode to fail")
	}
}

func TestExecuteReturnsVersionSuccessWithoutPanicking(t *testing.T) {
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Version: "test"}, []string{"version"})
	if code != 0 || !strings.Contains(out.String(), "mactriage test") {
		t.Fatalf("Execute code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestMissingApplicationProducesStructuredJSONDiagnosis(t *testing.T) {
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut}, []string{"--json", "diagnose", "/definitely/not/a/real/Test.app", "--no-launch"})
	if code != 1 {
		t.Fatalf("Execute code=%d, want 1; stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), `"code": "app.not_found"`) {
		t.Fatalf("missing structured finding: %s", out.String())
	}
}
