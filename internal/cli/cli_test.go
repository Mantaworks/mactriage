package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/upsidedly/mactriage/internal/cli"
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
