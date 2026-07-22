package cli_test

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/cli"
	"github.com/Mantaworks/mactriage/internal/platform"
)

func TestHelpExposesApprovedCommandSurface(t *testing.T) {
	var out, errOut bytes.Buffer
	app := cli.New(cli.Config{Out: &out, Err: &errOut, Version: "test"})
	app.SetArgs([]string{"--help"})
	if err := app.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("ExecuteContext returned error: %v", err)
	}
	help := out.String()
	for _, command := range []string{"doctor", "storage", "startup", "network", "relaunch", "baseline", "share", "diagnose", "collect", "hang", "permissions", "scan", "compare", "explain", "summarize", "schema", "system", "watch", "repair", "completion", "version"} {
		if !strings.Contains(help, command) {
			t.Fatalf("help missing %q:\n%s", command, help)
		}
	}
}

func TestAutomationFlagsSchemaOfflineAndStrictRedaction(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: warningCLIRunner{}}, []string{"--json", "--fail-on", "warning", "doctor", "--only", "storage"}); code != 1 {
		t.Fatalf("warning threshold code=%d stderr=%q", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, []string{"--offline", "network"}); code != 2 || !strings.Contains(errOut.String(), "cannot run with --offline") {
		t.Fatalf("offline code=%d stderr=%q", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, []string{"schema", "report"}); code != 0 || !strings.Contains(out.String(), `"case_id"`) {
		t.Fatalf("schema code=%d output=%q", code, out.String())
	}
	out.Reset()
	errOut.Reset()
	if code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, []string{"--json", "--redact", "strict", "diagnose", "/Applications/Secret.app", "--no-launch"}); code != 1 || strings.Contains(out.String(), "Secret") {
		t.Fatalf("redaction code=%d output=%q", code, out.String())
	}
}

func TestTotalTimeoutStopsReportCommands(t *testing.T) {
	var out, errOut bytes.Buffer
	started := time.Now()
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: blockingRunner{}}, []string{"--json", "--total-timeout", "10ms", "doctor", "--quick"})
	if code != 2 || time.Since(started) > time.Second || !strings.Contains(errOut.String(), "timeout") {
		t.Fatalf("code=%d elapsed=%s stderr=%q", code, time.Since(started), errOut.String())
	}
}

type blockingRunner struct{}

func (blockingRunner) Run(ctx context.Context, _ string, _ ...string) platform.Result {
	<-ctx.Done()
	return platform.Result{Err: ctx.Err(), TimedOut: true, ExitCode: -1}
}

type warningCLIRunner struct{ systemRunner }

func (warningCLIRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	if path == "/bin/df" {
		return platform.Result{Stdout: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk 1000000 900000 100000 90% /\n"}
	}
	return (systemRunner{}).Run(ctx, path, args...)
}

func TestShareCreatesSanitizedMarkdownWithoutCopyingNoninteractively(t *testing.T) {
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "report.json")
	contents := `{"schema_version":"1","command":"doctor","target":"this Mac","host":{"os_version":"14.5","arch":"arm64"},"completeness":"complete","evidence":[],"findings":[{"code":"doctor.storage_low","severity":"warning","title":"Low disk","explanation":"Free space","confidence":"high"}],"actions":[]}`
	if err := os.WriteFile(reportPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "share.md")
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, []string{"--json", "--output", outputPath, "share", reportPath, "--copy"})
	if code != 0 || !strings.Contains(out.String(), `"copy_available":true`) || !strings.Contains(out.String(), `# mactriage summary`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	markdown, err := os.ReadFile(outputPath)
	if err != nil || !strings.Contains(string(markdown), "doctor.storage_low") {
		t.Fatalf("output=%q error=%v", markdown, err)
	}
	if info, err := os.Stat(outputPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("share mode/error=%v %v", info.Mode().Perm(), err)
	}
}

func TestBaselineCommandsManagePrivateDoctorSnapshots(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "baselines")
	config := cli.Config{Runner: doctorCLIRunner{}, BaselineDir: dir}
	var saveOut, saveErr bytes.Buffer
	config.Out, config.Err = &saveOut, &saveErr
	if code := cli.Execute(context.Background(), config, []string{"--json", "baseline", "save", "morning", "--only", "storage"}); code != 1 {
		t.Fatalf("save code=%d stdout=%q stderr=%q", code, saveOut.String(), saveErr.String())
	}
	path := filepath.Join(dir, "morning.json")
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("baseline mode/error=%v %v", info.Mode().Perm(), err)
	}
	var listOut, listErr bytes.Buffer
	config.Out, config.Err = &listOut, &listErr
	if code := cli.Execute(context.Background(), config, []string{"--json", "baseline", "list"}); code != 0 || !strings.Contains(listOut.String(), `"name":"morning"`) {
		t.Fatalf("list code=%d stdout=%q stderr=%q", code, listOut.String(), listErr.String())
	}
	var deleteOut, deleteErr bytes.Buffer
	config.Out, config.Err = &deleteOut, &deleteErr
	if code := cli.Execute(context.Background(), config, []string{"--json", "baseline", "delete", "morning", "--yes"}); code != 0 || !strings.Contains(deleteOut.String(), `"deleted":"morning"`) {
		t.Fatalf("delete code=%d stdout=%q stderr=%q", code, deleteOut.String(), deleteErr.String())
	}
}

func TestDoctorSupportsCheckAndSeverityFiltersInJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: doctorCLIRunner{}}, []string{"--json", "doctor", "--only", "storage", "--severity", "error"})
	if code != 1 || !strings.Contains(out.String(), `"command": "doctor"`) || !strings.Contains(out.String(), `"code": "doctor.storage_low"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String(), `"id": "memory"`) || strings.Contains(out.String(), `"severity": "warning"`) || strings.Contains(out.String()+errOut.String(), "\x1b[") {
		t.Fatalf("filters or JSON purity failed: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

type doctorCLIRunner struct{ systemRunner }

func (doctorCLIRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	if path == "/bin/df" {
		return platform.Result{Stdout: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk 1000000 950000 50000 95% /\n"}
	}
	return (systemRunner{}).Run(ctx, path, args...)
}

func TestNetworkCommandUsesSafeDefaultAndStructuredOutput(t *testing.T) {
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: networkCLIRunner{}}, []string{"--json", "network"})
	if code != 0 || !strings.Contains(out.String(), `"command": "network"`) || !strings.Contains(out.String(), `"target": "example.com"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), "93.184.216.34") || strings.Contains(out.String()+errOut.String(), "\x1b[") {
		t.Fatalf("network output leaked raw facts or ANSI: stdout=%q stderr=%q", out.String(), errOut.String())
	}
}

type networkCLIRunner struct{ systemRunner }

func (networkCLIRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/dscacheutil":
		return platform.Result{Stdout: "name: example.com\nip_address: 93.184.216.34\n"}
	case "/sbin/route":
		return platform.Result{Stdout: "gateway: 192.0.2.1\n"}
	case "/usr/sbin/scutil":
		return platform.Result{Stdout: "<dictionary> {}\n"}
	case "/sbin/ifconfig":
		return platform.Result{Stdout: "lo0 en0\n"}
	case "/usr/bin/curl":
		return platform.Result{}
	case "/usr/sbin/lsof":
		return platform.Result{}
	default:
		return (systemRunner{}).Run(ctx, path, args...)
	}
}

func TestNoninteractiveRelaunchExplainsActionWithoutMutation(t *testing.T) {
	root := t.TempDir()
	appPath := filepath.Join(root, "Example.app")
	if err := os.MkdirAll(filepath.Join(appPath, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	runner := &relaunchCLIRunner{}
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: runner}, []string{"--json", "relaunch", appPath})
	if code != 0 || !strings.Contains(out.String(), `"id": "relaunch.app"`) || !strings.Contains(out.String(), `"pids": [`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if runner.mutations != 0 {
		t.Fatalf("noninteractive relaunch performed %d mutations", runner.mutations)
	}
}

type relaunchCLIRunner struct {
	systemRunner
	mutations int
}

func (r *relaunchCLIRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/plutil":
		return platform.Result{Stdout: `{"CFBundleName":"Example","CFBundleIdentifier":"com.example.App","CFBundleExecutable":"Example"}`}
	case "/usr/bin/pgrep":
		return platform.Result{Stdout: "42\n"}
	case "/bin/kill", "/usr/bin/open":
		r.mutations++
		return platform.Result{}
	default:
		return (systemRunner{}).Run(ctx, path, args...)
	}
}

func TestScanEmitsStructuredApplicationInventory(t *testing.T) {
	root := t.TempDir()
	appPath := filepath.Join(root, "Example.app")
	if err := os.MkdirAll(filepath.Join(appPath, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appPath, "Contents", "MacOS", "Example"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: scanCLIRunner{}}, []string{"--json", "scan", root, "--limit", "10"})
	if code != 0 || !strings.Contains(out.String(), `"command": "scan"`) || !strings.Contains(out.String(), `"name": "Example"`) {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestPermissionsEmitsOnlyStructuredCorrelatedDenials(t *testing.T) {
	root := t.TempDir()
	appPath := filepath.Join(root, "Example.app")
	if err := os.MkdirAll(filepath.Join(appPath, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appPath, "Contents", "MacOS", "Example"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: permissionCLIRunner{}}, []string{"--json", "permissions", appPath})
	if code != 1 || !strings.Contains(out.String(), `"code": "permission.denied"`) || strings.Contains(out.String()+errOut.String(), "Denying camera access") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

type scanCLIRunner struct{ systemRunner }

func (scanCLIRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/plutil":
		return platform.Result{Stdout: `{"CFBundleName":"Example","CFBundleIdentifier":"com.example.App","CFBundleExecutable":"Example","CFBundleShortVersionString":"1.0","LSMinimumSystemVersion":"13.0"}`}
	case "/usr/bin/codesign":
		return platform.Result{}
	case "/usr/bin/lipo":
		return platform.Result{Stdout: "arm64\n"}
	default:
		return (systemRunner{}).Run(ctx, path, args...)
	}
}

type permissionCLIRunner struct{ systemRunner }

func (permissionCLIRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/plutil":
		return platform.Result{Stdout: `{"CFBundleName":"Example","CFBundleIdentifier":"com.example.App","CFBundleExecutable":"Example"}`}
	case "/usr/bin/codesign":
		return platform.Result{Stderr: `<plist><dict><key>com.apple.security.device.camera</key><true/></dict></plist>`}
	case "/usr/bin/log":
		return platform.Result{Stdout: "{\"process\":\"tccd\",\"eventMessage\":\"Denying camera access to com.example.App\"}\n"}
	default:
		return (systemRunner{}).Run(ctx, path, args...)
	}
}

func TestHangReportsRunningProcessResourceFinding(t *testing.T) {
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: hangRunner{}}, []string{"--json", "hang", "Example", "--cpu-threshold", "80"})
	if code != 0 || !strings.Contains(out.String(), `"code": "resource.cpu_high"`) || strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

type hangRunner struct{ systemRunner }

func (hangRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/pgrep":
		return platform.Result{Stdout: "4242\n"}
	case "/bin/ps":
		if len(args) > 0 && args[0] == "-M" {
			return platform.Result{Stdout: "USER PID COMMAND\nuser 4242 Example\n"}
		}
		return platform.Result{Stdout: "4242 94.5 204800 S 01:02 /Applications/Example.app/Contents/MacOS/Example\n"}
	default:
		return (systemRunner{}).Run(ctx, path, args...)
	}
}

func TestExplainUsesPlainLanguageKnowledgeCatalog(t *testing.T) {
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, []string{"explain", "gatekeeper.rejected"})
	if code != 0 || !strings.Contains(out.String(), "Gatekeeper rejected the app") || !strings.Contains(out.String(), "will not") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}

func TestSummarizeAndCompareReadSanitizedReports(t *testing.T) {
	dir := t.TempDir()
	before := filepath.Join(dir, "before.json")
	after := filepath.Join(dir, "after.json")
	write := func(path, finding string) {
		t.Helper()
		contents := `{"schema_version":"1","command":"diagnose","target":"Example","host":{"os_version":"14.5","arch":"arm64"},"completeness":"complete","evidence":[{"id":"signature","status":"ok","summary":"checked"}],"findings":[{"code":"` + finding + `","severity":"error","title":"Problem","explanation":"Details","confidence":"high"}],"actions":[]}`
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(before, "signature.invalid")
	write(after, "gatekeeper.rejected")
	var summaryOut, summaryErr bytes.Buffer
	if code := cli.Execute(context.Background(), cli.Config{Out: &summaryOut, Err: &summaryErr, Runner: systemRunner{}}, []string{"summarize", after}); code != 0 || !strings.Contains(summaryOut.String(), "mactriage summary") {
		t.Fatalf("summarize code=%d stdout=%q stderr=%q", code, summaryOut.String(), summaryErr.String())
	}
	var compareOut, compareErr bytes.Buffer
	if code := cli.Execute(context.Background(), cli.Config{Out: &compareOut, Err: &compareErr, Runner: systemRunner{}}, []string{"--json", "compare", before, after}); code != 0 || !strings.Contains(compareOut.String(), `"added"`) || strings.Contains(compareOut.String(), "\x1b[") {
		t.Fatalf("compare code=%d stdout=%q stderr=%q", code, compareOut.String(), compareErr.String())
	}
}

func TestCollectWritesPrivateSanitizedBundleForDiagnosedFailure(t *testing.T) {
	var out, errOut bytes.Buffer
	path := filepath.Join(t.TempDir(), "triage.zip")
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut}, []string{"collect", "/definitely/not/a/real/Test.app", "--no-launch", "--output", path})
	if code != 1 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open support bundle: %v", err)
	}
	defer reader.Close()
	if len(reader.File) != 3 {
		t.Fatalf("archive entries=%d want=3", len(reader.File))
	}
}

func TestNoArgumentsShowsFriendlyGettingStartedInsteadOfUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, nil)
	if code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	text := out.String() + errOut.String()
	for _, want := range []string{"What would you like to troubleshoot?", "mactriage diagnose", "mactriage scan"} {
		if !strings.Contains(text, want) {
			t.Fatalf("getting-started output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Usage:") || strings.Contains(text, "Available Commands:") {
		t.Fatalf("no-argument output fell back to Cobra usage:\n%s", text)
	}
}

func TestNoArgumentsCanRenderColorfulGettingStartedPanel(t *testing.T) {
	var out, errOut bytes.Buffer
	code := cli.Execute(context.Background(), cli.Config{Out: &out, Err: &errOut, Runner: systemRunner{}}, []string{"--color", "always"})
	if code != 0 || !strings.Contains(out.String(), "\x1b[") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
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
