package macos_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestWrappedBundleFixtureResolvesThroughPublicResolver(t *testing.T) {
	appPath := materializeFixture(t, "bundles/wrapped/ThirdParty.app")
	target, err := os.ReadFile(filepath.Join(appPath, "WrappedBundle.target"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(strings.TrimSpace(string(target)), filepath.Join(appPath, "WrappedBundle")); err != nil {
		t.Fatal(err)
	}

	apps, err := (macos.Resolver{Runner: plistFixtureRunner{}}).Resolve(context.Background(), appPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || apps[0].Name != "Wrapped Fixture" || apps[0].BundleID != "dev.example.fixture.wrapped" {
		t.Fatalf("unexpected wrapped fixture: %#v", apps)
	}
	if !strings.HasSuffix(apps[0].ExecutablePath, filepath.Join("Wrapper", "Synthetic.app", "WrappedFixture")) {
		t.Fatalf("unexpected wrapped executable: %q", apps[0].ExecutablePath)
	}
}

func TestHelperHeavyBundleFixtureResolvesWithoutConfusingHelpers(t *testing.T) {
	appPath := materializeFixture(t, "bundles/helper-heavy/HelperHeavy.app")
	apps, err := (macos.Resolver{Runner: plistFixtureRunner{}}).Resolve(context.Background(), appPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || apps[0].Executable != "HelperHeavyFixture" || apps[0].BundleID != "dev.example.fixture.helperheavy" {
		t.Fatalf("unexpected helper-heavy fixture: %#v", apps)
	}
	for _, helper := range []string{
		filepath.Join("Contents", "Helpers", "SyntheticUpdater"),
		filepath.Join("Contents", "Library", "LoginItems", "SyntheticAgent.app", "Contents", "MacOS", "SyntheticAgent"),
	} {
		if _, err := os.Stat(filepath.Join(appPath, helper)); err != nil {
			t.Fatalf("missing helper fixture %q: %v", helper, err)
		}
	}
}

func TestUnusualRPathFixtureResolvesThroughCollector(t *testing.T) {
	fixtureRoot := filepath.Join("testdata", "dependencies", "unusual-rpaths")
	appPath := materializeFixture(t, "dependencies/unusual-rpaths/RPath.app")
	executable := filepath.Join(appPath, "Contents", "MacOS", "RPathFixture")
	if err := os.Chmod(executable, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := dependencyFixtureRunner{
		executable: executable,
		libraries:  mustReadFixture(t, filepath.Join(fixtureRoot, "otool-libraries.txt")),
		loadPaths:  mustReadFixture(t, filepath.Join(fixtureRoot, "otool-load-commands.txt")),
	}
	app := macos.App{Path: appPath, Name: "RPath Fixture", BundleID: "dev.example.fixture.rpath", Executable: "RPathFixture", ExecutablePath: executable, MinimumOS: "13.0"}
	r, err := (macos.Collector{Runner: runner}).Collect(context.Background(), app, macos.DiagnoseOptions{NoLaunch: true})
	if err != nil {
		t.Fatal(err)
	}
	data := evidenceData[report.DependencyData](t, r, report.EvidenceDependencies)
	if data.MissingCount != 0 {
		t.Fatalf("fixture dependencies did not resolve: %#v", data)
	}
}

func TestPermissionDenialFixtureUsesCorrelatedSyntheticEvents(t *testing.T) {
	runner := permissionFixtureRunner{
		entitlements: mustReadFixture(t, filepath.Join("testdata", "permissions", "entitlements.plist")),
		logs:         mustReadFixture(t, filepath.Join("testdata", "permissions", "denials.ndjson")),
	}
	app := macos.App{Name: "Permission Fixture", BundleID: "dev.example.fixture.permission", Path: "/Applications/PermissionFixture.app"}
	r, err := (macos.PermissionInspector{Runner: runner}).Inspect(context.Background(), app, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	data := evidenceData[report.PermissionsData](t, r, report.EvidencePermissions)
	if got := permissionCounts(data.Denials); fmt.Sprint(got) != "map[camera:1 microphone:1]" {
		t.Fatalf("unexpected permission denials: %#v", data.Denials)
	}
	if fmt.Sprint(data.Declared) != "[camera microphone]" {
		t.Fatalf("unexpected declared permissions: %#v", data.Declared)
	}
}

func TestCrashTerminationFixturesUseOnlyStructuredFields(t *testing.T) {
	tests := []struct {
		name      string
		extension string
		want      macos.CrashTermination
	}{
		{"abort.ips", ".ips", macos.CrashTermination{Namespace: "SIGNAL", Code: "6", Indicator: "Abort trap", Signal: "SIGABRT"}},
		{"resource.crash", ".crash", macos.CrashTermination{Namespace: "RESOURCE", Code: "0x8badf00d", Signal: "SIGKILL"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := macos.ParseCrashTermination([]byte(mustReadFixture(t, filepath.Join("testdata", "crashes", tc.name))), tc.extension)
			if got != tc.want {
				t.Fatalf("termination=%#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestManagedNetworkFixturesRemainSanitizedAtPublicBoundary(t *testing.T) {
	t.Run("managed", func(t *testing.T) {
		runner := loadCommandFixture(t, filepath.Join("testdata", "network", "managed.json"))
		r, err := (macos.NetworkInspector{Runner: runner, Detailed: true}).Inspect(context.Background(), "example.com")
		if err != nil {
			t.Fatal(err)
		}
		data := evidenceData[report.NetworkData](t, r, report.EvidenceNetwork)
		if !data.DNSResolved || !data.DefaultRoute || !data.ProxyConfigured || !data.HTTPSReachable || !data.TLSValid {
			t.Fatalf("managed facts missing: %#v", data)
		}
		if fmt.Sprint(data.VPNInterfaces) != "[utun4]" || data.ListeningSocketCount != 2 || data.DNSServerCount != 2 {
			t.Fatalf("unexpected managed aggregates: %#v", data)
		}
		encoded, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, privateValue := range []string{"managed-address", "managed-gateway", "proxy.example.invalid"} {
			if strings.Contains(string(encoded), privateValue) {
				t.Fatalf("network identifier leaked into report: %s", encoded)
			}
		}
	})

	t.Run("restricted", func(t *testing.T) {
		runner := loadCommandFixture(t, filepath.Join("testdata", "network", "restricted.json"))
		r, err := (macos.NetworkInspector{Runner: runner, Detailed: true}).Inspect(context.Background(), "example.com")
		if err != nil {
			t.Fatal(err)
		}
		data := evidenceData[report.NetworkData](t, r, report.EvidenceNetwork)
		if r.Evidence[0].Status != report.StatusPartial || data.DNSStatus != report.StatusUnavailable || data.HTTPSStatus != report.StatusTimedOut {
			t.Fatalf("restricted probe status was not preserved: %#v", data)
		}
	})
}

func TestFixtureCorpusContainsNoPersonalOrNetworkIdentifiers(t *testing.T) {
	var files []string
	err := filepath.WalkDir("testdata", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if len(files) < 10 {
		t.Fatalf("fixture corpus unexpectedly small: %d files", len(files))
	}
	for _, path := range files {
		content := mustReadFixture(t, path)
		lower := strings.ToLower(content)
		for _, banned := range []string{"/users/", "ssid", "bssid", "hardware uuid", "serial number", "io80211"} {
			if strings.Contains(lower, banned) {
				t.Errorf("%s contains banned fixture content %q", path, banned)
			}
		}
		if regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`).MatchString(content) {
			t.Errorf("%s contains an IP address", path)
		}
	}
}

type plistFixtureRunner struct{}

func (plistFixtureRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	if path != "/usr/bin/plutil" || len(args) == 0 || args[0] != "-convert" {
		return platform.Result{Err: errors.New("unexpected fixture command"), ExitCode: -1}
	}
	content, err := os.ReadFile(args[len(args)-1])
	if err != nil {
		return platform.Result{Err: err, ExitCode: -1}
	}
	values := map[string]string{}
	for _, key := range []string{"CFBundleName", "CFBundleIdentifier", "CFBundleExecutable", "CFBundleShortVersionString", "LSMinimumSystemVersion"} {
		pattern := regexp.MustCompile(`<key>` + regexp.QuoteMeta(key) + `</key>\s*<string>([^<]*)</string>`)
		if match := pattern.FindStringSubmatch(string(content)); len(match) == 2 {
			values[key] = match[1]
		}
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		return platform.Result{Err: err, ExitCode: -1}
	}
	return platform.Result{Stdout: string(encoded)}
}

type dependencyFixtureRunner struct {
	executable string
	libraries  string
	loadPaths  string
}

func (r dependencyFixtureRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/uname":
		return platform.Result{Stdout: "arm64\n"}
	case "/usr/bin/sw_vers":
		if len(args) > 0 && args[0] == "-buildVersion" {
			return platform.Result{Stdout: "23Z999\n"}
		}
		return platform.Result{Stdout: "14.5\n"}
	case "/usr/sbin/sysctl":
		if len(args) > 0 && args[0] == "-n" {
			return platform.Result{Stdout: "1\n"}
		}
		return platform.Result{Stdout: "kern.num_files: 10\nkern.maxfiles: 1000\nkern.maxfilesperproc: 256\n"}
	case "/usr/bin/codesign", "/usr/sbin/spctl", "/usr/bin/log":
		return platform.Result{}
	case "/usr/bin/xattr":
		return platform.Result{Err: errors.New("attribute not found"), Stderr: "attribute not found", ExitCode: 1}
	case "/usr/bin/lipo":
		return platform.Result{Stdout: "arm64\n"}
	case "/usr/bin/otool":
		if len(args) > 0 && args[0] == "-L" {
			return platform.Result{Stdout: strings.Replace(r.libraries, "RPathFixture:", r.executable+":", 1)}
		}
		return platform.Result{Stdout: r.loadPaths}
	case "/bin/launchctl":
		return platform.Result{Stdout: "maxfiles 256 unlimited\n"}
	default:
		return platform.Result{Err: fmt.Errorf("unexpected fixture command: %s", path), ExitCode: -1}
	}
}

type permissionFixtureRunner struct {
	entitlements string
	logs         string
}

func (r permissionFixtureRunner) Run(_ context.Context, path string, _ ...string) platform.Result {
	switch path {
	case "/usr/bin/codesign":
		return platform.Result{Stderr: r.entitlements}
	case "/usr/bin/log":
		return platform.Result{Stdout: r.logs}
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

type commandFixtureResult struct {
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  int    `json:"exit_code"`
	Error     string `json:"error"`
	TimedOut  bool   `json:"timed_out"`
	Truncated bool   `json:"truncated"`
}

type commandFixtureRunner map[string]commandFixtureResult

func loadCommandFixture(t *testing.T, path string) commandFixtureRunner {
	t.Helper()
	var runner commandFixtureRunner
	if err := json.Unmarshal([]byte(mustReadFixture(t, path)), &runner); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return runner
}

func (r commandFixtureRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	key := path
	for _, arg := range args {
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			key += " " + arg
			break
		}
	}
	if key == path && path == "/usr/sbin/scutil" && len(args) > 0 {
		key += " " + args[0]
	}
	fixture, ok := r[key]
	if !ok {
		fixture, ok = r[path]
	}
	if !ok {
		return platform.Result{Err: fmt.Errorf("fixture has no result for %s", key), ExitCode: -1}
	}
	result := platform.Result{Stdout: fixture.Stdout, Stderr: fixture.Stderr, ExitCode: fixture.ExitCode, TimedOut: fixture.TimedOut, Truncated: fixture.Truncated}
	if fixture.Error != "" {
		result.Err = errors.New(fixture.Error)
	}
	return result
}

func materializeFixture(t *testing.T, relative string) string {
	t.Helper()
	source := filepath.Join("testdata", filepath.FromSlash(relative))
	destination := filepath.Join(t.TempDir(), filepath.Base(source))
	if err := copyFixtureTree(source, destination); err != nil {
		t.Fatalf("materialize %s: %v", source, err)
	}
	return destination
}

func copyFixtureTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o644)
	})
}

func mustReadFixture(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	return string(content)
}

func permissionCounts(observations []report.PermissionObservation) map[string]int {
	counts := make(map[string]int, len(observations))
	for _, observation := range observations {
		counts[observation.Category] = observation.Count
	}
	return counts
}
