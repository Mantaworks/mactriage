package macos_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/upsidedly/mactriage/internal/macos"
	"github.com/upsidedly/mactriage/internal/platform"
)

func TestResolverReadsApplicationBundleMetadata(t *testing.T) {
	root := t.TempDir()
	appPath := filepath.Join(root, "Example.app")
	contents := filepath.Join(appPath, "Contents")
	macosDir := filepath.Join(contents, "MacOS")
	if err := os.MkdirAll(macosDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleDisplayName</key><string>Example</string>
<key>CFBundleIdentifier</key><string>dev.example.app</string>
<key>CFBundleExecutable</key><string>ExampleBin</string>
<key>CFBundleShortVersionString</key><string>2.4</string>
<key>LSMinimumSystemVersion</key><string>13.0</string>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(macosDir, "ExampleBin"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	resolver := macos.Resolver{Runner: platform.ExecRunner{Timeout: time.Second}}
	apps, err := resolver.Resolve(context.Background(), appPath)
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("Resolve returned %d apps, want 1", len(apps))
	}
	app := apps[0]
	if app.Name != "Example" || app.BundleID != "dev.example.app" || app.Executable != "ExampleBin" || app.Version != "2.4" || app.MinimumOS != "13.0" {
		t.Fatalf("unexpected app metadata: %#v", app)
	}
	wantExecutable, err := filepath.EvalSymlinks(filepath.Join(macosDir, "ExampleBin"))
	if err != nil {
		t.Fatal(err)
	}
	if app.ExecutablePath != wantExecutable {
		t.Fatalf("ExecutablePath = %q", app.ExecutablePath)
	}
}

func TestResolverRanksExactStandardPathBeforeSearch(t *testing.T) {
	root := t.TempDir()
	makeApp(t, filepath.Join(root, "Target.app"), "dev.target")
	resolver := macos.Resolver{
		Runner:      platform.ExecRunner{Timeout: time.Second},
		SearchRoots: []string{root},
	}
	apps, err := resolver.Resolve(context.Background(), "Target")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if len(apps) != 1 || apps[0].BundleID != "dev.target" {
		t.Fatalf("unexpected matches: %#v", apps)
	}
}

func makeApp(t *testing.T, path, bundleID string) {
	t.Helper()
	contents := filepath.Join(path, "Contents")
	if err := os.MkdirAll(filepath.Join(contents, "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleName</key><string>Target</string><key>CFBundleIdentifier</key><string>` + bundleID + `</string><key>CFBundleExecutable</key><string>Target</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(contents, "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(contents, "MacOS", "Target"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
}
