package macos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/upsidedly/mactriage/internal/platform"
)

type App struct {
	Path           string `json:"path"`
	Name           string `json:"name"`
	BundleID       string `json:"bundle_id,omitempty"`
	Executable     string `json:"executable,omitempty"`
	ExecutablePath string `json:"executable_path,omitempty"`
	Version        string `json:"version,omitempty"`
	MinimumOS      string `json:"minimum_os,omitempty"`
}

type ResolveError struct {
	Code  string
	Input string
	Err   error
}

func (e *ResolveError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Code
}

func (e *ResolveError) Unwrap() error { return e.Err }

type Resolver struct {
	Runner      platform.Runner
	SearchRoots []string
}

func (r Resolver) Resolve(ctx context.Context, input string) ([]App, error) {
	if strings.TrimSpace(input) == "" {
		return nil, errors.New("application name, bundle identifier, or path is required")
	}
	_, pathErr := os.Stat(input)
	if strings.Contains(input, string(filepath.Separator)) || pathErr == nil {
		path, err := filepath.Abs(input)
		if err != nil {
			return nil, err
		}
		app, err := r.readBundle(ctx, path)
		if err != nil {
			return nil, classifyResolveError(input, err)
		}
		return []App{app}, nil
	}

	roots := r.SearchRoots
	if len(roots) == 0 {
		home, _ := os.UserHomeDir()
		roots = []string{"/Applications", filepath.Join(home, "Applications"), "/System/Applications", "/System/Applications/Utilities"}
	}
	var paths []string
	seen := map[string]bool{}
	add := func(path string) {
		path = filepath.Clean(path)
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	name := strings.TrimSuffix(input, ".app")
	for _, root := range roots {
		candidate := filepath.Join(root, name+".app")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			add(candidate)
		}
	}

	if len(paths) == 0 {
		for _, root := range roots {
			entries, err := os.ReadDir(root)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".app") {
					add(filepath.Join(root, entry.Name()))
				}
			}
		}
	}
	exact, fuzzy := r.matchingApps(ctx, paths, input, name)
	if len(exact) > 0 {
		sortApps(exact, roots)
		return exact, nil
	}
	if len(fuzzy) > 0 {
		sortApps(fuzzy, roots)
		return fuzzy, nil
	}

	// Standard roots are evaluated first. Spotlight is a fallback when none of
	// those bundles match, including bundle-ID lookups and nonstandard installs.
	paths = nil
	seen = map[string]bool{}
	if r.Runner != nil {
		query := `kMDItemContentType == "com.apple.application-bundle"`
		result := r.Runner.Run(ctx, "/usr/bin/mdfind", query)
		if result.Err == nil {
			for _, path := range strings.Split(result.Stdout, "\n") {
				if strings.HasSuffix(strings.TrimSpace(path), ".app") {
					add(strings.TrimSpace(path))
				}
			}
		}
	}

	exact, fuzzy = r.matchingApps(ctx, paths, input, name)
	if len(exact) > 0 {
		sortApps(exact, roots)
		return exact, nil
	}
	if len(fuzzy) > 0 {
		sortApps(fuzzy, roots)
		return fuzzy, nil
	}
	return nil, &ResolveError{Code: "app.not_found", Input: input, Err: fmt.Errorf("application %q was not found", input)}
}

func (r Resolver) matchingApps(ctx context.Context, paths []string, input, name string) (exact, fuzzy []App) {
	for _, path := range paths {
		app, err := r.readBundle(ctx, path)
		if err != nil {
			continue
		}
		if strings.EqualFold(app.Name, name) || strings.EqualFold(strings.TrimSuffix(filepath.Base(app.Path), ".app"), name) || strings.EqualFold(app.BundleID, input) {
			exact = append(exact, app)
		} else if strings.Contains(strings.ToLower(app.Name), strings.ToLower(name)) {
			fuzzy = append(fuzzy, app)
		}
	}
	return exact, fuzzy
}

func classifyResolveError(input string, err error) error {
	code := "bundle.invalid"
	if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "does not exist") {
		code = "app.not_found"
	}
	return &ResolveError{Code: code, Input: input, Err: err}
}

func (r Resolver) readBundle(ctx context.Context, path string) (App, error) {
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return App{}, fmt.Errorf("application bundle does not exist: %s", path)
	}
	info, err := os.Stat(realPath)
	if err != nil || !info.IsDir() || !strings.HasSuffix(strings.ToLower(realPath), ".app") {
		return App{}, fmt.Errorf("not an application bundle: %s", path)
	}
	if r.Runner == nil {
		return App{}, errors.New("application resolver requires a command runner")
	}
	plistPath := filepath.Join(realPath, "Contents", "Info.plist")
	result := r.Runner.Run(ctx, "/usr/bin/plutil", "-convert", "json", "-o", "-", plistPath)
	if result.Err != nil {
		return App{}, fmt.Errorf("invalid Info.plist in %s", realPath)
	}
	var values map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &values); err != nil {
		return App{}, fmt.Errorf("invalid Info.plist JSON in %s: %w", realPath, err)
	}
	app := App{
		Path:       realPath,
		Name:       firstString(values, "CFBundleDisplayName", "CFBundleName"),
		BundleID:   stringValue(values, "CFBundleIdentifier"),
		Executable: stringValue(values, "CFBundleExecutable"),
		Version:    firstString(values, "CFBundleShortVersionString", "CFBundleVersion"),
		MinimumOS:  stringValue(values, "LSMinimumSystemVersion"),
	}
	if app.Name == "" {
		app.Name = strings.TrimSuffix(filepath.Base(realPath), ".app")
	}
	if app.Executable != "" {
		app.ExecutablePath = filepath.Join(realPath, "Contents", "MacOS", app.Executable)
	}
	return app, nil
}

func stringValue(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return value
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := stringValue(values, key); value != "" {
			return value
		}
	}
	return ""
}

func sortApps(apps []App, roots []string) {
	sort.SliceStable(apps, func(i, j int) bool {
		return rootRank(apps[i].Path, roots) < rootRank(apps[j].Path, roots)
	})
}

func rootRank(path string, roots []string) int {
	for i, root := range roots {
		if strings.HasPrefix(path, filepath.Clean(root)+string(filepath.Separator)) {
			return i
		}
	}
	return len(roots)
}
