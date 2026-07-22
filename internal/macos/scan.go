package macos

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

type AppScanner struct {
	Runner platform.Runner
	Quick  bool
}

func StandardApplicationRoots() []string {
	home, _ := os.UserHomeDir()
	return []string{"/Applications", filepath.Join(home, "Applications"), "/System/Applications", "/System/Applications/Utilities"}
}

func (s AppScanner) Scan(ctx context.Context, roots []string, limit, workers int) (report.Report, error) {
	if s.Runner == nil {
		return report.Report{}, errors.New("application scanner requires a command runner")
	}
	if len(roots) == 0 {
		roots = StandardApplicationRoots()
	}
	if limit < 1 {
		return report.Report{}, errors.New("scan limit must be positive")
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 16 {
		workers = 16
	}
	paths, truncated, err := discoverApps(roots, limit)
	if err != nil {
		return report.Report{}, err
	}
	host := (Collector{Runner: s.Runner}).host(ctx)
	jobs := make(chan string)
	results := make(chan report.ScannedApp, len(paths))
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for path := range jobs {
				results <- s.inspectApp(ctx, path, host)
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, path := range paths {
			select {
			case jobs <- path:
			case <-ctx.Done():
				return
			}
		}
	}()
	group.Wait()
	close(results)
	if err := ctx.Err(); err != nil {
		return report.Report{}, err
	}
	apps := make([]report.ScannedApp, 0, len(paths))
	for item := range results {
		apps = append(apps, item)
	}
	sort.Slice(apps, func(i, j int) bool { return strings.ToLower(apps[i].Path) < strings.ToLower(apps[j].Path) })
	r := report.New("scan", strings.Join(roots, ","))
	r.Host = host
	status := report.StatusOK
	summary := fmt.Sprintf("Inspected %d applications", len(apps))
	for _, app := range apps {
		if incompleteStatus(app.ArchitectureStatus) || (!s.Quick && incompleteStatus(app.SignatureStatus)) {
			status = report.StatusPartial
			break
		}
	}
	if truncated {
		status = report.StatusPartial
		summary += " (scan limit reached)"
	}
	r.Evidence = append(r.Evidence, report.Evidence{ID: report.EvidenceScan, Status: status, Summary: summary, Data: report.ScanData{Roots: append([]string(nil), roots...), Apps: apps, Truncated: truncated}})
	return r, nil
}

func discoverApps(roots []string, limit int) ([]string, bool, error) {
	seen := map[string]bool{}
	var paths []string
	truncated := false
	for _, root := range roots {
		absolute, err := filepath.Abs(root)
		if err != nil {
			return nil, false, err
		}
		info, err := os.Stat(absolute)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, false, err
		}
		if !info.IsDir() {
			return nil, false, fmt.Errorf("scan root is not a directory: %s", absolute)
		}
		if strings.HasSuffix(strings.ToLower(absolute), ".app") {
			if !seen[absolute] {
				paths = append(paths, absolute)
				seen[absolute] = true
			}
			continue
		}
		walkErr := filepath.WalkDir(absolute, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				if errors.Is(walkErr, fs.ErrPermission) {
					return fs.SkipDir
				}
				return nil
			}
			if path == absolute || !entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".app") {
				return nil
			}
			if len(paths) >= limit {
				truncated = true
				return fs.SkipAll
			}
			if !seen[path] {
				seen[path] = true
				paths = append(paths, path)
			}
			return fs.SkipDir
		})
		if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
			return nil, false, walkErr
		}
		if truncated {
			break
		}
	}
	sort.Strings(paths)
	return paths, truncated, nil
}

func (s AppScanner) inspectApp(ctx context.Context, path string, host report.Host) report.ScannedApp {
	item := report.ScannedApp{Path: path, Name: strings.TrimSuffix(filepath.Base(path), ".app"), SignatureStatus: report.StatusSkipped, ArchitectureStatus: report.StatusSkipped}
	resolver := Resolver{Runner: s.Runner}
	app, err := resolver.readBundle(ctx, path)
	if err != nil {
		return item
	}
	item.BundleReadable = true
	item.Name, item.BundleID, item.Version = app.Name, app.BundleID, app.Version
	if app.ExecutablePath == "" {
	} else if info, statErr := os.Stat(app.ExecutablePath); statErr != nil || info.IsDir() {
	} else {
		item.ExecutablePresent = true
		item.ExecutableRunnable = info.Mode()&0o111 != 0
	}
	if !s.Quick {
		signature := s.Runner.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", path)
		switch {
		case signature.TimedOut:
			item.SignatureStatus = report.StatusTimedOut
		case signature.Err != nil && signature.ExitCode < 0:
			item.SignatureStatus = report.StatusUnavailable
		default:
			valid := signature.Err == nil
			item.SignatureStatus = report.StatusOK
			item.SignatureValid = &valid
		}
	}
	if item.ExecutablePresent {
		arch := s.Runner.Run(ctx, "/usr/bin/lipo", "-archs", app.ExecutablePath)
		switch {
		case arch.TimedOut:
			item.ArchitectureStatus = report.StatusTimedOut
		case arch.Err != nil:
			item.ArchitectureStatus = report.StatusUnavailable
		default:
			item.ArchitectureStatus = report.StatusOK
			item.Architectures = strings.Fields(arch.Stdout)
		}
	}
	if app.MinimumOS != "" && host.OSVersion != "" {
		supported := compareVersions(host.OSVersion, app.MinimumOS) >= 0
		item.OSSupported = &supported
	}
	return item
}

func incompleteStatus(status report.Status) bool {
	return status == report.StatusUnavailable || status == report.StatusTimedOut || status == report.StatusPartial
}
