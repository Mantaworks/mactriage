package macos

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/upsidedly/mactriage/internal/platform"
	"github.com/upsidedly/mactriage/internal/report"
)

type ProgressEvent struct {
	ID       string
	Label    string
	Status   string
	Duration time.Duration
}

type DiagnoseOptions struct {
	Observe     time.Duration
	NoLaunch    bool
	NewInstance bool
	Privileged  bool
}

type Collector struct {
	Runner platform.Runner
	Emit   func(ProgressEvent)
}

func (c Collector) Collect(ctx context.Context, app App, opts DiagnoseOptions) (report.Report, error) {
	if c.Runner == nil {
		return report.Report{}, fmt.Errorf("diagnostic collector requires a command runner")
	}
	if opts.Observe <= 0 {
		opts.Observe = 5 * time.Second
	}
	r := report.New("diagnose", app.Path)
	r.Host = c.host(ctx)
	r.Evidence = append(r.Evidence, c.bundleEvidence(app, r.Host.OSVersion))

	probes := []struct {
		id    string
		label string
		run   func() report.Evidence
	}{
		{"signature", "Verify code signature", func() report.Evidence { return c.signature(ctx, app) }},
		{"gatekeeper", "Assess Gatekeeper policy", func() report.Evidence { return c.gatekeeper(ctx, app) }},
		{"quarantine", "Inspect quarantine metadata", func() report.Evidence { return c.quarantine(ctx, app) }},
		{"architecture", "Inspect executable architecture", func() report.Evidence { return c.architecture(ctx, app) }},
		{"dependencies", "Resolve dynamic libraries", func() report.Evidence { return c.dependencies(ctx, app) }},
		{"limits", "Measure descriptor limits", func() report.Evidence { return c.limits(ctx) }},
	}
	results := make([]report.Evidence, len(probes))
	var wg sync.WaitGroup
	for i := range probes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			started := time.Now()
			c.emit(probes[i].id, probes[i].label, "running", 0)
			results[i] = probes[i].run()
			c.emit(probes[i].id, probes[i].label, string(results[i].Status), time.Since(started))
		}(i)
	}
	wg.Wait()
	r.Evidence = append(r.Evidence, results...)

	launchStart := time.Now()
	if opts.NoLaunch {
		launchStart = launchStart.Add(-5 * time.Minute)
		r.Evidence = append(r.Evidence, report.Evidence{ID: "launch", Status: report.StatusSkipped, Summary: "Launch test disabled by --no-launch", Data: map[string]any{"skipped": true}})
	} else {
		c.emit("launch", "Launch and observe application", "running", 0)
		r.Evidence = append(r.Evidence, c.launch(ctx, app, opts))
		c.emit("launch", "Launch and observe application", string(r.Evidence[len(r.Evidence)-1].Status), time.Since(launchStart))
	}
	launchEnd := time.Now()

	post := make([]report.Evidence, 2)
	wg.Add(2)
	go func() {
		defer wg.Done()
		started := time.Now()
		c.emit("logs", "Correlate unified logs", "running", 0)
		post[0] = c.logs(ctx, app, launchStart, launchEnd)
		c.emit("logs", "Correlate unified logs", string(post[0].Status), time.Since(started))
	}()
	go func() {
		defer wg.Done()
		started := time.Now()
		c.emit("crash", "Inspect recent crash reports", "running", 0)
		post[1] = c.crashes(app, launchStart, launchEnd)
		c.emit("crash", "Inspect recent crash reports", string(post[1].Status), time.Since(started))
	}()
	wg.Wait()
	r.Evidence = append(r.Evidence, post...)

	if opts.Privileged {
		r.Evidence = append(r.Evidence, c.processDescriptors(ctx, "syspolicyd"))
	} else {
		r.Evidence = append(r.Evidence, report.Evidence{ID: "descriptors", Status: report.StatusSkipped, Summary: "Privileged process descriptor count not requested"})
	}
	return r, nil
}

func (c Collector) emit(id, label, status string, duration time.Duration) {
	if c.Emit != nil {
		c.Emit(ProgressEvent{ID: id, Label: label, Status: status, Duration: duration})
	}
}

func (c Collector) host(ctx context.Context) report.Host {
	host := report.Host{Arch: runtime.GOARCH}
	if result := c.Runner.Run(ctx, "/usr/bin/sw_vers", "-productVersion"); result.Err == nil {
		host.OSVersion = strings.TrimSpace(result.Stdout)
	}
	if result := c.Runner.Run(ctx, "/usr/bin/sw_vers", "-buildVersion"); result.Err == nil {
		host.Build = strings.TrimSpace(result.Stdout)
	}
	return host
}

func (c Collector) bundleEvidence(app App, osVersion string) report.Evidence {
	data := map[string]any{
		"path": app.Path, "name": app.Name, "bundle_id": app.BundleID, "executable": app.Executable,
		"version": app.Version, "minimum_os": app.MinimumOS,
	}
	data["executable_declared"] = app.Executable != ""
	status := report.StatusOK
	summary := "Application bundle metadata is readable"
	if app.Executable == "" {
		data["executable_present"] = false
		data["executable_runnable"] = false
		status, summary = report.StatusFailed, "Bundle does not declare CFBundleExecutable"
	} else if info, err := os.Stat(app.ExecutablePath); err != nil || info.IsDir() {
		data["executable_present"] = false
		data["executable_runnable"] = false
		status, summary = report.StatusFailed, "Bundle executable is missing"
	} else if info.Mode()&0o111 == 0 {
		data["executable_present"] = true
		data["executable_runnable"] = false
		status, summary = report.StatusFailed, "Bundle executable is not executable"
	} else {
		data["executable_present"] = true
		data["executable_runnable"] = true
	}
	if app.MinimumOS != "" && osVersion != "" {
		data["os_supported"] = compareVersions(osVersion, app.MinimumOS) >= 0
	}
	return report.Evidence{ID: "bundle", Status: status, Summary: summary, Data: data}
}

func (c Collector) signature(ctx context.Context, app App) report.Evidence {
	result := c.Runner.Run(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app.Path)
	if result.TimedOut {
		return timedOut("signature", "Code-signature verification timed out")
	}
	valid := result.Err == nil
	reason := "valid"
	if !valid {
		text := strings.ToLower(result.Stderr + result.Stdout)
		reason = "invalid"
		if strings.Contains(text, "not signed") || strings.Contains(text, "code object is not signed") {
			reason = "unsigned"
		}
	}
	status := report.StatusOK
	summary := "Strict recursive code signature is valid"
	if !valid {
		status, summary = report.StatusFailed, "Strict recursive code-signature verification failed"
	}
	return report.Evidence{ID: "signature", Status: status, Summary: summary, Data: map[string]any{"valid": valid, "reason": reason}}
}

func (c Collector) gatekeeper(ctx context.Context, app App) report.Evidence {
	result := c.Runner.Run(ctx, "/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", app.Path)
	if result.TimedOut {
		return timedOut("gatekeeper", "Gatekeeper assessment timed out")
	}
	accepted := result.Err == nil
	reason := "accepted"
	if !accepted {
		reason = "rejected"
	}
	status := report.StatusOK
	summary := "Gatekeeper accepted the application"
	if !accepted {
		status, summary = report.StatusFailed, "Gatekeeper did not accept the application"
	}
	return report.Evidence{ID: "gatekeeper", Status: status, Summary: summary, Data: map[string]any{"accepted": accepted, "reason": reason}}
}

func (c Collector) quarantine(ctx context.Context, app App) report.Evidence {
	result := c.Runner.Run(ctx, "/usr/bin/xattr", "-p", "com.apple.quarantine", app.Path)
	if result.TimedOut {
		return timedOut("quarantine", "Quarantine metadata check timed out")
	}
	present := result.Err == nil && strings.TrimSpace(result.Stdout) != ""
	summary := "No bundle-level quarantine attribute found"
	if present {
		summary = "Bundle has quarantine metadata"
	}
	return report.Evidence{ID: "quarantine", Status: report.StatusOK, Summary: summary, Data: map[string]any{"present": present}}
}

func (c Collector) architecture(ctx context.Context, app App) report.Evidence {
	if app.ExecutablePath == "" {
		return unavailable("architecture", "Bundle executable is unknown")
	}
	result := c.Runner.Run(ctx, "/usr/bin/lipo", "-archs", app.ExecutablePath)
	if result.TimedOut {
		return timedOut("architecture", "Architecture inspection timed out")
	}
	if result.Err != nil {
		return unavailable("architecture", "Could not inspect executable architectures")
	}
	architectures := strings.Fields(strings.TrimSpace(result.Stdout))
	hasARM, hasX86 := contains(architectures, "arm64") || contains(architectures, "arm64e"), contains(architectures, "x86_64")
	rosetta := runtime.GOARCH == "arm64" && hasX86 && !hasARM
	incompatible := (runtime.GOARCH == "arm64" && !hasARM && !hasX86) || (runtime.GOARCH == "amd64" && !hasX86)
	return report.Evidence{ID: "architecture", Status: report.StatusOK, Summary: "Executable architectures inspected", Data: map[string]any{"architectures": architectures, "rosetta_required": rosetta, "incompatible": incompatible}}
}

func (c Collector) dependencies(ctx context.Context, app App) report.Evidence {
	if app.ExecutablePath == "" {
		return unavailable("dependencies", "Bundle executable is unknown")
	}
	libsResult := c.Runner.Run(ctx, "/usr/bin/otool", "-L", app.ExecutablePath)
	pathsResult := c.Runner.Run(ctx, "/usr/bin/otool", "-l", app.ExecutablePath)
	if libsResult.TimedOut || pathsResult.TimedOut {
		return timedOut("dependencies", "Dynamic-library inspection timed out")
	}
	if libsResult.Err != nil {
		return unavailable("dependencies", "Could not inspect dynamic libraries")
	}
	rpaths := parseRPaths(pathsResult.Stdout, app.ExecutablePath)
	missing := 0
	lines := strings.Split(libsResult.Stdout, "\n")
	for _, line := range lines[1:] {
		library := strings.TrimSpace(strings.SplitN(strings.TrimSpace(line), " (", 2)[0])
		if library == "" || isSystemLibrary(library) {
			continue
		}
		if !dependencyExists(library, app.ExecutablePath, rpaths) {
			missing++
		}
	}
	status, summary := report.StatusOK, "Non-system dynamic libraries resolve"
	if missing > 0 {
		status, summary = report.StatusFailed, fmt.Sprintf("%d non-system dynamic libraries could not be resolved", missing)
	}
	return report.Evidence{ID: "dependencies", Status: status, Summary: summary, Data: map[string]any{"missing_count": missing}}
}

func (c Collector) limits(ctx context.Context) report.Evidence {
	data := map[string]any{}
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err == nil {
		data["process_soft"] = limit.Cur
		data["process_hard"] = limit.Max
	}
	result := c.Runner.Run(ctx, "/usr/sbin/sysctl", "kern.num_files", "kern.maxfiles", "kern.maxfilesperproc")
	if result.TimedOut {
		return timedOut("limits", "System descriptor limit check timed out")
	}
	if result.Err != nil {
		return unavailable("limits", "System descriptor limits are unavailable")
	}
	for _, line := range strings.Split(result.Stdout, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(parts[0]) {
		case "kern.num_files":
			data["global_used"] = value
		case "kern.maxfiles":
			data["global_max"] = value
		case "kern.maxfilesperproc":
			data["kernel_per_process_max"] = value
		}
	}
	if launchctl := c.Runner.Run(ctx, "/bin/launchctl", "limit", "maxfiles"); launchctl.Err == nil {
		data["launchctl"] = strings.Join(strings.Fields(launchctl.Stdout), " ")
	}
	return report.Evidence{ID: "limits", Status: report.StatusOK, Summary: "Descriptor limits collected", Data: data}
}

func (c Collector) launch(ctx context.Context, app App, opts DiagnoseOptions) report.Evidence {
	before := c.matchingPIDs(ctx, app.ExecutablePath)
	if len(before) > 0 && !opts.NewInstance {
		return report.Evidence{ID: "launch", Status: report.StatusSkipped, Summary: "Application is already running", Data: map[string]any{"already_running": true, "existing_processes": len(before)}}
	}
	args := []string{}
	if opts.NewInstance {
		args = append(args, "-n")
	}
	args = append(args, "-a", app.Path)
	result := c.Runner.Run(ctx, "/usr/bin/open", args...)
	if result.TimedOut {
		return timedOut("launch", "Launch request timed out")
	}
	if result.Err != nil {
		return report.Evidence{ID: "launch", Status: report.StatusFailed, Summary: "Launch Services rejected the launch request", Data: map[string]any{"spawned": false}}
	}
	deadline := time.Now().Add(opts.Observe)
	seen := map[int]bool{}
	terminated := false
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return report.Evidence{ID: "launch", Status: report.StatusTimedOut, Summary: "Launch observation was interrupted", Error: ctx.Err().Error()}
		case <-time.After(150 * time.Millisecond):
		}
		current := c.matchingPIDs(ctx, app.ExecutablePath)
		for pid := range current {
			if !before[pid] {
				seen[pid] = true
			}
		}
		for pid := range seen {
			if !current[pid] {
				terminated = true
			}
		}
	}
	current := c.matchingPIDs(ctx, app.ExecutablePath)
	survived := false
	for pid := range seen {
		if current[pid] {
			survived = true
		}
	}
	data := map[string]any{"spawned": len(seen) > 0, "survived": survived, "terminated": terminated && !survived, "observed_processes": len(seen), "exit_signal": "unknown"}
	summary := "No matching application process was observed"
	if survived {
		summary = "Application process survived the observation window"
	} else if terminated {
		summary = "Application process terminated during the observation window"
	}
	return report.Evidence{ID: "launch", Status: report.StatusOK, Summary: summary, Data: data}
}

func (c Collector) matchingPIDs(ctx context.Context, executablePath string) map[int]bool {
	result := c.Runner.Run(ctx, "/bin/ps", "-axo", "pid=,comm=")
	matched := map[int]bool{}
	if result.Err != nil || executablePath == "" {
		return matched
	}
	wanted := filepath.Clean(executablePath)
	for _, line := range strings.Split(result.Stdout, "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		command := strings.Join(fields[1:], " ")
		if filepath.Clean(command) == wanted {
			matched[pid] = true
		}
	}
	return matched
}

func (c Collector) logs(ctx context.Context, app App, start, end time.Time) report.Evidence {
	names := []string{app.Executable, "syspolicyd", "amfid", "launchservicesd", "runningboardd", "taskgated-helper", "XProtectService"}
	parts := make([]string, 0, len(names))
	for _, name := range names {
		if name != "" {
			parts = append(parts, `process == "`+predicateEscape(name)+`"`)
		}
	}
	predicate := strings.Join(parts, " OR ")
	format := "2006-01-02 15:04:05-0700"
	result := c.Runner.Run(ctx, "/usr/bin/log", "show", "--style", "ndjson", "--start", start.Local().Format(format), "--end", end.Local().Format(format), "--predicate", predicate)
	if result.TimedOut {
		return timedOut("logs", "Unified log query timed out")
	}
	if result.Err != nil {
		return unavailable("logs", "Unified logs could not be queried")
	}
	summary := ParseLogEvents([]byte(result.Stdout))
	return report.Evidence{ID: "logs", Status: report.StatusOK, Summary: "Correlated system logs inspected", Data: map[string]any{
		"emfile": summary.EMFILE, "enfile": summary.ENFILE, "sec_static_code": summary.SecStaticCode,
		"signature_errors": summary.Signature, "gatekeeper_errors": summary.Gatekeeper, "notarization_errors": summary.Notarization,
		"xprotect": summary.XProtect, "launch_services": summary.LaunchServices, "terminations": summary.Terminations, "missing_library": summary.MissingLibrary,
	}}
}

func (c Collector) crashes(app App, start, end time.Time) report.Evidence {
	home, err := os.UserHomeDir()
	if err != nil {
		return unavailable("crash", "User crash-report directory is unavailable")
	}
	dirs := []string{filepath.Join(home, "Library", "Logs", "DiagnosticReports"), "/Library/Logs/DiagnosticReports"}
	count := 0
	signals := map[string]int{}
	signalPattern := regexp.MustCompile(`(?i)\b(SIG[A-Z0-9]+)\b`)
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || (!strings.HasSuffix(entry.Name(), ".ips") && !strings.HasSuffix(entry.Name(), ".crash")) {
				continue
			}
			lowerName := strings.ToLower(entry.Name())
			if !strings.Contains(lowerName, strings.ToLower(app.Executable)) && !strings.Contains(lowerName, strings.ToLower(app.Name)) {
				continue
			}
			info, err := entry.Info()
			if err != nil || info.ModTime().Before(start.Add(-time.Second)) || info.ModTime().After(end.Add(3*time.Second)) {
				continue
			}
			file, err := os.Open(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			buf := make([]byte, 256*1024)
			n, _ := file.Read(buf)
			file.Close()
			count++
			if match := signalPattern.FindStringSubmatch(string(buf[:n])); len(match) > 1 {
				signals[strings.ToUpper(match[1])]++
			}
		}
	}
	return report.Evidence{ID: "crash", Status: report.StatusOK, Summary: fmt.Sprintf("Found %d correlated crash reports", count), Data: map[string]any{"count": count, "signals": signals}}
}

func (c Collector) processDescriptors(ctx context.Context, process string) report.Evidence {
	pids := c.Runner.Run(ctx, "/usr/bin/pgrep", "-x", process)
	if pids.Err != nil || strings.TrimSpace(pids.Stdout) == "" {
		return unavailable("descriptors", "Target process was not found")
	}
	pid := strings.Fields(pids.Stdout)[0]
	result := c.Runner.Run(ctx, "/usr/sbin/lsof", "-nP", "-a", "-p", pid, "-F0pcftn")
	if result.TimedOut {
		return timedOut("descriptors", "Descriptor enumeration timed out")
	}
	if result.Err != nil {
		return unavailable("descriptors", "Descriptor enumeration requires additional privileges")
	}
	sample := ParseLSOF([]byte(result.Stdout))
	return report.Evidence{ID: "descriptors", Status: report.StatusOK, Summary: fmt.Sprintf("Counted %d numeric descriptors for %s", sample.Count, process), Data: map[string]any{"process": process, "pid": pid, "count": sample.Count, "by_type": sample.ByType}}
}

func unavailable(id, summary string) report.Evidence {
	return report.Evidence{ID: id, Status: report.StatusUnavailable, Summary: summary}
}

func timedOut(id, summary string) report.Evidence {
	return report.Evidence{ID: id, Status: report.StatusTimedOut, Summary: summary, Error: "timed out"}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func compareVersions(a, b string) int {
	aParts, bParts := strings.Split(a, "."), strings.Split(b, ".")
	length := len(aParts)
	if len(bParts) > length {
		length = len(bParts)
	}
	for i := 0; i < length; i++ {
		av, bv := 0, 0
		if i < len(aParts) {
			av, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bv, _ = strconv.Atoi(bParts[i])
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

func parseRPaths(output, executable string) []string {
	var paths []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	wantPath := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "cmd LC_RPATH" {
			wantPath = true
			continue
		}
		if wantPath && strings.HasPrefix(line, "path ") {
			value := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(line, "path "), " (", 2)[0])
			value = strings.ReplaceAll(value, "@executable_path", filepath.Dir(executable))
			value = strings.ReplaceAll(value, "@loader_path", filepath.Dir(executable))
			paths = append(paths, filepath.Clean(value))
			wantPath = false
		}
	}
	return paths
}

func isSystemLibrary(path string) bool {
	return strings.HasPrefix(path, "/System/Library/") || strings.HasPrefix(path, "/usr/lib/")
}

func dependencyExists(library, executable string, rpaths []string) bool {
	base := filepath.Dir(executable)
	candidates := []string{}
	switch {
	case strings.HasPrefix(library, "@executable_path/"):
		candidates = append(candidates, filepath.Join(base, strings.TrimPrefix(library, "@executable_path/")))
	case strings.HasPrefix(library, "@loader_path/"):
		candidates = append(candidates, filepath.Join(base, strings.TrimPrefix(library, "@loader_path/")))
	case strings.HasPrefix(library, "@rpath/"):
		for _, rpath := range rpaths {
			candidates = append(candidates, filepath.Join(rpath, strings.TrimPrefix(library, "@rpath/")))
		}
	default:
		candidates = append(candidates, library)
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return true
		}
	}
	return false
}

func predicateEscape(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	return strings.ReplaceAll(value, `"`, `\"`)
}

func sortedKeys(values map[int]bool) []int {
	keys := make([]int, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Ints(keys)
	return keys
}
