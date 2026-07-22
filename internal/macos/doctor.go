package macos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

var DoctorChecks = []string{"storage", "memory", "cpu", "descriptors", "services", "updates", "crashes", "restarts", "startup", "apps", "network"}

type DoctorOptions struct {
	Only []string
	Skip []string
}

type Doctor struct {
	Runner platform.Runner
	Emit   func(ProgressEvent)
}

type doctorProbe struct {
	name  string
	label string
	run   func(context.Context) report.Evidence
}

func (d Doctor) Inspect(ctx context.Context, opts DoctorOptions) (report.Report, error) {
	if d.Runner == nil {
		return report.Report{}, errors.New("doctor requires a command runner")
	}
	selected, err := selectDoctorChecks(opts)
	if err != nil {
		return report.Report{}, err
	}
	r := report.New("doctor", "this Mac")
	r.Host = (Collector{Runner: d.Runner}).host(ctx)
	probes := []doctorProbe{
		{"storage", "Check startup disk space", d.storage},
		{"memory", "Measure memory and swap pressure", d.memory},
		{"cpu", "Inspect CPU load and process states", d.cpu},
		{"descriptors", "Measure descriptor-table pressure", d.descriptors},
		{"services", "Verify macOS security services", d.services},
		{"updates", "Check Software Update availability", d.updates},
		{"crashes", "Count recent crash reports", d.crashes},
		{"restarts", "Check repeated process restarts", d.restarts},
		{"startup", "Count startup agents and daemons", d.startup},
		{"apps", "Check installed-app compatibility", d.apps},
		{"network", "Check basic network configuration", d.network},
	}
	results := make([]report.Evidence, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		if !selected[probe.name] {
			continue
		}
		wg.Add(1)
		go func(index int, current doctorProbe) {
			defer wg.Done()
			d.emit(current.name, current.label, "running", 0)
			started := time.Now()
			results[index] = current.run(ctx)
			d.emit(current.name, current.label, string(results[index].Status), time.Since(started))
		}(i, probe)
	}
	wg.Wait()
	for _, evidence := range results {
		if evidence.ID != "" {
			r.Evidence = append(r.Evidence, evidence)
			if incompleteStatus(evidence.Status) {
				r.Completeness = report.Partial
			}
		}
	}
	return r, nil
}

func selectDoctorChecks(opts DoctorOptions) (map[string]bool, error) {
	known := make(map[string]bool, len(DoctorChecks))
	selected := make(map[string]bool, len(DoctorChecks))
	for _, check := range DoctorChecks {
		known[check] = true
		selected[check] = len(opts.Only) == 0
	}
	for _, check := range opts.Only {
		if !known[check] {
			return nil, fmt.Errorf("unknown doctor check %q", check)
		}
		selected[check] = true
	}
	for _, check := range opts.Skip {
		if !known[check] {
			return nil, fmt.Errorf("unknown doctor check %q", check)
		}
		selected[check] = false
	}
	return selected, nil
}

func (d Doctor) emit(id, label, status string, duration time.Duration) {
	if d.Emit != nil {
		d.Emit(ProgressEvent{ID: id, Label: label, Status: status, Duration: duration})
	}
}

func (d Doctor) storage(ctx context.Context) report.Evidence {
	result := d.Runner.Run(ctx, "/bin/df", "-kP", "/")
	if result.TimedOut {
		return timedOut(report.EvidenceStorage, "Startup disk check timed out")
	}
	if result.Err != nil {
		return unavailable(report.EvidenceStorage, "Startup disk capacity is unavailable")
	}
	lines := nonemptyLines(result.Stdout)
	if len(lines) < 2 {
		return unavailable(report.EvidenceStorage, "Startup disk capacity was incomplete")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 6 {
		return unavailable(report.EvidenceStorage, "Startup disk capacity was incomplete")
	}
	totalKB, totalErr := strconv.ParseUint(fields[1], 10, 64)
	availableKB, availableErr := strconv.ParseUint(fields[3], 10, 64)
	if totalErr != nil || availableErr != nil || totalKB == 0 {
		return unavailable(report.EvidenceStorage, "Startup disk capacity could not be parsed")
	}
	data := report.StorageData{TotalBytes: totalKB * 1024, AvailableBytes: availableKB * 1024, AvailablePercent: roundOne(float64(availableKB) * 100 / float64(totalKB))}
	return report.Evidence{ID: report.EvidenceStorage, Status: report.StatusOK, Summary: fmt.Sprintf("Startup disk has %.1f%% available", data.AvailablePercent), Data: data}
}

func (d Doctor) memory(ctx context.Context) report.Evidence {
	totalResult := d.Runner.Run(ctx, "/usr/sbin/sysctl", "-n", "hw.memsize")
	vmResult := d.Runner.Run(ctx, "/usr/bin/vm_stat")
	swapResult := d.Runner.Run(ctx, "/usr/sbin/sysctl", "-n", "vm.swapusage")
	if totalResult.TimedOut || vmResult.TimedOut || swapResult.TimedOut {
		return timedOut(report.EvidenceMemory, "Memory pressure check timed out")
	}
	if totalResult.Err != nil || vmResult.Err != nil || swapResult.Err != nil {
		return unavailable(report.EvidenceMemory, "Memory pressure is unavailable")
	}
	total, err := strconv.ParseUint(strings.TrimSpace(totalResult.Stdout), 10, 64)
	if err != nil || total == 0 {
		return unavailable(report.EvidenceMemory, "Total memory could not be parsed")
	}
	pageSize := uint64(4096)
	if match := regexp.MustCompile(`page size of ([0-9]+) bytes`).FindStringSubmatch(vmResult.Stdout); len(match) == 2 {
		pageSize, _ = strconv.ParseUint(match[1], 10, 64)
	}
	freePages := vmPageCount(vmResult.Stdout, "Pages free") + vmPageCount(vmResult.Stdout, "Pages inactive") + vmPageCount(vmResult.Stdout, "Pages speculative")
	freeBytes := freePages * pageSize
	swapUsed := parseSwapUsed(swapResult.Stdout)
	freePercent := roundOne(float64(freeBytes) * 100 / float64(total))
	if pressure := d.Runner.Run(ctx, "/usr/bin/memory_pressure", "-Q"); pressure.Err == nil {
		if measured := parseMemoryFreePercent(pressure.Stdout + "\n" + pressure.Stderr); measured > 0 {
			freePercent = measured
		}
	}
	data := report.MemoryData{TotalBytes: total, FreeBytes: freeBytes, FreePercent: freePercent, SwapUsedBytes: swapUsed}
	return report.Evidence{ID: report.EvidenceMemory, Status: report.StatusOK, Summary: fmt.Sprintf("Memory has %.1f%% readily available", data.FreePercent), Data: data}
}

func (d Doctor) cpu(ctx context.Context) report.Evidence {
	coresResult := d.Runner.Run(ctx, "/usr/sbin/sysctl", "-n", "hw.logicalcpu")
	loadResult := d.Runner.Run(ctx, "/usr/bin/uptime")
	processResult := d.Runner.Run(ctx, "/bin/ps", "-axo", "pid=,%cpu=,state=,comm=")
	if coresResult.TimedOut || loadResult.TimedOut || processResult.TimedOut {
		return timedOut(report.EvidenceCPU, "CPU health check timed out")
	}
	if coresResult.Err != nil || loadResult.Err != nil || processResult.Err != nil {
		return unavailable(report.EvidenceCPU, "CPU health is unavailable")
	}
	cores, _ := strconv.Atoi(strings.TrimSpace(coresResult.Stdout))
	load := parseLoadOne(loadResult.Stdout)
	data := report.CPUData{LogicalCores: cores, LoadOne: load, ProcessStates: map[string]int{}}
	for _, line := range nonemptyLines(processResult.Stdout) {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		cpu, err := strconv.ParseFloat(strings.ReplaceAll(fields[1], ",", "."), 64)
		if err != nil {
			continue
		}
		if cpu > data.HighestPercent {
			data.HighestPercent = cpu
			data.HighestProcess = filepath.Base(strings.Join(fields[3:], " "))
		}
		data.ProcessStates[strings.ToUpper(fields[2])]++
	}
	return report.Evidence{ID: report.EvidenceCPU, Status: report.StatusOK, Summary: fmt.Sprintf("Load average %.2f across %d logical cores", data.LoadOne, data.LogicalCores), Data: data}
}

func (d Doctor) descriptors(ctx context.Context) report.Evidence {
	return (Collector{Runner: d.Runner}).limits(ctx)
}

func (d Doctor) services(ctx context.Context) report.Evidence {
	names := []string{"syspolicyd", "trustd", "launchservicesd", "runningboardd"}
	data := report.ServicesData{Running: make(map[string]bool, len(names)), Statuses: make(map[string]report.Status, len(names))}
	status := report.StatusOK
	for _, name := range names {
		result := d.Runner.Run(ctx, "/usr/bin/pgrep", "-x", name)
		switch {
		case result.TimedOut:
			data.Statuses[name] = report.StatusTimedOut
			status = report.StatusPartial
		case result.Err != nil && result.ExitCode != 1:
			data.Statuses[name] = report.StatusUnavailable
			status = report.StatusPartial
		default:
			data.Statuses[name] = report.StatusOK
			data.Running[name] = strings.TrimSpace(result.Stdout) != ""
		}
	}
	return report.Evidence{ID: report.EvidenceServices, Status: status, Summary: "Collected process-presence facts for core macOS application and security services", Data: data}
}

func (d Doctor) updates(ctx context.Context) report.Evidence {
	result := d.Runner.Run(ctx, "/usr/sbin/softwareupdate", "-l", "--no-scan")
	if result.TimedOut {
		return timedOut(report.EvidenceUpdates, "Software Update check timed out")
	}
	if result.Err != nil {
		return unavailable(report.EvidenceUpdates, "Software Update availability could not be checked")
	}
	text := strings.ToLower(result.Stdout + "\n" + result.Stderr)
	available := !strings.Contains(text, "no new software available") && (strings.Contains(text, "label:") || strings.Contains(text, "recommended:"))
	return report.Evidence{ID: report.EvidenceUpdates, Status: report.StatusOK, Summary: "Cached Software Update availability checked without starting a new scan", Data: report.UpdatesData{Available: available, Cached: true}}
}

func (d Doctor) crashes(ctx context.Context) report.Evidence {
	dirs := []string{filepath.Join(os.Getenv("HOME"), "Library", "Logs", "DiagnosticReports"), "/Library/Logs/DiagnosticReports"}
	count := 0
	available := false
	for _, dir := range dirs {
		result := d.Runner.Run(ctx, "/usr/bin/find", dir, "-maxdepth", "1", "-type", "f", "-mtime", "-1", "(", "-name", "*.ips", "-o", "-name", "*.crash", ")", "-print")
		if result.Err == nil {
			available = true
			count += len(nonemptyLines(result.Stdout))
		}
	}
	if !available {
		return unavailable(report.EvidenceRecentCrashes, "Recent crash-report count is unavailable")
	}
	return report.Evidence{ID: report.EvidenceRecentCrashes, Status: report.StatusOK, Summary: fmt.Sprintf("Found %d crash reports created in the last day", count), Data: report.RecentCrashesData{Count: count}}
}

func (d Doctor) restarts(ctx context.Context) report.Evidence {
	result := d.Runner.Run(ctx, "/usr/bin/log", "show", "--last", "10m", "--style", "ndjson", "--predicate", `(process == "launchd" OR subsystem CONTAINS[c] "runningboard") AND (eventMessage CONTAINS[c] "exited" OR eventMessage CONTAINS[c] "terminated")`)
	if result.TimedOut {
		return timedOut(report.EvidenceRestartLoops, "Recent restart-log check timed out")
	}
	if result.Err != nil {
		return unavailable(report.EvidenceRestartLoops, "Recent restart logs are unavailable")
	}
	counts := map[string]int{}
	for _, line := range nonemptyLines(result.Stdout) {
		var event struct {
			Message string `json:"eventMessage"`
		}
		if json.Unmarshal([]byte(line), &event) != nil {
			continue
		}
		match := regexp.MustCompile(`(?i)(?:service|process)\s+([a-z0-9_.-]+)\s+(?:exited|terminated)`).FindStringSubmatch(event.Message)
		if len(match) == 2 {
			counts[match[1]]++
		}
	}
	var processes []report.ProcessRestartObservation
	for name, count := range counts {
		processes = append(processes, report.ProcessRestartObservation{Name: name, Count: count})
	}
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].Count == processes[j].Count {
			return processes[i].Name < processes[j].Name
		}
		return processes[i].Count > processes[j].Count
	})
	return report.Evidence{ID: report.EvidenceRestartLoops, Status: report.StatusOK, Summary: fmt.Sprintf("Observed exit events for %d named processes", len(processes)), Data: report.RestartLoopsData{Processes: processes}}
}

func (d Doctor) startup(ctx context.Context) report.Evidence {
	background := d.Runner.Run(ctx, "/usr/bin/sfltool", "dumpbtm")
	if background.TimedOut {
		return timedOut(report.EvidenceStartupItems, "Login and background item count timed out")
	}
	if background.Err == nil {
		count := len(regexp.MustCompile(`(?im)^\s*UUID\s*:`).FindAllString(background.Stdout, -1))
		return report.Evidence{ID: report.EvidenceStartupItems, Status: report.StatusOK, Summary: fmt.Sprintf("Counted %d registered login and background items", count), Data: report.StartupItemsData{Count: count, Source: "background-task-management"}}
	}
	dirs := []string{filepath.Join(os.Getenv("HOME"), "Library", "LaunchAgents"), "/Library/LaunchAgents", "/Library/LaunchDaemons"}
	count := 0
	available := false
	for _, dir := range dirs {
		result := d.Runner.Run(ctx, "/bin/ls", "-1", dir)
		if result.Err != nil {
			continue
		}
		available = true
		for _, line := range nonemptyLines(result.Stdout) {
			if strings.HasSuffix(strings.ToLower(line), ".plist") {
				count++
			}
		}
	}
	if !available {
		return unavailable(report.EvidenceStartupItems, "Startup agent count is unavailable")
	}
	return report.Evidence{ID: report.EvidenceStartupItems, Status: report.StatusPartial, Summary: fmt.Sprintf("Counted %d launch agents and daemons; registered Login Items were unavailable", count), Data: report.StartupItemsData{Count: count, Source: "launch-agent-fallback"}}
}

func (d Doctor) apps(ctx context.Context) report.Evidence {
	r, err := (AppScanner{Runner: d.Runner, Quick: true}).Scan(ctx, nil, 500, 8)
	if err != nil || len(r.Evidence) == 0 {
		return unavailable(report.EvidenceScan, "Installed-app compatibility scan is unavailable")
	}
	return r.Evidence[0]
}

func (d Doctor) network(ctx context.Context) report.Evidence {
	r, err := (NetworkInspector{Runner: d.Runner}).Inspect(ctx, "example.com")
	if err != nil || len(r.Evidence) == 0 {
		return unavailable(report.EvidenceNetwork, "Basic network configuration is unavailable")
	}
	return r.Evidence[0]
}

func nonemptyLines(text string) []string {
	var lines []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, strings.TrimSpace(line))
		}
	}
	return lines
}

func vmPageCount(text, label string) uint64 {
	re := regexp.MustCompile(regexp.QuoteMeta(label) + `:\s*([0-9]+)\.?`)
	match := re.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	value, _ := strconv.ParseUint(match[1], 10, 64)
	return value
}

func parseSwapUsed(text string) uint64 {
	match := regexp.MustCompile(`used = ([0-9]+(?:\.[0-9]+)?)([MG])`).FindStringSubmatch(text)
	if len(match) != 3 {
		return 0
	}
	value, _ := strconv.ParseFloat(match[1], 64)
	multiplier := float64(1 << 20)
	if match[2] == "G" {
		multiplier = 1 << 30
	}
	return uint64(value * multiplier)
}

func parseLoadOne(text string) float64 {
	match := regexp.MustCompile(`load averages?:\s*([0-9]+(?:\.[0-9]+)?)`).FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	value, _ := strconv.ParseFloat(match[1], 64)
	return value
}

func parseMemoryFreePercent(text string) float64 {
	match := regexp.MustCompile(`System-wide memory free percentage:\s*([0-9]+(?:\.[0-9]+)?)%`).FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	value, _ := strconv.ParseFloat(match[1], 64)
	return value
}

func roundOne(value float64) float64 { return math.Round(value*10) / 10 }
