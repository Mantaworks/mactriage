package macos

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

type CheckID string

const (
	CheckStorage     CheckID = "storage"
	CheckMemory      CheckID = "memory"
	CheckCPU         CheckID = "cpu"
	CheckDescriptors CheckID = "descriptors"
	CheckServices    CheckID = "services"
	CheckUpdates     CheckID = "updates"
	CheckCrashes     CheckID = "crashes"
	CheckRestarts    CheckID = "restarts"
	CheckStartup     CheckID = "startup"
	CheckApps        CheckID = "apps"
	CheckNetwork     CheckID = "network"
	CheckBattery     CheckID = "battery"
	CheckThermal     CheckID = "thermal"
	CheckBackup      CheckID = "backup"
)

var DoctorChecks = []CheckID{
	CheckStorage,
	CheckMemory,
	CheckCPU,
	CheckDescriptors,
	CheckServices,
	CheckUpdates,
	CheckCrashes,
	CheckRestarts,
	CheckStartup,
	CheckApps,
	CheckNetwork,
	CheckBattery,
	CheckThermal,
	CheckBackup,
}

var doctorCheckAliases = map[string]CheckID{
	"disk":         CheckStorage,
	"ram":          CheckMemory,
	"fd":           CheckDescriptors,
	"fds":          CheckDescriptors,
	"crash":        CheckCrashes,
	"restart":      CheckRestarts,
	"login-items":  CheckStartup,
	"applications": CheckApps,
	"wifi":         CheckNetwork,
	"time-machine": CheckBackup,
}

func DoctorCheckNames() []string {
	names := make([]string, len(DoctorChecks))
	for i, check := range DoctorChecks {
		names[i] = string(check)
	}
	return names
}

type DoctorProfile string

const (
	DoctorProfileQuick DoctorProfile = "quick"
	DoctorProfileFull  DoctorProfile = "full"
	DoctorProfileFleet DoctorProfile = "fleet"
)

type DoctorOptions struct {
	Only    []string
	Skip    []string
	Profile DoctorProfile
	Offline bool
}

type Doctor struct {
	Runner platform.Runner
	Emit   func(ProgressEvent)
}

type doctorProbe struct {
	id    CheckID
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
		{CheckStorage, "Check startup disk space", d.storage},
		{CheckMemory, "Measure memory and swap pressure", d.memory},
		{CheckCPU, "Inspect CPU load and process states", d.cpu},
		{CheckDescriptors, "Measure descriptor-table pressure", d.descriptors},
		{CheckServices, "Verify macOS security services", d.services},
		{CheckUpdates, "Check Software Update availability", d.updates},
		{CheckCrashes, "Count recent crash reports", d.crashes},
		{CheckRestarts, "Check repeated process restarts", d.restarts},
		{CheckStartup, "Count startup agents and daemons", d.startup},
		{CheckApps, "Check installed-app compatibility", d.apps},
		{CheckNetwork, "Check network configuration", func(ctx context.Context) report.Evidence {
			networkReport, inspectErr := (NetworkInspector{Runner: d.Runner, Detailed: opts.Profile != DoctorProfileQuick}).Inspect(ctx, "example.com")
			if inspectErr != nil || len(networkReport.Evidence) == 0 {
				return unavailable(report.EvidenceNetwork, "Network configuration is unavailable")
			}
			return networkReport.Evidence[0]
		}},
		{CheckBattery, "Check battery condition", func(ctx context.Context) report.Evidence { return (HealthInspector{Runner: d.Runner}).Battery(ctx) }},
		{CheckThermal, "Check thermal limits", func(ctx context.Context) report.Evidence { return (HealthInspector{Runner: d.Runner}).Thermal(ctx) }},
		{CheckBackup, "Check Time Machine freshness", func(ctx context.Context) report.Evidence { return (HealthInspector{Runner: d.Runner}).Backup(ctx) }},
	}
	results := make([]report.Evidence, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		if !selected[probe.id] {
			continue
		}
		wg.Add(1)
		go func(index int, current doctorProbe) {
			defer wg.Done()
			d.emit(string(current.id), current.label, "running", 0)
			started := time.Now()
			results[index] = current.run(ctx)
			d.emit(string(current.id), current.label, string(results[index].Status), time.Since(started))
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

func selectDoctorChecks(opts DoctorOptions) (map[CheckID]bool, error) {
	selected := make(map[CheckID]bool, len(DoctorChecks))
	profile := opts.Profile
	if profile == "" {
		profile = DoctorProfileFull
	}
	if profile != DoctorProfileQuick && profile != DoctorProfileFull && profile != DoctorProfileFleet {
		return nil, fmt.Errorf("unknown doctor profile %q", profile)
	}
	quick := map[CheckID]bool{
		CheckStorage: true, CheckMemory: true, CheckCPU: true,
		CheckDescriptors: true, CheckServices: true, CheckNetwork: true,
	}
	for _, check := range DoctorChecks {
		switch {
		case len(opts.Only) != 0:
			selected[check] = false
		case profile == DoctorProfileQuick:
			selected[check] = quick[check]
		case profile == DoctorProfileFleet:
			selected[check] = check != CheckUpdates
		default:
			selected[check] = true
		}
	}
	for _, name := range opts.Only {
		check, ok := parseCheckID(name)
		if !ok {
			return nil, fmt.Errorf("unknown doctor check %q", name)
		}
		selected[check] = true
	}
	for _, name := range opts.Skip {
		check, ok := parseCheckID(name)
		if !ok {
			return nil, fmt.Errorf("unknown doctor check %q", name)
		}
		selected[check] = false
	}
	if opts.Offline {
		selected[CheckNetwork] = false
		selected[CheckUpdates] = false
	}
	return selected, nil
}

func parseCheckID(name string) (CheckID, bool) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for _, check := range DoctorChecks {
		if normalized == string(check) {
			return check, true
		}
	}
	check, ok := doctorCheckAliases[normalized]
	return check, ok
}

func (d Doctor) emit(id, label, status string, duration time.Duration) {
	if d.Emit != nil {
		d.Emit(ProgressEvent{ID: id, Label: label, Status: status, Duration: duration})
	}
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
