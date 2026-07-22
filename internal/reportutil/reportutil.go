package reportutil

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/Mantaworks/mactriage/internal/knowledge"
	"github.com/Mantaworks/mactriage/internal/report"
)

const maxReportBytes = 16 << 20

type EvidenceChange struct {
	ID     report.EvidenceID `json:"id"`
	Before report.Status     `json:"before"`
	After  report.Status     `json:"after"`
}

type MetricChange struct {
	Metric string  `json:"metric"`
	Before float64 `json:"before"`
	After  float64 `json:"after"`
	Unit   string  `json:"unit"`
}

type Comparison struct {
	SchemaVersion   string           `json:"schema_version"`
	Type            string           `json:"type"`
	GeneratedAt     time.Time        `json:"generated_at"`
	BeforeTarget    string           `json:"before_target,omitempty"`
	AfterTarget     string           `json:"after_target,omitempty"`
	Added           []string         `json:"added"`
	Resolved        []string         `json:"resolved"`
	Unchanged       []string         `json:"unchanged"`
	EvidenceChanges []EvidenceChange `json:"evidence_changes"`
	MetricChanges   []MetricChange   `json:"metric_changes"`
	NewIntelOnly    []string         `json:"new_intel_only"`
}

func Load(path string) (report.Report, error) {
	file, err := os.Open(path)
	if err != nil {
		return report.Report{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxReportBytes+1))
	if err != nil {
		return report.Report{}, err
	}
	if len(data) > maxReportBytes {
		return report.Report{}, fmt.Errorf("report exceeds %d MiB limit", maxReportBytes>>20)
	}
	type evidenceWire struct {
		ID      report.EvidenceID `json:"id"`
		Status  report.Status     `json:"status"`
		Summary string            `json:"summary"`
		Error   string            `json:"error,omitempty"`
		Data    json.RawMessage   `json:"data,omitempty"`
	}
	type document struct {
		SchemaVersion string              `json:"schema_version"`
		CaseID        string              `json:"case_id"`
		Command       string              `json:"command"`
		GeneratedAt   time.Time           `json:"generated_at"`
		Target        string              `json:"target"`
		Host          report.Host         `json:"host"`
		Completeness  report.Completeness `json:"completeness"`
		Evidence      []evidenceWire      `json:"evidence"`
		Findings      []report.Finding    `json:"findings"`
		Actions       []report.Action     `json:"actions"`
	}
	var decoded document
	if err := json.Unmarshal(data, &decoded); err != nil {
		return report.Report{}, fmt.Errorf("parse report: %w", err)
	}
	if decoded.SchemaVersion != report.SchemaVersion {
		return report.Report{}, fmt.Errorf("unsupported report schema %q", decoded.SchemaVersion)
	}
	r := report.Report{SchemaVersion: decoded.SchemaVersion, CaseID: decoded.CaseID, Command: decoded.Command, GeneratedAt: decoded.GeneratedAt, Target: decoded.Target, Host: decoded.Host, Completeness: decoded.Completeness, Findings: decoded.Findings, Actions: decoded.Actions, Evidence: []report.Evidence{}}
	for _, item := range decoded.Evidence {
		data, decodeErr := decodeEvidenceData(item.ID, item.Data)
		if decodeErr != nil {
			return report.Report{}, fmt.Errorf("parse %s evidence: %w", item.ID, decodeErr)
		}
		r.Evidence = append(r.Evidence, report.Evidence{ID: item.ID, Status: item.Status, Summary: item.Summary, Error: item.Error, Data: data})
	}
	return r, nil
}

func decodeEvidenceData(id report.EvidenceID, raw json.RawMessage) (report.EvidencePayload, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	switch id {
	case report.EvidenceBundle:
		var discriminator map[string]json.RawMessage
		if err := json.Unmarshal(raw, &discriminator); err != nil {
			return nil, err
		}
		if _, ok := discriminator["resolve_code"]; ok {
			return decodePayload[report.ResolutionData](raw)
		}
		return decodePayload[report.BundleData](raw)
	case report.EvidenceSignature:
		return decodePayload[report.SignatureData](raw)
	case report.EvidenceGatekeeper:
		return decodePayload[report.GatekeeperData](raw)
	case report.EvidenceQuarantine:
		return decodePayload[report.QuarantineData](raw)
	case report.EvidenceArchitecture:
		return decodePayload[report.ArchitectureData](raw)
	case report.EvidenceDependencies:
		return decodePayload[report.DependencyData](raw)
	case report.EvidenceLimits:
		return decodePayload[report.LimitsData](raw)
	case report.EvidenceLaunch:
		return decodePayload[report.LaunchData](raw)
	case report.EvidenceLogs:
		return decodePayload[report.LogsData](raw)
	case report.EvidenceCrash:
		return decodePayload[report.CrashData](raw)
	case report.EvidenceDescriptors:
		return decodePayload[report.DescriptorData](raw)
	case report.EvidenceRestart:
		return decodePayload[report.RestartData](raw)
	case report.EvidenceTopProcesses:
		return decodePayload[report.TopProcessesData](raw)
	case report.EvidenceProcess:
		return decodePayload[report.ProcessData](raw)
	case report.EvidencePermissions:
		return decodePayload[report.PermissionsData](raw)
	case report.EvidenceScan:
		return decodePayload[report.ScanData](raw)
	case report.EvidenceStorage:
		return decodePayload[report.StorageData](raw)
	case report.EvidenceMemory:
		return decodePayload[report.MemoryData](raw)
	case report.EvidenceCPU:
		return decodePayload[report.CPUData](raw)
	case report.EvidenceServices:
		return decodePayload[report.ServicesData](raw)
	case report.EvidenceUpdates:
		return decodePayload[report.UpdatesData](raw)
	case report.EvidenceRecentCrashes:
		return decodePayload[report.RecentCrashesData](raw)
	case report.EvidenceStartupItems:
		return decodePayload[report.StartupItemsData](raw)
	case report.EvidenceNetwork:
		return decodePayload[report.NetworkData](raw)
	case report.EvidenceRestartLoops:
		return decodePayload[report.RestartLoopsData](raw)
	case report.EvidenceRelaunch:
		return decodePayload[report.RelaunchData](raw)
	case report.EvidenceBattery:
		return decodePayload[report.BatteryData](raw)
	case report.EvidenceThermal:
		return decodePayload[report.ThermalData](raw)
	case report.EvidenceBackup:
		return decodePayload[report.BackupData](raw)
	case report.EvidenceStorageDetail:
		return decodePayload[report.StorageDetailsData](raw)
	default:
		return nil, nil
	}
}

func decodePayload[T report.EvidencePayload](raw json.RawMessage) (report.EvidencePayload, error) {
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	return value, nil
}

func Compare(before, after report.Report) Comparison {
	beforeCodes := findingSet(before.Findings)
	afterCodes := findingSet(after.Findings)
	comparison := Comparison{SchemaVersion: report.SchemaVersion, Type: "comparison", GeneratedAt: time.Now().UTC(), BeforeTarget: before.Target, AfterTarget: after.Target, Added: []string{}, Resolved: []string{}, Unchanged: []string{}, EvidenceChanges: []EvidenceChange{}, MetricChanges: []MetricChange{}, NewIntelOnly: []string{}}
	for code := range afterCodes {
		if beforeCodes[code] {
			comparison.Unchanged = append(comparison.Unchanged, code)
		} else {
			comparison.Added = append(comparison.Added, code)
		}
	}
	for code := range beforeCodes {
		if !afterCodes[code] {
			comparison.Resolved = append(comparison.Resolved, code)
		}
	}
	beforeEvidence := evidenceStatuses(before.Evidence)
	afterEvidence := evidenceStatuses(after.Evidence)
	for id, oldStatus := range beforeEvidence {
		if newStatus, ok := afterEvidence[id]; ok && newStatus != oldStatus {
			comparison.EvidenceChanges = append(comparison.EvidenceChanges, EvidenceChange{ID: id, Before: oldStatus, After: newStatus})
		}
	}
	appendMetricChanges(&comparison, before, after)
	comparison.NewIntelOnly = newIntelOnlyApps(before, after)
	sort.Strings(comparison.Added)
	sort.Strings(comparison.Resolved)
	sort.Strings(comparison.Unchanged)
	sort.Slice(comparison.EvidenceChanges, func(i, j int) bool { return comparison.EvidenceChanges[i].ID < comparison.EvidenceChanges[j].ID })
	sort.Slice(comparison.MetricChanges, func(i, j int) bool { return comparison.MetricChanges[i].Metric < comparison.MetricChanges[j].Metric })
	return comparison
}

func appendMetricChanges(comparison *Comparison, before, after report.Report) {
	beforeData := evidenceData(before)
	afterData := evidenceData(after)
	appendChange := func(metric string, oldValue, newValue float64, unit string) {
		if oldValue != newValue {
			comparison.MetricChanges = append(comparison.MetricChanges, MetricChange{Metric: metric, Before: oldValue, After: newValue, Unit: unit})
		}
	}
	if oldValue, ok := beforeData[report.EvidenceStorage].(report.StorageData); ok {
		if newValue, exists := afterData[report.EvidenceStorage].(report.StorageData); exists {
			appendChange("storage.available", oldValue.AvailablePercent, newValue.AvailablePercent, "percent")
		}
	}
	if oldValue, ok := beforeData[report.EvidenceMemory].(report.MemoryData); ok {
		if newValue, exists := afterData[report.EvidenceMemory].(report.MemoryData); exists {
			appendChange("memory.free", oldValue.FreePercent, newValue.FreePercent, "percent")
			appendChange("memory.swap", float64(oldValue.SwapUsedBytes), float64(newValue.SwapUsedBytes), "bytes")
		}
	}
	if oldValue, ok := beforeData[report.EvidenceCPU].(report.CPUData); ok {
		if newValue, exists := afterData[report.EvidenceCPU].(report.CPUData); exists {
			appendChange("cpu.load_one", oldValue.LoadOne, newValue.LoadOne, "load")
			appendChange("cpu.highest_process", oldValue.HighestPercent, newValue.HighestPercent, "percent")
		}
	}
	if oldValue, ok := beforeData[report.EvidenceStartupItems].(report.StartupItemsData); ok {
		if newValue, exists := afterData[report.EvidenceStartupItems].(report.StartupItemsData); exists {
			appendChange("startup_items.count", float64(oldValue.Count), float64(newValue.Count), "count")
		}
	}
	if oldValue, ok := beforeData[report.EvidenceLimits].(report.LimitsData); ok {
		if newValue, exists := afterData[report.EvidenceLimits].(report.LimitsData); exists {
			appendChange("descriptors.global_used", float64(oldValue.GlobalUsed), float64(newValue.GlobalUsed), "count")
		}
	}
	if oldValue, ok := beforeData[report.EvidenceBattery].(report.BatteryData); ok {
		if newValue, exists := afterData[report.EvidenceBattery].(report.BatteryData); exists {
			appendChange("battery.health", oldValue.HealthPercent, newValue.HealthPercent, "percent")
			appendChange("battery.cycles", float64(oldValue.CycleCount), float64(newValue.CycleCount), "count")
		}
	}
	if oldValue, ok := beforeData[report.EvidenceBackup].(report.BackupData); ok {
		if newValue, exists := afterData[report.EvidenceBackup].(report.BackupData); exists {
			appendChange("backup.age", oldValue.LatestAgeHours, newValue.LatestAgeHours, "hours")
		}
	}
	if oldValue, ok := beforeData[report.EvidenceThermal].(report.ThermalData); ok {
		if newValue, exists := afterData[report.EvidenceThermal].(report.ThermalData); exists {
			appendChange("thermal.cpu_limit", float64(oldValue.CPUSpeedLimit), float64(newValue.CPUSpeedLimit), "percent")
		}
	}
}

func evidenceData(r report.Report) map[report.EvidenceID]report.EvidencePayload {
	data := make(map[report.EvidenceID]report.EvidencePayload, len(r.Evidence))
	for _, evidence := range r.Evidence {
		data[evidence.ID] = evidence.Data
	}
	return data
}

func newIntelOnlyApps(before, after report.Report) []string {
	beforeIntel := findingSubjects(before.Findings, knowledge.CodeScanIntelOnly)
	afterIntel := findingSubjects(after.Findings, knowledge.CodeScanIntelOnly)
	var added []string
	for name := range afterIntel {
		if !beforeIntel[name] {
			added = append(added, name)
		}
	}
	sort.Strings(added)
	return added
}

func findingSubjects(findings []report.Finding, code string) map[string]bool {
	values := map[string]bool{}
	for _, finding := range findings {
		if finding.Code == code {
			for _, subject := range finding.Subjects {
				values[subject] = true
			}
		}
	}
	return values
}

func findingSet(findings []report.Finding) map[string]bool {
	values := make(map[string]bool, len(findings))
	for _, finding := range findings {
		if finding.Code != "" {
			values[finding.Code] = true
		}
	}
	return values
}

func evidenceStatuses(evidence []report.Evidence) map[report.EvidenceID]report.Status {
	values := make(map[report.EvidenceID]report.Status, len(evidence))
	for _, item := range evidence {
		values[item.ID] = item.Status
	}
	return values
}
