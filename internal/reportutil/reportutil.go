package reportutil

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/Mantaworks/mactriage/internal/report"
)

const maxReportBytes = 16 << 20

type EvidenceChange struct {
	ID     report.EvidenceID `json:"id"`
	Before report.Status     `json:"before"`
	After  report.Status     `json:"after"`
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
	}
	type document struct {
		SchemaVersion string              `json:"schema_version"`
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
	r := report.Report{SchemaVersion: decoded.SchemaVersion, Command: decoded.Command, GeneratedAt: decoded.GeneratedAt, Target: decoded.Target, Host: decoded.Host, Completeness: decoded.Completeness, Findings: decoded.Findings, Actions: decoded.Actions, Evidence: []report.Evidence{}}
	for _, item := range decoded.Evidence {
		r.Evidence = append(r.Evidence, report.Evidence{ID: item.ID, Status: item.Status, Summary: item.Summary, Error: item.Error})
	}
	return r, nil
}

func Compare(before, after report.Report) Comparison {
	beforeCodes := findingSet(before.Findings)
	afterCodes := findingSet(after.Findings)
	comparison := Comparison{SchemaVersion: report.SchemaVersion, Type: "comparison", GeneratedAt: time.Now().UTC(), BeforeTarget: before.Target, AfterTarget: after.Target, Added: []string{}, Resolved: []string{}, Unchanged: []string{}, EvidenceChanges: []EvidenceChange{}}
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
	sort.Strings(comparison.Added)
	sort.Strings(comparison.Resolved)
	sort.Strings(comparison.Unchanged)
	sort.Slice(comparison.EvidenceChanges, func(i, j int) bool { return comparison.EvidenceChanges[i].ID < comparison.EvidenceChanges[j].ID })
	return comparison
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
