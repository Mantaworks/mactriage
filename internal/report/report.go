package report

import "time"

const SchemaVersion = "1"

type Completeness string

const (
	Complete Completeness = "complete"
	Partial  Completeness = "partial"
)

type Status string

const (
	StatusOK          Status = "ok"
	StatusFailed      Status = "failed"
	StatusUnavailable Status = "unavailable"
	StatusTimedOut    Status = "timed_out"
	StatusSkipped     Status = "skipped"
)

type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Error    Severity = "error"
	Critical Severity = "critical"
)

type Host struct {
	OSVersion string `json:"os_version,omitempty"`
	Build     string `json:"build,omitempty"`
	Arch      string `json:"arch,omitempty"`
}

type Evidence struct {
	ID      string         `json:"id"`
	Status  Status         `json:"status"`
	Summary string         `json:"summary"`
	Data    map[string]any `json:"data,omitempty"`
	Error   string         `json:"error,omitempty"`
}

type Finding struct {
	Code           string   `json:"code"`
	Severity       Severity `json:"severity"`
	Title          string   `json:"title"`
	Explanation    string   `json:"explanation"`
	Confidence     string   `json:"confidence"`
	EvidenceIDs    []string `json:"evidence_ids,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}

type Action struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Command      []string `json:"command,omitempty"`
	RequiresRoot bool     `json:"requires_root"`
	Available    bool     `json:"available"`
}

type Report struct {
	SchemaVersion string       `json:"schema_version"`
	Command       string       `json:"command"`
	GeneratedAt   time.Time    `json:"generated_at"`
	Target        string       `json:"target,omitempty"`
	Host          Host         `json:"host"`
	Completeness  Completeness `json:"completeness"`
	Evidence      []Evidence   `json:"evidence"`
	Findings      []Finding    `json:"findings"`
	Actions       []Action     `json:"actions"`
}

func New(command, target string) Report {
	return Report{
		SchemaVersion: SchemaVersion,
		Command:       command,
		GeneratedAt:   time.Now().UTC(),
		Target:        target,
		Completeness:  Complete,
		Evidence:      []Evidence{},
		Findings:      []Finding{},
		Actions:       []Action{},
	}
}

func (r Report) ExitCode() int {
	for _, finding := range r.Findings {
		if finding.Severity == Error || finding.Severity == Critical {
			return 1
		}
	}
	if r.Completeness == Partial {
		return 3
	}
	return 0
}
