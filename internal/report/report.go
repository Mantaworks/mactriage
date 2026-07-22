package report

import "time"

const SchemaVersion = "1"

type Completeness string

const (
	Complete Completeness = "complete"
	Partial  Completeness = "partial"
)

type Status string

type EvidenceID string

const (
	EvidenceBundle       EvidenceID = "bundle"
	EvidenceSignature    EvidenceID = "signature"
	EvidenceGatekeeper   EvidenceID = "gatekeeper"
	EvidenceQuarantine   EvidenceID = "quarantine"
	EvidenceArchitecture EvidenceID = "architecture"
	EvidenceDependencies EvidenceID = "dependencies"
	EvidenceLimits       EvidenceID = "limits"
	EvidenceLaunch       EvidenceID = "launch"
	EvidenceLogs         EvidenceID = "logs"
	EvidenceCrash        EvidenceID = "crash"
	EvidenceDescriptors  EvidenceID = "descriptors"
	EvidenceRestart      EvidenceID = "restart"
	EvidenceTopProcesses EvidenceID = "top_processes"
	EvidenceProcess      EvidenceID = "process"
	EvidencePermissions  EvidenceID = "permissions"
	EvidenceScan         EvidenceID = "scan"
)

const (
	StatusOK          Status = "ok"
	StatusPartial     Status = "partial"
	StatusFailed      Status = "failed"
	StatusUnavailable Status = "unavailable"
	StatusTimedOut    Status = "timed_out"
	StatusSkipped     Status = "skipped"
)

type Severity string

type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

type ActionID string

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

type EvidencePayload interface{ evidencePayload() }
type evidenceMarker struct{}

func (evidenceMarker) evidencePayload() {}

type ResolutionData struct {
	evidenceMarker
	ResolveCode string `json:"resolve_code"`
}

type BundleData struct {
	evidenceMarker
	Path               string `json:"path,omitempty"`
	Name               string `json:"name,omitempty"`
	BundleID           string `json:"bundle_id,omitempty"`
	Executable         string `json:"executable,omitempty"`
	Version            string `json:"version,omitempty"`
	MinimumOS          string `json:"minimum_os,omitempty"`
	ExecutableDeclared bool   `json:"executable_declared"`
	ExecutablePresent  bool   `json:"executable_present"`
	ExecutableRunnable bool   `json:"executable_runnable"`
	OSSupported        *bool  `json:"os_supported,omitempty"`
}

type SignatureData struct {
	evidenceMarker
	Valid  bool   `json:"valid"`
	Reason string `json:"reason"`
}

type GatekeeperData struct {
	evidenceMarker
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason"`
}

type QuarantineData struct {
	evidenceMarker
	Present bool `json:"present"`
}

type ArchitectureData struct {
	evidenceMarker
	Architectures []string `json:"architectures"`
}

type DependencyData struct {
	evidenceMarker
	MissingCount int `json:"missing_count"`
}

type LimitsData struct {
	evidenceMarker
	ProcessSoft        uint64 `json:"process_soft,omitempty"`
	ProcessHard        uint64 `json:"process_hard,omitempty"`
	GlobalUsed         uint64 `json:"global_used,omitempty"`
	GlobalMax          uint64 `json:"global_max,omitempty"`
	KernelProcessMax   uint64 `json:"kernel_per_process_max,omitempty"`
	Launchctl          string `json:"launchctl,omitempty"`
	LaunchdProcessSoft uint64 `json:"launchd_process_soft,omitempty"`
}

type LaunchData struct {
	evidenceMarker
	Skipped           bool   `json:"skipped,omitempty"`
	AlreadyRunning    bool   `json:"already_running,omitempty"`
	ExistingProcesses int    `json:"existing_processes,omitempty"`
	Spawned           *bool  `json:"spawned,omitempty"`
	Survived          bool   `json:"survived,omitempty"`
	Terminated        bool   `json:"terminated,omitempty"`
	ObservedProcesses int    `json:"observed_processes,omitempty"`
	ExitSignal        string `json:"exit_signal,omitempty"`
	TerminationSource string `json:"termination_source,omitempty"`
}

type LogsData struct {
	evidenceMarker
	EMFILE                  int `json:"emfile"`
	ENFILE                  int `json:"enfile"`
	SecStaticCode           int `json:"sec_static_code"`
	SyspolicydEMFILE        int `json:"syspolicyd_emfile"`
	SyspolicydENFILE        int `json:"syspolicyd_enfile"`
	SyspolicydSecStaticCode int `json:"syspolicyd_sec_static_code"`
	SyspolicydWedgeSequence int `json:"syspolicyd_wedge_sequence"`
	SignatureErrors         int `json:"signature_errors"`
	GatekeeperErrors        int `json:"gatekeeper_errors"`
	NotarizationErrors      int `json:"notarization_errors"`
	XProtect                int `json:"xprotect"`
	LaunchServices          int `json:"launch_services"`
	Terminations            int `json:"terminations"`
	MissingLibrary          int `json:"missing_library"`
}

type CrashTermination struct {
	Namespace string `json:"namespace,omitempty"`
	Code      string `json:"code,omitempty"`
	Indicator string `json:"indicator,omitempty"`
	Signal    string `json:"signal,omitempty"`
}

type CrashData struct {
	evidenceMarker
	Count        int                `json:"count"`
	Signals      map[string]int     `json:"signals,omitempty"`
	Terminations []CrashTermination `json:"terminations,omitempty"`
}

type DescriptorData struct {
	evidenceMarker
	Process     string         `json:"process"`
	PID         string         `json:"pid"`
	Count       int            `json:"count"`
	ByType      map[string]int `json:"by_type,omitempty"`
	ProcessSoft uint64         `json:"process_soft,omitempty"`
	ProcessHard uint64         `json:"process_hard,omitempty"`
}

type RestartData struct {
	evidenceMarker
	OldPID    int  `json:"old_pid"`
	NewPID    int  `json:"new_pid"`
	Restarted bool `json:"restarted"`
}

type ProcessDescriptorSummary struct {
	PID     int    `json:"pid"`
	Command string `json:"command"`
	Count   int    `json:"count"`
}

type TopProcessesData struct {
	evidenceMarker
	Processes []ProcessDescriptorSummary `json:"processes"`
	Truncated bool                       `json:"truncated"`
}

type ProcessData struct {
	evidenceMarker
	PID             int     `json:"pid"`
	Name            string  `json:"name"`
	State           string  `json:"state,omitempty"`
	CPUPercent      float64 `json:"cpu_percent"`
	RSSBytes        uint64  `json:"rss_bytes"`
	Threads         int     `json:"threads"`
	Elapsed         string  `json:"elapsed,omitempty"`
	CPUThreshold    float64 `json:"cpu_threshold"`
	MemoryThreshold uint64  `json:"memory_threshold_bytes"`
}

type PermissionObservation struct {
	Category string `json:"category"`
	Decision string `json:"decision"`
	Count    int    `json:"count"`
}

type PermissionsData struct {
	evidenceMarker
	BundleID string                  `json:"bundle_id"`
	Declared []string                `json:"declared,omitempty"`
	Denials  []PermissionObservation `json:"denials,omitempty"`
}

type ScannedApp struct {
	Path               string   `json:"path"`
	Name               string   `json:"name"`
	BundleID           string   `json:"bundle_id,omitempty"`
	Version            string   `json:"version,omitempty"`
	Architectures      []string `json:"architectures,omitempty"`
	ExecutablePresent  bool     `json:"executable_present"`
	ExecutableRunnable bool     `json:"executable_runnable"`
	SignatureValid     *bool    `json:"signature_valid,omitempty"`
	OSSupported        *bool    `json:"os_supported,omitempty"`
	Issues             []string `json:"issues"`
}

type ScanData struct {
	evidenceMarker
	Roots     []string     `json:"roots"`
	Apps      []ScannedApp `json:"apps"`
	Truncated bool         `json:"truncated"`
}

type Evidence struct {
	ID      EvidenceID      `json:"id"`
	Status  Status          `json:"status"`
	Summary string          `json:"summary"`
	Data    EvidencePayload `json:"data,omitempty"`
	Error   string          `json:"error,omitempty"`
}

type Finding struct {
	Code           string       `json:"code"`
	Severity       Severity     `json:"severity"`
	Title          string       `json:"title"`
	Explanation    string       `json:"explanation"`
	Confidence     Confidence   `json:"confidence"`
	EvidenceIDs    []EvidenceID `json:"evidence_ids,omitempty"`
	Recommendation string       `json:"recommendation,omitempty"`
}

type Action struct {
	ID           ActionID `json:"id"`
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
