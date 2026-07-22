package report

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

const SchemaVersion = "1"

type Completeness string

const (
	Complete Completeness = "complete"
	Partial  Completeness = "partial"
)

type Status string

type EvidenceID string

const (
	EvidenceBundle        EvidenceID = "bundle"
	EvidenceSignature     EvidenceID = "signature"
	EvidenceGatekeeper    EvidenceID = "gatekeeper"
	EvidenceQuarantine    EvidenceID = "quarantine"
	EvidenceArchitecture  EvidenceID = "architecture"
	EvidenceDependencies  EvidenceID = "dependencies"
	EvidenceLimits        EvidenceID = "limits"
	EvidenceLaunch        EvidenceID = "launch"
	EvidenceLogs          EvidenceID = "logs"
	EvidenceCrash         EvidenceID = "crash"
	EvidenceDescriptors   EvidenceID = "descriptors"
	EvidenceRestart       EvidenceID = "restart"
	EvidenceTopProcesses  EvidenceID = "top_processes"
	EvidenceProcess       EvidenceID = "process"
	EvidencePermissions   EvidenceID = "permissions"
	EvidenceScan          EvidenceID = "scan"
	EvidenceStorage       EvidenceID = "storage"
	EvidenceMemory        EvidenceID = "memory"
	EvidenceCPU           EvidenceID = "cpu"
	EvidenceServices      EvidenceID = "services"
	EvidenceUpdates       EvidenceID = "updates"
	EvidenceRecentCrashes EvidenceID = "recent_crashes"
	EvidenceStartupItems  EvidenceID = "startup_items"
	EvidenceNetwork       EvidenceID = "network"
	EvidenceRestartLoops  EvidenceID = "restart_loops"
	EvidenceRelaunch      EvidenceID = "relaunch"
	EvidenceBattery       EvidenceID = "battery"
	EvidenceThermal       EvidenceID = "thermal"
	EvidenceBackup        EvidenceID = "backup"
	EvidenceStorageDetail EvidenceID = "storage_details"
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
	BundleID           string                  `json:"bundle_id"`
	EntitlementsStatus Status                  `json:"entitlements_status"`
	Declared           []string                `json:"declared,omitempty"`
	Denials            []PermissionObservation `json:"denials,omitempty"`
}

type ScannedApp struct {
	Path               string   `json:"path"`
	Name               string   `json:"name"`
	BundleID           string   `json:"bundle_id,omitempty"`
	Version            string   `json:"version,omitempty"`
	BundleReadable     bool     `json:"bundle_readable"`
	Architectures      []string `json:"architectures,omitempty"`
	ArchitectureStatus Status   `json:"architecture_status"`
	ExecutablePresent  bool     `json:"executable_present"`
	ExecutableRunnable bool     `json:"executable_runnable"`
	SignatureValid     *bool    `json:"signature_valid,omitempty"`
	SignatureStatus    Status   `json:"signature_status"`
	OSSupported        *bool    `json:"os_supported,omitempty"`
}

type ScanData struct {
	evidenceMarker
	Roots     []string     `json:"roots"`
	Apps      []ScannedApp `json:"apps"`
	Truncated bool         `json:"truncated"`
}

type StorageData struct {
	evidenceMarker
	TotalBytes       uint64  `json:"total_bytes"`
	AvailableBytes   uint64  `json:"available_bytes"`
	AvailablePercent float64 `json:"available_percent"`
}

type StorageCategory struct {
	Name  string `json:"name"`
	Bytes uint64 `json:"bytes"`
}

type StorageDetailsData struct {
	evidenceMarker
	Categories []StorageCategory `json:"categories"`
}

type BatteryData struct {
	evidenceMarker
	Present       bool    `json:"present"`
	Percent       int     `json:"percent,omitempty"`
	Charging      bool    `json:"charging"`
	CycleCount    int     `json:"cycle_count,omitempty"`
	HealthPercent float64 `json:"health_percent,omitempty"`
	Condition     string  `json:"condition,omitempty"`
}

type ThermalData struct {
	evidenceMarker
	CPUSpeedLimit   int  `json:"cpu_speed_limit,omitempty"`
	SchedulerLimit  int  `json:"scheduler_limit,omitempty"`
	CPUAvailable    int  `json:"cpu_available,omitempty"`
	WarningRecorded bool `json:"warning_recorded"`
}

type BackupData struct {
	evidenceMarker
	Configured       bool    `json:"configured"`
	HasBackup        bool    `json:"has_backup"`
	LatestAgeHours   float64 `json:"latest_age_hours,omitempty"`
	DestinationCount int     `json:"destination_count,omitempty"`
}

type MemoryData struct {
	evidenceMarker
	TotalBytes    uint64  `json:"total_bytes"`
	FreeBytes     uint64  `json:"free_bytes"`
	FreePercent   float64 `json:"free_percent"`
	SwapUsedBytes uint64  `json:"swap_used_bytes"`
}

type CPUData struct {
	evidenceMarker
	LogicalCores   int            `json:"logical_cores"`
	LoadOne        float64        `json:"load_one"`
	HighestPercent float64        `json:"highest_percent"`
	HighestProcess string         `json:"highest_process,omitempty"`
	ProcessStates  map[string]int `json:"process_states,omitempty"`
}

type ServicesData struct {
	evidenceMarker
	Running  map[string]bool   `json:"running"`
	Statuses map[string]Status `json:"statuses"`
}

type UpdatesData struct {
	evidenceMarker
	Available bool `json:"available"`
	Cached    bool `json:"cached"`
}

type RecentCrashesData struct {
	evidenceMarker
	Count int `json:"count"`
}

type StartupItemsData struct {
	evidenceMarker
	Count  int           `json:"count"`
	Source string        `json:"source"`
	Items  []StartupItem `json:"items,omitempty"`
}

type StartupItem struct {
	Name       string `json:"name,omitempty"`
	Identifier string `json:"identifier,omitempty"`
	TeamID     string `json:"team_id,omitempty"`
}

type NetworkData struct {
	evidenceMarker
	Host                 string   `json:"host,omitempty"`
	DNSStatus            Status   `json:"dns_status"`
	DNSResolved          bool     `json:"dns_resolved"`
	HTTPSStatus          Status   `json:"https_status"`
	HTTPSReachable       bool     `json:"https_reachable"`
	TLSValid             bool     `json:"tls_valid"`
	RouteStatus          Status   `json:"route_status"`
	DefaultRoute         bool     `json:"default_route"`
	ProxyStatus          Status   `json:"proxy_status"`
	ProxyConfigured      bool     `json:"proxy_configured"`
	VPNStatus            Status   `json:"vpn_status"`
	VPNInterfaces        []string `json:"vpn_interfaces,omitempty"`
	ListenersStatus      Status   `json:"listeners_status"`
	ListeningSocketCount int      `json:"listening_socket_count"`
	InterfaceStatus      Status   `json:"interface_status,omitempty"`
	ActiveInterface      bool     `json:"active_interface"`
	SelfAssigned         bool     `json:"self_assigned"`
	WiFiStatus           Status   `json:"wifi_status,omitempty"`
	WiFiPowered          bool     `json:"wifi_powered"`
	WiFiAssociated       bool     `json:"wifi_associated"`
	DNSConfigStatus      Status   `json:"dns_config_status,omitempty"`
	DNSServerCount       int      `json:"dns_server_count"`
	HTTPStatus           Status   `json:"http_status,omitempty"`
	HTTPReachable        bool     `json:"http_reachable"`
	ClockYear            int      `json:"clock_year,omitempty"`
}

type ProcessRestartObservation struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type RestartLoopsData struct {
	evidenceMarker
	Processes []ProcessRestartObservation `json:"processes,omitempty"`
}

type RelaunchData struct {
	evidenceMarker
	ProcessName string `json:"process_name"`
	PIDs        []int  `json:"pids,omitempty"`
	NewPIDs     []int  `json:"new_pids,omitempty"`
	Forced      bool   `json:"forced"`
	Survived    bool   `json:"survived"`
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
	Subjects       []string     `json:"subjects,omitempty"`
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
	CaseID        string       `json:"case_id"`
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
		CaseID:        newCaseID(),
		Command:       command,
		GeneratedAt:   time.Now().UTC(),
		Target:        target,
		Completeness:  Complete,
		Evidence:      []Evidence{},
		Findings:      []Finding{},
		Actions:       []Action{},
	}
}

func newCaseID() string {
	var value [6]byte
	if _, err := rand.Read(value[:]); err == nil {
		return "MT-" + strings.ToUpper(hex.EncodeToString(value[:]))
	}
	return fmt.Sprintf("MT-%X", time.Now().UTC().UnixNano())
}

func (r Report) ExitCode() int {
	return r.ExitCodeAt(Error)
}

func (r Report) ExitCodeAt(threshold Severity) int {
	weights := map[Severity]int{Info: 0, Warning: 1, Error: 2, Critical: 3}
	minimum, ok := weights[threshold]
	if !ok {
		minimum = weights[Error]
	}
	for _, finding := range r.Findings {
		if weights[finding.Severity] >= minimum {
			return 1
		}
	}
	if r.Completeness == Partial {
		return 3
	}
	return 0
}
