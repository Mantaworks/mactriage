package diagnosis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Mantaworks/mactriage/internal/action"
	"github.com/Mantaworks/mactriage/internal/knowledge"
	"github.com/Mantaworks/mactriage/internal/report"
)

func Analyze(r report.Report) report.Report {
	byID := make(map[report.EvidenceID]report.Evidence, len(r.Evidence))
	for _, evidence := range r.Evidence {
		byID[evidence.ID] = evidence
		if evidence.Status == report.StatusUnavailable || evidence.Status == report.StatusTimedOut || evidence.Status == report.StatusPartial {
			r.Completeness = report.Partial
		}
	}
	resolution, _ := byID[report.EvidenceBundle].Data.(report.ResolutionData)
	if resolveCode := resolution.ResolveCode; resolveCode != "" {
		title := "Application was not found"
		explanation := "No matching macOS application bundle could be resolved."
		if resolveCode == knowledge.CodeBundleInvalid {
			title = "The application bundle is invalid"
			explanation = "The path exists but does not contain readable application bundle metadata."
		}
		addFinding(&r, resolveCode, report.Error, title, explanation, "high", []report.EvidenceID{"bundle"}, "Check the path or reinstall the application from its publisher.")
	}
	if restart := byID[report.EvidenceRestart]; restart.ID != "" && restart.Status == report.StatusFailed {
		addFinding(&r, knowledge.CodeRepairFailed, report.Error, "syspolicyd restart failed", restart.Error, "high", []report.EvidenceID{"restart"}, "Review the error and confirm administrator access before retrying.")
	}
	process, hasProcess := byID[report.EvidenceProcess].Data.(report.ProcessData)
	if hasProcess {
		state := strings.ToUpper(process.State)
		if strings.ContainsAny(state, "DUT") {
			addFinding(&r, knowledge.CodeHangSuspected, report.Error, "The application may be unresponsive", fmt.Sprintf("Process %d is in state %s, which can indicate an uninterruptible, stopped, or suspended process.", process.PID, process.State), "medium", []report.EvidenceID{report.EvidenceProcess}, "Capture a process sample and share it with the application developer.")
		}
		if process.CPUThreshold > 0 && process.CPUPercent >= process.CPUThreshold {
			addFinding(&r, knowledge.CodeResourceCPUHigh, report.Warning, "The application is using high CPU", fmt.Sprintf("Process %d is using %.1f%% CPU, above the %.1f%% threshold.", process.PID, process.CPUPercent, process.CPUThreshold), "medium", []report.EvidenceID{report.EvidenceProcess}, "Observe the process for longer and capture a sample if usage remains high.")
		}
		if process.MemoryThreshold > 0 && process.RSSBytes >= process.MemoryThreshold {
			addFinding(&r, knowledge.CodeResourceMemoryHigh, report.Warning, "The application is using high memory", fmt.Sprintf("Process %d is using %d bytes of resident memory.", process.PID, process.RSSBytes), "medium", []report.EvidenceID{report.EvidenceProcess}, "Check system memory pressure and reproduce the workload before reporting it.")
		}
	}
	permissions, hasPermissions := byID[report.EvidencePermissions].Data.(report.PermissionsData)
	if hasPermissions && len(permissions.Denials) > 0 {
		categories := make([]string, 0, len(permissions.Denials))
		for _, denial := range permissions.Denials {
			categories = append(categories, denial.Category)
		}
		addFinding(&r, knowledge.CodePermissionDenied, report.Error, "macOS denied an application permission", "Correlated privacy logs recorded explicit denials for: "+strings.Join(categories, ", ")+".", "high", []report.EvidenceID{report.EvidencePermissions}, "Review only the expected categories in Privacy & Security.")
		addAction(&r, action.OpenSecurity)
	}
	scan, hasScan := byID[report.EvidenceScan].Data.(report.ScanData)
	if hasScan {
		affected := map[string][]string{}
		for _, app := range scan.Apps {
			if !app.BundleReadable {
				affected["malformed_bundle"] = append(affected["malformed_bundle"], app.Name)
				continue
			}
			if !app.ExecutablePresent || !app.ExecutableRunnable {
				affected["executable_problem"] = append(affected["executable_problem"], app.Name)
			}
			if app.SignatureStatus == report.StatusOK && app.SignatureValid != nil && !*app.SignatureValid {
				affected["signature_invalid"] = append(affected["signature_invalid"], app.Name)
			}
			if app.OSSupported != nil && !*app.OSSupported {
				affected["os_unsupported"] = append(affected["os_unsupported"], app.Name)
			}
			hasARM := contains(app.Architectures, "arm64") || contains(app.Architectures, "arm64e")
			if r.Host.Arch == "arm64" && contains(app.Architectures, "x86_64") && !hasARM {
				affected["intel_only"] = append(affected["intel_only"], app.Name)
			}
		}
		if names := affected["malformed_bundle"]; len(names) > 0 {
			addFinding(&r, knowledge.CodeScanMalformedBundle, report.Error, "Some application bundles are malformed", scanExplanation(names, "could not be parsed as complete bundles"), "high", []report.EvidenceID{report.EvidenceScan}, "Reinstall the affected applications from their publishers.")
		}
		if names := affected["executable_problem"]; len(names) > 0 {
			addFinding(&r, knowledge.CodeScanExecutableProblem, report.Error, "Some applications have executable problems", scanExplanation(names, "have a missing or non-runnable executable"), "high", []report.EvidenceID{report.EvidenceScan}, "Reinstall the affected applications rather than modifying their bundles manually.")
		}
		if names := affected["signature_invalid"]; len(names) > 0 {
			addFinding(&r, knowledge.CodeScanSignatureInvalid, report.Error, "Some application signatures are invalid", scanExplanation(names, "failed strict signature verification"), "high", []report.EvidenceID{report.EvidenceScan}, "Replace affected applications with trusted publisher-provided copies.")
		}
		if names := affected["os_unsupported"]; len(names) > 0 {
			addFinding(&r, knowledge.CodeScanOSUnsupported, report.Error, "Some applications require a newer macOS", scanExplanation(names, "declare a newer minimum macOS version"), "high", []report.EvidenceID{report.EvidenceScan}, "Update macOS or install compatible application versions.")
		}
		if names := affected["intel_only"]; len(names) > 0 {
			addFindingWithSubjects(&r, knowledge.CodeScanIntelOnly, report.Warning, "Some applications are Intel-only", scanExplanation(names, "require Rosetta on this Apple silicon Mac"), "high", []report.EvidenceID{report.EvidenceScan}, "Check publishers for Apple silicon-native updates.", names)
		}
	}
	storage, hasStorage := byID[report.EvidenceStorage].Data.(report.StorageData)
	if hasStorage && storage.AvailablePercent < 15 {
		severity := report.Warning
		if storage.AvailablePercent <= 5 {
			severity = report.Error
		}
		addFinding(&r, knowledge.CodeDoctorStorageLow, severity, "Startup disk space is low", fmt.Sprintf("Only %.1f%% of the startup disk is available.", storage.AvailablePercent), report.ConfidenceHigh, []report.EvidenceID{report.EvidenceStorage}, "Free space by moving or removing files you recognize, then rerun doctor.")
		addAction(&r, action.OpenStorage)
	}
	memory, hasMemory := byID[report.EvidenceMemory].Data.(report.MemoryData)
	if hasMemory && ((memory.FreePercent > 0 && memory.FreePercent <= 10) || (memory.FreePercent == 0 && memory.SwapUsedBytes >= 4<<30)) {
		addFinding(&r, knowledge.CodeDoctorMemoryPressure, report.Warning, "Memory pressure is elevated", fmt.Sprintf("Readily available memory is %.1f%% and swap usage is %d MiB.", memory.FreePercent, memory.SwapUsedBytes>>20), report.ConfidenceMedium, []report.EvidenceID{report.EvidenceMemory}, "Close memory-heavy applications and check whether pressure falls.")
		addAction(&r, action.OpenActivityMonitor)
	}
	cpu, hasCPU := byID[report.EvidenceCPU].Data.(report.CPUData)
	if hasCPU && ((cpu.LogicalCores > 0 && cpu.LoadOne >= float64(cpu.LogicalCores)*1.5) || cpu.HighestPercent >= 90) {
		explanation := fmt.Sprintf("The one-minute load is %.2f across %d logical cores.", cpu.LoadOne, cpu.LogicalCores)
		if cpu.HighestProcess != "" {
			explanation += fmt.Sprintf(" %s is currently using %.1f%% CPU.", cpu.HighestProcess, cpu.HighestPercent)
		}
		addFinding(&r, knowledge.CodeDoctorCPUPressure, report.Warning, "CPU pressure is elevated", explanation, report.ConfidenceMedium, []report.EvidenceID{report.EvidenceCPU}, "Observe the busiest process and capture a sample if usage persists.")
		addAction(&r, action.OpenActivityMonitor)
	}
	stalledProcesses := 0
	for state, count := range cpu.ProcessStates {
		if strings.ContainsAny(state, "DUT") {
			stalledProcesses += count
		}
	}
	if hasCPU && stalledProcesses > 0 {
		addFinding(&r, knowledge.CodeDoctorProcessStalled, report.Warning, "A process may be stalled or suspended", fmt.Sprintf("%d processes were stopped, suspended, or waiting uninterruptibly.", stalledProcesses), report.ConfidenceMedium, []report.EvidenceID{report.EvidenceCPU}, "Use mactriage hang on the affected process before relaunching it.")
	}
	doctorLimits, hasDoctorLimits := byID[report.EvidenceLimits].Data.(report.LimitsData)
	if r.Command == "doctor" && hasDoctorLimits && doctorLimits.GlobalMax > 0 && float64(doctorLimits.GlobalUsed) >= float64(doctorLimits.GlobalMax)*0.8 {
		addFinding(&r, knowledge.CodeDoctorDescriptorPressure, report.Warning, "System descriptor pressure is high", fmt.Sprintf("The global file table is using %d of %d entries.", doctorLimits.GlobalUsed, doctorLimits.GlobalMax), report.ConfidenceHigh, []report.EvidenceID{report.EvidenceLimits}, "Use mactriage system --top to identify aggregate descriptor consumers.")
	}
	services, hasServices := byID[report.EvidenceServices].Data.(report.ServicesData)
	if hasServices {
		var missing []string
		for name, running := range services.Running {
			if services.Statuses[name] == report.StatusOK && !running {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			addFinding(&r, knowledge.CodeDoctorServiceMissing, report.Error, "A core macOS service is unavailable", "Not running when checked: "+strings.Join(missing, ", ")+".", report.ConfidenceHigh, []report.EvidenceID{report.EvidenceServices}, "Retry doctor; restart only a service mactriage explicitly confirms is wedged.")
		}
	}
	updates, hasUpdates := byID[report.EvidenceUpdates].Data.(report.UpdatesData)
	if hasUpdates && updates.Available {
		confidence := report.ConfidenceHigh
		explanation := "macOS reported one or more available updates."
		if updates.Cached {
			confidence = report.ConfidenceMedium
			explanation = "The cached Software Update state contains one or more available updates."
		}
		addFinding(&r, knowledge.CodeDoctorUpdatesAvailable, report.Info, "Software updates are available", explanation, confidence, []report.EvidenceID{report.EvidenceUpdates}, "Open Software Update to refresh and review the offered updates.")
		addAction(&r, action.OpenSoftwareUpdate)
	}
	crashes, hasCrashes := byID[report.EvidenceRecentCrashes].Data.(report.RecentCrashesData)
	if hasCrashes && crashes.Count >= 10 {
		addFinding(&r, knowledge.CodeDoctorCrashVolume, report.Warning, "Many recent crashes were found", fmt.Sprintf("macOS created %d crash reports during the last day.", crashes.Count), report.ConfidenceMedium, []report.EvidenceID{report.EvidenceRecentCrashes}, "Identify repeated application names and diagnose the affected app.")
	}
	startup, hasStartup := byID[report.EvidenceStartupItems].Data.(report.StartupItemsData)
	if hasStartup && startup.Count >= 100 {
		label := "startup items"
		if startup.Source == "background-task-management" {
			label = "registered login and background items"
		}
		addFinding(&r, knowledge.CodeDoctorStartupItemsHigh, report.Warning, "Many startup items are installed", fmt.Sprintf("Found %d %s.", startup.Count, label), report.ConfidenceMedium, []report.EvidenceID{report.EvidenceStartupItems}, "Review Login Items in System Settings; mactriage will not remove them.")
		addAction(&r, action.OpenLoginItems)
	}
	restarts, hasRestarts := byID[report.EvidenceRestartLoops].Data.(report.RestartLoopsData)
	if hasRestarts && len(restarts.Processes) > 0 {
		labels := make([]string, 0, len(restarts.Processes))
		for _, process := range restarts.Processes {
			if process.Count >= 3 {
				labels = append(labels, fmt.Sprintf("%s (%d)", process.Name, process.Count))
			}
		}
		if len(labels) > 0 {
			addFinding(&r, knowledge.CodeDoctorRestartLoop, report.Warning, "A process is repeatedly restarting", "Repeated exits in the last ten minutes: "+strings.Join(labels, ", ")+".", report.ConfidenceHigh, []report.EvidenceID{report.EvidenceRestartLoops}, "Diagnose or update the named process; do not repeatedly force-restart its parent service.")
		}
	}
	network, hasNetwork := byID[report.EvidenceNetwork].Data.(report.NetworkData)
	if hasNetwork {
		if network.SelfAssigned {
			addFinding(&r, knowledge.CodeNetworkSelfAssigned, report.Error, "The active interface has a self-assigned address", "macOS reported a 169.254 address instead of an address supplied by the network.", report.ConfidenceHigh, []report.EvidenceID{report.EvidenceNetwork}, "Reconnect to Wi-Fi or Ethernet and review the router's DHCP service.")
			addAction(&r, action.OpenNetwork)
		}
		if network.RouteStatus == report.StatusOK && !network.DefaultRoute {
			recommendation := "Reconnect Wi-Fi or Ethernet and review VPN configuration."
			if network.WiFiStatus == report.StatusOK && !network.WiFiPowered {
				recommendation = "Turn on Wi-Fi in Network settings, or connect Ethernet."
			}
			if network.WiFiStatus == report.StatusOK && network.WiFiPowered && !network.WiFiAssociated {
				recommendation = "Join the expected Wi-Fi network or connect Ethernet."
			}
			addFinding(&r, knowledge.CodeNetworkNoRoute, report.Error, "No default network route was found", "The Mac did not report a default route for internet traffic.", report.ConfidenceHigh, []report.EvidenceID{report.EvidenceNetwork}, recommendation)
			addAction(&r, action.OpenNetwork)
		}
		if network.DNSStatus == report.StatusOK && !network.DNSResolved {
			explanation := fmt.Sprintf("%s did not resolve through the current DNS configuration.", network.Host)
			if network.DNSConfigStatus == report.StatusOK && network.DNSServerCount == 0 {
				explanation += " No DNS servers were present in the active resolver configuration."
			}
			addFinding(&r, knowledge.CodeNetworkDNSFailed, report.Error, "DNS lookup failed", explanation, report.ConfidenceHigh, []report.EvidenceID{report.EvidenceNetwork}, "Check the hostname, VPN, DNS service, and network connection.")
			addAction(&r, action.OpenNetwork)
		}
		if network.HTTPSStatus == report.StatusOK && network.HTTPSReachable && !network.TLSValid {
			recommendation := "Check the date, proxy or VPN interception, and the site's certificate; do not bypass validation."
			if network.ClockYear > 0 && network.ClockYear < 2024 {
				recommendation = "Correct the Mac's date and time in System Settings, then retry; do not bypass certificate validation."
			}
			addFinding(&r, knowledge.CodeNetworkTLSInvalid, report.Error, "TLS certificate validation failed", "The host was reachable, but its certificate could not be validated.", report.ConfidenceHigh, []report.EvidenceID{report.EvidenceNetwork}, recommendation)
			addAction(&r, action.OpenNetwork)
		} else if network.HTTPSStatus == report.StatusOK && !network.HTTPSReachable && !(network.HTTPStatus == report.StatusOK && network.HTTPReachable) {
			addFinding(&r, knowledge.CodeNetworkHTTPSFailed, report.Error, "HTTPS connection failed", fmt.Sprintf("Could not establish an HTTPS connection to %s.", network.Host), report.ConfidenceHigh, []report.EvidenceID{report.EvidenceNetwork}, "Check connectivity, proxy, VPN, and firewall policy.")
			addAction(&r, action.OpenNetwork)
		}
		if network.HTTPStatus == report.StatusOK && network.HTTPReachable && !network.HTTPSReachable {
			addFinding(&r, knowledge.CodeNetworkCaptivePortal, report.Warning, "A network sign-in page may be blocking HTTPS", "Plain HTTP was reachable while the HTTPS check failed.", report.ConfidenceMedium, []report.EvidenceID{report.EvidenceNetwork}, "Open a browser and complete the network sign-in if this is a guest or public network.")
			addAction(&r, action.OpenNetwork)
		}
		if network.ProxyStatus == report.StatusOK && network.ProxyConfigured {
			addFinding(&r, knowledge.CodeNetworkProxyDetected, report.Info, "A network proxy is configured", "A system HTTP, HTTPS, or SOCKS proxy is enabled.", report.ConfidenceHigh, []report.EvidenceID{report.EvidenceNetwork}, "Confirm the proxy is expected and available.")
		}
		if network.VPNStatus == report.StatusOK && len(network.VPNInterfaces) > 0 {
			addFinding(&r, knowledge.CodeNetworkVPNDetected, report.Info, "A VPN interface is active", fmt.Sprintf("Active tunnel interfaces: %s.", strings.Join(network.VPNInterfaces, ", ")), report.ConfidenceHigh, []report.EvidenceID{report.EvidenceNetwork}, "Compare with the VPN disconnected only if your policy permits it.")
		}
		if network.ListenersStatus == report.StatusOK && network.ListeningSocketCount >= 1000 {
			addFinding(&r, knowledge.CodeNetworkListenersHigh, report.Warning, "Many listening sockets are open", fmt.Sprintf("Counted %d listening TCP descriptors.", network.ListeningSocketCount), report.ConfidenceMedium, []report.EvidenceID{report.EvidenceNetwork}, "Use system monitoring to identify the largest socket owners.")
		}
	}
	battery, hasBattery := byID[report.EvidenceBattery].Data.(report.BatteryData)
	if hasBattery && battery.Present && ((battery.HealthPercent > 0 && battery.HealthPercent < 80) || (battery.Condition != "" && !strings.EqualFold(battery.Condition, "good") && !strings.EqualFold(battery.Condition, "normal"))) {
		addFinding(&r, knowledge.CodeDoctorBatteryHealth, report.Warning, "Battery health may need attention", fmt.Sprintf("Estimated capacity is %.1f%% and the reported condition is %q.", battery.HealthPercent, battery.Condition), report.ConfidenceHigh, []report.EvidenceID{report.EvidenceBattery}, "Review Battery settings and Apple service guidance.")
		addAction(&r, action.OpenBattery)
	}
	thermal, hasThermal := byID[report.EvidenceThermal].Data.(report.ThermalData)
	if hasThermal && (thermal.WarningRecorded || (thermal.CPUSpeedLimit > 0 && thermal.CPUSpeedLimit < 100) || (thermal.SchedulerLimit > 0 && thermal.SchedulerLimit < 100)) {
		addFinding(&r, knowledge.CodeDoctorThermalPressure, report.Warning, "Thermal limits are active", "macOS reported a thermal warning or reduced CPU scheduling limits.", report.ConfidenceMedium, []report.EvidenceID{report.EvidenceThermal}, "Improve airflow and recheck after the Mac cools.")
		addAction(&r, action.OpenActivityMonitor)
	}
	backup, hasBackup := byID[report.EvidenceBackup].Data.(report.BackupData)
	if hasBackup && backup.Configured && (!backup.HasBackup || backup.LatestAgeHours > 168) {
		addFinding(&r, knowledge.CodeDoctorBackupStale, report.Warning, "Time Machine has no recent backup", fmt.Sprintf("The latest observed backup is %.1f hours old.", backup.LatestAgeHours), report.ConfidenceHigh, []report.EvidenceID{report.EvidenceBackup}, "Open Time Machine settings and review the latest backup attempt.")
		addAction(&r, action.OpenTimeMachine)
	}
	if relaunch := byID[report.EvidenceRelaunch]; relaunch.ID != "" && relaunch.Status == report.StatusFailed {
		addFinding(&r, knowledge.CodeRelaunchFailed, report.Error, "Application relaunch failed", relaunch.Error, report.ConfidenceHigh, []report.EvidenceID{report.EvidenceRelaunch}, "Review the reported step and diagnose the app before trying again.")
	}

	logs, _ := byID[report.EvidenceLogs].Data.(report.LogsData)
	descriptors, _ := byID[report.EvidenceDescriptors].Data.(report.DescriptorData)
	limits, _ := byID[report.EvidenceLimits].Data.(report.LimitsData)
	processPressure := nearProcessLimit(descriptors)
	globalPressure := nearGlobalLimit(byID[report.EvidenceLimits].Status, limits)
	if logs.SyspolicydEMFILE > 0 && processPressure {
		addFinding(&r, knowledge.CodePolicyEMFILE, report.Critical, "A process exhausted its file descriptors", "macOS reported EMFILE (error 24), which is a per-process descriptor-table failure.", "high", []report.EvidenceID{"logs", "limits", "launch"}, "Restart the affected daemon after reviewing the action.")
		if confirmedSyspolicydWedge(logs, descriptors) {
			addAction(&r, action.RepairSyspolicyd)
		}
	} else if logs.EMFILE > 0 {
		addFinding(&r, knowledge.CodeResourceEMFILEReported, report.Warning, "A per-process descriptor error was reported", "macOS reported EMFILE, but the affected process was not measured near its file-descriptor limit.", "medium", []report.EvidenceID{"logs", "descriptors"}, "Collect a privileged descriptor sample while the failure is active before restarting a service.")
	}
	if logs.ENFILE > 0 && globalPressure {
		addFinding(&r, knowledge.CodeSystemENFILE, report.Critical, "The system file table is exhausted", "macOS reported ENFILE, indicating system-wide descriptor exhaustion.", "high", []report.EvidenceID{"logs", "limits"}, "Identify the largest descriptor consumers before restarting services.")
	} else if logs.ENFILE > 0 {
		addFinding(&r, knowledge.CodeResourceENFILEReported, report.Warning, "A system descriptor-table error was reported", "macOS reported ENFILE, but current global measurements did not show the file table near its limit.", "medium", []report.EvidenceID{"logs", "limits"}, "Continue monitoring global descriptor pressure to corroborate the event.")
	}
	if logs.XProtect > 0 {
		addFinding(&r, knowledge.CodeXProtectBlocked, report.Critical, "XProtect blocked the application", "Correlated system logs contain an explicit XProtect block.", "high", []string{"logs"}, "Do not bypass the block; obtain a trusted build from the publisher.")
	}
	if logs.LaunchServices > 0 {
		addFinding(&r, knowledge.CodeLaunchServicesFailure, report.Error, "Launch Services reported a failure", "The application could not be opened through Launch Services.", "medium", []string{"logs", "launch"}, "Review the bundle and executable evidence before retrying.")
	}
	if logs.MissingLibrary > 0 {
		addFinding(&r, knowledge.CodeDependencyMissing, report.Error, "A required library could not be loaded", "The dynamic loader reported a missing dependency.", "high", []string{"logs", "dependencies"}, "Reinstall or update the application from its publisher.")
	}
	if logs.SignatureErrors > 0 {
		addFinding(&r, knowledge.CodeSignatureRuntimeInvalid, report.Error, "macOS reported a runtime signature failure", "Correlated launch logs contain an explicit invalid-signature event.", "high", []string{"logs", "signature"}, "Replace the application with a trusted copy from its publisher.")
	}
	if logs.NotarizationErrors > 0 {
		addFinding(&r, knowledge.CodeNotarizationFailed, report.Error, "The notarization check failed", "Correlated system logs contain a notarization failure or rejection.", "high", []string{"logs", "gatekeeper"}, "Obtain a current notarized build from the publisher.")
	}

	bundle, hasBundle := byID[report.EvidenceBundle].Data.(report.BundleData)
	if hasBundle {
		if !bundle.ExecutablePresent {
			addFinding(&r, knowledge.CodeBundleExecutableMissing, report.Error, "The bundle executable is missing", "The application metadata does not resolve to an executable file inside the bundle.", "high", []string{"bundle"}, "Reinstall the application from its publisher.")
		} else if !bundle.ExecutableRunnable {
			addFinding(&r, knowledge.CodeBundleExecutableNotRunnable, report.Error, "The bundle executable is not runnable", "The main executable does not have an executable permission bit.", "high", []string{"bundle"}, "Reinstall the application instead of changing bundle permissions manually.")
		}
	}
	if hasBundle && bundle.OSSupported != nil && !*bundle.OSSupported {
		addFinding(&r, knowledge.CodeOSUnsupported, report.Error, "This macOS version is not supported by the application", "The bundle's minimum system version is newer than the current macOS version.", "high", []string{"bundle"}, "Update macOS or install a compatible application version.")
	}

	quarantine, _ := byID[report.EvidenceQuarantine].Data.(report.QuarantineData)
	if quarantine.Present {
		addFinding(&r, knowledge.CodeQuarantinePresent, report.Info, "The application has quarantine metadata", "macOS may perform first-launch Gatekeeper checks for this downloaded application.", "high", []string{"quarantine", "gatekeeper"}, "Review the Gatekeeper result; mactriage will not remove quarantine metadata.")
	}

	crash, _ := byID[report.EvidenceCrash].Data.(report.CrashData)
	if crash.Count > 0 {
		addFinding(&r, knowledge.CodeCrashDetected, report.Error, "A correlated crash report was created", "macOS wrote a crash report for this application during the observation window.", "high", []string{"crash", "launch"}, "Use the structured termination evidence and update or reinstall the application.")
	}

	signature, hasSignature := byID[report.EvidenceSignature].Data.(report.SignatureData)
	if hasSignature && !signature.Valid {
		code := knowledge.CodeSignatureInvalid
		if strings.EqualFold(signature.Reason, "unsigned") {
			code = knowledge.CodeSignatureUnsigned
		}
		addFinding(&r, code, report.Error, "The application signature is not valid", "Strict recursive code-signature verification failed.", "high", []string{"signature"}, "Replace the application with a trusted copy; mactriage will not rewrite signatures.")
	}

	gatekeeper, assessed := byID[report.EvidenceGatekeeper].Data.(report.GatekeeperData)
	if assessed && !gatekeeper.Accepted {
		addFinding(&r, knowledge.CodeGatekeeperRejected, report.Error, "Gatekeeper rejected the application", "The system policy assessment did not accept this bundle.", "high", []string{"gatekeeper", "signature"}, "Review the publisher and system security decision before proceeding.")
		if signature.Valid {
			addAction(&r, action.OpenSecurity)
		}
	}

	arch, _ := byID[report.EvidenceArchitecture].Data.(report.ArchitectureData)
	architectures := arch.Architectures
	hasARM := contains(architectures, "arm64") || contains(architectures, "arm64e")
	hasX86 := contains(architectures, "x86_64")
	if r.Host.Arch == "arm64" && hasX86 && !hasARM {
		addFinding(&r, knowledge.CodeArchitectureRosetta, report.Warning, "This application requires Rosetta", "The main executable contains Intel code but no native Apple silicon slice.", "high", []string{"architecture"}, "Launch it to let macOS offer the supported Rosetta installation flow.")
		addAction(&r, action.LaunchRosetta)
	}
	if len(architectures) > 0 && ((r.Host.Arch == "arm64" && !hasARM && !hasX86) || (r.Host.Arch == "amd64" && !hasX86)) {
		addFinding(&r, knowledge.CodeArchitectureIncompatible, report.Error, "The executable architecture is incompatible", "The app has no executable slice supported by this Mac.", "high", []string{"architecture"}, "Install a build intended for this Mac architecture.")
	}

	dependencies, _ := byID[report.EvidenceDependencies].Data.(report.DependencyData)
	if dependencies.MissingCount > 0 {
		addFinding(&r, knowledge.CodeDependencyMissing, report.Error, "The application has missing non-system dependencies", fmt.Sprintf("%d required library paths could not be resolved.", dependencies.MissingCount), "high", []string{"dependencies"}, "Reinstall or update the application from its publisher.")
	}

	launchEvidence := byID[report.EvidenceLaunch]
	launch, hasLaunch := launchEvidence.Data.(report.LaunchData)
	if launch.AlreadyRunning {
		addFinding(&r, knowledge.CodeLaunchSkippedRunning, report.Info, "Active launch test skipped", "The application was already running, so mactriage did not create a duplicate instance.", "high", []string{"launch"}, "Use --new-instance only if a duplicate launch is safe.")
	} else if launch.Spawned != nil && !*launch.Spawned {
		addFinding(&r, knowledge.CodeLaunchFailedToSpawn, report.Error, "Launch Services could not start the application", "The open command failed before a new application process was observed.", "high", []string{"launch", "logs"}, "Review the correlated evidence before retrying.")
		addRetryAction(&r)
	} else if launch.Terminated {
		explanation := "A new application process appeared and exited during the observation window; the exit signal is unknown unless separately reported by macOS."
		if launch.ExitSignal != "" && launch.ExitSignal != "unknown" {
			explanation = fmt.Sprintf("A new application process appeared and exited during the observation window; a correlated crash report supplied signal %s.", launch.ExitSignal)
		}
		addFinding(&r, knowledge.CodeLaunchTerminated, report.Error, "The application terminated immediately", explanation, "high", []string{"launch", "logs", "crash"}, "Address the highest-confidence correlated finding and retry.")
		addRetryAction(&r)
	} else if launch.Survived {
		addFinding(&r, knowledge.CodeLaunchSurvived, report.Info, "The application survived the launch check", "The application process remained present for the observation window.", "high", []string{"launch"}, "")
	} else if hasLaunch && launchEvidence.Status != report.StatusSkipped {
		addFinding(&r, knowledge.CodeLaunchInconclusive, report.Warning, "Launch result was inconclusive", "No stable matching application process could be correlated with the launch request.", "low", []string{"launch", "logs"}, "Retry with a longer --observe duration.")
		addRetryAction(&r)
	}

	sort.SliceStable(r.Actions, func(i, j int) bool {
		priority := func(id report.ActionID) int {
			switch id {
			case action.RepairSyspolicyd:
				return 0
			case action.OpenSoftwareUpdate:
				return 1
			default:
				return 2
			}
		}
		return priority(r.Actions[i].ID) < priority(r.Actions[j].ID)
	})
	return r
}

func addRetryAction(r *report.Report) {
	addAction(r, action.RetryLaunch)
}

func addAction(r *report.Report, id report.ActionID) {
	for _, existing := range r.Actions {
		if existing.ID == id {
			return
		}
	}
	if definition, ok := action.Definition(id, r.Target); ok {
		r.Actions = append(r.Actions, definition)
	}
}

func confirmedSyspolicydWedge(logs report.LogsData, descriptors report.DescriptorData) bool {
	return logs.SyspolicydWedgeSequence > 0 && descriptors.Process == "syspolicyd" && nearProcessLimit(descriptors)
}

func nearProcessLimit(descriptors report.DescriptorData) bool {
	return descriptors.Count > 0 && descriptors.ProcessSoft > 0 && float64(descriptors.Count) >= float64(descriptors.ProcessSoft)*0.8
}

func nearGlobalLimit(status report.Status, limits report.LimitsData) bool {
	return status == report.StatusOK && limits.GlobalUsed > 0 && limits.GlobalMax > 0 && float64(limits.GlobalUsed) >= float64(limits.GlobalMax)*0.9
}

func addFinding[T ~string](r *report.Report, code string, severity report.Severity, title, explanation string, confidence report.Confidence, evidence []T, recommendation string) {
	addFindingWithSubjects(r, code, severity, title, explanation, confidence, evidence, recommendation, nil)
}

func addFindingWithSubjects[T ~string](r *report.Report, code string, severity report.Severity, title, explanation string, confidence report.Confidence, evidence []T, recommendation string, subjects []string) {
	for _, existing := range r.Findings {
		if existing.Code == code {
			return
		}
	}
	evidenceIDs := make([]report.EvidenceID, 0, len(evidence))
	for _, id := range evidence {
		evidenceIDs = append(evidenceIDs, report.EvidenceID(id))
	}
	r.Findings = append(r.Findings, report.Finding{Code: code, Severity: severity, Title: title, Explanation: explanation, Confidence: confidence, EvidenceIDs: evidenceIDs, Subjects: append([]string(nil), subjects...), Recommendation: recommendation})
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func scanExplanation(names []string, condition string) string {
	displayed := names
	if len(displayed) > 5 {
		displayed = displayed[:5]
	}
	label := "applications"
	if len(names) == 1 {
		label = "application"
	}
	extra := ""
	if len(names) > len(displayed) {
		extra = fmt.Sprintf(" and %d more", len(names)-len(displayed))
	}
	return fmt.Sprintf("%d scanned %s (%s%s) %s.", len(names), label, strings.Join(displayed, ", "), extra, condition)
}
