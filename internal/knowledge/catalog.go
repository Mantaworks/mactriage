package knowledge

type Entry struct {
	Code    string `json:"code"`
	Title   string `json:"title"`
	Meaning string `json:"meaning"`
	Next    string `json:"next"`
	Safety  string `json:"safety"`
}

const (
	CodeAppNotFound                 = "app.not_found"
	CodeBundleInvalid               = "bundle.invalid"
	CodeBundleExecutableMissing     = "bundle.executable_missing"
	CodeBundleExecutableNotRunnable = "bundle.executable_not_runnable"
	CodeOSUnsupported               = "os.unsupported"
	CodeSignatureInvalid            = "signature.invalid"
	CodeSignatureUnsigned           = "signature.unsigned"
	CodeSignatureRuntimeInvalid     = "signature.runtime_invalid"
	CodeGatekeeperRejected          = "gatekeeper.rejected"
	CodeNotarizationFailed          = "notarization.failed"
	CodeQuarantinePresent           = "quarantine.present"
	CodeXProtectBlocked             = "xprotect.blocked"
	CodeArchitectureRosetta         = "architecture.rosetta_required"
	CodeArchitectureIncompatible    = "architecture.incompatible"
	CodeDependencyMissing           = "dependency.missing"
	CodeCrashDetected               = "crash.detected"
	CodeLaunchServicesFailure       = "launchservices.failure"
	CodeLaunchFailedToSpawn         = "launch.failed_to_spawn"
	CodeLaunchTerminated            = "launch.terminated"
	CodeLaunchInconclusive          = "launch.inconclusive"
	CodeLaunchSurvived              = "launch.survived"
	CodeLaunchSkippedRunning        = "launch.skipped_already_running"
	CodePolicyEMFILE                = "policy.emfile"
	CodeResourceEMFILEReported      = "resource.emfile_reported"
	CodeSystemENFILE                = "system.enfile"
	CodeResourceENFILEReported      = "resource.enfile_reported"
	CodeRepairFailed                = "repair.failed"
	CodeHangSuspected               = "hang.suspected"
	CodeResourceCPUHigh             = "resource.cpu_high"
	CodeResourceMemoryHigh          = "resource.memory_high"
	CodePermissionDenied            = "permission.denied"
	CodeScanMalformedBundle         = "scan.malformed_bundle"
	CodeScanExecutableProblem       = "scan.executable_problem"
	CodeScanSignatureInvalid        = "scan.signature_invalid"
	CodeScanOSUnsupported           = "scan.os_unsupported"
	CodeScanIntelOnly               = "scan.intel_only"
)

var entries = map[string]Entry{
	CodeAppNotFound:                 entry("Application not found", "mactriage could not resolve the supplied name, bundle identifier, or path to an installed application.", "Check the spelling or provide the full .app path."),
	CodeBundleInvalid:               entry("Invalid application bundle", "The selected path is not a readable macOS application bundle.", "Reinstall a complete copy from the publisher."),
	CodeBundleExecutableMissing:     entry("Executable missing", "The bundle metadata points to an executable that is not present.", "Reinstall the application rather than constructing bundle files manually."),
	CodeBundleExecutableNotRunnable: entry("Executable is not runnable", "The application executable lacks an executable permission bit.", "Replace the application with an intact publisher-provided copy."),
	CodeOSUnsupported:               entry("macOS version unsupported", "The application requires a newer macOS release than this Mac is running.", "Update macOS or install a compatible version of the application."),
	CodeSignatureInvalid:            entry("Invalid code signature", "The application's cryptographic seal does not validate, which can indicate damage or modification.", "Replace it with a trusted copy from the publisher."),
	CodeSignatureUnsigned:           entry("Application is unsigned", "The application has no code signature macOS can verify.", "Confirm its origin and obtain a signed build where possible."),
	CodeSignatureRuntimeInvalid:     entry("Runtime signature rejection", "macOS recorded an explicit signature failure while starting the app.", "Install a current trusted build from the publisher."),
	CodeGatekeeperRejected:          entry("Gatekeeper rejected the app", "macOS security policy did not approve this application for execution.", "Verify the publisher and review Privacy & Security for Apple's decision."),
	CodeNotarizationFailed:          entry("Notarization failed", "macOS could not validate the publisher's Apple notarization ticket.", "Obtain a current notarized build from the publisher."),
	CodeQuarantinePresent:           entry("Downloaded-app quarantine present", "The app carries normal download quarantine metadata and may receive first-launch security checks.", "Review the Gatekeeper result; quarantine alone is not a failure."),
	CodeXProtectBlocked:             entry("XProtect blocked the app", "Apple's malware protection recorded an explicit block.", "Do not bypass it; obtain a trusted replacement and investigate the source."),
	CodeArchitectureRosetta:         entry("Rosetta required", "This Apple silicon Mac found an Intel-only application.", "Launch it and use Apple's supported Rosetta installation prompt if offered."),
	CodeArchitectureIncompatible:    entry("Incompatible architecture", "The executable contains no processor slice this Mac can run.", "Install a build for this Mac's architecture."),
	CodeDependencyMissing:           entry("Required library missing", "The app references a non-system dynamic library that cannot be resolved.", "Reinstall or update the complete application package."),
	CodeCrashDetected:               entry("Crash detected", "macOS created a crash report during the launch observation window.", "Use the termination fields when reporting the problem to the publisher."),
	CodeLaunchServicesFailure:       entry("Launch Services failure", "The macOS service responsible for opening apps reported a failure.", "Address higher-confidence bundle or security findings, then retry."),
	CodeLaunchFailedToSpawn:         entry("Application did not start", "Launch Services accepted or attempted the request but no new process started.", "Review the correlated security, dependency, and log findings."),
	CodeLaunchTerminated:            entry("Application stopped immediately", "A new process appeared and exited within the observation window.", "Address the highest-confidence correlated finding and retry."),
	CodeLaunchInconclusive:          entry("Launch result inconclusive", "mactriage could not reliably correlate a stable process with the launch request.", "Retry with a longer observation window."),
	CodeLaunchSurvived:              entry("Launch survived", "The application remained running throughout the observation window.", "If symptoms remain, inspect permissions, hangs, or resource usage."),
	CodeLaunchSkippedRunning:        entry("Launch test skipped", "The application was already running, so mactriage avoided creating a duplicate.", "Quit the app first or explicitly use --new-instance when safe."),
	CodePolicyEMFILE:                entry("Process descriptor exhaustion", "A process reached its own open-file descriptor limit and macOS reported EMFILE.", "Identify descriptor growth and restart only the confirmed affected service."),
	CodeResourceEMFILEReported:      entry("Descriptor error reported", "macOS reported EMFILE but current measurements did not corroborate active pressure.", "Monitor the process while the problem is occurring."),
	CodeSystemENFILE:                entry("System file table exhausted", "The global macOS file table is near capacity and an ENFILE error was reported.", "Find the largest descriptor consumers before restarting services."),
	CodeResourceENFILEReported:      entry("System descriptor error reported", "macOS reported ENFILE without current global measurements confirming exhaustion.", "Continue monitoring system-wide pressure."),
	CodeRepairFailed:                entry("Recovery action failed", "The requested allowlisted recovery action did not complete or could not be verified.", "Confirm administrator access and review the reported error."),
	CodeHangSuspected:               entry("Application may be unresponsive", "The process state or sampled resource behavior indicates it may not be responding normally.", "Capture a process sample and share it with the application developer."),
	CodeResourceCPUHigh:             entry("High CPU usage", "The selected process is using sustained CPU above the configured diagnostic threshold.", "Observe it for longer and capture a sample if the behavior persists."),
	CodeResourceMemoryHigh:          entry("High memory usage", "The selected process has unusually high resident memory usage.", "Check memory pressure and reproduce the workload before reporting it."),
	CodePermissionDenied:            entry("Privacy permission denied", "macOS privacy controls recorded a denial involving this application.", "Review the named category in Privacy & Security and grant access only if expected."),
	CodeScanMalformedBundle:         entry("Malformed installed applications", "One or more scanned paths could not be read as complete macOS application bundles.", "Reinstall the named applications from their publishers."),
	CodeScanExecutableProblem:       entry("Installed application executable problems", "One or more scanned bundles have a missing or non-runnable main executable.", "Reinstall the affected applications rather than modifying their bundles manually."),
	CodeScanSignatureInvalid:        entry("Invalid installed application signatures", "One or more scanned applications failed strict recursive signature verification.", "Replace affected applications with trusted publisher-provided copies."),
	CodeScanOSUnsupported:           entry("Applications require newer macOS", "One or more scanned applications declare a minimum macOS version newer than this Mac.", "Update macOS or install compatible application versions."),
	CodeScanIntelOnly:               entry("Intel-only installed applications", "One or more scanned applications require Rosetta on Apple silicon.", "Check their publishers for native Apple silicon updates."),
}

func entry(title, meaning, next string) Entry {
	return Entry{Title: title, Meaning: meaning, Next: next, Safety: "mactriage reports evidence and uses only allowlisted actions; it does not bypass macOS security controls or rewrite application data."}
}

func Lookup(code string) (Entry, bool) {
	value, ok := entries[code]
	if !ok {
		return Entry{}, false
	}
	value.Code = code
	return value, true
}
