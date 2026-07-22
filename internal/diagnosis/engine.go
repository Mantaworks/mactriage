package diagnosis

import (
	"fmt"
	"strings"

	"github.com/Mantaworks/mactriage/internal/action"
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
		if resolveCode == "bundle.invalid" {
			title = "The application bundle is invalid"
			explanation = "The path exists but does not contain readable application bundle metadata."
		}
		addFinding(&r, resolveCode, report.Error, title, explanation, "high", []report.EvidenceID{"bundle"}, "Check the path or reinstall the application from its publisher.")
	}
	if restart := byID[report.EvidenceRestart]; restart.ID != "" && restart.Status == report.StatusFailed {
		addFinding(&r, "repair.failed", report.Error, "syspolicyd restart failed", restart.Error, "high", []report.EvidenceID{"restart"}, "Review the error and confirm administrator access before retrying.")
	}

	logs, _ := byID[report.EvidenceLogs].Data.(report.LogsData)
	descriptors, _ := byID[report.EvidenceDescriptors].Data.(report.DescriptorData)
	limits, _ := byID[report.EvidenceLimits].Data.(report.LimitsData)
	processPressure := nearProcessLimit(descriptors)
	globalPressure := nearGlobalLimit(byID[report.EvidenceLimits].Status, limits)
	if logs.SyspolicydEMFILE > 0 && processPressure {
		addFinding(&r, "policy.emfile", report.Critical, "A process exhausted its file descriptors", "macOS reported EMFILE (error 24), which is a per-process descriptor-table failure.", "high", []report.EvidenceID{"logs", "limits", "launch"}, "Restart the affected daemon after reviewing the action.")
		if confirmedSyspolicydWedge(logs, descriptors) {
			addAction(&r, action.RepairSyspolicyd)
		}
	} else if logs.EMFILE > 0 {
		addFinding(&r, "resource.emfile_reported", report.Warning, "A per-process descriptor error was reported", "macOS reported EMFILE, but the affected process was not measured near its file-descriptor limit.", "medium", []report.EvidenceID{"logs", "descriptors"}, "Collect a privileged descriptor sample while the failure is active before restarting a service.")
	}
	if logs.ENFILE > 0 && globalPressure {
		addFinding(&r, "system.enfile", report.Critical, "The system file table is exhausted", "macOS reported ENFILE, indicating system-wide descriptor exhaustion.", "high", []report.EvidenceID{"logs", "limits"}, "Identify the largest descriptor consumers before restarting services.")
	} else if logs.ENFILE > 0 {
		addFinding(&r, "resource.enfile_reported", report.Warning, "A system descriptor-table error was reported", "macOS reported ENFILE, but current global measurements did not show the file table near its limit.", "medium", []report.EvidenceID{"logs", "limits"}, "Continue monitoring global descriptor pressure to corroborate the event.")
	}
	if logs.XProtect > 0 {
		addFinding(&r, "xprotect.blocked", report.Critical, "XProtect blocked the application", "Correlated system logs contain an explicit XProtect block.", "high", []string{"logs"}, "Do not bypass the block; obtain a trusted build from the publisher.")
	}
	if logs.LaunchServices > 0 {
		addFinding(&r, "launchservices.failure", report.Error, "Launch Services reported a failure", "The application could not be opened through Launch Services.", "medium", []string{"logs", "launch"}, "Review the bundle and executable evidence before retrying.")
	}
	if logs.MissingLibrary > 0 {
		addFinding(&r, "dependency.missing", report.Error, "A required library could not be loaded", "The dynamic loader reported a missing dependency.", "high", []string{"logs", "dependencies"}, "Reinstall or update the application from its publisher.")
	}
	if logs.SignatureErrors > 0 {
		addFinding(&r, "signature.runtime_invalid", report.Error, "macOS reported a runtime signature failure", "Correlated launch logs contain an explicit invalid-signature event.", "high", []string{"logs", "signature"}, "Replace the application with a trusted copy from its publisher.")
	}
	if logs.NotarizationErrors > 0 {
		addFinding(&r, "notarization.failed", report.Error, "The notarization check failed", "Correlated system logs contain a notarization failure or rejection.", "high", []string{"logs", "gatekeeper"}, "Obtain a current notarized build from the publisher.")
	}

	bundle, hasBundle := byID[report.EvidenceBundle].Data.(report.BundleData)
	if hasBundle {
		if !bundle.ExecutablePresent {
			addFinding(&r, "bundle.executable_missing", report.Error, "The bundle executable is missing", "The application metadata does not resolve to an executable file inside the bundle.", "high", []string{"bundle"}, "Reinstall the application from its publisher.")
		} else if !bundle.ExecutableRunnable {
			addFinding(&r, "bundle.executable_not_runnable", report.Error, "The bundle executable is not runnable", "The main executable does not have an executable permission bit.", "high", []string{"bundle"}, "Reinstall the application instead of changing bundle permissions manually.")
		}
	}
	if hasBundle && bundle.OSSupported != nil && !*bundle.OSSupported {
		addFinding(&r, "os.unsupported", report.Error, "This macOS version is not supported by the application", "The bundle's minimum system version is newer than the current macOS version.", "high", []string{"bundle"}, "Update macOS or install a compatible application version.")
	}

	quarantine, _ := byID[report.EvidenceQuarantine].Data.(report.QuarantineData)
	if quarantine.Present {
		addFinding(&r, "quarantine.present", report.Info, "The application has quarantine metadata", "macOS may perform first-launch Gatekeeper checks for this downloaded application.", "high", []string{"quarantine", "gatekeeper"}, "Review the Gatekeeper result; mactriage will not remove quarantine metadata.")
	}

	crash, _ := byID[report.EvidenceCrash].Data.(report.CrashData)
	if crash.Count > 0 {
		addFinding(&r, "crash.detected", report.Error, "A correlated crash report was created", "macOS wrote a crash report for this application during the observation window.", "high", []string{"crash", "launch"}, "Use the structured termination evidence and update or reinstall the application.")
	}

	signature, hasSignature := byID[report.EvidenceSignature].Data.(report.SignatureData)
	if hasSignature && !signature.Valid {
		code := "signature.invalid"
		if strings.EqualFold(signature.Reason, "unsigned") {
			code = "signature.unsigned"
		}
		addFinding(&r, code, report.Error, "The application signature is not valid", "Strict recursive code-signature verification failed.", "high", []string{"signature"}, "Replace the application with a trusted copy; mactriage will not rewrite signatures.")
	}

	gatekeeper, assessed := byID[report.EvidenceGatekeeper].Data.(report.GatekeeperData)
	if assessed && !gatekeeper.Accepted {
		addFinding(&r, "gatekeeper.rejected", report.Error, "Gatekeeper rejected the application", "The system policy assessment did not accept this bundle.", "high", []string{"gatekeeper", "signature"}, "Review the publisher and system security decision before proceeding.")
		if signature.Valid {
			addAction(&r, action.OpenSecurity)
		}
	}

	arch, _ := byID[report.EvidenceArchitecture].Data.(report.ArchitectureData)
	architectures := arch.Architectures
	hasARM := contains(architectures, "arm64") || contains(architectures, "arm64e")
	hasX86 := contains(architectures, "x86_64")
	if r.Host.Arch == "arm64" && hasX86 && !hasARM {
		addFinding(&r, "architecture.rosetta_required", report.Warning, "This application requires Rosetta", "The main executable contains Intel code but no native Apple silicon slice.", "high", []string{"architecture"}, "Launch it to let macOS offer the supported Rosetta installation flow.")
		addAction(&r, action.LaunchRosetta)
	}
	if len(architectures) > 0 && ((r.Host.Arch == "arm64" && !hasARM && !hasX86) || (r.Host.Arch == "amd64" && !hasX86)) {
		addFinding(&r, "architecture.incompatible", report.Error, "The executable architecture is incompatible", "The app has no executable slice supported by this Mac.", "high", []string{"architecture"}, "Install a build intended for this Mac architecture.")
	}

	dependencies, _ := byID[report.EvidenceDependencies].Data.(report.DependencyData)
	if dependencies.MissingCount > 0 {
		addFinding(&r, "dependency.missing", report.Error, "The application has missing non-system dependencies", fmt.Sprintf("%d required library paths could not be resolved.", dependencies.MissingCount), "high", []string{"dependencies"}, "Reinstall or update the application from its publisher.")
	}

	launchEvidence := byID[report.EvidenceLaunch]
	launch, hasLaunch := launchEvidence.Data.(report.LaunchData)
	if launch.AlreadyRunning {
		addFinding(&r, "launch.skipped_already_running", report.Info, "Active launch test skipped", "The application was already running, so mactriage did not create a duplicate instance.", "high", []string{"launch"}, "Use --new-instance only if a duplicate launch is safe.")
	} else if launch.Spawned != nil && !*launch.Spawned {
		addFinding(&r, "launch.failed_to_spawn", report.Error, "Launch Services could not start the application", "The open command failed before a new application process was observed.", "high", []string{"launch", "logs"}, "Review the correlated evidence before retrying.")
		addRetryAction(&r)
	} else if launch.Terminated {
		explanation := "A new application process appeared and exited during the observation window; the exit signal is unknown unless separately reported by macOS."
		if launch.ExitSignal != "" && launch.ExitSignal != "unknown" {
			explanation = fmt.Sprintf("A new application process appeared and exited during the observation window; a correlated crash report supplied signal %s.", launch.ExitSignal)
		}
		addFinding(&r, "launch.terminated", report.Error, "The application terminated immediately", explanation, "high", []string{"launch", "logs", "crash"}, "Address the highest-confidence correlated finding and retry.")
		addRetryAction(&r)
	} else if launch.Survived {
		addFinding(&r, "launch.survived", report.Info, "The application survived the launch check", "The application process remained present for the observation window.", "high", []string{"launch"}, "")
	} else if hasLaunch && launchEvidence.Status != report.StatusSkipped {
		addFinding(&r, "launch.inconclusive", report.Warning, "Launch result was inconclusive", "No stable matching application process could be correlated with the launch request.", "low", []string{"launch", "logs"}, "Retry with a longer --observe duration.")
		addRetryAction(&r)
	}

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
	for _, existing := range r.Findings {
		if existing.Code == code {
			return
		}
	}
	evidenceIDs := make([]report.EvidenceID, 0, len(evidence))
	for _, id := range evidence {
		evidenceIDs = append(evidenceIDs, report.EvidenceID(id))
	}
	r.Findings = append(r.Findings, report.Finding{Code: code, Severity: severity, Title: title, Explanation: explanation, Confidence: confidence, EvidenceIDs: evidenceIDs, Recommendation: recommendation})
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
