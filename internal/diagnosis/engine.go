package diagnosis

import (
	"fmt"
	"strings"

	"github.com/upsidedly/mactriage/internal/report"
)

func Analyze(r report.Report) report.Report {
	byID := make(map[string]report.Evidence, len(r.Evidence))
	for _, evidence := range r.Evidence {
		byID[evidence.ID] = evidence
		if evidence.Status == report.StatusUnavailable || evidence.Status == report.StatusTimedOut {
			r.Completeness = report.Partial
		}
	}

	logs := byID["logs"]
	if number(logs.Data, "emfile") > 0 {
		addFinding(&r, "policy.emfile", report.Critical, "A process exhausted its file descriptors", "macOS reported EMFILE (error 24), which is a per-process descriptor-table failure.", "high", []string{"logs", "limits", "launch"}, "Restart the affected daemon after reviewing the action.")
		if number(logs.Data, "sec_static_code") > 0 {
			r.Actions = append(r.Actions, report.Action{ID: "repair.syspolicyd", Title: "Restart syspolicyd", Description: "Terminate the wedged policy daemon and verify that launchd starts a new process.", Command: []string{"mactriage", "repair", "syspolicyd"}, RequiresRoot: true, Available: true})
		}
	}
	if number(logs.Data, "enfile") > 0 {
		addFinding(&r, "system.enfile", report.Critical, "The system file table is exhausted", "macOS reported ENFILE, indicating system-wide descriptor exhaustion.", "high", []string{"logs", "limits"}, "Identify the largest descriptor consumers before restarting services.")
	}
	if number(logs.Data, "xprotect") > 0 {
		addFinding(&r, "xprotect.blocked", report.Critical, "XProtect blocked the application", "Correlated system logs contain an explicit XProtect block.", "high", []string{"logs"}, "Do not bypass the block; obtain a trusted build from the publisher.")
	}
	if number(logs.Data, "launch_services") > 0 {
		addFinding(&r, "launchservices.failure", report.Error, "Launch Services reported a failure", "The application could not be opened through Launch Services.", "medium", []string{"logs", "launch"}, "Review the bundle and executable evidence before retrying.")
	}
	if number(logs.Data, "missing_library") > 0 {
		addFinding(&r, "dependency.missing", report.Error, "A required library could not be loaded", "The dynamic loader reported a missing dependency.", "high", []string{"logs", "dependencies"}, "Reinstall or update the application from its publisher.")
	}
	if number(logs.Data, "signature_errors") > 0 {
		addFinding(&r, "signature.runtime_invalid", report.Error, "macOS reported a runtime signature failure", "Correlated launch logs contain an explicit invalid-signature event.", "high", []string{"logs", "signature"}, "Replace the application with a trusted copy from its publisher.")
	}
	if number(logs.Data, "notarization_errors") > 0 {
		addFinding(&r, "notarization.failed", report.Error, "The notarization check failed", "Correlated system logs contain a notarization failure or rejection.", "high", []string{"logs", "gatekeeper"}, "Obtain a current notarized build from the publisher.")
	}

	bundle := byID["bundle"]
	if present, known := boolean(bundle.Data, "executable_present"); known && !present {
		addFinding(&r, "bundle.executable_missing", report.Error, "The bundle executable is missing", "The application metadata does not resolve to an executable file inside the bundle.", "high", []string{"bundle"}, "Reinstall the application from its publisher.")
	} else if runnable, known := boolean(bundle.Data, "executable_runnable"); known && !runnable {
		addFinding(&r, "bundle.executable_not_runnable", report.Error, "The bundle executable is not runnable", "The main executable does not have an executable permission bit.", "high", []string{"bundle"}, "Reinstall the application instead of changing bundle permissions manually.")
	}
	if supported, known := boolean(bundle.Data, "os_supported"); known && !supported {
		addFinding(&r, "os.unsupported", report.Error, "This macOS version is not supported by the application", "The bundle's minimum system version is newer than the current macOS version.", "high", []string{"bundle"}, "Update macOS or install a compatible application version.")
	}

	quarantine := byID["quarantine"]
	if present, _ := boolean(quarantine.Data, "present"); present {
		addFinding(&r, "quarantine.present", report.Info, "The application has quarantine metadata", "macOS may perform first-launch Gatekeeper checks for this downloaded application.", "high", []string{"quarantine", "gatekeeper"}, "Review the Gatekeeper result; mactriage will not remove quarantine metadata.")
	}

	crash := byID["crash"]
	if number(crash.Data, "count") > 0 {
		addFinding(&r, "crash.detected", report.Error, "A correlated crash report was created", "macOS wrote a crash report for this application during the observation window.", "high", []string{"crash", "launch"}, "Use the structured termination evidence and update or reinstall the application.")
	}

	signature := byID["signature"]
	validSignature, hasSignature := boolean(signature.Data, "valid")
	if hasSignature && !validSignature {
		code := "signature.invalid"
		if stringValue(signature.Data, "reason") == "unsigned" {
			code = "signature.unsigned"
		}
		addFinding(&r, code, report.Error, "The application signature is not valid", "Strict recursive code-signature verification failed.", "high", []string{"signature"}, "Replace the application with a trusted copy; mactriage will not rewrite signatures.")
	}

	gatekeeper := byID["gatekeeper"]
	accepted, assessed := boolean(gatekeeper.Data, "accepted")
	if assessed && !accepted {
		addFinding(&r, "gatekeeper.rejected", report.Error, "Gatekeeper rejected the application", "The system policy assessment did not accept this bundle.", "high", []string{"gatekeeper", "signature"}, "Review the publisher and system security decision before proceeding.")
		if validSignature {
			r.Actions = append(r.Actions, report.Action{ID: "open.security", Title: "Open Privacy & Security", Description: "Open the macOS settings pane where the system decision can be reviewed.", Command: []string{"open", "x-apple.systempreferences:com.apple.preference.security?General"}, Available: true})
		}
	}

	arch := byID["architecture"]
	if required, _ := boolean(arch.Data, "rosetta_required"); required {
		addFinding(&r, "architecture.rosetta_required", report.Warning, "This application requires Rosetta", "The main executable contains Intel code but no native Apple silicon slice.", "high", []string{"architecture"}, "Launch it to let macOS offer the supported Rosetta installation flow.")
		r.Actions = append(r.Actions, report.Action{ID: "launch.rosetta_prompt", Title: "Launch and install Rosetta if needed", Description: "Open the Intel application so macOS can present Apple's Rosetta installation prompt.", Command: []string{"open", r.Target}, Available: true})
	}
	if incompatible, _ := boolean(arch.Data, "incompatible"); incompatible {
		addFinding(&r, "architecture.incompatible", report.Error, "The executable architecture is incompatible", "The app has no executable slice supported by this Mac.", "high", []string{"architecture"}, "Install a build intended for this Mac architecture.")
	}

	dependencies := byID["dependencies"]
	if missing := number(dependencies.Data, "missing_count"); missing > 0 {
		addFinding(&r, "dependency.missing", report.Error, "The application has missing non-system dependencies", fmt.Sprintf("%d required library paths could not be resolved.", int(missing)), "high", []string{"dependencies"}, "Reinstall or update the application from its publisher.")
	}

	launch := byID["launch"]
	if skipped, _ := boolean(launch.Data, "already_running"); skipped {
		addFinding(&r, "launch.skipped_already_running", report.Info, "Active launch test skipped", "The application was already running, so mactriage did not create a duplicate instance.", "high", []string{"launch"}, "Use --new-instance only if a duplicate launch is safe.")
	} else if spawned, present := boolean(launch.Data, "spawned"); present && !spawned {
		addFinding(&r, "launch.failed_to_spawn", report.Error, "Launch Services could not start the application", "The open command failed before a new application process was observed.", "high", []string{"launch", "logs"}, "Review the correlated evidence before retrying.")
	} else if terminated, _ := boolean(launch.Data, "terminated"); terminated {
		addFinding(&r, "launch.terminated", report.Error, "The application terminated immediately", "A new application process appeared and exited during the observation window; the exit signal is unknown unless separately reported by macOS.", "high", []string{"launch", "logs", "crash"}, "Address the highest-confidence correlated finding and retry.")
	} else if survived, _ := boolean(launch.Data, "survived"); survived {
		addFinding(&r, "launch.survived", report.Info, "The application survived the launch check", "The application process remained present for the observation window.", "high", []string{"launch"}, "")
	} else if launch.ID != "" && launch.Status != report.StatusSkipped {
		addFinding(&r, "launch.inconclusive", report.Warning, "Launch result was inconclusive", "No stable matching application process could be correlated with the launch request.", "low", []string{"launch", "logs"}, "Retry with a longer --observe duration.")
	}

	return r
}

func addFinding(r *report.Report, code string, severity report.Severity, title, explanation, confidence string, evidence []string, recommendation string) {
	for _, existing := range r.Findings {
		if existing.Code == code {
			return
		}
	}
	r.Findings = append(r.Findings, report.Finding{Code: code, Severity: severity, Title: title, Explanation: explanation, Confidence: confidence, EvidenceIDs: evidence, Recommendation: recommendation})
}

func number(data map[string]any, key string) float64 {
	if data == nil {
		return 0
	}
	switch value := data[key].(type) {
	case float64:
		return value
	case float32:
		return float64(value)
	case int:
		return float64(value)
	case int64:
		return float64(value)
	case jsonNumber:
		return value.Float64()
	}
	return 0
}

type jsonNumber string

func (n jsonNumber) Float64() float64 {
	var value float64
	fmt.Sscan(string(n), &value)
	return value
}

func boolean(data map[string]any, key string) (bool, bool) {
	if data == nil {
		return false, false
	}
	value, ok := data[key].(bool)
	return value, ok
}

func stringValue(data map[string]any, key string) string {
	if data == nil {
		return ""
	}
	value, _ := data[key].(string)
	return strings.ToLower(value)
}
