package present

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Mantaworks/mactriage/internal/report"
)

type Style struct {
	Color bool
	Width int
}

func JSON(w io.Writer, r report.Report) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}

func NDJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

func Human(w io.Writer, r report.Report, style Style) {
	width := style.Width
	if width <= 0 {
		width = 88
	}
	title := "mactriage"
	if r.Target != "" {
		title += " · " + r.Target
	}
	fmt.Fprintln(w, decorate(title, "12", true, style.Color))
	fmt.Fprintf(w, "%s  Case %s\n", decorate(verdict(r), verdictColor(r), true, style.Color), r.CaseID)
	fmt.Fprintf(w, "Command: %s   Evidence: %d   Completeness: %s\n", r.Command, len(r.Evidence), strings.ToUpper(string(r.Completeness)))
	if r.Command == "doctor" {
		doctorSnapshot(w, r)
	} else if r.Command == "storage" || r.Command == "startup" {
		healthDetails(w, r)
	}

	if len(r.Findings) == 0 {
		if r.Completeness == report.Partial {
			fmt.Fprintln(w, "\n"+decorate("INCONCLUSIVE", "11", true, style.Color)+"  Some evidence was unavailable, so mactriage cannot call this result healthy.")
		} else {
			fmt.Fprintln(w, "\n"+decorate("OK", "10", true, style.Color)+"  No diagnostic problems were identified.")
		}
	} else {
		fmt.Fprintln(w, "\nFindings")
		for _, finding := range sortedFindings(r.Findings) {
			label, color := severityStyle(finding.Severity)
			fmt.Fprintf(w, "  %s  %s\n", decorate(label, color, true, style.Color), finding.Title)
			fmt.Fprintf(w, "      %s\n", wrap(finding.Explanation, width-6))
			if finding.Recommendation != "" {
				fmt.Fprintf(w, "      Next: %s\n", wrap(finding.Recommendation, width-12))
			}
		}
	}
	if len(r.Actions) > 0 {
		fmt.Fprintln(w, "\nAvailable actions")
		for _, action := range r.Actions {
			root := ""
			if action.RequiresRoot {
				root = " (requires administrator access)"
			}
			fmt.Fprintf(w, "  → %s%s\n    %s\n", action.Title, root, wrap(action.Description, width-4))
		}
	}
	steps := nextSteps(r.Findings, 3)
	if len(steps) > 0 {
		fmt.Fprintln(w, "\nNext best steps")
		for i, step := range steps {
			fmt.Fprintf(w, "  %d. %s\n", i+1, wrap(step, width-5))
		}
	}
	var unknown []string
	for _, evidence := range r.Evidence {
		if evidence.Status == report.StatusUnavailable || evidence.Status == report.StatusTimedOut || evidence.Status == report.StatusPartial {
			unknown = append(unknown, string(evidence.ID))
		}
	}
	if len(unknown) > 0 {
		fmt.Fprintln(w, "\nUnknown checks\n  "+strings.Join(unknown, ", "))
	}
}

func healthDetails(w io.Writer, r report.Report) {
	for _, evidence := range r.Evidence {
		switch data := evidence.Data.(type) {
		case report.StorageData:
			fmt.Fprintf(w, "\nStartup disk\n  %.1f%% available · %d GiB free of %d GiB\n", data.AvailablePercent, data.AvailableBytes>>30, data.TotalBytes>>30)
		case report.StorageDetailsData:
			fmt.Fprintln(w, "\nAggregate categories")
			for _, category := range data.Categories {
				fmt.Fprintf(w, "  %-14s %6.1f GiB\n", category.Name, float64(category.Bytes)/(1<<30))
			}
		case report.StartupItemsData:
			fmt.Fprintf(w, "\nStartup items (%d, source: %s)\n", data.Count, data.Source)
			for _, item := range data.Items {
				label := item.Name
				if label == "" {
					label = item.Identifier
				}
				if label != "" {
					fmt.Fprintln(w, "  "+label)
				}
			}
		}
	}
}

func verdict(r report.Report) string {
	for _, f := range r.Findings {
		if f.Severity == report.Critical || f.Severity == report.Error {
			return "NEEDS ATTENTION"
		}
	}
	for _, f := range r.Findings {
		if f.Severity == report.Warning {
			return "CHECK RECOMMENDED"
		}
	}
	if r.Completeness == report.Partial {
		return "INCOMPLETE"
	}
	return "LOOKS GOOD"
}

func verdictColor(r report.Report) string {
	switch verdict(r) {
	case "NEEDS ATTENTION":
		return "9"
	case "CHECK RECOMMENDED", "INCOMPLETE":
		return "11"
	default:
		return "10"
	}
}

func nextSteps(findings []report.Finding, limit int) []string {
	seen := map[string]bool{}
	var out []string
	for _, finding := range sortedFindings(findings) {
		if finding.Recommendation != "" && !seen[finding.Recommendation] {
			seen[finding.Recommendation] = true
			out = append(out, finding.Recommendation)
		}
		if len(out) == limit {
			break
		}
	}
	return out
}

func doctorSnapshot(w io.Writer, r report.Report) {
	if len(r.Evidence) == 0 {
		return
	}
	fmt.Fprintln(w, "\nHealth snapshot")
	for _, evidence := range r.Evidence {
		switch data := evidence.Data.(type) {
		case report.StorageData:
			fmt.Fprintf(w, "  Disk      %.1f%% available\n", data.AvailablePercent)
		case report.MemoryData:
			fmt.Fprintf(w, "  Memory    %.1f%% readily available · %d MiB swap used\n", data.FreePercent, data.SwapUsedBytes>>20)
		case report.CPUData:
			fmt.Fprintf(w, "  CPU       load %.2f across %d logical cores\n", data.LoadOne, data.LogicalCores)
		case report.NetworkData:
			fmt.Fprintf(w, "  Network   DNS %s · HTTPS %s · TLS %s\n",
				networkFact(data.DNSStatus, data.DNSResolved, "resolved", "not resolved"),
				networkFact(data.HTTPSStatus, data.HTTPSReachable, "reachable", "not reachable"),
				networkFact(data.HTTPSStatus, data.TLSValid, "valid", "not valid"))
			if data.InterfaceStatus != "" || data.DNSConfigStatus != "" {
				dnsServers := "unknown"
				if data.DNSConfigStatus == report.StatusOK {
					dnsServers = fmt.Sprintf("%d", data.DNSServerCount)
				}
				fmt.Fprintf(w, "            interface %s · Wi-Fi %s · DNS servers %s · clock year %d\n",
					networkFact(data.InterfaceStatus, data.ActiveInterface && !data.SelfAssigned, "active", "unavailable"),
					networkFact(data.WiFiStatus, data.WiFiPowered && data.WiFiAssociated, "connected", "not connected"), dnsServers, data.ClockYear)
			}
		case report.ScanData:
			fmt.Fprintf(w, "  Apps      %d inspected\n", len(data.Apps))
		case report.StartupItemsData:
			fmt.Fprintf(w, "  Startup   %d registered items\n", data.Count)
		case report.BatteryData:
			if data.Present {
				fmt.Fprintf(w, "  Battery   %d%% charge · %.1f%% estimated health · %d cycles\n", data.Percent, data.HealthPercent, data.CycleCount)
			}
		case report.ThermalData:
			fmt.Fprintf(w, "  Thermal   CPU limit %d%% · warning recorded %t\n", data.CPUSpeedLimit, data.WarningRecorded)
		case report.BackupData:
			if !data.Configured {
				fmt.Fprintf(w, "  Backup    Time Machine is not configured\n")
			} else if data.HasBackup {
				fmt.Fprintf(w, "  Backup    latest backup %.1f hours ago\n", data.LatestAgeHours)
			} else {
				fmt.Fprintf(w, "  Backup    configured · latest backup was unavailable\n")
			}
		}
	}
}

func networkFact(status report.Status, value bool, whenTrue, whenFalse string) string {
	if status != report.StatusOK {
		return "unknown"
	}
	if value {
		return whenTrue
	}
	return whenFalse
}

func HumanWatch(w io.Writer, timestamp string, severity report.Severity, message string, color bool) {
	fmt.Fprintf(w, "%s  %-8s  %s\n", timestamp, SeverityLabel(severity, color), message)
}

func SeverityLabel(severity report.Severity, color bool) string {
	label, code := severityStyle(severity)
	return decorate(label, code, true, color)
}

func WriteAtomic(path string, mode os.FileMode, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".mactriage-*")
	if err != nil {
		return err
	}
	temp := file.Name()
	defer os.Remove(temp)
	if err := file.Chmod(mode); err != nil {
		file.Close()
		return err
	}
	if err := write(file); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func severityStyle(severity report.Severity) (string, string) {
	switch severity {
	case report.Critical:
		return "CRITICAL", "9"
	case report.Error:
		return "ERROR", "9"
	case report.Warning:
		return "WARNING", "11"
	default:
		return "INFO", "12"
	}
}

func decorate(text, color string, bold, enabled bool) string {
	if !enabled {
		return text
	}
	ansi := map[string]string{"8": "90", "9": "91", "10": "92", "11": "93", "12": "94"}[color]
	if ansi == "" {
		ansi = "39"
	}
	if bold {
		ansi = "1;" + ansi
	}
	return "\x1b[" + ansi + "m" + text + "\x1b[0m"
}

func sortedFindings(findings []report.Finding) []report.Finding {
	copyOf := append([]report.Finding(nil), findings...)
	weight := map[report.Severity]int{report.Critical: 0, report.Error: 1, report.Warning: 2, report.Info: 3}
	sort.SliceStable(copyOf, func(i, j int) bool { return weight[copyOf[i].Severity] < weight[copyOf[j].Severity] })
	return copyOf
}

func wrap(text string, width int) string {
	if width < 20 || len(text) <= width {
		return text
	}
	words := strings.Fields(text)
	var out strings.Builder
	line := 0
	for _, word := range words {
		if line > 0 && line+1+len(word) > width {
			out.WriteString("\n      ")
			line = 0
		}
		if line > 0 {
			out.WriteByte(' ')
			line++
		}
		out.WriteString(word)
		line += len(word)
	}
	return out.String()
}
