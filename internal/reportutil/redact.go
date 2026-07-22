package reportutil

import (
	"sort"
	"strings"

	"github.com/Mantaworks/mactriage/internal/report"
)

// RedactStrict removes application, process, account-adjacent, and path labels
// while retaining the aggregate facts and stable diagnostic codes needed by IT.
func RedactStrict(input report.Report) report.Report {
	r := input
	values := []string{r.Target}
	r.Target = "<redacted>"
	for i := range r.Evidence {
		e := &r.Evidence[i]
		switch data := e.Data.(type) {
		case report.BundleData:
			values = append(values, data.Path, data.Name, data.BundleID, data.Executable)
			data.Path, data.Name, data.BundleID, data.Executable = "<redacted>", "<redacted>", "<redacted>", "<redacted>"
			e.Data = data
		case report.ProcessData:
			values = append(values, data.Name)
			data.Name = "<redacted>"
			e.Data = data
		case report.DescriptorData:
			values = append(values, data.Process)
			data.Process, data.PID = "<redacted>", ""
			e.Data = data
		case report.CPUData:
			values = append(values, data.HighestProcess)
			data.HighestProcess = "<redacted>"
			e.Data = data
		case report.PermissionsData:
			values = append(values, data.BundleID)
			data.BundleID = "<redacted>"
			e.Data = data
		case report.ScanData:
			for j := range data.Apps {
				values = append(values, data.Apps[j].Path, data.Apps[j].Name, data.Apps[j].BundleID)
				data.Apps[j].Path, data.Apps[j].Name, data.Apps[j].BundleID = "<redacted>", "<redacted>", "<redacted>"
			}
			data.Roots = nil
			e.Data = data
		case report.StartupItemsData:
			for j := range data.Items {
				values = append(values, data.Items[j].Name, data.Items[j].Identifier, data.Items[j].TeamID)
				data.Items[j] = report.StartupItem{Name: "<redacted>"}
			}
			e.Data = data
		case report.NetworkData:
			values = append(values, data.Host)
			data.Host, data.VPNInterfaces = "<redacted>", nil
			e.Data = data
		case report.TopProcessesData:
			for j := range data.Processes {
				values = append(values, data.Processes[j].Command)
				data.Processes[j].Command = "<redacted>"
			}
			e.Data = data
		case report.RelaunchData:
			values = append(values, data.ProcessName)
			data.ProcessName = "<redacted>"
			data.PIDs, data.NewPIDs = nil, nil
			e.Data = data
		}
	}
	sort.Slice(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
	replace := func(s string) string {
		for _, value := range values {
			if strings.TrimSpace(value) != "" && value != "<redacted>" {
				s = strings.ReplaceAll(s, value, "<redacted>")
			}
		}
		return s
	}
	for i := range r.Evidence {
		r.Evidence[i].Summary = replace(r.Evidence[i].Summary)
		r.Evidence[i].Error = replace(r.Evidence[i].Error)
	}
	for i := range r.Findings {
		r.Findings[i].Title = replace(r.Findings[i].Title)
		r.Findings[i].Explanation = replace(r.Findings[i].Explanation)
		r.Findings[i].Recommendation = replace(r.Findings[i].Recommendation)
		if len(r.Findings[i].Subjects) > 0 {
			r.Findings[i].Subjects = []string{"<redacted>"}
		}
	}
	for i := range r.Actions {
		r.Actions[i].Command = nil
	}
	return r
}
