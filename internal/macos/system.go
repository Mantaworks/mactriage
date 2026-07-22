package macos

import (
	"context"
	"fmt"
	"time"

	"github.com/Mantaworks/mactriage/internal/report"
)

func (c Collector) System(ctx context.Context, top int, privileged bool) (report.Report, error) {
	r := report.New("system", "")
	r.Host = c.host(ctx)
	c.emit("limits", "Measure descriptor limits", "running", 0)
	started := time.Now()
	r.Evidence = append(r.Evidence, c.limits(ctx))
	c.emit("limits", "Measure descriptor limits", string(r.Evidence[0].Status), time.Since(started))

	c.emit("logs", "Check recent resource errors", "running", 0)
	started = time.Now()
	logResult := c.Runner.Run(ctx, "/usr/bin/log", "show", "--last", "5m", "--style", "ndjson", "--predicate", `(eventMessage CONTAINS[c] "too many open files" OR eventMessage CONTAINS[c] "file table overflow" OR eventMessage CONTAINS[c] "EMFILE" OR eventMessage CONTAINS[c] "ENFILE") AND process != "log"`)
	if logResult.TimedOut {
		r.Evidence = append(r.Evidence, timedOut("logs", "Recent resource-error log query timed out"))
	} else if logResult.Err != nil {
		r.Evidence = append(r.Evidence, unavailable("logs", "Recent resource-error logs are unavailable"))
	} else {
		summary := ParseLogEvents([]byte(logResult.Stdout))
		status, text := report.StatusOK, "Recent resource-error logs inspected"
		if logResult.Truncated {
			status, text = report.StatusPartial, "Recent resource-error logs inspected (bounded output was truncated)"
		}
		r.Evidence = append(r.Evidence, report.Evidence{ID: report.EvidenceLogs, Status: status, Summary: text, Data: report.LogsData{EMFILE: summary.EMFILE, ENFILE: summary.ENFILE, SecStaticCode: summary.SecStaticCode}})
	}
	c.emit("logs", "Check recent resource errors", string(r.Evidence[len(r.Evidence)-1].Status), time.Since(started))

	if top > 0 {
		if !privileged {
			r.Evidence = append(r.Evidence, report.Evidence{ID: "top_processes", Status: report.StatusSkipped, Summary: "Top descriptor consumers require administrator access"})
		} else {
			c.emit("top_processes", "Aggregate descriptor consumers", "running", 0)
			started = time.Now()
			result := c.Runner.Run(ctx, "/usr/sbin/lsof", "-nP", "-F0pcf")
			if result.TimedOut {
				r.Evidence = append(r.Evidence, timedOut("top_processes", "System-wide descriptor aggregation timed out"))
			} else if result.Err != nil {
				r.Evidence = append(r.Evidence, unavailable("top_processes", "System-wide descriptor aggregation failed"))
			} else {
				counts := ParseProcessDescriptorCounts([]byte(result.Stdout))
				if len(counts) > top {
					counts = counts[:top]
				}
				rows := make([]report.ProcessDescriptorSummary, 0, len(counts))
				for _, count := range counts {
					rows = append(rows, report.ProcessDescriptorSummary{PID: count.PID, Command: count.Command, Count: count.Count})
				}
				status, text := report.StatusOK, fmt.Sprintf("Aggregated the top %d descriptor consumers", len(rows))
				if result.Truncated {
					status, text = report.StatusPartial, text+" (bounded output was truncated)"
				}
				r.Evidence = append(r.Evidence, report.Evidence{ID: report.EvidenceTopProcesses, Status: status, Summary: text, Data: report.TopProcessesData{Processes: rows, Truncated: result.Truncated}})
			}
			c.emit("top_processes", "Aggregate descriptor consumers", string(r.Evidence[len(r.Evidence)-1].Status), time.Since(started))
		}
	}
	return r, nil
}
