package macos

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/upsidedly/mactriage/internal/report"
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
		r.Evidence = append(r.Evidence, report.Evidence{ID: "logs", Status: report.StatusOK, Summary: "Recent resource-error logs inspected", Data: map[string]any{"emfile": summary.EMFILE, "enfile": summary.ENFILE, "sec_static_code": summary.SecStaticCode}})
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
				rows := make([]map[string]any, 0, len(counts))
				for _, count := range counts {
					rows = append(rows, map[string]any{"pid": count.PID, "command": count.Command, "count": count.Count})
				}
				r.Evidence = append(r.Evidence, report.Evidence{ID: "top_processes", Status: report.StatusOK, Summary: fmt.Sprintf("Aggregated the top %d descriptor consumers", len(rows)), Data: map[string]any{"processes": rows, "truncated": result.Truncated}})
			}
			c.emit("top_processes", "Aggregate descriptor consumers", string(r.Evidence[len(r.Evidence)-1].Status), time.Since(started))
		}
	}
	return r, nil
}

func TopDescriptorCounts(data []byte, limit int) []ProcessDescriptorCount {
	counts := ParseProcessDescriptorCounts(data)
	sort.SliceStable(counts, func(i, j int) bool {
		if counts[i].Count == counts[j].Count {
			return strings.Compare(counts[i].Command, counts[j].Command) < 0
		}
		return counts[i].Count > counts[j].Count
	})
	if limit > 0 && len(counts) > limit {
		return counts[:limit]
	}
	return counts
}
