package macos

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Mantaworks/mactriage/internal/report"
)

func (d Doctor) storage(ctx context.Context) report.Evidence {
	result := d.Runner.Run(ctx, "/bin/df", "-kP", "/")
	if result.TimedOut {
		return timedOut(report.EvidenceStorage, "Startup disk check timed out")
	}
	if result.Err != nil {
		return unavailable(report.EvidenceStorage, "Startup disk capacity is unavailable")
	}
	lines := nonemptyLines(result.Stdout)
	if len(lines) < 2 {
		return unavailable(report.EvidenceStorage, "Startup disk capacity was incomplete")
	}
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 6 {
		return unavailable(report.EvidenceStorage, "Startup disk capacity was incomplete")
	}
	totalKB, totalErr := strconv.ParseUint(fields[1], 10, 64)
	availableKB, availableErr := strconv.ParseUint(fields[3], 10, 64)
	if totalErr != nil || availableErr != nil || totalKB == 0 {
		return unavailable(report.EvidenceStorage, "Startup disk capacity could not be parsed")
	}
	data := report.StorageData{
		TotalBytes:       totalKB * 1024,
		AvailableBytes:   availableKB * 1024,
		AvailablePercent: roundOne(float64(availableKB) * 100 / float64(totalKB)),
	}
	return report.Evidence{
		ID:      report.EvidenceStorage,
		Status:  report.StatusOK,
		Summary: fmt.Sprintf("Startup disk has %.1f%% available", data.AvailablePercent),
		Data:    data,
	}
}
