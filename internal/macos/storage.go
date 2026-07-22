package macos

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

type StorageInspector struct{ Runner platform.Runner }

func (s StorageInspector) Inspect(ctx context.Context, details bool) (report.Report, error) {
	r := report.New("storage", "startup disk")
	r.Host = (Collector{Runner: s.Runner}).host(ctx)
	r.Evidence = append(r.Evidence, (Doctor{Runner: s.Runner}).storage(ctx))
	if details {
		home, _ := os.UserHomeDir()
		categories := []struct{ name, path string }{
			{"Applications", "/Applications"}, {"Desktop", filepath.Join(home, "Desktop")}, {"Documents", filepath.Join(home, "Documents")}, {"Downloads", filepath.Join(home, "Downloads")}, {"Movies", filepath.Join(home, "Movies")}, {"Music", filepath.Join(home, "Music")}, {"Pictures", filepath.Join(home, "Pictures")}, {"Developer", filepath.Join(home, "Developer")},
		}
		data := report.StorageDetailsData{Categories: []report.StorageCategory{}}
		status := report.StatusOK
		for _, category := range categories {
			if _, err := os.Stat(category.path); err != nil {
				continue
			}
			result := s.Runner.Run(ctx, "/usr/bin/du", "-sk", category.path)
			if result.Err != nil {
				status = report.StatusPartial
				continue
			}
			fields := strings.Fields(result.Stdout)
			if len(fields) == 0 {
				status = report.StatusPartial
				continue
			}
			kb, err := strconv.ParseUint(fields[0], 10, 64)
			if err != nil {
				status = report.StatusPartial
				continue
			}
			data.Categories = append(data.Categories, report.StorageCategory{Name: category.name, Bytes: kb * 1024})
		}
		r.Evidence = append(r.Evidence, report.Evidence{ID: report.EvidenceStorageDetail, Status: status, Summary: "Measured aggregate sizes for standard storage categories without listing files", Data: data})
		if status == report.StatusPartial {
			r.Completeness = report.Partial
		}
	}
	return r, nil
}
