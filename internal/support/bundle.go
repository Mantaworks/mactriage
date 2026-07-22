package support

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/Mantaworks/mactriage/internal/present"
	"github.com/Mantaworks/mactriage/internal/report"
)

type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	CreatedAt     time.Time         `json:"created_at"`
	Files         []string          `json:"files"`
	SHA256        map[string]string `json:"sha256"`
}

func FileList() []string {
	return []string{"manifest.json", "report.json", "summary.txt"}
}

func WriteBundle(path string, r report.Report) (Manifest, error) {
	reportBytes, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	reportBytes = append(reportBytes, '\n')
	summaryBytes := []byte(MarkdownSummary(r))
	files := map[string][]byte{"report.json": reportBytes, "summary.txt": summaryBytes}
	manifest := Manifest{SchemaVersion: report.SchemaVersion, CreatedAt: time.Now().UTC(), Files: FileList(), SHA256: map[string]string{}}
	for name, contents := range files {
		digest := sha256.Sum256(contents)
		manifest.SHA256[name] = hex.EncodeToString(digest[:])
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	files["manifest.json"] = append(manifestBytes, '\n')
	err = present.WriteAtomic(path, 0o600, func(w io.Writer) error {
		archive := zip.NewWriter(w)
		for _, name := range manifest.Files {
			header := &zip.FileHeader{Name: name, Method: zip.Deflate}
			header.SetMode(0o600)
			entry, createErr := archive.CreateHeader(header)
			if createErr != nil {
				archive.Close()
				return createErr
			}
			if _, writeErr := entry.Write(files[name]); writeErr != nil {
				archive.Close()
				return writeErr
			}
		}
		return archive.Close()
	})
	return manifest, err
}

func MarkdownSummary(r report.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# mactriage summary\n\n- Command: `%s`\n", sanitize(r.Command))
	if r.CaseID != "" {
		fmt.Fprintf(&b, "- Case: `%s`\n", sanitize(r.CaseID))
	}
	if r.Target != "" {
		fmt.Fprintf(&b, "- Target: `%s`\n", sanitize(r.Target))
	}
	fmt.Fprintf(&b, "- Completeness: %s\n- macOS: %s (%s)\n\n", sanitize(string(r.Completeness)), sanitize(fallback(r.Host.OSVersion, "unknown")), sanitize(fallback(r.Host.Arch, "unknown")))
	if len(r.Findings) == 0 {
		b.WriteString("## Findings\n\nNo diagnostic problems were identified.\n")
		return b.String()
	}
	findings := append([]report.Finding(nil), r.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return severityWeight(findings[i].Severity) < severityWeight(findings[j].Severity)
	})
	b.WriteString("## Findings\n\n")
	for _, finding := range findings {
		fmt.Fprintf(&b, "- **%s — %s** (`%s`): %s", strings.ToUpper(sanitize(string(finding.Severity))), sanitize(finding.Title), sanitize(finding.Code), sanitize(finding.Explanation))
		if finding.Recommendation != "" {
			fmt.Fprintf(&b, " Next: %s", sanitize(finding.Recommendation))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func sanitize(value string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		value = strings.ReplaceAll(value, home, "~")
	}
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	return strings.ReplaceAll(value, "`", "'")
}

func fallback(value, replacement string) string {
	if strings.TrimSpace(value) == "" {
		return replacement
	}
	return value
}

func severityWeight(value report.Severity) int {
	switch value {
	case report.Critical:
		return 0
	case report.Error:
		return 1
	case report.Warning:
		return 2
	default:
		return 3
	}
}
