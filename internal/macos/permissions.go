package macos

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

type PermissionInspector struct {
	Runner platform.Runner
}

func (p PermissionInspector) Inspect(ctx context.Context, app App, lookback time.Duration) (report.Report, error) {
	if p.Runner == nil {
		return report.Report{}, errors.New("permission inspector requires a command runner")
	}
	if app.BundleID == "" {
		return report.Report{}, errors.New("application has no bundle identifier for privacy-log correlation")
	}
	if lookback <= 0 {
		lookback = 10 * time.Minute
	}
	r := report.New("permissions", app.Path)
	r.Host = (Collector{Runner: p.Runner}).host(ctx)
	entitlements := p.Runner.Run(ctx, "/usr/bin/codesign", "-d", "--entitlements", ":-", app.Path)
	entitlementsStatus := report.StatusOK
	switch {
	case entitlements.TimedOut:
		entitlementsStatus = report.StatusTimedOut
	case entitlements.Err != nil:
		entitlementsStatus = report.StatusUnavailable
	case entitlements.Truncated:
		entitlementsStatus = report.StatusPartial
	}
	declared := []string(nil)
	if entitlementsStatus == report.StatusOK || entitlementsStatus == report.StatusPartial {
		declared = permissionCategories(entitlements.Stdout + "\n" + entitlements.Stderr)
	}
	predicate := fmt.Sprintf(`process == "tccd" AND eventMessage CONTAINS[c] "%s"`, predicateEscape(app.BundleID))
	logs := p.Runner.Run(ctx, "/usr/bin/log", "show", "--last", fmt.Sprintf("%.0fs", lookback.Seconds()), "--style", "ndjson", "--predicate", predicate)
	if logs.TimedOut {
		r.Evidence = append(r.Evidence, timedOut(report.EvidencePermissions, "Privacy log query timed out"))
		return r, nil
	}
	if logs.Err != nil {
		r.Evidence = append(r.Evidence, unavailable(report.EvidencePermissions, "Privacy logs could not be queried"))
		return r, nil
	}
	denials := parsePermissionDenials(logs.Stdout, app.BundleID)
	status := report.StatusOK
	summary := "No explicit correlated privacy denials were found"
	if len(denials) > 0 {
		status = report.StatusFailed
		summary = fmt.Sprintf("Found explicit privacy denials in %d categories", len(denials))
	}
	if logs.Truncated {
		status = report.StatusPartial
		summary += " (bounded output was truncated)"
	}
	if entitlementsStatus != report.StatusOK {
		status = report.StatusPartial
		summary += " (declared entitlements were not completely available)"
	}
	r.Evidence = append(r.Evidence, report.Evidence{ID: report.EvidencePermissions, Status: status, Summary: summary, Data: report.PermissionsData{BundleID: app.BundleID, EntitlementsStatus: entitlementsStatus, Declared: declared, Denials: denials}})
	return r, nil
}

func parsePermissionDenials(text, bundleID string) []report.PermissionObservation {
	counts := map[string]int{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	buffer := make([]byte, 64*1024)
	scanner.Buffer(buffer, 512*1024)
	for scanner.Scan() {
		var event struct {
			EventMessage    string `json:"eventMessage"`
			ComposedMessage string `json:"composedMessage"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		message := strings.ToLower(event.EventMessage + " " + event.ComposedMessage)
		if !strings.Contains(message, strings.ToLower(bundleID)) || !containsAny(message, "deny", "denied", "refused", "not authorized", "not allowed") {
			continue
		}
		category := categorizePermission(message)
		counts[category]++
	}
	values := make([]report.PermissionObservation, 0, len(counts))
	for category, count := range counts {
		values = append(values, report.PermissionObservation{Category: category, Decision: "denied", Count: count})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Category < values[j].Category })
	return values
}

func permissionCategories(text string) []string {
	lower := strings.ToLower(text)
	seen := map[string]bool{}
	for _, keyword := range permissionKeywords {
		if strings.Contains(lower, keyword.needle) {
			seen[keyword.category] = true
		}
	}
	values := make([]string, 0, len(seen))
	for category := range seen {
		values = append(values, category)
	}
	sort.Strings(values)
	return values
}

var permissionKeywords = []struct {
	needle   string
	category string
}{
	{"camera", "camera"}, {"microphone", "microphone"}, {"audio-input", "microphone"},
	{"screen capture", "screen-recording"}, {"screen recording", "screen-recording"}, {"screencapture", "screen-recording"},
	{"accessibility", "accessibility"}, {"postevent", "accessibility"}, {"listen event", "accessibility"},
	{"systempolicyallfiles", "full-disk-access"}, {"full disk", "full-disk-access"},
	{"appleevents", "automation"}, {"automation", "automation"}, {"bluetooth", "bluetooth"},
	{"location", "location"}, {"addressbook", "contacts"}, {"contacts", "contacts"},
}

func categorizePermission(message string) string {
	for _, keyword := range permissionKeywords {
		if strings.Contains(message, keyword.needle) {
			return keyword.category
		}
	}
	return "other"
}

func containsAny(text string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(text, value) {
			return true
		}
	}
	return false
}
