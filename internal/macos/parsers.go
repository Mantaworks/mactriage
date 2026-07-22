package macos

import (
	"bufio"
	"bytes"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/upsidedly/mactriage/internal/report"
)

type DescriptorSample struct {
	Count  int            `json:"count"`
	ByType map[string]int `json:"by_type"`
	ByPath map[string]int `json:"by_path,omitempty"`
}

type ProcessDescriptorCount struct {
	PID     int    `json:"pid"`
	Command string `json:"command"`
	Count   int    `json:"count"`
}

func ParseProcessDescriptorCounts(data []byte) []ProcessDescriptorCount {
	byPID := map[int]*ProcessDescriptorCount{}
	currentPID := 0
	for _, raw := range bytes.Split(data, []byte{0}) {
		raw = bytes.TrimLeft(raw, "\r\n")
		if len(raw) < 2 {
			continue
		}
		field, value := raw[0], string(raw[1:])
		switch field {
		case 'p':
			pid, err := strconv.Atoi(value)
			if err != nil {
				currentPID = 0
				continue
			}
			currentPID = pid
			if byPID[pid] == nil {
				byPID[pid] = &ProcessDescriptorCount{PID: pid}
			}
		case 'c':
			if currentPID != 0 {
				byPID[currentPID].Command = value
			}
		case 'f':
			if currentPID != 0 && numericDescriptor.MatchString(value) {
				byPID[currentPID].Count++
			}
		}
	}
	counts := make([]ProcessDescriptorCount, 0, len(byPID))
	for _, count := range byPID {
		counts = append(counts, *count)
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Count == counts[j].Count {
			return counts[i].PID < counts[j].PID
		}
		return counts[i].Count > counts[j].Count
	})
	return counts
}

var numericDescriptor = regexp.MustCompile(`^[0-9]+[a-zA-Z]*$`)

func ParseLSOF(data []byte) DescriptorSample {
	sample := DescriptorSample{ByType: map[string]int{}, ByPath: map[string]int{}}
	currentNumeric := false
	for _, raw := range bytes.Split(data, []byte{0}) {
		raw = bytes.TrimLeft(raw, "\r\n")
		if len(raw) < 2 {
			continue
		}
		field, value := raw[0], string(raw[1:])
		switch field {
		case 'f':
			currentNumeric = numericDescriptor.MatchString(value)
			if currentNumeric {
				sample.Count++
			}
		case 't':
			if currentNumeric && value != "" {
				sample.ByType[value]++
			}
		case 'n':
			if currentNumeric && value != "" {
				sample.ByPath[value]++
			}
		}
	}
	return sample
}

type LogSummary struct {
	EMFILE                  int `json:"emfile"`
	ENFILE                  int `json:"enfile"`
	SecStaticCode           int `json:"sec_static_code"`
	SyspolicydEMFILE        int `json:"syspolicyd_emfile"`
	SyspolicydENFILE        int `json:"syspolicyd_enfile"`
	SyspolicydSecStaticCode int `json:"syspolicyd_sec_static_code"`
	SyspolicydWedgeSequence int `json:"syspolicyd_wedge_sequence"`
	Signature               int `json:"signature_errors"`
	Gatekeeper              int `json:"gatekeeper_errors"`
	Notarization            int `json:"notarization_errors"`
	XProtect                int `json:"xprotect"`
	LaunchServices          int `json:"launch_services"`
	Terminations            int `json:"terminations"`
	MissingLibrary          int `json:"missing_library"`
}

func ParseLogEvents(data []byte) LogSummary {
	var summary LogSummary
	type resourceEvent struct {
		pid int
		at  time.Time
	}
	var syspolicyEMFILE []resourceEvent
	var syspolicySecCode []resourceEvent
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var event struct {
			Message          string `json:"eventMessage"`
			Process          string `json:"process"`
			ProcessImagePath string `json:"processImagePath"`
			ProcessID        int    `json:"processID"`
			Timestamp        string `json:"timestamp"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		if event.Process == "log" || event.ProcessImagePath == "/usr/bin/log" {
			continue
		}
		message := strings.ToLower(event.Message)
		process := strings.ToLower(filepath.Base(firstNonEmpty(event.ProcessImagePath, event.Process)))
		emfile := strings.Contains(message, "too many open files") && !strings.Contains(message, "too many open files in system") || strings.Contains(message, "error exception: 24") || strings.Contains(message, "errno 24")
		enfile := strings.Contains(message, "too many open files in system") || strings.Contains(message, "file table overflow") || strings.Contains(message, "error exception: 23") || strings.Contains(message, "errno 23")
		at := parseLogTimestamp(event.Timestamp)
		if emfile {
			summary.EMFILE++
			if process == "syspolicyd" {
				summary.SyspolicydEMFILE++
				syspolicyEMFILE = append(syspolicyEMFILE, resourceEvent{pid: event.ProcessID, at: at})
			}
		}
		if enfile {
			summary.ENFILE++
			if process == "syspolicyd" {
				summary.SyspolicydENFILE++
			}
		}
		if strings.Contains(message, "failed to generate secstaticcode") {
			summary.SecStaticCode++
			if process == "syspolicyd" {
				summary.SyspolicydSecStaticCode++
				syspolicySecCode = append(syspolicySecCode, resourceEvent{pid: event.ProcessID, at: at})
			}
		}
		if strings.Contains(message, "code signature invalid") || strings.Contains(message, "invalid signature") {
			summary.Signature++
		}
		if strings.Contains(message, "gatekeeper") {
			summary.Gatekeeper++
		}
		if strings.Contains(message, "notari") && (strings.Contains(message, "fail") || strings.Contains(message, "reject")) {
			summary.Notarization++
		}
		if strings.Contains(message, "xprotect") && (strings.Contains(message, "block") || strings.Contains(message, "malware")) {
			summary.XProtect++
		}
		if strings.Contains(message, "launchservices") && (strings.Contains(message, "fail") || strings.Contains(message, "error")) {
			summary.LaunchServices++
		}
		if strings.Contains(message, "termination reported") || strings.Contains(message, "terminated with") || strings.Contains(message, "exited with") {
			summary.Terminations++
		}
		if strings.Contains(message, "library not loaded") || strings.Contains(message, "dyld: library") {
			summary.MissingLibrary++
		}
	}
	for _, resource := range syspolicyEMFILE {
		for _, code := range syspolicySecCode {
			if resource.pid > 0 && resource.pid == code.pid && !resource.at.IsZero() && !code.at.IsZero() && absoluteDuration(resource.at.Sub(code.at)) <= 2*time.Second {
				summary.SyspolicydWedgeSequence++
				break
			}
		}
	}
	return summary
}

func parseLogTimestamp(value string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.000000-0700"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed
		}
	}
	return time.Time{}
}

func absoluteDuration(value time.Duration) time.Duration {
	if value < 0 {
		return -value
	}
	return value
}

func ParseNOFILELimit(data string) (soft, hard uint64, ok bool) {
	for _, line := range strings.Split(data, "\n") {
		upper := strings.ToUpper(line)
		if !strings.Contains(upper, "NOFILE") && !strings.Contains(strings.ToLower(line), "maxfiles") {
			continue
		}
		var numbers []uint64
		for _, field := range strings.FieldsFunc(line, func(r rune) bool { return r < '0' || r > '9' }) {
			if value, err := strconv.ParseUint(field, 10, 64); err == nil {
				numbers = append(numbers, value)
			}
		}
		if len(numbers) >= 2 {
			return numbers[0], numbers[1], true
		}
		if len(numbers) == 1 {
			return numbers[0], 0, true
		}
	}
	return 0, 0, false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

type CrashTermination = report.CrashTermination

func ParseCrashTermination(data []byte, extension string) CrashTermination {
	if strings.EqualFold(extension, ".ips") {
		decoder := json.NewDecoder(bytes.NewReader(data))
		for {
			var object map[string]any
			if err := decoder.Decode(&object); err != nil {
				break
			}
			if termination := structuredTermination(object); termination != (CrashTermination{}) {
				return termination
			}
		}
		return CrashTermination{}
	}

	var result CrashTermination
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "Exception Type:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "Exception Type:"))
			if start := strings.LastIndex(value, "(SIG"); start >= 0 && strings.HasSuffix(value, ")") {
				result.Signal = strings.TrimSuffix(value[start+1:], ")")
			}
		case strings.HasPrefix(line, "Termination Reason:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "Termination Reason:"))
			for _, field := range strings.Split(value, ",") {
				field = strings.TrimSpace(field)
				if strings.HasPrefix(field, "Namespace ") {
					result.Namespace = strings.TrimSpace(strings.TrimPrefix(field, "Namespace "))
				} else if strings.HasPrefix(field, "Code ") {
					result.Code = strings.TrimSpace(strings.TrimPrefix(field, "Code "))
				}
			}
		}
	}
	return result
}

func structuredTermination(object map[string]any) CrashTermination {
	var result CrashTermination
	if raw, ok := object["termination"].(map[string]any); ok {
		result.Namespace = exactString(raw, "namespace")
		result.Code = scalarString(raw["code"])
		result.Indicator = exactString(raw, "indicator")
		result.Signal = exactString(raw, "signal")
	}
	if raw, ok := object["exception"].(map[string]any); ok && result.Signal == "" {
		result.Signal = exactString(raw, "signal")
	}
	return result
}

func exactString(data map[string]any, key string) string {
	value, _ := data[key].(string)
	return value
}

func scalarString(value any) string {
	switch value := value.(type) {
	case string:
		return value
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	default:
		return ""
	}
}
