package macos

import (
	"bufio"
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	EMFILE         int `json:"emfile"`
	ENFILE         int `json:"enfile"`
	SecStaticCode  int `json:"sec_static_code"`
	Signature      int `json:"signature_errors"`
	Gatekeeper     int `json:"gatekeeper_errors"`
	Notarization   int `json:"notarization_errors"`
	XProtect       int `json:"xprotect"`
	LaunchServices int `json:"launch_services"`
	Terminations   int `json:"terminations"`
	MissingLibrary int `json:"missing_library"`
}

func ParseLogEvents(data []byte) LogSummary {
	var summary LogSummary
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		var event struct {
			Message          string `json:"eventMessage"`
			Process          string `json:"process"`
			ProcessImagePath string `json:"processImagePath"`
		}
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		if event.Process == "log" || event.ProcessImagePath == "/usr/bin/log" {
			continue
		}
		message := strings.ToLower(event.Message)
		if strings.Contains(message, "too many open files") || strings.Contains(message, "error exception: 24") || strings.Contains(message, "emfile") {
			summary.EMFILE++
		}
		if strings.Contains(message, "file table overflow") || strings.Contains(message, "error exception: 23") || strings.Contains(message, "enfile") {
			summary.ENFILE++
		}
		if strings.Contains(message, "failed to generate secstaticcode") {
			summary.SecStaticCode++
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
	return summary
}
