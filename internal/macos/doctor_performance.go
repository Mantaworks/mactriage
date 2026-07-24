package macos

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Mantaworks/mactriage/internal/report"
)

func (d Doctor) memory(ctx context.Context) report.Evidence {
	totalResult := d.Runner.Run(ctx, "/usr/sbin/sysctl", "-n", "hw.memsize")
	vmResult := d.Runner.Run(ctx, "/usr/bin/vm_stat")
	swapResult := d.Runner.Run(ctx, "/usr/sbin/sysctl", "-n", "vm.swapusage")
	if totalResult.TimedOut || vmResult.TimedOut || swapResult.TimedOut {
		return timedOut(report.EvidenceMemory, "Memory pressure check timed out")
	}
	if totalResult.Err != nil || vmResult.Err != nil || swapResult.Err != nil {
		return unavailable(report.EvidenceMemory, "Memory pressure is unavailable")
	}
	total, err := strconv.ParseUint(strings.TrimSpace(totalResult.Stdout), 10, 64)
	if err != nil || total == 0 {
		return unavailable(report.EvidenceMemory, "Total memory could not be parsed")
	}
	pageSize := uint64(4096)
	if match := regexp.MustCompile(`page size of ([0-9]+) bytes`).FindStringSubmatch(vmResult.Stdout); len(match) == 2 {
		pageSize, _ = strconv.ParseUint(match[1], 10, 64)
	}
	freePages := vmPageCount(vmResult.Stdout, "Pages free") + vmPageCount(vmResult.Stdout, "Pages inactive") + vmPageCount(vmResult.Stdout, "Pages speculative")
	freeBytes := freePages * pageSize
	swapUsed := parseSwapUsed(swapResult.Stdout)
	freePercent := roundOne(float64(freeBytes) * 100 / float64(total))
	if pressure := d.Runner.Run(ctx, "/usr/bin/memory_pressure", "-Q"); pressure.Err == nil {
		if measured := parseMemoryFreePercent(pressure.Stdout + "\n" + pressure.Stderr); measured > 0 {
			freePercent = measured
		}
	}
	data := report.MemoryData{TotalBytes: total, FreeBytes: freeBytes, FreePercent: freePercent, SwapUsedBytes: swapUsed}
	return report.Evidence{ID: report.EvidenceMemory, Status: report.StatusOK, Summary: fmt.Sprintf("Memory has %.1f%% readily available", data.FreePercent), Data: data}
}

func (d Doctor) cpu(ctx context.Context) report.Evidence {
	coresResult := d.Runner.Run(ctx, "/usr/sbin/sysctl", "-n", "hw.logicalcpu")
	loadResult := d.Runner.Run(ctx, "/usr/bin/uptime")
	processResult := d.Runner.Run(ctx, "/bin/ps", "-axo", "pid=,%cpu=,state=,comm=")
	if coresResult.TimedOut || loadResult.TimedOut || processResult.TimedOut {
		return timedOut(report.EvidenceCPU, "CPU health check timed out")
	}
	if coresResult.Err != nil || loadResult.Err != nil || processResult.Err != nil {
		return unavailable(report.EvidenceCPU, "CPU health is unavailable")
	}
	cores, _ := strconv.Atoi(strings.TrimSpace(coresResult.Stdout))
	load := parseLoadOne(loadResult.Stdout)
	data := report.CPUData{LogicalCores: cores, LoadOne: load, ProcessStates: map[string]int{}}
	for _, line := range nonemptyLines(processResult.Stdout) {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		cpu, err := strconv.ParseFloat(strings.ReplaceAll(fields[1], ",", "."), 64)
		if err != nil {
			continue
		}
		if cpu > data.HighestPercent {
			data.HighestPercent = cpu
			data.HighestProcess = filepath.Base(strings.Join(fields[3:], " "))
		}
		data.ProcessStates[strings.ToUpper(fields[2])]++
	}
	return report.Evidence{ID: report.EvidenceCPU, Status: report.StatusOK, Summary: fmt.Sprintf("Load average %.2f across %d logical cores", data.LoadOne, data.LogicalCores), Data: data}
}

func vmPageCount(text, label string) uint64 {
	re := regexp.MustCompile(regexp.QuoteMeta(label) + `:\s*([0-9]+)\.?`)
	match := re.FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	value, _ := strconv.ParseUint(match[1], 10, 64)
	return value
}

func parseSwapUsed(text string) uint64 {
	match := regexp.MustCompile(`used = ([0-9]+(?:\.[0-9]+)?)([MG])`).FindStringSubmatch(text)
	if len(match) != 3 {
		return 0
	}
	value, _ := strconv.ParseFloat(match[1], 64)
	multiplier := float64(1 << 20)
	if match[2] == "G" {
		multiplier = 1 << 30
	}
	return uint64(value * multiplier)
}

func parseLoadOne(text string) float64 {
	match := regexp.MustCompile(`load averages?:\s*([0-9]+(?:\.[0-9]+)?)`).FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	value, _ := strconv.ParseFloat(match[1], 64)
	return value
}

func parseMemoryFreePercent(text string) float64 {
	match := regexp.MustCompile(`System-wide memory free percentage:\s*([0-9]+(?:\.[0-9]+)?)%`).FindStringSubmatch(text)
	if len(match) != 2 {
		return 0
	}
	value, _ := strconv.ParseFloat(match[1], 64)
	return value
}

func roundOne(value float64) float64 { return math.Round(value*10) / 10 }
