package macos_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

type healthRunner struct{}

func (healthRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/usr/bin/pmset":
		if len(args) > 1 && args[1] == "batt" {
			return platform.Result{Stdout: "Now drawing from 'Battery Power'\n -InternalBattery-0 73%; discharging"}
		}
		return platform.Result{Stdout: "CPU_Speed_Limit = 80\nScheduler_Limit = 90\nCPU_Available = 100\n"}
	case "/usr/sbin/ioreg":
		return platform.Result{Stdout: `"CycleCount" = 412\n"AppleRawMaxCapacity" = 800\n"DesignCapacity" = 1000\n"BatteryHealth" = "Good"`}
	case "/usr/bin/tmutil":
		if len(args) > 0 && args[0] == "destinationinfo" {
			return platform.Result{Stdout: "Name : Backup"}
		}
		return platform.Result{Stdout: "/Volumes/Backup/2026-07-20-120000"}
	}
	return platform.Result{}
}

type deniedBackupRunner struct{ healthRunner }

func (deniedBackupRunner) Run(ctx context.Context, path string, args ...string) platform.Result {
	if path == "/usr/bin/tmutil" && len(args) > 0 && args[0] == "destinationinfo" {
		return platform.Result{Err: errors.New("operation not permitted"), ExitCode: 1, Stderr: "Operation not permitted"}
	}
	return (healthRunner{}).Run(ctx, path, args...)
}

func TestBackupPermissionFailureIsUnknownNotUnconfigured(t *testing.T) {
	evidence := (macos.HealthInspector{Runner: deniedBackupRunner{}}).Backup(context.Background())
	if evidence.Status != report.StatusUnavailable {
		t.Fatalf("status=%s evidence=%#v", evidence.Status, evidence)
	}
}

func TestHealthInspectorReturnsTypedBatteryThermalAndBackupFacts(t *testing.T) {
	h := macos.HealthInspector{Runner: healthRunner{}, Now: func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.Local) }}
	battery := h.Battery(context.Background()).Data.(report.BatteryData)
	if battery.Percent != 73 || battery.CycleCount != 412 || battery.HealthPercent != 80 {
		t.Fatalf("battery=%#v", battery)
	}
	thermal := h.Thermal(context.Background()).Data.(report.ThermalData)
	if thermal.CPUSpeedLimit != 80 || thermal.SchedulerLimit != 90 {
		t.Fatalf("thermal=%#v", thermal)
	}
	backup := h.Backup(context.Background()).Data.(report.BackupData)
	if !backup.Configured || !backup.HasBackup || backup.LatestAgeHours != 48 {
		t.Fatalf("backup=%#v", backup)
	}
}
