package macos_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestDoctorCollectsTypedMacHealthEvidence(t *testing.T) {
	r, err := (macos.Doctor{Runner: doctorRunner{}}).Inspect(context.Background(), macos.DoctorOptions{Skip: []string{"apps", "network"}})
	if err != nil {
		t.Fatalf("Inspect returned error: %v", err)
	}
	if r.Command != "doctor" || len(r.Evidence) < 7 {
		t.Fatalf("incomplete doctor report: %#v", r)
	}
	storage := evidenceData[report.StorageData](t, r, report.EvidenceStorage)
	if storage.AvailablePercent != 5 {
		t.Fatalf("available percent=%v want=5", storage.AvailablePercent)
	}
	memory := evidenceData[report.MemoryData](t, r, report.EvidenceMemory)
	if memory.SwapUsedBytes != 2<<30 || memory.FreePercent != 4 {
		t.Fatalf("unexpected memory facts: %#v", memory)
	}
	restarts := evidenceData[report.RestartLoopsData](t, r, report.EvidenceRestartLoops)
	if len(restarts.Processes) != 2 || restarts.Processes[0].Name != "com.example.Helper" || restarts.Processes[0].Count != 3 || restarts.Processes[1].Name != "com.example.Once" || restarts.Processes[1].Count != 1 {
		t.Fatalf("unexpected restart facts: %#v", restarts)
	}
}

func TestDoctorOnlyCollectsSelectedChecks(t *testing.T) {
	r, err := (macos.Doctor{Runner: doctorRunner{}}).Inspect(context.Background(), macos.DoctorOptions{Only: []string{"storage"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Evidence) != 1 || r.Evidence[0].ID != report.EvidenceStorage {
		t.Fatalf("evidence=%#v", r.Evidence)
	}
}

func TestDoctorCheckAliasesSelectCanonicalChecks(t *testing.T) {
	r, err := (macos.Doctor{Runner: doctorRunner{}}).Inspect(context.Background(), macos.DoctorOptions{Only: []string{"disk", "ram", "fds", "login-items", "time-machine"}})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[report.EvidenceID]bool{}
	for _, evidence := range r.Evidence {
		seen[evidence.ID] = true
	}
	for _, id := range []report.EvidenceID{
		report.EvidenceStorage,
		report.EvidenceMemory,
		report.EvidenceLimits,
		report.EvidenceStartupItems,
		report.EvidenceBackup,
	} {
		if !seen[id] {
			t.Errorf("alias did not select canonical evidence %q: %#v", id, seen)
		}
	}
	if len(r.Evidence) != 5 {
		t.Fatalf("aliases selected %d checks, want 5: %#v", len(r.Evidence), seen)
	}
}

func TestDoctorRejectsUnknownCheckWithStableError(t *testing.T) {
	_, err := (macos.Doctor{Runner: doctorRunner{}}).Inspect(context.Background(), macos.DoctorOptions{Only: []string{"mystery"}})
	if err == nil || err.Error() != `unknown doctor check "mystery"` {
		t.Fatalf("error=%v", err)
	}
}

func TestDoctorProfilesSelectTheirDocumentedChecks(t *testing.T) {
	tests := []struct {
		name    string
		profile macos.DoctorProfile
		require []report.EvidenceID
		exclude []report.EvidenceID
	}{
		{
			name:    "quick",
			profile: macos.DoctorProfileQuick,
			require: []report.EvidenceID{report.EvidenceStorage, report.EvidenceNetwork},
			exclude: []report.EvidenceID{report.EvidenceBattery, report.EvidenceUpdates},
		},
		{
			name:    "full",
			profile: macos.DoctorProfileFull,
			require: []report.EvidenceID{report.EvidenceStorage, report.EvidenceUpdates, report.EvidenceBattery},
		},
		{
			name:    "fleet",
			profile: macos.DoctorProfileFleet,
			require: []report.EvidenceID{report.EvidenceStorage, report.EvidenceBattery},
			exclude: []report.EvidenceID{report.EvidenceUpdates},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, err := (macos.Doctor{Runner: doctorRunner{}}).Inspect(context.Background(), macos.DoctorOptions{Profile: test.profile})
			if err != nil {
				t.Fatal(err)
			}
			seen := map[report.EvidenceID]bool{}
			for _, evidence := range r.Evidence {
				seen[evidence.ID] = true
			}
			for _, id := range test.require {
				if !seen[id] {
					t.Errorf("profile %q omitted %q: %#v", test.profile, id, seen)
				}
			}
			for _, id := range test.exclude {
				if seen[id] {
					t.Errorf("profile %q unexpectedly ran %q: %#v", test.profile, id, seen)
				}
			}
		})
	}
}

func TestDoctorRejectsUnknownProfileWithStableError(t *testing.T) {
	_, err := (macos.Doctor{Runner: doctorRunner{}}).Inspect(context.Background(), macos.DoctorOptions{Profile: "mystery"})
	if err == nil || err.Error() != `unknown doctor profile "mystery"` {
		t.Fatalf("error=%v", err)
	}
}

func TestDoctorOfflineSkipsNetworkAndUpdates(t *testing.T) {
	r, err := (macos.Doctor{Runner: doctorRunner{}}).Inspect(context.Background(), macos.DoctorOptions{Profile: macos.DoctorProfileFull, Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, evidence := range r.Evidence {
		if evidence.ID == report.EvidenceNetwork || evidence.ID == report.EvidenceUpdates {
			t.Fatalf("offline profile collected %s", evidence.ID)
		}
	}
}

func TestDoctorMarksUnavailableServiceProbesPartial(t *testing.T) {
	r, err := (macos.Doctor{Runner: unavailableServiceRunner{}}).Inspect(context.Background(), macos.DoctorOptions{Only: []string{"services"}})
	if err != nil {
		t.Fatal(err)
	}
	data := evidenceData[report.ServicesData](t, r, report.EvidenceServices)
	if r.Evidence[0].Status != report.StatusPartial || data.Statuses["syspolicyd"] != report.StatusUnavailable {
		t.Fatalf("service probe failure became a missing service: %#v", r.Evidence[0])
	}
}

type unavailableServiceRunner struct{}

func (unavailableServiceRunner) Run(_ context.Context, path string, _ ...string) platform.Result {
	if path == "/usr/bin/pgrep" {
		return platform.Result{ExitCode: -1, Err: errors.New("pgrep unavailable")}
	}
	return platform.Result{}
}

func evidenceData[T any](t *testing.T, r report.Report, id report.EvidenceID) T {
	t.Helper()
	for _, evidence := range r.Evidence {
		if evidence.ID == id {
			value, ok := evidence.Data.(T)
			if !ok {
				t.Fatalf("evidence %s data=%T", id, evidence.Data)
			}
			return value
		}
	}
	var zero T
	t.Fatalf("evidence %s not found", id)
	return zero
}

type doctorRunner struct{}

func (doctorRunner) Run(_ context.Context, path string, args ...string) platform.Result {
	switch path {
	case "/bin/df":
		return platform.Result{Stdout: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/disk 1000000 950000 50000 95% /\n"}
	case "/usr/bin/vm_stat":
		return platform.Result{Stdout: "Mach Virtual Memory Statistics: (page size of 4096 bytes)\nPages free: 1024.\nPages inactive: 0.\nPages speculative: 0.\n"}
	case "/usr/sbin/sysctl":
		if len(args) > 1 && args[1] == "hw.memsize" {
			return platform.Result{Stdout: "104857600\n"}
		}
		if len(args) > 1 && args[1] == "vm.swapusage" {
			return platform.Result{Stdout: "total = 4096.00M used = 2048.00M free = 2048.00M\n"}
		}
		return platform.Result{Stdout: "4\n"}
	case "/usr/bin/uptime":
		return platform.Result{Stdout: "load averages: 8.00 4.00 2.00\n"}
	case "/bin/ps":
		return platform.Result{Stdout: "  PID %CPU STAT COMM\n  42 99.0 R Example\n"}
	case "/usr/bin/pgrep":
		return platform.Result{Stdout: "42\n"}
	case "/usr/sbin/softwareupdate":
		return platform.Result{Stdout: "No new software available.\n"}
	case "/usr/bin/find":
		return platform.Result{Stdout: "one.ips\ntwo.ips\n"}
	case "/bin/ls":
		return platform.Result{Stdout: "one.plist\ntwo.plist\n"}
	case "/usr/bin/sfltool":
		return platform.Result{Stdout: "UUID: one\nUUID: two\n"}
	case "/usr/bin/log":
		return platform.Result{Stdout: "{\"eventMessage\":\"service com.example.Helper exited\"}\n{\"eventMessage\":\"service com.example.Helper exited\"}\n{\"eventMessage\":\"service com.example.Helper exited\"}\n{\"eventMessage\":\"service com.example.Once exited\"}\n"}
	case "/usr/bin/sw_vers":
		return platform.Result{Stdout: "14.5\n"}
	case "/usr/bin/uname":
		return platform.Result{Stdout: "arm64\n"}
	default:
		return platform.Result{}
	}
}
