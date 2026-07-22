package macos_test

import (
	"strings"
	"testing"

	"github.com/upsidedly/mactriage/internal/macos"
)

func TestParseLSOFCountsOnlyNumericDescriptorFields(t *testing.T) {
	input := strings.Join([]string{
		"p497", "csyspolicyd", "\nfcwd", "tDIR", "n/", "\nftxt", "tREG", "n/usr/libexec/syspolicyd",
		"\nf0", "tCHR", "n/dev/null", "\nf12u", "tREG", "n/private/tmp/db", "\nf15", "tIPv4", "nlocalhost:1234",
	}, "\x00") + "\x00"

	sample := macos.ParseLSOF([]byte(input))
	if sample.Count != 3 {
		t.Fatalf("Count = %d, want 3", sample.Count)
	}
	if sample.ByType["REG"] != 1 || sample.ByType["CHR"] != 1 || sample.ByType["IPv4"] != 1 {
		t.Fatalf("unexpected type counts: %#v", sample.ByType)
	}
	if sample.ByPath["/private/tmp/db"] != 1 {
		t.Fatalf("unexpected path counts: %#v", sample.ByPath)
	}
}

func TestParseLogEventsRecognizesResourceAndSecurityEvidence(t *testing.T) {
	input := strings.Join([]string{
		`{"process":"log","eventMessage":"args contained EMFILE and ENFILE"}`,
		`{"timestamp":"2026-01-01T12:00:00Z","process":"syspolicyd","processID":42,"eventMessage":"UNIX error exception: 24, Too many open files"}`,
		`{"timestamp":"2026-01-01T12:00:01Z","process":"syspolicyd","processID":42,"eventMessage":"Failed to generate SecStaticCode"}`,
		`{"process":"runningboardd","eventMessage":"termination reported by launchd"}`,
		`{"process":"XProtectService","eventMessage":"malware blocked by XProtect"}`,
	}, "\n")

	summary := macos.ParseLogEvents([]byte(input))
	if summary.EMFILE != 1 || summary.SecStaticCode != 1 || summary.Terminations != 1 || summary.XProtect != 1 {
		t.Fatalf("unexpected log summary: %#v", summary)
	}
	if summary.SyspolicydSecStaticCode != 1 || summary.SyspolicydEMFILE != 1 || summary.SyspolicydWedgeSequence != 1 {
		t.Fatalf("unexpected process-correlated summary: %#v", summary)
	}
}

func TestParseLogEventsDoesNotTreatErrnoNamesAsExplicitEvidence(t *testing.T) {
	summary := macos.ParseLogEvents([]byte(`{"process":"example","eventMessage":"debug query contained EMFILE and ENFILE"}`))
	if summary.EMFILE != 0 || summary.ENFILE != 0 {
		t.Fatalf("mere errno names were treated as evidence: %#v", summary)
	}
}

func TestParseNOFILELimit(t *testing.T) {
	soft, hard, ok := macos.ParseNOFILELimit("    NOFILE = { soft = 256, hard = 10240 }\n")
	if !ok || soft != 256 || hard != 10240 {
		t.Fatalf("soft=%d hard=%d ok=%v", soft, hard, ok)
	}
}

func TestParseCrashTerminationUsesStructuredFieldsOnly(t *testing.T) {
	data := []byte("{\"app_name\":\"Example\"}\n{\"termination\":{\"namespace\":\"SIGNAL\",\"code\":6,\"indicator\":\"Abort trap\"},\"exception\":{\"signal\":\"SIGABRT\"}}")
	got := macos.ParseCrashTermination(data, ".ips")
	if got.Namespace != "SIGNAL" || got.Code != "6" || got.Signal != "SIGABRT" {
		t.Fatalf("unexpected structured termination: %#v", got)
	}
	noise := macos.ParseCrashTermination([]byte("random stack symbol SIGKILL"), ".crash")
	if noise.Signal != "" {
		t.Fatalf("unstructured stack text supplied a signal: %#v", noise)
	}
}

func TestParseProcessDescriptorCountsGroupsNumericFDsByPID(t *testing.T) {
	input := strings.Join([]string{
		"p10", "cone", "\nfcwd", "\nf0", "\nf1", "p20", "ctwo", "\nftxt", "\nf4u", "\nf8",
	}, "\x00") + "\x00"
	counts := macos.ParseProcessDescriptorCounts([]byte(input))
	if len(counts) != 2 || counts[0].PID != 10 || counts[0].Count != 2 || counts[1].PID != 20 || counts[1].Count != 2 {
		t.Fatalf("unexpected process counts: %#v", counts)
	}
}
