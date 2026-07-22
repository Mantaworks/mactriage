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
		`{"process":"syspolicyd","eventMessage":"UNIX error exception: 24, Too many open files"}`,
		`{"process":"syspolicyd","eventMessage":"Failed to generate SecStaticCode"}`,
		`{"process":"runningboardd","eventMessage":"termination reported by launchd"}`,
		`{"process":"XProtectService","eventMessage":"malware blocked by XProtect"}`,
	}, "\n")

	summary := macos.ParseLogEvents([]byte(input))
	if summary.EMFILE != 1 || summary.SecStaticCode != 1 || summary.Terminations != 1 || summary.XProtect != 1 {
		t.Fatalf("unexpected log summary: %#v", summary)
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
