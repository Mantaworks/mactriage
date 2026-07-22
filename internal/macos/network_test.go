package macos_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

func TestNetworkInspectorCollectsSanitizedConnectivityFacts(t *testing.T) {
	r, err := (macos.NetworkInspector{Runner: networkRunner{}}).Inspect(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	data := evidenceData[report.NetworkData](t, r, report.EvidenceNetwork)
	if !data.DNSResolved || !data.DefaultRoute || !data.HTTPSReachable || !data.TLSValid || !data.ProxyConfigured {
		t.Fatalf("missing network facts: %#v", data)
	}
	if len(data.VPNInterfaces) != 1 || data.VPNInterfaces[0] != "utun3" || data.ListeningSocketCount != 2 {
		t.Fatalf("unexpected aggregate network data: %#v", data)
	}
}

func TestNetworkInspectorReportsFailedTLSWithoutLeakingCommandOutput(t *testing.T) {
	r, err := (macos.NetworkInspector{Runner: networkRunner{curlError: true}}).Inspect(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	data := evidenceData[report.NetworkData](t, r, report.EvidenceNetwork)
	if data.TLSValid || !data.HTTPSReachable || len(r.Evidence) != 1 || r.Evidence[0].Error != "" {
		t.Fatalf("unsafe or incorrect failed result: %#v", r)
	}
}

type networkRunner struct{ curlError bool }

func (r networkRunner) Run(_ context.Context, path string, _ ...string) platform.Result {
	switch path {
	case "/usr/bin/dscacheutil":
		return platform.Result{Stdout: "name: example.com\nip_address: 93.184.216.34\n"}
	case "/sbin/route":
		return platform.Result{Stdout: "gateway: 192.0.2.1\n"}
	case "/usr/sbin/scutil":
		return platform.Result{Stdout: "<dictionary> {\n  HTTPEnable : 1\n  HTTPProxy : proxy.internal\n}\n"}
	case "/sbin/ifconfig":
		return platform.Result{Stdout: "en0: flags=...\nutun3: flags=...\n"}
	case "/usr/bin/curl":
		if r.curlError {
			return platform.Result{ExitCode: 60, Err: errors.New("certificate problem"), Stderr: "private output"}
		}
		return platform.Result{Stdout: "HTTP/2 200\n"}
	case "/usr/sbin/lsof":
		return platform.Result{Stdout: "p10\x00f12u\x00tIPv4\x00f13u\x00tIPv6\x00fcwd\x00tDIR\x00"}
	case "/usr/bin/sw_vers":
		return platform.Result{Stdout: "14.5\n"}
	case "/usr/bin/uname":
		return platform.Result{Stdout: "arm64\n"}
	default:
		return platform.Result{}
	}
}
