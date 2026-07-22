package macos

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/Mantaworks/mactriage/internal/platform"
	"github.com/Mantaworks/mactriage/internal/report"
)

type NetworkInspector struct {
	Runner platform.Runner
}

func (n NetworkInspector) Inspect(ctx context.Context, target string) (report.Report, error) {
	if n.Runner == nil {
		return report.Report{}, errors.New("network inspector requires a command runner")
	}
	host, err := normalizeNetworkHost(target)
	if err != nil {
		return report.Report{}, err
	}
	data := report.NetworkData{Host: host}
	dns := n.Runner.Run(ctx, "/usr/bin/dscacheutil", "-q", "host", "-a", "name", host)
	data.DNSResolved = net.ParseIP(host) != nil || (dns.Err == nil && strings.Contains(dns.Stdout, "ip_address:"))

	route := n.Runner.Run(ctx, "/sbin/route", "-n", "get", "default")
	data.DefaultRoute = route.Err == nil && strings.Contains(strings.ToLower(route.Stdout), "gateway:")

	proxy := n.Runner.Run(ctx, "/usr/sbin/scutil", "--proxy")
	if proxy.Err == nil {
		data.ProxyConfigured = regexp.MustCompile(`(?m)^\s*(HTTP|HTTPS|SOCKS)Enable\s*:\s*1\s*$`).MatchString(proxy.Stdout)
	}

	interfaces := n.Runner.Run(ctx, "/sbin/ifconfig", "-l")
	if interfaces.Err == nil {
		for _, name := range strings.Fields(interfaces.Stdout) {
			if regexp.MustCompile(`^(utun|ppp|ipsec)[0-9]+$`).MatchString(name) {
				data.VPNInterfaces = append(data.VPNInterfaces, name)
			}
		}
		if len(data.VPNInterfaces) == 0 {
			for _, line := range nonemptyLines(interfaces.Stdout) {
				name := strings.TrimSuffix(strings.Fields(line)[0], ":")
				if regexp.MustCompile(`^(utun|ppp|ipsec)[0-9]+$`).MatchString(name) {
					data.VPNInterfaces = append(data.VPNInterfaces, name)
				}
			}
		}
	}
	sort.Strings(data.VPNInterfaces)

	urlHost := host
	if strings.Contains(host, ":") {
		urlHost = "[" + host + "]"
	}
	request := n.Runner.Run(ctx, "/usr/bin/curl", "--silent", "--show-error", "--head", "--output", "/dev/null", "--connect-timeout", "5", "--max-time", "8", "https://"+urlHost+"/")
	data.HTTPSReachable = request.Err == nil || request.ExitCode == 60
	data.TLSValid = request.Err == nil

	listeners := n.Runner.Run(ctx, "/usr/sbin/lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F0pft")
	if listeners.Err == nil {
		data.ListeningSocketCount = ParseLSOF([]byte(listeners.Stdout)).Count
	}

	r := report.New("network", host)
	r.Host = (Collector{Runner: n.Runner}).host(ctx)
	r.Evidence = append(r.Evidence, report.Evidence{ID: report.EvidenceNetwork, Status: report.StatusOK, Summary: fmt.Sprintf("Checked DNS, routing, proxy, VPN, HTTPS, TLS, and %d listening sockets", data.ListeningSocketCount), Data: data})
	return r, nil
}

func normalizeNetworkHost(value string) (string, error) {
	host := strings.TrimSpace(strings.ToLower(value))
	if host == "" {
		host = "example.com"
	}
	if strings.Contains(host, "://") || strings.ContainsAny(host, "/?#@") || len(host) > 253 {
		return "", errors.New("network target must be a hostname or IP address without a URL path")
	}
	if net.ParseIP(host) != nil {
		return host, nil
	}
	valid := regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	if !valid.MatchString(host) {
		return "", fmt.Errorf("invalid network hostname %q", value)
	}
	return host, nil
}
