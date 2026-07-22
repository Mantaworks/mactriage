package cli

import (
	"fmt"

	"github.com/Mantaworks/mactriage/internal/diagnosis"
	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/spf13/cobra"
)

func (a *application) networkCommand() *cobra.Command {
	var detail bool
	cmd := &cobra.Command{
		Use:   "network [host]",
		Short: "Check DNS, routing, proxy, VPN, HTTPS, and TLS",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if a.opts.offline {
				return fmt.Errorf("network cannot run with --offline")
			}
			target := "example.com"
			if len(args) == 1 {
				target = args[0]
			}
			if !a.opts.json {
				fmt.Fprintf(a.config.Err, "mactriage will make one bounded HTTPS request to %s and inspect local network configuration. It will not change DNS, proxy, VPN, or firewall settings.\n\n", target)
			}
			r, err := (macos.NetworkInspector{Runner: a.runner, Detailed: detail}).Inspect(cmd.Context(), target)
			if err != nil {
				return err
			}
			r = diagnosis.Analyze(r)
			if err := a.renderReport(r); err != nil {
				return err
			}
			a.setReportExit(cmd, r)
			return nil
		},
	}
	cmd.Flags().BoolVar(&detail, "detail", false, "include interface, Wi-Fi, DNS configuration, HTTP, and clock checks")
	return cmd
}
