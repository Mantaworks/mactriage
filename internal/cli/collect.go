package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/Mantaworks/mactriage/internal/macos"
	"github.com/Mantaworks/mactriage/internal/support"
	"github.com/spf13/cobra"
)

func (a *application) collectCommand() *cobra.Command {
	var observe time.Duration
	var noLaunch, newInstance, privileged bool
	cmd := &cobra.Command{
		Use:   "collect <application>",
		Short: "Create a private sanitized support bundle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if privileged && os.Geteuid() != 0 {
				handled, code, err := a.elevate(cmd.Context(), "Privileged collection can count descriptors owned by protected system daemons.", os.Args[1:])
				if err != nil {
					return err
				}
				if handled {
					a.setExit(cmd, code)
					return nil
				}
			}
			opts := macos.DiagnoseOptions{Observe: observe, NoLaunch: noLaunch, NewInstance: newInstance, Privileged: privileged}
			r, selected, err := a.collectDiagnosis(cmd.Context(), args[0], opts)
			if err != nil {
				return err
			}
			r.Command = "collect"
			r = a.redactReport(r)
			path := a.opts.output
			if path == "" {
				name := selected.Name
				if name == "" {
					name = strings.TrimSuffix(filepath.Base(args[0]), filepath.Ext(args[0]))
				}
				path = fmt.Sprintf("%s-mactriage-%s.zip", safeFilename(name), time.Now().Format("20060102-150405"))
			}
			if !a.opts.json {
				fmt.Fprintf(a.config.Err, "\nSupport bundle preview\n  report.json    sanitized structured evidence\n  summary.txt    help-desk-ready summary\n  manifest.json  file list and SHA-256 checksums\n\nNo raw logs or crash reports will be included.\n")
			}
			if _, err := support.WriteBundle(path, r); err != nil {
				return fmt.Errorf("write support bundle: %w", err)
			}
			if err := a.renderReportOnly(r); err != nil {
				return err
			}
			if !a.opts.json {
				fmt.Fprintf(a.config.Err, "\nSupport bundle written privately to %s\n", path)
			}
			a.setReportExit(cmd, r)
			return nil
		},
	}
	cmd.Flags().DurationVar(&observe, "observe", 5*time.Second, "how long to observe the launched process")
	cmd.Flags().BoolVar(&noLaunch, "no-launch", false, "collect passive evidence without launching the app")
	cmd.Flags().BoolVar(&newInstance, "new-instance", false, "launch a new instance even when the app is already running")
	cmd.Flags().BoolVar(&privileged, "privileged", false, "include protected system-process descriptor evidence")
	return cmd
}

func safeFilename(value string) string {
	value = strings.TrimSpace(value)
	var out strings.Builder
	for _, char := range value {
		if unicode.IsLetter(char) || unicode.IsDigit(char) || char == '-' || char == '_' {
			out.WriteRune(char)
		} else if out.Len() > 0 && !strings.HasSuffix(out.String(), "-") {
			out.WriteByte('-')
		}
	}
	result := strings.Trim(out.String(), "-")
	if result == "" {
		return "app"
	}
	return result
}
