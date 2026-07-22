package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/upsidedly/mactriage/internal/action"
	"github.com/upsidedly/mactriage/internal/diagnosis"
	"github.com/upsidedly/mactriage/internal/macos"
	"github.com/upsidedly/mactriage/internal/platform"
	"github.com/upsidedly/mactriage/internal/present"
	"github.com/upsidedly/mactriage/internal/report"
)

type Config struct {
	Out     io.Writer
	Err     io.Writer
	Runner  platform.Runner
	Version string
	Commit  string
	Date    string
}

type options struct {
	json       bool
	output     string
	verbose    bool
	plain      bool
	accessible bool
	color      string
	animation  string
	timeout    time.Duration
}

type application struct {
	config   Config
	opts     options
	runner   platform.Runner
	exitCode int
}

func New(config Config) *cobra.Command {
	if config.Out == nil {
		config.Out = os.Stdout
	}
	if config.Err == nil {
		config.Err = os.Stderr
	}
	app := &application{config: config}
	root := &cobra.Command{
		Use:           "mactriage",
		Short:         "Explain why a macOS application will not launch",
		Long:          "mactriage collects bounded macOS launch evidence, explains the likely cause, and offers only explicitly approved safe actions.",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return app.prepare()
		},
	}
	root.SetOut(config.Out)
	root.SetErr(config.Err)
	flags := root.PersistentFlags()
	flags.BoolVar(&app.opts.json, "json", false, "emit versioned JSON (NDJSON for watch)")
	flags.StringVarP(&app.opts.output, "output", "o", "", "also write a sanitized JSON report to PATH")
	flags.BoolVarP(&app.opts.verbose, "verbose", "v", false, "show the macOS commands being run on stderr")
	flags.BoolVar(&app.opts.plain, "plain", false, "disable color, animation, and terminal UI control sequences")
	flags.BoolVar(&app.opts.accessible, "accessible", false, "use screen-reader-friendly prompts and static progress")
	flags.StringVar(&app.opts.color, "color", "auto", "color mode: auto, always, or never")
	flags.StringVar(&app.opts.animation, "animation", "auto", "animation mode: auto, always, or never")
	flags.DurationVar(&app.opts.timeout, "timeout", 15*time.Second, "timeout for each macOS evidence command")

	root.AddCommand(app.diagnoseCommand(), app.systemCommand(), app.watchCommand(), app.repairCommand(), app.completionCommand(root), app.versionCommand())
	return root
}

func Execute(ctx context.Context, config Config, args []string) int {
	root := New(config)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		if state, ok := root.Annotations["exit_code"]; ok {
			code, _ := strconv.Atoi(state)
			return code
		}
		return 0
	}
	if errors.Is(err, context.Canceled) {
		return 130
	}
	fmt.Fprintf(configWriter(config.Err, os.Stderr), "Error: %v\n", err)
	return 2
}

func (a *application) prepare() error {
	if !oneOf(a.opts.color, "auto", "always", "never") {
		return fmt.Errorf("invalid --color value %q (use auto, always, or never)", a.opts.color)
	}
	if !oneOf(a.opts.animation, "auto", "always", "never") {
		return fmt.Errorf("invalid --animation value %q (use auto, always, or never)", a.opts.animation)
	}
	if a.opts.timeout < time.Second || a.opts.timeout > 5*time.Minute {
		return errors.New("--timeout must be between 1s and 5m")
	}
	if a.opts.plain {
		a.opts.color, a.opts.animation = "never", "never"
	}
	if os.Getenv("MACTRIAGE_ACCESSIBLE") != "" {
		a.opts.accessible = true
	}
	if a.opts.accessible {
		a.opts.animation = "never"
	}
	if a.config.Runner != nil {
		a.runner = a.config.Runner
	} else {
		verbose := func(string) {}
		if a.opts.verbose {
			verbose = func(command string) { fmt.Fprintln(a.config.Err, "  $", command) }
		}
		a.runner = platform.ExecRunner{Timeout: a.opts.timeout, MaxOutput: 16 << 20, Verbose: verbose}
	}
	return nil
}

func (a *application) setExit(cmd *cobra.Command, code int) {
	a.exitCode = code
	root := cmd.Root()
	if root.Annotations == nil {
		root.Annotations = map[string]string{}
	}
	root.Annotations["exit_code"] = strconv.Itoa(code)
}

func (a *application) diagnoseCommand() *cobra.Command {
	var observe time.Duration
	var noLaunch, newInstance, privileged bool
	cmd := &cobra.Command{
		Use:   "diagnose <application>",
		Short: "Inspect an application and observe a launch attempt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if privileged && os.Geteuid() != 0 {
				handled, code, err := a.elevate(cmd.Context(), "Privileged diagnosis can count descriptors owned by protected system daemons.", os.Args[1:])
				if err != nil {
					return err
				}
				if handled {
					a.setExit(cmd, code)
					return nil
				}
			}
			if !a.opts.json {
				launchText := "It will not launch the app because --no-launch was supplied."
				if !noLaunch {
					launchText = fmt.Sprintf("It will launch the app and observe it for %s.", observe)
				}
				fmt.Fprintf(a.config.Err, "mactriage will inspect the bundle, security policy, dependencies, limits, and recent logs. %s No system settings will be changed.\n\n", launchText)
			}
			opts := macos.DiagnoseOptions{Observe: observe, NoLaunch: noLaunch, NewInstance: newInstance, Privileged: privileged}
			r, selected, err := a.collectDiagnosis(cmd.Context(), args[0], opts)
			if err != nil {
				return err
			}
			if err := a.renderReport(r); err != nil {
				return err
			}
			a.setExit(cmd, r.ExitCode())
			if a.canPrompt() && !a.opts.json {
				if err := a.offerActions(cmd.Context(), selected, opts, r); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().DurationVar(&observe, "observe", 5*time.Second, "how long to observe the launched process")
	cmd.Flags().BoolVar(&noLaunch, "no-launch", false, "collect passive evidence without launching the app")
	cmd.Flags().BoolVar(&newInstance, "new-instance", false, "launch a new instance even when the app is already running")
	cmd.Flags().BoolVar(&privileged, "privileged", false, "include protected system-process descriptor evidence")
	return cmd
}

func (a *application) collectDiagnosis(ctx context.Context, target string, opts macos.DiagnoseOptions) (report.Report, macos.App, error) {
	var selected macos.App
	work := func(emit func(present.ProgressEvent)) (report.Report, error) {
		emit(present.ProgressEvent{ID: "resolve", Label: "Resolve application bundle", Status: "running"})
		started := time.Now()
		resolver := macos.Resolver{Runner: a.runner}
		apps, err := resolver.Resolve(ctx, target)
		if err != nil {
			emit(present.ProgressEvent{ID: "resolve", Label: "Resolve application bundle", Status: string(report.StatusFailed), Duration: time.Since(started)})
			var resolveErr *macos.ResolveError
			if errors.As(err, &resolveErr) {
				r := report.New("diagnose", target)
				title := "Application was not found"
				explanation := "No matching macOS application bundle could be resolved."
				if resolveErr.Code == "bundle.invalid" {
					title = "The application bundle is invalid"
					explanation = "The path exists but does not contain readable application bundle metadata."
				}
				r.Evidence = append(r.Evidence, report.Evidence{ID: "bundle", Status: report.StatusFailed, Summary: title, Error: resolveErr.Error()})
				r.Findings = append(r.Findings, report.Finding{Code: resolveErr.Code, Severity: report.Error, Title: title, Explanation: explanation, Confidence: "high", EvidenceIDs: []string{"bundle"}, Recommendation: "Check the path or reinstall the application from its publisher."})
				return r, nil
			}
			return report.Report{}, err
		}
		selected, err = a.chooseApp(apps)
		if err != nil {
			return report.Report{}, err
		}
		emit(present.ProgressEvent{ID: "resolve", Label: "Resolve application bundle", Status: string(report.StatusOK), Duration: time.Since(started)})
		collector := macos.Collector{Runner: a.runner, Emit: func(event macos.ProgressEvent) {
			emit(present.ProgressEvent{ID: event.ID, Label: event.Label, Status: event.Status, Duration: event.Duration})
		}}
		r, err := collector.Collect(ctx, selected, opts)
		if err != nil {
			return report.Report{}, err
		}
		return diagnosis.Analyze(r), nil
	}
	if a.opts.json {
		r, err := work(func(present.ProgressEvent) {})
		return r, selected, err
	}
	if a.animate() {
		r, err := present.RunProgress(ctx, a.config.Err, a.color(), work)
		return r, selected, err
	}
	r, err := present.PlainProgress(a.config.Err, work)
	return r, selected, err
}

func (a *application) chooseApp(apps []macos.App) (macos.App, error) {
	if len(apps) == 0 {
		return macos.App{}, errors.New("application was not found")
	}
	if len(apps) == 1 {
		return apps[0], nil
	}
	if !a.canPrompt() || a.opts.json {
		paths := make([]string, 0, len(apps))
		for _, app := range apps {
			paths = append(paths, app.Path)
		}
		return macos.App{}, fmt.Errorf("application name is ambiguous; candidates: %s", strings.Join(paths, ", "))
	}
	choices := make([]present.Choice, 0, len(apps))
	for _, app := range apps {
		choices = append(choices, present.Choice{Label: fmt.Sprintf("%s — %s", app.Name, app.Path), Value: app.Path})
	}
	selected, err := present.Select("Which application should mactriage inspect?", choices, a.opts.accessible)
	if err != nil {
		return macos.App{}, err
	}
	for _, app := range apps {
		if app.Path == selected {
			return app, nil
		}
	}
	return macos.App{}, errors.New("selected application is no longer available")
}

func (a *application) systemCommand() *cobra.Command {
	var top int
	cmd := &cobra.Command{
		Use:   "system",
		Short: "Inspect descriptor limits and system-wide pressure",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if top < 0 || top > 100 {
				return errors.New("--top must be between 0 and 100")
			}
			privileged := top > 0
			if privileged && os.Geteuid() != 0 {
				handled, code, err := a.elevate(cmd.Context(), "Listing the largest descriptor consumers requires administrator access; only aggregate counts will be retained.", os.Args[1:])
				if err != nil {
					return err
				}
				if handled {
					a.setExit(cmd, code)
					return nil
				}
			}
			collector := macos.Collector{Runner: a.runner}
			work := func(emit func(present.ProgressEvent)) (report.Report, error) {
				collector.Emit = func(event macos.ProgressEvent) {
					emit(present.ProgressEvent{ID: event.ID, Label: event.Label, Status: event.Status, Duration: event.Duration})
				}
				r, err := collector.System(cmd.Context(), top, privileged)
				return diagnosis.Analyze(r), err
			}
			var r report.Report
			var err error
			switch {
			case a.opts.json:
				r, err = work(func(present.ProgressEvent) {})
			case a.animate():
				r, err = present.RunProgress(cmd.Context(), a.config.Err, a.color(), work)
			default:
				r, err = present.PlainProgress(a.config.Err, work)
			}
			if err != nil {
				return err
			}
			if err := a.renderReport(r); err != nil {
				return err
			}
			a.setExit(cmd, r.ExitCode())
			return nil
		},
	}
	cmd.Flags().IntVar(&top, "top", 0, "include the N largest descriptor consumers (requires administrator access)")
	return cmd
}

func (a *application) watchCommand() *cobra.Command {
	var interval, window, duration time.Duration
	var warnGrowth int
	var includePaths bool
	cmd := &cobra.Command{
		Use:   "watch [process-or-pid]",
		Short: "Watch a process for descriptor growth and resource errors",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := "syspolicyd"
			if len(args) == 1 {
				target = args[0]
			}
			if target == "syspolicyd" && os.Geteuid() != 0 {
				handled, code, err := a.elevate(cmd.Context(), "Watching syspolicyd's descriptor table requires administrator access.", os.Args[1:])
				if err != nil {
					return err
				}
				if handled {
					a.setExit(cmd, code)
					return nil
				}
			}
			if interval < 250*time.Millisecond || window < interval || warnGrowth < 1 || duration < 0 {
				return errors.New("watch requires interval >= 250ms, window >= interval, positive warning growth, and non-negative duration")
			}
			watcher := macos.Watcher{Runner: a.runner}
			var stream *atomicStream
			var err error
			if a.opts.output != "" {
				stream, err = newAtomicStream(a.opts.output)
				if err != nil {
					return err
				}
				defer stream.Abort()
			}
			emit := func(event macos.WatchEvent) error {
				if stream != nil {
					if err := present.NDJSON(stream.file, event); err != nil {
						return err
					}
				}
				if a.opts.json {
					return present.NDJSON(a.config.Out, event)
				}
				message := fmt.Sprintf("PID %d · %d descriptors · Δ%d · %s", event.PID, event.DescriptorCount, event.Growth, event.Message)
				present.HumanWatch(a.config.Out, event.Timestamp.Local().Format("15:04:05"), event.Severity, message, a.color())
				return nil
			}
			err = watcher.Run(cmd.Context(), macos.WatchOptions{Target: target, Interval: interval, Window: window, WarnGrowth: warnGrowth, Duration: duration, IncludePaths: includePaths}, emit)
			if stream != nil {
				if commitErr := stream.Commit(); commitErr != nil && err == nil {
					err = commitErr
				}
			}
			if errors.Is(err, context.Canceled) {
				a.setExit(cmd, 130)
				return nil
			}
			if err != nil {
				return err
			}
			a.setExit(cmd, 0)
			return nil
		},
	}
	cmd.Flags().DurationVar(&interval, "interval", 5*time.Second, "sampling interval")
	cmd.Flags().DurationVar(&window, "window", 60*time.Second, "rolling growth window")
	cmd.Flags().IntVar(&warnGrowth, "warn-growth", 150, "warn after this many additional descriptors within the window")
	cmd.Flags().DurationVar(&duration, "duration", 0, "stop after this duration (zero runs until interrupted)")
	cmd.Flags().BoolVar(&includePaths, "include-paths", false, "include target-process path aggregation in watch events")
	return cmd
}

func (a *application) repairCommand() *cobra.Command {
	var yes bool
	repair := &cobra.Command{Use: "repair", Short: "Perform a narrowly allowlisted recovery action"}
	syspolicyd := &cobra.Command{
		Use:   "syspolicyd",
		Short: "Restart syspolicyd and verify launchd relaunches it",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if os.Geteuid() != 0 {
				if yes || !a.canPrompt() || a.opts.json {
					return errors.New("repair requires root; run interactively or use sudo mactriage repair syspolicyd --yes")
				}
				approved, err := present.Confirm("Restart syspolicyd?", "This will terminate syspolicyd. macOS should restart it automatically. mactriage will verify the new PID. Default: No.", a.opts.accessible)
				if err != nil {
					return err
				}
				if !approved {
					fmt.Fprintln(a.config.Err, "No changes made.")
					a.setExit(cmd, 0)
					return nil
				}
				code, err := a.runSudo(cmd.Context(), []string{"repair", "syspolicyd", "--yes"})
				if err != nil {
					return err
				}
				a.setExit(cmd, code)
				return nil
			}
			if !yes {
				if !a.canPrompt() || a.opts.json {
					return errors.New("noninteractive repair requires --yes")
				}
				approved, err := present.Confirm("Restart syspolicyd?", "This will terminate syspolicyd. macOS should restart it automatically. mactriage will verify the new PID. Default: No.", a.opts.accessible)
				if err != nil || !approved {
					if err == nil {
						fmt.Fprintln(a.config.Err, "No changes made.")
						a.setExit(cmd, 0)
					}
					return err
				}
			}
			executor := action.Executor{Runner: a.runner}
			result, err := executor.RestartSyspolicyd(cmd.Context())
			r := report.New("repair", "syspolicyd")
			if err != nil {
				r.Evidence = append(r.Evidence, report.Evidence{ID: "restart", Status: report.StatusFailed, Summary: "syspolicyd did not restart", Error: err.Error()})
				r.Findings = append(r.Findings, report.Finding{Code: "repair.failed", Severity: report.Error, Title: "syspolicyd restart failed", Explanation: err.Error(), Confidence: "high"})
			} else {
				r.Evidence = append(r.Evidence, report.Evidence{ID: "restart", Status: report.StatusOK, Summary: fmt.Sprintf("syspolicyd restarted with PID %d", result.NewPID), Data: map[string]any{"old_pid": result.OldPID, "new_pid": result.NewPID, "restarted": result.Restarted}})
			}
			if renderErr := a.renderReport(r); renderErr != nil {
				return renderErr
			}
			a.setExit(cmd, r.ExitCode())
			return nil
		},
	}
	syspolicyd.Flags().BoolVar(&yes, "yes", false, "confirm the explicit repair without an interactive prompt")
	repair.AddCommand(syspolicyd)
	return repair
}

func (a *application) offerActions(ctx context.Context, selected macos.App, opts macos.DiagnoseOptions, r report.Report) error {
	for _, available := range r.Actions {
		description := available.Description
		if len(available.Command) > 0 {
			description += "\nCommand: " + strings.Join(available.Command, " ")
		}
		approved, err := present.Confirm(available.Title+"?", description+"\nDefault: No.", a.opts.accessible)
		if err != nil {
			return err
		}
		if !approved {
			continue
		}
		switch available.ID {
		case "repair.syspolicyd":
			if os.Geteuid() != 0 {
				code, err := a.runSudo(ctx, []string{"repair", "syspolicyd", "--yes"})
				if err != nil || code != 0 {
					return fmt.Errorf("syspolicyd repair exited with code %d: %w", code, err)
				}
			} else {
				if _, err := (action.Executor{Runner: a.runner}).RestartSyspolicyd(ctx); err != nil {
					return err
				}
			}
			fmt.Fprintln(a.config.Err, "\nRepair completed. Rechecking the application…")
			rechecked, _, err := a.collectDiagnosis(ctx, selected.Path, opts)
			if err != nil {
				return err
			}
			return a.renderReport(rechecked)
		case "open.security":
			result := a.runner.Run(ctx, "/usr/bin/open", "x-apple.systempreferences:com.apple.preference.security?General")
			if result.Err != nil {
				return result.Err
			}
			fmt.Fprintln(a.config.Err, "Privacy & Security is open. mactriage has not changed the policy decision.")
		case "launch.rosetta_prompt":
			result := a.runner.Run(ctx, "/usr/bin/open", "-a", selected.Path)
			if result.Err != nil {
				return result.Err
			}
			fmt.Fprintln(a.config.Err, "The app was launched. If Rosetta is missing, macOS will present Apple's installation prompt.")
		}
	}
	return nil
}

func (a *application) completionCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish|powershell]",
		Short:     "Generate a shell completion script",
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(_ *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletion(a.config.Out)
			case "zsh":
				return root.GenZshCompletion(a.config.Out)
			case "fish":
				return root.GenFishCompletion(a.config.Out, true)
			case "powershell":
				return root.GenPowerShellCompletion(a.config.Out)
			default:
				return fmt.Errorf("unsupported shell %q", args[0])
			}
		},
	}
}

func (a *application) versionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			version := a.config.Version
			if version == "" {
				version = "dev"
			}
			if a.opts.json {
				return json.NewEncoder(a.config.Out).Encode(map[string]string{"version": version, "commit": a.config.Commit, "date": a.config.Date})
			}
			fmt.Fprintf(a.config.Out, "mactriage %s", version)
			if a.config.Commit != "" {
				fmt.Fprintf(a.config.Out, " (%s)", a.config.Commit)
			}
			fmt.Fprintln(a.config.Out)
			a.setExit(cmd, 0)
			return nil
		},
	}
}

func (a *application) renderReport(r report.Report) error {
	if a.opts.output != "" {
		if err := present.WriteAtomic(a.opts.output, 0o600, func(w io.Writer) error { return present.JSON(w, r) }); err != nil {
			return fmt.Errorf("write report: %w", err)
		}
	}
	if a.opts.json {
		return present.JSON(a.config.Out, r)
	}
	present.Human(a.config.Out, r, present.Style{Color: a.color(), Width: terminalWidth()})
	return nil
}

func (a *application) color() bool {
	if a.opts.plain || a.opts.json || a.opts.color == "never" {
		return false
	}
	if a.opts.color == "always" {
		return true
	}
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return writerTTY(a.config.Out)
}

func (a *application) animate() bool {
	if a.opts.plain || a.opts.accessible || a.opts.json || a.opts.animation == "never" {
		return false
	}
	if a.opts.animation == "always" {
		return true
	}
	if os.Getenv("CI") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return writerTTY(a.config.Err)
}

func (a *application) canPrompt() bool {
	return !a.opts.json && fileTTY(os.Stdin) && writerTTY(a.config.Err)
}

func (a *application) elevate(ctx context.Context, reason string, args []string) (bool, int, error) {
	if a.opts.json || !a.canPrompt() {
		return false, 0, errors.New("administrator access is required; rerun this command with sudo")
	}
	approved, err := present.Confirm("Continue with administrator access?", reason+"\nThe exact mactriage command will be re-run through /usr/bin/sudo. Default: No.", a.opts.accessible)
	if err != nil {
		return false, 0, err
	}
	if !approved {
		return false, 0, errors.New("administrator access was declined; no changes were made")
	}
	code, err := a.runSudo(ctx, args)
	return true, code, err
}

func (a *application) runSudo(ctx context.Context, args []string) (int, error) {
	executable, err := os.Executable()
	if err != nil {
		return 2, err
	}
	commandArgs := append([]string{"--", executable}, args...)
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", commandArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = a.config.Out
	cmd.Stderr = a.config.Err
	err = cmd.Run()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 2, err
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func writerTTY(writer io.Writer) bool {
	file, ok := writer.(*os.File)
	return ok && fileTTY(file)
}

func fileTTY(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func terminalWidth() int {
	if width, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && width >= 40 {
		return width
	}
	return 88
}

func configWriter(value, fallback io.Writer) io.Writer {
	if value != nil {
		return value
	}
	return fallback
}

type atomicStream struct {
	path string
	temp string
	file *os.File
}

func newAtomicStream(path string) (*atomicStream, error) {
	dir := filepath.Dir(path)
	file, err := os.CreateTemp(dir, ".mactriage-watch-*")
	if err != nil {
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		os.Remove(file.Name())
		return nil, err
	}
	return &atomicStream{path: path, temp: file.Name(), file: file}, nil
}

func (s *atomicStream) Commit() error {
	if s.file == nil {
		return nil
	}
	if err := s.file.Sync(); err != nil {
		return err
	}
	if err := s.file.Close(); err != nil {
		return err
	}
	s.file = nil
	return os.Rename(s.temp, s.path)
}

func (s *atomicStream) Abort() {
	if s.file != nil {
		s.file.Close()
	}
	if s.temp != "" {
		os.Remove(s.temp)
	}
}
