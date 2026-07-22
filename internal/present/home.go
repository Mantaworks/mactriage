package present

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/huh"
)

type HomeChoice struct {
	Task   string
	Target string
}

func GettingStarted(w io.Writer, color bool) {
	name := "mactriage"
	tagline := "Mac app troubleshooting, explained in plain language."
	if color {
		name = decorate(name, "12", true, true)
		tagline = decorate(tagline, "8", false, true)
	}
	fmt.Fprintf(w, "%s\n%s\n\nWhat would you like to troubleshoot?\n\n", name, tagline)
	task := func(label, command string) {
		fmt.Fprintf(w, "  %s %-23s %s\n", decorate("◆", "12", true, color), label, decorate(command, "8", false, color))
	}
	task("App will not open", "mactriage diagnose <app>")
	task("App is frozen or slow", "mactriage hang <app|pid>")
	task("Permission problem", "mactriage permissions <app>")
	task("Check installed apps", "mactriage scan")
	task("Mac resource pressure", "mactriage system")
	fmt.Fprintln(w, "\nRun mactriage in a terminal for the guided menu, or mactriage --help for every command.")
}

func Home(accessible bool) (HomeChoice, error) {
	var task string
	options := []huh.Option[string]{
		huh.NewOption("An app will not open", "diagnose"),
		huh.NewOption("An app is frozen or slow", "hang"),
		huh.NewOption("An app cannot access something", "permissions"),
		huh.NewOption("Check all installed apps", "scan"),
		huh.NewOption("Check Mac resource pressure", "system"),
		huh.NewOption("Watch a running process", "watch"),
		huh.NewOption("Create a support bundle", "collect"),
		huh.NewOption("Explain a diagnostic code", "explain"),
	}
	selectField := huh.NewSelect[string]().Title("What would you like to troubleshoot?").Options(options...).Value(&task)
	form := huh.NewForm(huh.NewGroup(selectField)).WithShowHelp(true).WithShowErrors(true)
	if accessible {
		form = form.WithAccessible(true)
	}
	if err := form.Run(); err != nil {
		return HomeChoice{}, err
	}
	if task == "system" || task == "scan" {
		return HomeChoice{Task: task}, nil
	}
	label := "Application name, bundle ID, or .app path"
	placeholder := "Safari, com.apple.Safari, or /Applications/Safari.app"
	if task == "watch" || task == "hang" {
		label = "Process name or PID"
		placeholder = "Discord or 497"
	} else if task == "explain" {
		label = "Diagnostic code"
		placeholder = "gatekeeper.rejected"
	}
	var target string
	input := huh.NewInput().Title(label).Placeholder(placeholder).Value(&target).Validate(func(value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("a value is required")
		}
		return nil
	})
	form = huh.NewForm(huh.NewGroup(input)).WithShowHelp(true).WithShowErrors(true)
	if accessible {
		form = form.WithAccessible(true)
	}
	if err := form.Run(); err != nil {
		return HomeChoice{}, err
	}
	return HomeChoice{Task: task, Target: strings.TrimSpace(target)}, nil
}
