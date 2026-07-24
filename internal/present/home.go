package present

import (
	"fmt"
	"io"
	"strings"

	"github.com/Mantaworks/mactriage/internal/localize"
	"github.com/charmbracelet/huh"
)

type HomeChoice struct {
	Task   string
	Target string
}

func GettingStarted(w io.Writer, color bool) {
	GettingStartedWithMessages(w, color, localize.Default())
}

func GettingStartedWithMessages(w io.Writer, color bool, messages localize.Messages) {
	name := messages.Text(localize.AppName)
	tagline := messages.Text(localize.HomeTagline)
	if color {
		name = decorate(name, "12", true, true)
		tagline = decorate(tagline, "8", false, true)
	}
	fmt.Fprintf(w, "%s\n%s\n\n%s\n\n", name, tagline, messages.Text(localize.HomePrompt))
	task := func(label, command string) {
		fmt.Fprintf(w, "  %s %-23s %s\n", decorate("◆", "12", true, color), label, decorate(command, "8", false, color))
	}
	task(messages.Text(localize.GettingStartedQuick), "mactriage doctor --quick")
	task(messages.Text(localize.GettingStartedStorage), "mactriage storage --details")
	task(messages.Text(localize.GettingStartedDiagnose), "mactriage diagnose <app>")
	task(messages.Text(localize.GettingStartedHang), "mactriage hang <app|pid>")
	task(messages.Text(localize.GettingStartedNetwork), "mactriage network [host]")
	task(messages.Text(localize.GettingStartedPermissions), "mactriage permissions <app>")
	task(messages.Text(localize.GettingStartedScan), "mactriage scan")
	task(messages.Text(localize.GettingStartedShare), "mactriage share <app|report>")
	fmt.Fprintln(w, "\n"+messages.Text(localize.GettingStartedHint))
}

func Home(accessible bool) (HomeChoice, error) {
	return HomeWithMessages(accessible, localize.Default())
}

func HomeWithMessages(accessible bool, messages localize.Messages) (HomeChoice, error) {
	var task string
	options := []huh.Option[string]{
		huh.NewOption(messages.Text(localize.HomeOptionDoctor), "doctor"),
		huh.NewOption(messages.Text(localize.HomeOptionStorage), "storage"),
		huh.NewOption(messages.Text(localize.HomeOptionStartup), "startup"),
		huh.NewOption(messages.Text(localize.HomeOptionDoctorHealth), "doctor-health"),
		huh.NewOption(messages.Text(localize.HomeOptionDiagnose), "diagnose"),
		huh.NewOption(messages.Text(localize.HomeOptionHang), "hang"),
		huh.NewOption(messages.Text(localize.HomeOptionNetwork), "network"),
		huh.NewOption(messages.Text(localize.HomeOptionPermissions), "permissions"),
		huh.NewOption(messages.Text(localize.HomeOptionRelaunch), "relaunch"),
		huh.NewOption(messages.Text(localize.HomeOptionBaselineCompare), "baseline-compare"),
		huh.NewOption(messages.Text(localize.HomeOptionShare), "share"),
		huh.NewOption(messages.Text(localize.HomeOptionScan), "scan"),
		huh.NewOption(messages.Text(localize.HomeOptionSystem), "system"),
		huh.NewOption(messages.Text(localize.HomeOptionWatch), "watch"),
		huh.NewOption(messages.Text(localize.HomeOptionCollect), "collect"),
		huh.NewOption(messages.Text(localize.HomeOptionExplain), "explain"),
	}
	selectField := huh.NewSelect[string]().Title(messages.Text(localize.HomePrompt)).Options(options...).Value(&task)
	form := huh.NewForm(huh.NewGroup(selectField)).WithShowHelp(true).WithShowErrors(true)
	if accessible {
		form = form.WithAccessible(true)
	}
	if err := form.Run(); err != nil {
		return HomeChoice{}, err
	}
	if task == "doctor" || task == "doctor-health" || task == "storage" || task == "startup" || task == "system" || task == "scan" {
		return HomeChoice{Task: task}, nil
	}
	label := messages.Text(localize.HomeInputApplicationTitle)
	placeholder := messages.Text(localize.HomeInputApplicationHint)
	if task == "watch" || task == "hang" {
		label = messages.Text(localize.HomeInputProcessTitle)
		placeholder = messages.Text(localize.HomeInputProcessHint)
	} else if task == "explain" {
		label = messages.Text(localize.HomeInputCodeTitle)
		placeholder = messages.Text(localize.HomeInputCodeHint)
	} else if task == "network" {
		label = messages.Text(localize.HomeInputNetworkTitle)
		placeholder = messages.Text(localize.HomeInputNetworkHint)
	} else if task == "baseline-compare" {
		label = messages.Text(localize.HomeInputBaselineTitle)
		placeholder = messages.Text(localize.HomeInputBaselineHint)
	} else if task == "share" {
		label = messages.Text(localize.HomeInputShareTitle)
		placeholder = messages.Text(localize.HomeInputShareHint)
	}
	var target string
	input := huh.NewInput().Title(label).Placeholder(placeholder).Value(&target).Validate(func(value string) error {
		if task == "network" {
			return nil
		}
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s", messages.Text(localize.HomeInputRequired))
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
