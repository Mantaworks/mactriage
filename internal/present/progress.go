package present

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/upsidedly/mactriage/internal/report"
)

type ProgressEvent struct {
	ID       string
	Label    string
	Status   string
	Duration time.Duration
}

type progressResult struct {
	Report report.Report
	Err    error
}

type progressMessage ProgressEvent
type resultMessage progressResult

type progressModel struct {
	spinner spinner.Model
	events  <-chan any
	items   map[string]ProgressEvent
	order   []string
	color   bool
	done    bool
	result  progressResult
}

func RunProgress(ctx context.Context, out io.Writer, color bool, work func(func(ProgressEvent)) (report.Report, error)) (report.Report, error) {
	events := make(chan any, 32)
	spin := spinner.New()
	spin.Spinner = spinner.Dot
	spin.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	model := progressModel{spinner: spin, events: events, items: map[string]ProgressEvent{}, color: color}
	program := tea.NewProgram(model, tea.WithOutput(out), tea.WithInput(nil), tea.WithContext(ctx))
	go func() {
		r, err := work(func(event ProgressEvent) { events <- progressMessage(event) })
		events <- resultMessage{Report: r, Err: err}
	}()
	final, err := program.Run()
	if err != nil {
		return report.Report{}, err
	}
	return final.(progressModel).result.Report, final.(progressModel).result.Err
}

func (m progressModel) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, waitForProgress(m.events))
}

func waitForProgress(events <-chan any) tea.Cmd {
	return func() tea.Msg { return <-events }
}

func (m progressModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case progressMessage:
		event := ProgressEvent(msg)
		if _, exists := m.items[event.ID]; !exists {
			m.order = append(m.order, event.ID)
		}
		m.items[event.ID] = event
		return m, waitForProgress(m.events)
	case resultMessage:
		m.result = progressResult(msg)
		m.done = true
		return m, tea.Quit
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m progressModel) View() string {
	if len(m.order) == 0 {
		if m.done {
			return ""
		}
		return m.spinner.View() + " Preparing diagnostic checks…\n"
	}
	var b strings.Builder
	for _, id := range m.order {
		event := m.items[id]
		icon := m.spinner.View()
		if event.Status != "running" {
			icon = statusIcon(event.Status, m.color)
		}
		fmt.Fprintf(&b, "%s %s", icon, event.Label)
		if event.Duration > 0 {
			fmt.Fprintf(&b, "  %s", muted(event.Duration.Round(10*time.Millisecond).String(), m.color))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func PlainProgress(out io.Writer, work func(func(ProgressEvent)) (report.Report, error)) (report.Report, error) {
	return work(func(event ProgressEvent) {
		if event.Status != "running" {
			fmt.Fprintf(out, "%s %s\n", statusIcon(event.Status, false), event.Label)
		}
	})
}

func Confirm(title, description string, accessible bool) (bool, error) {
	confirmed := false
	field := huh.NewConfirm().Title(title).Description(description).Affirmative("Yes").Negative("No").Value(&confirmed)
	form := huh.NewForm(huh.NewGroup(field)).WithInput(os.Stdin).WithOutput(os.Stderr).WithAccessible(accessible)
	if err := form.Run(); err != nil {
		return false, err
	}
	return confirmed, nil
}

type Choice struct {
	Label string
	Value string
}

func Select(title string, choices []Choice, accessible bool) (string, error) {
	if len(choices) == 0 {
		return "", fmt.Errorf("no choices available")
	}
	selected := choices[0].Value
	options := make([]huh.Option[string], 0, len(choices))
	for _, choice := range choices {
		options = append(options, huh.NewOption(choice.Label, choice.Value))
	}
	field := huh.NewSelect[string]().Title(title).Options(options...).Value(&selected)
	form := huh.NewForm(huh.NewGroup(field)).WithInput(os.Stdin).WithOutput(os.Stderr).WithAccessible(accessible)
	if err := form.Run(); err != nil {
		return "", err
	}
	return selected, nil
}

func statusIcon(status string, color bool) string {
	switch status {
	case string(report.StatusOK):
		return decorate("✓", "10", true, color)
	case string(report.StatusFailed):
		return decorate("✗", "9", true, color)
	case string(report.StatusTimedOut):
		return decorate("!", "11", true, color)
	case string(report.StatusUnavailable):
		return decorate("?", "11", true, color)
	case string(report.StatusSkipped):
		return decorate("–", "8", true, color)
	default:
		return "•"
	}
}

func muted(text string, color bool) string {
	if !color {
		return text
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Render(text)
}
