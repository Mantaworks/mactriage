package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"github.com/upsidedly/mactriage/internal/present"
)

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

func summarizeCounts(values map[string]int, limit int) string {
	type pair struct {
		key   string
		count int
	}
	pairs := make([]pair, 0, len(values))
	for key, count := range values {
		pairs = append(pairs, pair{key: key, count: count})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count == pairs[j].count {
			return pairs[i].key < pairs[j].key
		}
		return pairs[i].count > pairs[j].count
	})
	if len(pairs) > limit {
		pairs = pairs[:limit]
	}
	parts := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		parts = append(parts, fmt.Sprintf("%s=%d", pair.key, pair.count))
	}
	return strings.Join(parts, ", ")
}

func writerTTY(writer io.Writer) bool { file, ok := writer.(*os.File); return ok && fileTTY(file) }
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
