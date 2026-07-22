package action

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Mantaworks/mactriage/internal/platform"
)

var ErrNeedsElevation = errors.New("this action requires root privileges")

type RestartResult struct {
	OldPID    int  `json:"old_pid"`
	NewPID    int  `json:"new_pid"`
	Restarted bool `json:"restarted"`
}

type Outcome struct {
	Restart *RestartResult
}

type Executor struct {
	Runner       platform.Runner
	EUID         func() int
	PollInterval time.Duration
}

func (e Executor) openSecurity(ctx context.Context) error {
	if result := e.Runner.Run(ctx, "/usr/bin/open", "x-apple.systempreferences:com.apple.preference.security?General"); result.Err != nil {
		return result.Err
	}
	if err := e.waitForProcess(ctx, "System Settings", 5*time.Second); err != nil {
		return fmt.Errorf("verify System Settings: %w", err)
	}
	return nil
}

func (e Executor) launchRosetta(ctx context.Context, target string) error {
	return e.Runner.Run(ctx, "/usr/bin/open", "-a", target).Err
}

func (e Executor) waitForProcess(ctx context.Context, name string, timeout time.Duration) error {
	interval := e.PollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		result := e.Runner.Run(ctx, "/usr/bin/pgrep", "-x", name)
		if result.Err == nil && strings.TrimSpace(result.Stdout) != "" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
	return errors.New("process did not appear before the verification deadline")
}

func (e Executor) RestartSyspolicyd(ctx context.Context) (RestartResult, error) {
	euid := e.EUID
	if euid == nil {
		euid = os.Geteuid
	}
	if euid() != 0 {
		return RestartResult{}, ErrNeedsElevation
	}
	if e.Runner == nil {
		return RestartResult{}, errors.New("repair executor requires a command runner")
	}
	oldPID, err := e.pid(ctx)
	if err != nil {
		return RestartResult{}, fmt.Errorf("locate syspolicyd: %w", err)
	}
	if result := e.Runner.Run(ctx, "/usr/bin/killall", "syspolicyd"); result.Err != nil {
		return RestartResult{OldPID: oldPID}, fmt.Errorf("terminate syspolicyd: %w", result.Err)
	}
	interval := e.PollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		newPID, pidErr := e.pid(ctx)
		if pidErr == nil && newPID != 0 && newPID != oldPID {
			return RestartResult{OldPID: oldPID, NewPID: newPID, Restarted: true}, nil
		}
		select {
		case <-ctx.Done():
			return RestartResult{OldPID: oldPID}, ctx.Err()
		case <-time.After(interval):
		}
	}
	return RestartResult{OldPID: oldPID}, errors.New("launchd did not start a new syspolicyd process within 10 seconds")
}

func (e Executor) pid(ctx context.Context) (int, error) {
	result := e.Runner.Run(ctx, "/usr/bin/pgrep", "-x", "syspolicyd")
	if result.Err != nil {
		return 0, result.Err
	}
	fields := strings.Fields(result.Stdout)
	if len(fields) == 0 {
		return 0, errors.New("process not found")
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, fmt.Errorf("invalid PID %q", fields[0])
	}
	return pid, nil
}
