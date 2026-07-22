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
var ErrProcessStillRunning = errors.New("the application did not quit after SIGTERM")

type RestartResult struct {
	OldPID    int  `json:"old_pid"`
	NewPID    int  `json:"new_pid"`
	Restarted bool `json:"restarted"`
}

type Outcome struct {
	Restart *RestartResult
}

type RelaunchResult struct {
	OldPIDs  []int `json:"old_pids"`
	NewPIDs  []int `json:"new_pids"`
	Forced   bool  `json:"forced"`
	Survived bool  `json:"survived"`
}

type Executor struct {
	Runner           platform.Runner
	EUID             func() int
	PollInterval     time.Duration
	TerminateTimeout time.Duration
}

func (e Executor) AppPIDs(ctx context.Context, processName string) ([]int, error) {
	if e.Runner == nil {
		return nil, errors.New("action executor requires a command runner")
	}
	return e.pidsNamed(ctx, processName)
}

func (e Executor) RelaunchApp(ctx context.Context, target, processName string, force bool, observe time.Duration) (RelaunchResult, error) {
	if e.Runner == nil {
		return RelaunchResult{}, errors.New("action executor requires a command runner")
	}
	if strings.TrimSpace(target) == "" || strings.TrimSpace(processName) == "" {
		return RelaunchResult{}, errors.New("relaunch requires an application and process name")
	}
	oldPIDs, _ := e.pidsNamed(ctx, processName)
	result := RelaunchResult{OldPIDs: append([]int(nil), oldPIDs...), Forced: force}
	if len(oldPIDs) > 0 {
		if err := e.signal(ctx, "-TERM", oldPIDs); err != nil {
			return result, fmt.Errorf("request application termination: %w", err)
		}
		if !e.waitGone(ctx, processName) {
			if !force {
				return result, ErrProcessStillRunning
			}
			remaining, _ := e.pidsNamed(ctx, processName)
			if len(remaining) > 0 {
				if err := e.signal(ctx, "-KILL", remaining); err != nil {
					return result, fmt.Errorf("force application termination: %w", err)
				}
				if !e.waitGone(ctx, processName) {
					return result, errors.New("application remained running after SIGKILL")
				}
			}
		}
	}
	if opened := e.Runner.Run(ctx, "/usr/bin/open", "-a", target); opened.Err != nil {
		return result, fmt.Errorf("reopen application: %w", opened.Err)
	}
	newPIDs, err := e.waitAppear(ctx, processName, 5*time.Second)
	if err != nil {
		return result, err
	}
	result.NewPIDs = newPIDs
	if observe <= 0 {
		observe = 3 * time.Second
	}
	timer := time.NewTimer(observe)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return result, ctx.Err()
	case <-timer.C:
	}
	stillRunning, _ := e.pidsNamed(ctx, processName)
	result.Survived = len(stillRunning) > 0
	if !result.Survived {
		return result, errors.New("application exited during relaunch verification")
	}
	return result, nil
}

func (e Executor) signal(ctx context.Context, signal string, pids []int) error {
	args := []string{signal}
	for _, pid := range pids {
		args = append(args, strconv.Itoa(pid))
	}
	return e.Runner.Run(ctx, "/bin/kill", args...).Err
}

func (e Executor) pidsNamed(ctx context.Context, processName string) ([]int, error) {
	result := e.Runner.Run(ctx, "/usr/bin/pgrep", "-x", processName)
	if result.Err != nil || strings.TrimSpace(result.Stdout) == "" {
		return nil, result.Err
	}
	var pids []int
	for _, field := range strings.Fields(result.Stdout) {
		pid, err := strconv.Atoi(field)
		if err == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

func (e Executor) waitGone(ctx context.Context, processName string) bool {
	timeout := e.TerminateTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	interval := e.PollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pids, _ := e.pidsNamed(ctx, processName)
		if len(pids) == 0 {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(interval):
		}
	}
	return false
}

func (e Executor) waitAppear(ctx context.Context, processName string, timeout time.Duration) ([]int, error) {
	interval := e.PollInterval
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		pids, _ := e.pidsNamed(ctx, processName)
		if len(pids) > 0 {
			return pids, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
	return nil, errors.New("restarted application did not appear before the verification deadline")
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

func (e Executor) openSoftwareUpdate(ctx context.Context) error {
	if result := e.Runner.Run(ctx, "/usr/bin/open", "/System/Library/PreferencePanes/SoftwareUpdate.prefPane"); result.Err != nil {
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
