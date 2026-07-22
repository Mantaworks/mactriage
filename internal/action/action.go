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

func (e Executor) RelaunchApp(ctx context.Context, target, processName string, approvedPIDs []int, force bool, observe time.Duration) (RelaunchResult, error) {
	if e.Runner == nil {
		return RelaunchResult{}, errors.New("action executor requires a command runner")
	}
	if strings.TrimSpace(target) == "" || strings.TrimSpace(processName) == "" {
		return RelaunchResult{}, errors.New("relaunch requires an application and process name")
	}
	approvedPIDs = validPIDs(approvedPIDs)
	result := RelaunchResult{OldPIDs: append([]int(nil), approvedPIDs...), Forced: force}
	if len(approvedPIDs) > 0 {
		if force {
			remaining, err := e.pidsNamed(ctx, processName)
			if err != nil {
				return result, fmt.Errorf("verify approved application processes: %w", err)
			}
			remaining = intersectPIDs(remaining, approvedPIDs)
			if len(remaining) > 0 {
				if err := e.signal(ctx, "-KILL", remaining); err != nil {
					return result, fmt.Errorf("force application termination: %w", err)
				}
				if err := e.waitGone(ctx, processName, approvedPIDs); err != nil {
					if !errors.Is(err, errVerificationDeadline) {
						return result, fmt.Errorf("verify forced application termination: %w", err)
					}
					return result, errors.New("application remained running after SIGKILL")
				}
			}
		} else {
			if err := e.signal(ctx, "-TERM", approvedPIDs); err != nil {
				return result, fmt.Errorf("request application termination: %w", err)
			}
			if err := e.waitGone(ctx, processName, approvedPIDs); err != nil {
				if !errors.Is(err, errVerificationDeadline) {
					return result, fmt.Errorf("verify application termination: %w", err)
				}
				return result, ErrProcessStillRunning
			}
		}
	}
	preOpenPIDs, err := e.pidsNamed(ctx, processName)
	if err != nil {
		return result, fmt.Errorf("snapshot processes before reopening: %w", err)
	}
	if opened := e.Runner.Run(ctx, "/usr/bin/open", "-a", target); opened.Err != nil {
		return result, fmt.Errorf("reopen application: %w", opened.Err)
	}
	newPIDs, err := e.waitAppear(ctx, processName, preOpenPIDs, 5*time.Second)
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
	stillRunning, err := e.pidsNamed(ctx, processName)
	if err != nil {
		return result, fmt.Errorf("verify relaunched application survival: %w", err)
	}
	result.Survived = len(intersectPIDs(stillRunning, newPIDs)) > 0
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
		if result.ExitCode == 1 && strings.TrimSpace(result.Stdout) == "" {
			return nil, nil
		}
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

func (e Executor) waitGone(ctx context.Context, processName string, approvedPIDs []int) error {
	timeout := e.TerminateTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	_, err := pollUntil(ctx, e.PollInterval, timeout, func() (struct{}, bool, error) {
		pids, probeErr := e.pidsNamed(ctx, processName)
		return struct{}{}, len(intersectPIDs(pids, approvedPIDs)) == 0, probeErr
	})
	return err
}

func (e Executor) waitAppear(ctx context.Context, processName string, excludedPIDs []int, timeout time.Duration) ([]int, error) {
	pids, err := pollUntil(ctx, e.PollInterval, timeout, func() ([]int, bool, error) {
		pids, probeErr := e.pidsNamed(ctx, processName)
		pids = excludePIDs(pids, excludedPIDs)
		return pids, len(pids) > 0, probeErr
	})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("restarted application did not appear before the verification deadline")
	}
	return pids, nil
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

func (e Executor) openAndVerify(ctx context.Context, process string, args ...string) error {
	if result := e.Runner.Run(ctx, "/usr/bin/open", args...); result.Err != nil {
		return result.Err
	}
	if err := e.waitForProcess(ctx, process, 5*time.Second); err != nil {
		return fmt.Errorf("verify %s: %w", process, err)
	}
	return nil
}

func (e Executor) launchRosetta(ctx context.Context, target string) error {
	return e.Runner.Run(ctx, "/usr/bin/open", "-a", target).Err
}

func (e Executor) waitForProcess(ctx context.Context, name string, timeout time.Duration) error {
	if _, err := e.waitAppear(ctx, name, nil, timeout); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("process did not appear before the verification deadline")
	}
	return nil
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
	newPID, waitErr := pollUntil(ctx, e.PollInterval, 10*time.Second, func() (int, bool, error) {
		newPID, pidErr := e.pid(ctx)
		if pidErr != nil {
			if errors.Is(pidErr, errProcessNotFound) {
				return 0, false, nil
			}
			return 0, false, pidErr
		}
		return newPID, newPID != 0 && newPID != oldPID, nil
	})
	if waitErr == nil {
		return RestartResult{OldPID: oldPID, NewPID: newPID, Restarted: true}, nil
	}
	if ctx.Err() != nil {
		return RestartResult{OldPID: oldPID}, ctx.Err()
	}
	return RestartResult{OldPID: oldPID}, errors.New("launchd did not start a new syspolicyd process within 10 seconds")
}

func validPIDs(pids []int) []int {
	seen := map[int]bool{}
	valid := make([]int, 0, len(pids))
	for _, pid := range pids {
		if pid > 0 && !seen[pid] {
			seen[pid] = true
			valid = append(valid, pid)
		}
	}
	return valid
}

func intersectPIDs(current, allowed []int) []int {
	allowedSet := make(map[int]bool, len(allowed))
	for _, pid := range allowed {
		allowedSet[pid] = true
	}
	var matching []int
	for _, pid := range current {
		if allowedSet[pid] {
			matching = append(matching, pid)
		}
	}
	return matching
}

func excludePIDs(current, excluded []int) []int {
	excludedSet := make(map[int]bool, len(excluded))
	for _, pid := range excluded {
		excludedSet[pid] = true
	}
	var remaining []int
	for _, pid := range current {
		if !excludedSet[pid] {
			remaining = append(remaining, pid)
		}
	}
	return remaining
}

var errVerificationDeadline = errors.New("verification deadline exceeded")
var errProcessNotFound = errors.New("process not found")

func pollUntil[T any](ctx context.Context, interval, timeout time.Duration, probe func() (T, bool, error)) (T, error) {
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		value, ready, err := probe()
		if err != nil {
			var zero T
			return zero, err
		}
		if ready {
			return value, nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			var zero T
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	var zero T
	return zero, errVerificationDeadline
}

func (e Executor) pid(ctx context.Context) (int, error) {
	pids, err := e.pidsNamed(ctx, "syspolicyd")
	if err != nil {
		return 0, err
	}
	if len(pids) == 0 {
		return 0, errProcessNotFound
	}
	return pids[0], nil
}
