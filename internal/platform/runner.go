package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Duration  time.Duration
	Err       error
	TimedOut  bool
	Truncated bool
}

type Runner interface {
	Run(context.Context, string, ...string) Result
}

type ExecRunner struct {
	Timeout   time.Duration
	MaxOutput int
	Verbose   func(string)
}

func (r ExecRunner) Run(parent context.Context, path string, args ...string) Result {
	if !filepath.IsAbs(path) {
		return Result{ExitCode: -1, Err: fmt.Errorf("executable path must be absolute: %q", path)}
	}
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	limit := r.MaxOutput
	if limit <= 0 {
		limit = 1 << 20
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	if r.Verbose != nil {
		r.Verbose(path + " " + joinArgs(args))
	}
	stdout := newLimitedBuffer(limit)
	stderr := newLimitedBuffer(limit)
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	started := time.Now()
	err := cmd.Run()
	result := Result{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Duration:  time.Since(started),
		Err:       err,
		TimedOut:  errors.Is(ctx.Err(), context.DeadlineExceeded),
		Truncated: stdout.truncated || stderr.truncated,
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	} else {
		result.ExitCode = -1
	}
	return result
}

func joinArgs(args []string) string {
	var out bytes.Buffer
	for i, arg := range args {
		if i > 0 {
			out.WriteByte(' ')
		}
		fmt.Fprintf(&out, "%q", arg)
	}
	return out.String()
}

type limitedBuffer struct {
	buf       bytes.Buffer
	remaining int
	truncated bool
}

func newLimitedBuffer(limit int) *limitedBuffer { return &limitedBuffer{remaining: limit} }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if b.remaining == 0 {
		b.truncated = b.truncated || original > 0
		return original, nil
	}
	toWrite := p
	if len(toWrite) > b.remaining {
		toWrite = toWrite[:b.remaining]
		b.truncated = true
	}
	n, err := b.buf.Write(toWrite)
	b.remaining -= n
	if err != nil && !errors.Is(err, io.EOF) {
		return n, err
	}
	return original, nil
}

func (b *limitedBuffer) String() string { return b.buf.String() }
