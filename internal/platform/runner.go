package platform

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

type LineStreamer interface {
	StreamLines(context.Context, string, func([]byte) error, ...string) error
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

func (r ExecRunner) StreamLines(ctx context.Context, path string, consume func([]byte) error, args ...string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("executable path must be absolute: %q", path)
	}
	if consume == nil {
		return errors.New("line stream requires a consumer")
	}
	if r.Verbose != nil {
		r.Verbose(path + " " + joinArgs(args))
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	limit := r.MaxOutput
	if limit <= 0 {
		limit = 1 << 20
	}
	stderr := newLimitedBuffer(limit)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if err := consume(line); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err != nil {
		return fmt.Errorf("stream command failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
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
