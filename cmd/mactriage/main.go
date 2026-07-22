package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mantaworks/mactriage/internal/cli"
)

var (
	version = "dev"
	commit  = ""
	date    = ""
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code := cli.Execute(ctx, cli.Config{Out: os.Stdout, Err: os.Stderr, Version: version, Commit: commit, Date: date}, os.Args[1:])
	os.Exit(code)
}
