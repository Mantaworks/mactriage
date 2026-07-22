package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/Mantaworks/mactriage/internal/cli"
	"github.com/spf13/cobra/doc"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen-docs OUTPUT_DIRECTORY")
		os.Exit(2)
	}
	rootDir := os.Args[1]
	manDir := filepath.Join(rootDir, "man")
	completionDir := filepath.Join(rootDir, "completions")
	for _, dir := range []string{manDir, completionDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			fatal(err)
		}
	}
	root := cli.New(cli.Config{Version: "generated"})
	root.DisableAutoGenTag = true
	date := time.Unix(0, 0)
	header := &doc.GenManHeader{Title: "MACTRIAGE", Section: "1", Source: "mactriage", Manual: "mactriage Manual", Date: &date}
	if err := doc.GenManTree(root, header, manDir); err != nil {
		fatal(err)
	}
	generators := map[string]func(io.Writer) error{
		"mactriage.bash": root.GenBashCompletion,
		"_mactriage":     root.GenZshCompletion,
		"mactriage.fish": func(file io.Writer) error { return root.GenFishCompletion(file, true) },
		"mactriage.ps1":  root.GenPowerShellCompletion,
	}
	for name, generate := range generators {
		file, err := os.Create(filepath.Join(completionDir, name))
		if err != nil {
			fatal(err)
		}
		if err := generate(file); err != nil {
			file.Close()
			fatal(err)
		}
		if err := file.Close(); err != nil {
			fatal(err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
