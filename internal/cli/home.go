package cli

import "github.com/Mantaworks/mactriage/internal/present"

func homeArgs(opts options, choice present.HomeChoice) []string {
	args := make([]string, 0, 14)
	if opts.output != "" {
		args = append(args, "--output", opts.output)
	}
	if opts.verbose {
		args = append(args, "--verbose")
	}
	if opts.plain {
		args = append(args, "--plain")
	}
	if opts.accessible {
		args = append(args, "--accessible")
	}
	args = append(args, "--color", opts.color, "--animation", opts.animation, "--timeout", opts.timeout.String())
	if opts.totalTimeout > 0 {
		args = append(args, "--total-timeout", opts.totalTimeout.String())
	}
	if opts.failOn != "" {
		args = append(args, "--fail-on", opts.failOn)
	}
	if opts.redact != "" {
		args = append(args, "--redact", opts.redact)
	}
	if opts.offline {
		args = append(args, "--offline")
	}
	if opts.json {
		args = append(args, "--json")
	}
	if choice.Task == "baseline-compare" {
		args = append(args, "baseline", "compare")
	} else if choice.Task == "doctor" {
		args = append(args, "doctor", "--quick", "--fix")
	} else if choice.Task == "doctor-health" {
		args = append(args, "doctor", "--full", "--only", "battery,thermal,backup")
	} else if choice.Task == "storage" {
		args = append(args, "storage", "--details", "--fix")
	} else if choice.Task == "startup" {
		args = append(args, "startup", "--fix")
	} else {
		args = append(args, choice.Task)
	}
	if choice.Target != "" {
		args = append(args, choice.Target)
	}
	return args
}
