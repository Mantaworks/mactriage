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
	if opts.json {
		args = append(args, "--json")
	}
	if choice.Task == "baseline-compare" {
		args = append(args, "baseline", "compare")
	} else {
		args = append(args, choice.Task)
	}
	if choice.Target != "" {
		args = append(args, choice.Target)
	}
	return args
}
