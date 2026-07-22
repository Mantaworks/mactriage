package cli

import (
	"fmt"
	"io"

	"github.com/Mantaworks/mactriage/internal/present"
	"github.com/Mantaworks/mactriage/internal/schema"
	"github.com/spf13/cobra"
)

func (a *application) schemaCommand() *cobra.Command {
	return &cobra.Command{
		Use: "schema [report|watch]", Short: "Print a machine-readable JSON Schema", Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind := "report"
			if len(args) == 1 {
				kind = args[0]
			}
			data, err := schema.Document(kind)
			if err != nil {
				return err
			}
			data = append(data, '\n')
			if a.opts.output != "" {
				if err := present.WriteAtomic(a.opts.output, 0o600, func(w io.Writer) error { _, e := w.Write(data); return e }); err != nil {
					return fmt.Errorf("write schema: %w", err)
				}
			}
			_, err = a.config.Out.Write(data)
			a.setExit(cmd, 0)
			return err
		},
	}
}
