package report

import (
	"encoding/json"
	"io"

	"github.com/user/pnpm-vuln-fixer/internal/analyzer"
)

// PrintJSON marshals the report to indented JSON and writes it to w.
func PrintJSON(w io.Writer, r *analyzer.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
