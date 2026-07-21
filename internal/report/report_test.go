package report_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/user/pnpm-vuln-fixer/internal/analyzer"
	"github.com/user/pnpm-vuln-fixer/internal/graph"
	"github.com/user/pnpm-vuln-fixer/internal/report"
)

func importerNode(path string) *graph.Node {
	return &graph.Node{DepPath: path, Name: path, IsRoot: true}
}

func pkgNode(name, version string) *graph.Node {
	return &graph.Node{DepPath: name + "@" + version, Name: name, Version: version}
}

func TestPrintHuman_NoBumpNeeded(t *testing.T) {
	r := &analyzer.Report{
		VulnPkg:    "lodash",
		VulnVer:    "4.17.10",
		FixedVer:   "4.17.21",
		AllFixable: true,
		Chains: []*analyzer.ChainResult{
			{
				Chain:   []*graph.Node{importerNode("."), pkgNode("express", "4.16.0"), pkgNode("lodash", "4.17.10")},
				Verdict: analyzer.VerdictNoBumpNeeded,
			},
		},
	}

	var buf bytes.Buffer
	report.PrintHuman(&buf, r)
	out := buf.String()

	checks := []struct {
		label string
		want  string
	}{
		{"vulnerable line", "Vulnerable: lodash@4.17.10"},
		{"fixed version", "fixed 4.17.21"},
		{"chain line", "Chain 1:"},
		{"chain path", ". > express@4.16.0 > lodash@4.17.10"},
		{"satisfied message", "already satisfied"},
		{"fix line", "FIX: no package updates needed"},
	}
	for _, c := range checks {
		if !strings.Contains(out, c.want) {
			t.Errorf("missing %s (%q) in output:\n%s", c.label, c.want, out)
		}
	}
}

func TestPrintHuman_DirectDep(t *testing.T) {
	r := &analyzer.Report{
		VulnPkg:    "lodash",
		VulnVer:    "4.17.10",
		FixedVer:   "4.17.21",
		AllFixable: true,
		Chains: []*analyzer.ChainResult{
			{
				Chain:   []*graph.Node{importerNode("."), pkgNode("lodash", "4.17.10")},
				Verdict: analyzer.VerdictDirectDep,
				Actions: []analyzer.FixAction{{Package: "lodash", ToVer: "4.17.21"}},
			},
		},
	}

	var buf bytes.Buffer
	report.PrintHuman(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "direct dependency") {
		t.Errorf("missing 'direct dependency' in output:\n%s", out)
	}
	if !strings.Contains(out, "4.17.21") {
		t.Errorf("missing fixedVer in output:\n%s", out)
	}
	if !strings.Contains(out, "FIX:") {
		t.Errorf("missing FIX line in output:\n%s", out)
	}
}

func TestPrintHuman_Bump(t *testing.T) {
	r := &analyzer.Report{
		VulnPkg:    "lodash",
		VulnVer:    "4.17.10",
		FixedVer:   "4.17.21",
		AllFixable: true,
		Chains: []*analyzer.ChainResult{
			{
				Chain:   []*graph.Node{importerNode("."), pkgNode("express", "4.16.0"), pkgNode("lodash", "4.17.10")},
				Verdict: analyzer.VerdictBump,
				Actions: []analyzer.FixAction{
					{Package: "express", FromVer: "4.16.0", ToVer: "4.17.1"},
				},
			},
		},
		MinUnion: []analyzer.FixAction{
			{Package: "express", ToVer: "4.17.1"},
		},
	}

	var buf bytes.Buffer
	report.PrintHuman(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "bump express from 4.16.0 to 4.17.1") {
		t.Errorf("missing bump action in output:\n%s", out)
	}
	if !strings.Contains(out, "FIX:") {
		t.Errorf("missing FIX line in output:\n%s", out)
	}
	if !strings.Contains(out, "express → 4.17.1") {
		t.Errorf("missing MinUnion entry in output:\n%s", out)
	}
}

func TestPrintHuman_BumpWithSpecifier(t *testing.T) {
	r := &analyzer.Report{
		VulnPkg:    "lodash",
		VulnVer:    "4.17.10",
		FixedVer:   "4.17.21",
		AllFixable: true,
		Chains: []*analyzer.ChainResult{
			{
				Chain:   []*graph.Node{importerNode("."), pkgNode("express", "4.16.0"), pkgNode("lodash", "4.17.10")},
				Verdict: analyzer.VerdictBump,
				Actions: []analyzer.FixAction{
					{Package: "express", FromVer: "4.16.0", ToVer: "4.17.1"},
					{Package: "express", ToVer: "^4.17.1", IsSpecifier: true},
				},
			},
		},
		// MinUnion includes both the version bump and the specifier update so that
		// the FIX summary is self-sufficient (users need both changes).
		MinUnion: []analyzer.FixAction{
			{Package: "express", ToVer: "4.17.1"},
			{Package: "express", ToVer: "^4.17.1", IsSpecifier: true},
		},
	}

	var buf bytes.Buffer
	report.PrintHuman(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "bump express") {
		t.Errorf("missing per-chain bump action in output:\n%s", out)
	}
	// Per-chain output must show the specifier update.
	if !strings.Contains(out, "specifier") {
		t.Errorf("missing specifier update in per-chain output:\n%s", out)
	}
	// FIX summary must also show the specifier update (not just the version bump).
	if !strings.Contains(out, "FIX:") {
		t.Errorf("missing FIX line in output:\n%s", out)
	}
	if !strings.Contains(out, "package.json") {
		t.Errorf("FIX summary missing package.json specifier instruction:\n%s", out)
	}
	if !strings.Contains(out, "^4.17.1") {
		t.Errorf("missing new specifier value in output:\n%s", out)
	}
}

func TestPrintHuman_DeadEnd_Override(t *testing.T) {
	r := &analyzer.Report{
		VulnPkg:       "lodash",
		VulnVer:       "1.0.0",
		FixedVer:      "2.0.0",
		AllFixable:    false,
		NeedsOverride: true,
		Chains: []*analyzer.ChainResult{
			{
				Chain:       []*graph.Node{importerNode("."), pkgNode("blocker", "1.0.0"), pkgNode("lodash", "1.0.0")},
				Verdict:     analyzer.VerdictDeadEnd,
				BlockedBy:   "blocker",
				BlockReason: "blocker@1.0.0 has no published version whose range for lodash admits 2.0.0",
			},
		},
	}

	var buf bytes.Buffer
	report.PrintHuman(&buf, r)
	out := buf.String()

	checks := []struct {
		label string
		want  string
	}{
		{"BLOCKED line", "BLOCKED:"},
		{"block reason", "blocker@1.0.0"},
		{"NO FIX line", "NO FIX:"},
		{"OVERRIDE section", "OVERRIDE"},
		{"pnpm overrides key", "\"pnpm\""},
		{"package in override", "\"lodash\""},
		{"fixed version in override", "\"2.0.0\""},
	}
	for _, c := range checks {
		if !strings.Contains(out, c.want) {
			t.Errorf("missing %s (%q) in output:\n%s", c.label, c.want, out)
		}
	}
}

func TestPrintHuman_PartialFix(t *testing.T) {
	r := &analyzer.Report{
		VulnPkg:       "lodash",
		VulnVer:       "1.0.0",
		FixedVer:      "2.0.0",
		AllFixable:    false,
		NeedsOverride: true,
		Chains: []*analyzer.ChainResult{
			{
				Chain:   []*graph.Node{importerNode("."), pkgNode("express", "4.16.0"), pkgNode("lodash", "1.0.0")},
				Verdict: analyzer.VerdictBump,
				Actions: []analyzer.FixAction{{Package: "express", FromVer: "4.16.0", ToVer: "4.17.1"}},
			},
			{
				Chain:       []*graph.Node{importerNode("."), pkgNode("blocker", "1.0.0"), pkgNode("lodash", "1.0.0")},
				Verdict:     analyzer.VerdictDeadEnd,
				BlockedBy:   "blocker",
				BlockReason: "blocker@1.0.0 has no published version whose range for lodash admits 2.0.0",
			},
		},
		MinUnion: []analyzer.FixAction{{Package: "express", ToVer: "4.17.1"}},
	}

	var buf bytes.Buffer
	report.PrintHuman(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "PARTIAL FIX") {
		t.Errorf("missing PARTIAL FIX in output:\n%s", out)
	}
	if !strings.Contains(out, "1/2") {
		t.Errorf("missing chain count (1/2) in output:\n%s", out)
	}
	if !strings.Contains(out, "OVERRIDE") {
		t.Errorf("missing OVERRIDE section in output:\n%s", out)
	}
}

func TestPrintHuman_ChainPathFormat_Scoped(t *testing.T) {
	r := &analyzer.Report{
		VulnPkg:    "@babel/traverse",
		VulnVer:    "7.22.0",
		FixedVer:   "7.23.0",
		AllFixable: true,
		Chains: []*analyzer.ChainResult{
			{
				Chain: []*graph.Node{
					importerNode("."),
					pkgNode("webpack", "5.0.0"),
					pkgNode("@babel/traverse", "7.22.0"),
				},
				Verdict: analyzer.VerdictNoBumpNeeded,
			},
		},
	}

	var buf bytes.Buffer
	report.PrintHuman(&buf, r)
	out := buf.String()

	if !strings.Contains(out, "@babel/traverse@7.22.0") {
		t.Errorf("missing scoped package in chain path:\n%s", out)
	}
}

func TestPrintJSON_RoundTrip(t *testing.T) {
	r := &analyzer.Report{
		VulnPkg:    "lodash",
		VulnVer:    "4.17.10",
		FixedVer:   "4.17.21",
		AllFixable: true,
		Chains: []*analyzer.ChainResult{
			{
				Chain:   []*graph.Node{importerNode("."), pkgNode("express", "4.16.0"), pkgNode("lodash", "4.17.10")},
				Verdict: analyzer.VerdictBump,
				Actions: []analyzer.FixAction{
					{Package: "express", FromVer: "4.16.0", ToVer: "4.17.1"},
				},
			},
		},
		MinUnion: []analyzer.FixAction{{Package: "express", ToVer: "4.17.1"}},
	}

	var buf bytes.Buffer
	if err := report.PrintJSON(&buf, r); err != nil {
		t.Fatalf("PrintJSON error: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\nOutput:\n%s", err, buf.String())
	}

	if decoded["VulnPkg"] != "lodash" {
		t.Errorf("VulnPkg = %v, want lodash", decoded["VulnPkg"])
	}
	if decoded["FixedVer"] != "4.17.21" {
		t.Errorf("FixedVer = %v, want 4.17.21", decoded["FixedVer"])
	}
	if decoded["AllFixable"] != true {
		t.Errorf("AllFixable = %v, want true", decoded["AllFixable"])
	}

	chains, ok := decoded["Chains"].([]interface{})
	if !ok || len(chains) == 0 {
		t.Errorf("Chains missing or empty in JSON output")
	}
	minUnion, ok := decoded["MinUnion"].([]interface{})
	if !ok || len(minUnion) == 0 {
		t.Errorf("MinUnion missing or empty in JSON output")
	}
}

func TestPrintJSON_Empty(t *testing.T) {
	r := &analyzer.Report{
		VulnPkg:  "pkg",
		VulnVer:  "1.0.0",
		FixedVer: "2.0.0",
	}

	var buf bytes.Buffer
	if err := report.PrintJSON(&buf, r); err != nil {
		t.Fatalf("PrintJSON error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Errorf("output is not valid JSON:\n%s", buf.String())
	}

	// Verify required fields are present even when zero-valued.
	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"AllFixable", "NeedsOverride", "Chains", "MinUnion"} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("field %q missing from JSON output", field)
		}
	}
}
