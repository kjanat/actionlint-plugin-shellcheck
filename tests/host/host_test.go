package host_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"actionlint.kjanat.dev/analysis"
	"actionlint.kjanat.dev/analyzer"
	"actionlint.kjanat.dev/diagnostic"
	"actionlint.kjanat.dev/plugin"
)

const workflow = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo $HOME\n      - run: |\n          [[ -n \"$HOME\" ]]\n        shell: sh\n      - run: Write-Host $x\n        shell: pwsh\n"

func pluginPath() string {
	if path := os.Getenv("ACTIONLINT_PLUGIN_SHELLCHECK"); path != "" {
		return path
	}
	return filepath.Join("..", "..", "target", "wasm32-wasip2", "release", "actionlint_plugin_shellcheck.wasm")
}

func analyze(t *testing.T, options string) []diagnostic.Diagnostic {
	t.Helper()
	ctx := context.Background()
	component, err := plugin.Load(ctx, pluginPath(), plugin.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer component.Close(ctx)
	if name := component.Descriptor().Name; name != "shellcheck-rs" {
		t.Fatalf("plugin name %q", name)
	}
	registration := analyzer.Registration{Analyzer: component}
	if options != "" {
		registration.Options = json.RawMessage(options)
	}
	result, err := analysis.Analyze(ctx, analysis.Request{
		Sources: []analysis.Source{{Path: "workflow.yml", Content: []byte(workflow)}},
		Options: analysis.Options{Analyzers: []analyzer.Registration{registration}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var findings []diagnostic.Diagnostic
	for _, finding := range result.Diagnostics {
		if finding.Rule == "shellcheck-rs" {
			findings = append(findings, finding)
		}
	}
	return findings
}

func TestPluginReportsShellCheckFindings(t *testing.T) {
	findings := analyze(t, "")
	if len(findings) != 2 {
		t.Fatalf("findings: %+v", findings)
	}
	quote, bashism := findings[0], findings[1]
	if quote.Code != "SC2086" || quote.Start.Line != 6 || quote.Start.Column != 19 || quote.End.Column != 24 || quote.Severity != "info" {
		t.Fatalf("quote: %+v", quote)
	}
	if len(quote.Fixes) != 1 || len(quote.Fixes[0].Edits) != 2 {
		t.Fatalf("quote fixes: %+v", quote.Fixes)
	}
	if bashism.Code != "SC3010" || bashism.Start.Line != 8 || bashism.Start.Column != 11 || bashism.Severity != "warning" {
		t.Fatalf("bashism: %+v", bashism)
	}
}

func TestPluginOptionsDisableCodes(t *testing.T) {
	findings := analyze(t, `{"disable": ["SC2086"]}`)
	if len(findings) != 1 || findings[0].Code != "SC3010" {
		t.Fatalf("findings: %+v", findings)
	}
}

func TestPluginRejectsUnknownOptions(t *testing.T) {
	ctx := context.Background()
	component, err := plugin.Load(ctx, pluginPath(), plugin.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer component.Close(ctx)
	_, err = analysis.Analyze(ctx, analysis.Request{
		Sources: []analysis.Source{{Path: "workflow.yml", Content: []byte(workflow)}},
		Options: analysis.Options{Analyzers: []analyzer.Registration{{Analyzer: component, Options: json.RawMessage(`{"shel": "sh"}`)}}},
	})
	if err == nil {
		t.Fatal("unknown option accepted")
	}
}
