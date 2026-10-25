package host_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"actionlint.kjanat.dev/v2/analysis"
	"actionlint.kjanat.dev/v2/analyzer"
	"actionlint.kjanat.dev/v2/diagnostic"
	"actionlint.kjanat.dev/v2/plugin"
	"actionlint.kjanat.dev/v2/rule"
)

const workflow = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo $HOME\n      - run: |\n          [[ -n \"$HOME\" ]]\n        shell: sh\n      - run: Write-Host $x\n        shell: pwsh\n"

func pluginPath() string {
	if path := os.Getenv("ACTIONLINT_PLUGIN_SHELLCHECK"); path != "" {
		return path
	}
	return filepath.Join("..", "..", "artifacts", "plugin.wasm")
}

func load(t *testing.T) *plugin.Component {
	t.Helper()
	component, err := plugin.Load(t.Context(), pluginPath(), plugin.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := component.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return component
}

func analyze(t *testing.T, options string) []diagnostic.Diagnostic {
	t.Helper()
	ctx := context.Background()
	component := load(t)
	if name := component.Descriptor().Name; name != "shellcheck" {
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
		if finding.Rule == "shellcheck" {
			findings = append(findings, finding)
		}
	}
	return findings
}

// A component can compile successfully while its host adapter drops findings or
// shifts their locations. This loads the packaged Wasm through the public host,
// analyzes Bash and sh steps, and checks their diagnostics and quote edits. The
// PowerShell step also catches accidental shell analysis of another language.
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
	for i, column := range []int{19, 24} {
		edit := quote.Fixes[0].Edits[i]
		position := diagnostic.Position{Line: 6, Column: column}
		if edit.Path != "workflow.yml" || edit.Start != position || edit.End != position || edit.Replacement != `"` {
			t.Fatalf("quote edit: %+v", edit)
		}
	}
	if bashism.Code != "SC3010" || bashism.Start.Line != 8 || bashism.Start.Column != 11 || bashism.Severity != "warning" {
		t.Fatalf("bashism: %+v", bashism)
	}
}

// Users expect a disabled ShellCheck code to disappear without losing unrelated
// findings. This passes the option through the host and component boundary and
// checks the remaining bashism diagnostic. It catches configuration that parses
// correctly in Rust but gets lost while the host invokes the Wasm plugin.
func TestPluginOptionsDisableCodes(t *testing.T) {
	findings := analyze(t, `{"disable": ["SC2086"]}`)
	if len(findings) != 1 || findings[0].Code != "SC3010" {
		t.Fatalf("findings: %+v", findings)
	}
}

// Misspelled settings must produce a useful error for both supported call paths.
// This submits an unknown key through the host's schema validation and directly
// to the component, checking that each names the bad key. Otherwise one caller
// could silently ignore a setting that another caller correctly rejects.
func TestPluginRejectsUnknownOptions(t *testing.T) {
	ctx := context.Background()
	component := load(t)
	_, err := analysis.Analyze(ctx, analysis.Request{
		Sources: []analysis.Source{{Path: "workflow.yml", Content: []byte(workflow)}},
		Options: analysis.Options{Analyzers: []analyzer.Registration{{Analyzer: component, Options: json.RawMessage(`{"shel": "sh"}`)}}},
	})
	if err == nil || !strings.Contains(err.Error(), "additional properties") || !strings.Contains(err.Error(), "shel") {
		t.Fatalf("expected host schema error, got %v", err)
	}
	findings, err := component.Analyze(ctx, analyzer.Input{Options: json.RawMessage(`{"shel":"sh"}`)})
	if len(findings) != 0 || err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "shel") {
		t.Fatalf("expected component option outcome, got %v, %v", findings, err)
	}
}

// Optional-check names and diagnostic numbers select different ShellCheck
// features, and confusing them previously accepted ineffective configuration.
// This sends misspellings and numeric selectors through the host and guest, then
// checks that all remains accepted. Both the packaged schema and the runtime
// parser must reject the bad selectors and accept the supported one.
func TestPluginValidatesOptionalCheckNames(t *testing.T) {
	component := load(t)
	for _, name := range []string{"require-variable-brace", "SC2086", "2086"} {
		t.Run(name, func(t *testing.T) {
			options, err := json.Marshal(struct {
				Enable []string `json:"enable"`
			}{Enable: []string{name}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = analysis.Analyze(t.Context(), analysis.Request{
				Sources: []analysis.Source{{Path: "workflow.yml", Content: []byte(workflow)}},
				Options: analysis.Options{Analyzers: []analyzer.Registration{{Analyzer: component, Options: options}}},
			})
			if err == nil || !strings.Contains(err.Error(), "jsonschema validation failed") || !strings.Contains(err.Error(), "/enable/0") {
				t.Fatalf("expected schema rejection for %q, got %v", name, err)
			}
			findings, err := component.Analyze(t.Context(), analyzer.Input{Options: options})
			if len(findings) != 0 || err == nil || !strings.Contains(err.Error(), "enable entry") || !strings.Contains(err.Error(), name) {
				t.Fatalf("expected component optional-check rejection, got %v, %v", findings, err)
			}
		})
	}
	if _, err := component.Analyze(t.Context(), analyzer.Input{Options: json.RawMessage(`{"enable":["all"]}`)}); err != nil {
		t.Fatalf("all selector rejected: %v", err)
	}
}

type rawFixAnalyzer struct {
	analyzer.Analyzer
	analyzer.ToolIntegrator
	inspected bool
}

func (a *rawFixAnalyzer) Analyze(ctx context.Context, input analyzer.Input) ([]diagnostic.Diagnostic, error) {
	findings, err := a.Analyzer.Analyze(ctx, input)
	if err != nil {
		return findings, err
	}
	for _, finding := range findings {
		for _, fix := range finding.Fixes {
			a.inspected = true
			if len(fix.Revisions) != 1 || fix.Revisions[input.Path] != input.Reference.Revision {
				return nil, fmt.Errorf("raw fix revisions %v; expected path %q revision %q", fix.Revisions, input.Path, input.Reference.Revision)
			}
			for _, edit := range fix.Edits {
				if edit.Path != input.Path {
					return nil, fmt.Errorf("raw edit path %q; expected %q", edit.Path, input.Path)
				}
			}
		}
	}
	return findings, nil
}

// The host can normalize diagnostic paths after an analyzer returns, hiding a
// plugin that created edits against the wrong path or revision. This intercepts
// actual component findings before that policy runs and checks every raw fix.
// Editors need those original revision keys to reject edits against changed files.
func TestFixRevisionsUseDeclaringPathBeforePolicy(t *testing.T) {
	component := load(t)
	checked := &rawFixAnalyzer{Analyzer: component, ToolIntegrator: component}
	_, err := analysis.Analyze(t.Context(), analysis.Request{
		Sources: []analysis.Source{{Path: "workflow.yml", Content: []byte(workflow)}},
		Options: analysis.Options{Analyzers: []analyzer.Registration{{Analyzer: checked}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !checked.inspected {
		t.Fatal("no fixes inspected")
	}
}

// Compare the packaged declaration with the descriptor exported by the loaded guest.
func TestPackagedDeclarationMatchesRuntime(t *testing.T) {
	info, err := plugin.Inspect(t.Context(), pluginPath(), plugin.ArtifactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != plugin.ComponentArtifact {
		t.Fatalf("artifact kind %q", info.Kind)
	}
	type componentDeclaration struct {
		rule.Descriptor
		Requires []analyzer.Fact `json:"requires"`
	}
	var declaration struct {
		ID         string                `json:"id"`
		Descriptor *componentDeclaration `json:"descriptor"`
	}
	if err := json.Unmarshal(info.Metadata, &declaration); err != nil {
		t.Fatal(err)
	}
	component := load(t)
	descriptor := component.Descriptor()
	if declaration.ID != "shellcheck-rs" || descriptor.Name != "shellcheck" {
		t.Fatalf("package id %q, rule name %q", declaration.ID, descriptor.Name)
	}
	if !component.HasAnalyzer() || component.HasRunnerProvider() || declaration.Descriptor == nil {
		t.Fatalf("unexpected component roles or descriptor: %+v", declaration.Descriptor)
	}
	static, err := json.Marshal(declaration.Descriptor)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := json.Marshal(componentDeclaration{Descriptor: descriptor.Descriptor, Requires: descriptor.Requires})
	if err != nil {
		t.Fatal(err)
	}
	staticJSON, runtimeJSON := jsontext.Value(static), jsontext.Value(actual)
	if err := staticJSON.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	if err := runtimeJSON.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(staticJSON, runtimeJSON) {
		t.Fatalf("static descriptor differs from runtime:\n%s\n%s", staticJSON, runtimeJSON)
	}
}

// Release files can become stale even when the component itself still loads.
// This opens the produced package, compares its metadata sidecar with the Wasm
// section, and hashes every file listed in SHA256SUMS. It catches packaging that
// ships files from different builds or checksum entries pointing outside the package.
func TestPackageSidecarsAndChecksums(t *testing.T) {
	info, err := plugin.Inspect(t.Context(), pluginPath(), plugin.ArtifactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(pluginPath())
	sidecar, err := os.ReadFile(filepath.Join(dir, "metadata.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(info.Metadata, sidecar) {
		t.Fatal("embedded metadata differs from sidecar")
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(manifest)), "\n")
	expected := map[string]bool{"LICENSE": false, "metadata.json": false, "plugin.wasm": false, "schema.json": false}
	if len(lines) != len(expected) {
		t.Fatalf("checksum entries: %v", lines)
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || filepath.Base(fields[1]) != fields[1] {
			t.Fatalf("invalid checksum entry %q", line)
		}
		if seen, known := expected[fields[1]]; !known || seen {
			t.Fatalf("unexpected or repeated checksum entry %q", line)
		}
		expected[fields[1]] = true
		data, err := os.ReadFile(filepath.Join(dir, fields[1]))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != fields[0] {
			t.Fatalf("checksum for %s: %s != %s", fields[1], got, fields[0])
		}
	}
}
