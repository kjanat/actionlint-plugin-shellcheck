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

	"actionlint.kjanat.dev/analysis"
	"actionlint.kjanat.dev/analyzer"
	"actionlint.kjanat.dev/diagnostic"
	"actionlint.kjanat.dev/plugin"
	"actionlint.kjanat.dev/rule"
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

func TestFixRevisionsUseDeclaringPathBeforePolicy(t *testing.T) {
	checked := &rawFixAnalyzer{Analyzer: load(t)}
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

func TestPackagedDeclarationMatchesRuntimeAndContract(t *testing.T) {
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
		Version       int                   `json:"metadata_version"`
		ID            string                `json:"id"`
		Name          string                `json:"name"`
		Description   string                `json:"description"`
		License       string                `json:"license"`
		Repository    string                `json:"repository"`
		PluginVersion string                `json:"plugin_version"`
		Transport     string                `json:"transport"`
		Interface     string                `json:"interface"`
		Contract      string                `json:"contract_sha256"`
		Descriptor    *componentDeclaration `json:"descriptor"`
	}
	if err := json.Unmarshal(info.Metadata, &declaration); err != nil {
		t.Fatal(err)
	}
	wit, err := os.ReadFile(filepath.Join("..", "..", "wit", "analyzer.wit"))
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(bytes.ReplaceAll(wit, []byte("\r\n"), []byte("\n"))))
	if declaration.Version != 1 || declaration.ID != "shellcheck-rs" || declaration.Name != "ShellCheck" || declaration.Description == "" || declaration.License != "GPL-3.0-or-later" || declaration.Repository != "https://github.com/kjanat/actionlint-plugin-shellcheck" || declaration.PluginVersion == "" || declaration.Transport != "wasm-component" || declaration.Interface != "kjanat:actionlint/analyzer@0.1.0" || declaration.Contract != digest {
		t.Fatalf("invalid declaration: %+v", declaration)
	}
	component := load(t)
	descriptor := component.Descriptor()
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
	if len(lines) != 4 {
		t.Fatalf("checksum entries: %v", lines)
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 || filepath.Base(fields[1]) != fields[1] {
			t.Fatalf("invalid checksum entry %q", line)
		}
		data, err := os.ReadFile(filepath.Join(dir, fields[1]))
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != fields[0] {
			t.Fatalf("checksum for %s: %s != %s", fields[1], got, fields[0])
		}
	}
}
