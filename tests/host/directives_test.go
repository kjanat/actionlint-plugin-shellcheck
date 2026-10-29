package host_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"actionlint.kjanat.dev/v2/analysis"
	"actionlint.kjanat.dev/v2/analyzer"
	"actionlint.kjanat.dev/v2/diagnostic"
)

const directiveWorkflowPrefix = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"

func directiveFindings(t *testing.T, component analyzer.Analyzer, source string) []diagnostic.Diagnostic {
	t.Helper()
	result, err := analysis.Analyze(t.Context(), analysis.Request{
		Sources: []analysis.Source{{Path: "workflow.yml", Content: []byte(source)}},
		Options: analysis.Options{Analyzers: []analyzer.Registration{{Analyzer: component}}},
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

func TestYAMLDirectivesReachThePackagedEngine(t *testing.T) {
	component := load(t)
	for name, step := range map[string]string{
		"before-run":    "      - name: leading\n        # shellcheck disable=SC2086\n        run: echo $HI\n",
		"before-step":   "      # shellcheck disable=SC2086\n      - run: echo $HI\n",
		"trailing":      "      - run: echo $HI # shellcheck disable=SC2086\n",
		"block-header":  "      - run: | # shellcheck disable=SC2086\n          echo $HI\n",
		"native-header": "      - run: |\n          # shellcheck disable=SC2086\n          echo $HI\n",
		"both":          "      - name: combined\n        # shellcheck disable=SC2034\n        run: | # shellcheck disable=SC2086\n          echo $HI\n",
	} {
		for _, newline := range []string{"\n", "\r\n"} {
			t.Run(name+newline, func(t *testing.T) {
				source := strings.ReplaceAll(directiveWorkflowPrefix+step, "\n", newline)
				if findings := directiveFindings(t, component, source); len(findings) != 0 {
					t.Fatalf("findings=%+v", findings)
				}
			})
		}
	}
	// Reuse the same host after every annotated call. An identical script without
	// a YAML directive must still report its original diagnostic and quote edits.
	plain := directiveWorkflowPrefix + "      - run: echo $HI\n"
	findings := directiveFindings(t, component, plain)
	if len(findings) != 1 || findings[0].Code != "SC2086" || findings[0].Start != (diagnostic.Position{Line: 6, Column: 19}) {
		t.Fatalf("plain findings after annotated calls=%+v", findings)
	}
	if len(findings[0].Fixes) != 1 || len(findings[0].Fixes[0].Edits) != 2 {
		t.Fatalf("plain fixes=%+v", findings[0].Fixes)
	}
}

func TestYAMLDirectiveErrorsAndRemainingFixesUseOriginalCoordinates(t *testing.T) {
	component := load(t)
	source := directiveWorkflowPrefix + "      - run: echo ok # shellcheck shell=unknown\n"
	findings := directiveFindings(t, component, source)
	found := false
	for _, finding := range findings {
		if finding.Code == "SC1103" {
			found = true
			if finding.Start != (diagnostic.Position{Line: 6, Column: 41}) || len(finding.Fixes) != 0 {
				t.Fatalf("directive error=%+v", finding)
			}
		}
	}
	if !found {
		t.Fatalf("missing invalid YAML directive finding: %+v", findings)
	}
	source = directiveWorkflowPrefix + "      - run: echo $HI # shellcheck disable=SC2034\n"
	findings = directiveFindings(t, component, source)
	if len(findings) != 1 || findings[0].Code != "SC2086" || findings[0].Start != (diagnostic.Position{Line: 6, Column: 19}) {
		t.Fatalf("remaining findings=%+v", findings)
	}
	for i, column := range []int{19, 22} {
		edit := findings[0].Fixes[0].Edits[i]
		if edit.Path != "workflow.yml" || edit.Start != (diagnostic.Position{Line: 6, Column: column}) || edit.End != edit.Start || edit.Replacement != `"` {
			t.Fatalf("remaining quote edit=%+v", edit)
		}
	}
	quoted := directiveWorkflowPrefix + "      - run: 'echo $HI # shellcheck disable=SC2086'\n"
	findings = directiveFindings(t, component, quoted)
	found = false
	for _, finding := range findings {
		found = found || finding.Code == "SC1126"
	}
	if !found {
		t.Fatalf("quoted shell directive must retain shell placement error: %+v", findings)
	}
}

func TestYAMLDirectivesBelongToEachInvokedDocument(t *testing.T) {
	component := load(t)
	root := t.TempDir()
	files := map[string]string{
		".git/HEAD":                          "ref: refs/heads/main\n",
		".github/workflows/ci.yml":           directiveWorkflowPrefix + "      # shellcheck disable=SC2086\n      - run: echo $ROOT\n      - uses: ./.github/actions/example\n",
		".github/actions/example/action.yml": "name: example\ndescription: example\nruns:\n  using: composite\n  steps:\n    # shellcheck disable=SC2086\n    - run: echo $FIRST\n      shell: bash\n    - run: echo $SECOND # shellcheck disable=SC2034\n      shell: bash\n",
	}
	for relative, content := range files {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := analysis.Files(t.Context(), []string{filepath.Join(root, ".github", "workflows", "ci.yml")}, analysis.FileOptions{
		WorkingDir: root, Analyzers: []analyzer.Registration{{Analyzer: component}},
		SkipProjectConfig: true,
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
	if len(findings) != 1 || findings[0].Code != "SC2086" || findings[0].Start != (diagnostic.Position{Line: 9, Column: 17}) {
		t.Fatalf("invoked findings=%+v", findings)
	}
	finding := findings[0]
	if !strings.HasSuffix(filepath.ToSlash(finding.Path), ".github/actions/example/action.yml") || finding.Reference == nil || finding.Reference.Revision == "" {
		t.Fatalf("invoked identity=%+v", finding)
	}
	if len(finding.Fixes) != 1 || len(finding.Fixes[0].Edits) != 2 || len(finding.Fixes[0].Revisions) != 1 {
		t.Fatalf("invoked fixes=%+v", finding.Fixes)
	}
	for i, column := range []int{17, 24} {
		edit := finding.Fixes[0].Edits[i]
		if edit.Path != filepath.Join(root, ".github", "actions", "example", "action.yml") || edit.Start != (diagnostic.Position{Line: 9, Column: column}) || edit.End != edit.Start || edit.Replacement != `"` {
			t.Fatalf("invoked quote edit=%+v", edit)
		}
	}
}

func TestYAMLDirectiveOnAliasKeepsAnchorFixes(t *testing.T) {
	component := load(t)
	source := directiveWorkflowPrefix + "      - run: &script echo $HI # shellcheck disable=SC2034\n      - run: *script # shellcheck disable=SC2086\n      - run: *script\n"
	findings := directiveFindings(t, component, source)
	if len(findings) != 2 {
		t.Fatalf("alias-specific directive scope=%+v", findings)
	}
	for _, finding := range findings {
		if finding.Code != "SC2086" || finding.Start != (diagnostic.Position{Line: 6, Column: 27}) || len(finding.Fixes) != 1 || len(finding.Fixes[0].Edits) != 2 {
			t.Fatalf("alias finding=%+v", finding)
		}
		for i, column := range []int{27, 30} {
			edit := finding.Fixes[0].Edits[i]
			if edit.Start != (diagnostic.Position{Line: 6, Column: column}) || edit.End != edit.Start || edit.Path != "workflow.yml" {
				t.Fatalf("alias quote edit=%+v", edit)
			}
		}
	}
}
