package host_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"actionlint.kjanat.dev/v2/internal/checking"
	checkinputs "actionlint.kjanat.dev/v2/internal/checking/inputs"
	"actionlint.kjanat.dev/v2/internal/input/workspace"
	"actionlint.kjanat.dev/v2/internal/results"
)

func TestScopedEnvironmentNamesThroughComponent(t *testing.T) {
	for _, tc := range []struct {
		name, runner, workflowEnv, steps string
		codes                            []string
		line                             int
	}{
		{
			name: "declared spellings", runner: "ubuntu-latest",
			workflowEnv: "env: { lowercase: one, UPPERCASE: two, miXedCase: three }\n",
			steps:       "      - run: printf '%s' \"$lowercase\" \"$UPPERCASE\" \"$miXedCase\"\n",
		},
		{
			name: "runner may supply an undeclared name", runner: "ubuntu-latest",
			steps: "      - run: printf '%s' \"$not_declared_anywhere\"\n",
		},
		{
			name: "Windows runner may supply either spelling", runner: "windows-latest",
			workflowEnv: "env: { lowercase: one }\n",
			steps:       "      - run: printf '%s' \"$LOWERCASE\"\n        shell: bash\n        env: { LOWERCASE: two }\n",
		},
		{
			name: "Linux declarations distinguish casing", runner: "ubuntu-latest",
			workflowEnv: "env: { lowercase: one }\n",
			steps:       "      - run: printf '%s' \"$lowercase\" \"$LOWERCASE\"\n        env: { LOWERCASE: two }\n",
		},
		{
			name: "unknown runner names do not suppress quoting checks", runner: "ubuntu-latest",
			steps: "      - run: echo $HOME\n",
			codes: []string{"SC2086"}, line: 6,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			component := load(t)
			source := fmt.Sprintf("on: push\n%sjobs:\n  build:\n    runs-on: %s\n    steps:\n%spermissions: {}\n", tc.workflowEnv, tc.runner, tc.steps)
			result, err := checking.Analyze(t.Context(), checking.Options{
				Tools: pluginTools(), Analyzers: []checkinputs.Registration{{Checker: component}},
			}, []workspace.Source{{Path: "workflow.yml", Content: []byte(source)}})
			if err != nil {
				t.Fatal(err)
			}
			var codes []string
			for _, finding := range result.Diagnostics {
				if finding.Rule == "shellcheck" {
					codes = append(codes, finding.Code)
					if finding.Start.Line != tc.line {
						t.Errorf("diagnostic line = %d, want %d: %+v", finding.Start.Line, tc.line, finding)
					}
				}
			}
			if !slices.Equal(codes, tc.codes) {
				t.Fatalf("ShellCheck codes = %v, want %v. Diagnostics: %+v", codes, tc.codes, result.Diagnostics)
			}
		})
	}
}

type environmentInspector struct {
	checkinputs.Checker
	checkinputs.ToolIntegrator
	scripts []checkinputs.Script
}

func (a *environmentInspector) CheckDocument(ctx context.Context, input checkinputs.Input) ([]results.Diagnostic, error) {
	a.scripts = append(a.scripts, input.Scripts...)
	return a.Checker.CheckDocument(ctx, input)
}

func TestStepEnvironmentNamesDoNotLeakToLaterSteps(t *testing.T) {
	component := load(t)
	inspector := &environmentInspector{Checker: component, ToolIntegrator: component}
	const source = "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo first\n        env: { step_only_variable: one }\n      - run: echo second\npermissions: {}\n"
	_, err := checking.Analyze(t.Context(), checking.Options{
		Tools: pluginTools(), Analyzers: []checkinputs.Registration{{Checker: inspector}},
	}, []workspace.Source{{Path: "workflow.yml", Content: []byte(source)}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inspector.scripts) != 2 {
		t.Fatalf("plugin received %d scripts, want 2", len(inspector.scripts))
	}
	for index, script := range inspector.scripts {
		if len(script.Environment) == 0 {
			t.Fatalf("step %d has no environment information", index+1)
		}
		for _, environment := range script.Environment {
			found := false
			for _, name := range environment.Names() {
				found = found || name.Name == "step_only_variable"
			}
			if found != (index == 0) {
				t.Errorf("step %d declares step_only_variable=%t, want %t", index+1, found, index == 0)
			}
			if !environment.UnknownNames() {
				t.Errorf("step %d incorrectly treats inherited runner names as fully known", index+1)
			}
		}
	}
}
