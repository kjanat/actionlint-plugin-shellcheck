package host_test

import (
	"fmt"
	"slices"
	"testing"

	"actionlint.kjanat.dev/v2/internal/checking"
	checkinputs "actionlint.kjanat.dev/v2/internal/checking/inputs"
	"actionlint.kjanat.dev/v2/internal/input/workspace"
)

func TestScopedEnvironmentNamesThroughComponent(t *testing.T) {
	for _, tc := range []struct {
		name, runner, workflowEnv, steps string
		codes                           []string
		line                            int
	}{
		{
			name: "declared spellings", runner: "ubuntu-latest",
			workflowEnv: "env: { lowercase: one, UPPERCASE: two, miXedCase: three }\n",
			steps: "      - run: printf '%s' \"$lowercase\" \"$UPPERCASE\" \"$miXedCase\"\n",
		},
		{
			name: "undeclared name", runner: "ubuntu-latest",
			steps: "      - run: printf '%s' \"$not_declared_anywhere\"\n",
			codes: []string{"SC2154"}, line: 6,
		},
		{
			name: "step declarations do not leak", runner: "ubuntu-latest",
			steps: "      - run: printf '%s' \"$step_only_variable\"\n        env: { step_only_variable: one }\n      - run: printf '%s' \"$step_only_variable\"\n",
			codes: []string{"SC2154"}, line: 8,
		},
		{
			name: "Windows merging preserves first spelling for Bash", runner: "windows-latest",
			workflowEnv: "env: { lowercase: one }\n",
			steps: "      - run: printf '%s' \"$LOWERCASE\"\n        shell: bash\n        env: { LOWERCASE: two }\n",
			codes: []string{"SC2153"}, line: 7,
		},
		{
			name: "Linux declarations distinguish casing", runner: "ubuntu-latest",
			workflowEnv: "env: { lowercase: one }\n",
			steps: "      - run: printf '%s' \"$lowercase\" \"$LOWERCASE\"\n        env: { LOWERCASE: two }\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			component := load(t)
			source := fmt.Sprintf("on: push\n%sjobs:\n  build:\n    runs-on: %s\n    steps:\n%s", tc.workflowEnv, tc.runner, tc.steps)
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
				t.Fatalf("ShellCheck codes = %v, want %v; diagnostics: %+v", codes, tc.codes, result.Diagnostics)
			}
		})
	}
}
