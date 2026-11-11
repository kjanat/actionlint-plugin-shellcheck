package host_test

import (
	"encoding/json"
	"testing"

	"actionlint.kjanat.dev/v2/internal/checking"
	checkinputs "actionlint.kjanat.dev/v2/internal/checking/inputs"
	"actionlint.kjanat.dev/v2/internal/input/workspace"
)

func TestDialectOverrideDoesNotEnableUnsupportedShells(t *testing.T) {
	const source = "on: push\npermissions: {}\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - shell: pwsh\n        run: Write-Host $x\n      - shell: python\n        run: print(undefined_name)\n"
	for _, options := range []string{"", `{"shell":"bash"}`} {
		t.Run(options, func(t *testing.T) {
			component := load(t)
			registration := checkinputs.Registration{Checker: component}
			if options != "" {
				registration.Options = json.RawMessage(options)
			}
			result, err := checking.Analyze(t.Context(), checking.Options{Tools: pluginTools(), Analyzers: []checkinputs.Registration{registration}}, []workspace.Source{{Path: "workflow.yml", Content: []byte(source)}})
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range result.Diagnostics {
				if finding.Rule == "shellcheck" {
					t.Fatalf("unsupported shell produced a ShellCheck finding: %+v", finding)
				}
			}
		})
	}
}
