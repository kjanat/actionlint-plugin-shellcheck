package host_test

import (
	"strings"
	"testing"
)

func TestNonShellLanguagesDoNotProduceShellCheckFindings(t *testing.T) {
	component := load(t)
	for _, tc := range []struct{ shell, body string }{
		{"pwsh", "$venv = Join-Path $env:RUNNER_TEMP pypi-smoke-venv\n$python = $IsWindows ? 'python' : 'python3'\n& $python -m venv --clear $venv"},
		{"powershell", "Write-Output $env:GITHUB_SHA"},
		{"python", "print('hello')"},
		{"cmd", "echo %GITHUB_SHA%"},
	} {
		t.Run(tc.shell, func(t *testing.T) {
			source := directiveWorkflowPrefix + "      - shell: " + tc.shell + "\n        run: |\n          " + strings.ReplaceAll(tc.body, "\n", "\n          ") + "\n"
			if findings := directiveFindings(t, component, source); len(findings) != 0 {
				t.Fatalf("ShellCheck analyzed %s: %+v", tc.shell, findings)
			}
		})
	}
}
