package host_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v4"
)

func TestReleaseInstallationCommand(t *testing.T) {
	content, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Name string
				Run  string
			}
		}
	}
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		t.Fatal(err)
	}
	var command string
	for _, step := range workflow.Jobs["publish"].Steps {
		if step.Name == "Verify fresh installation and locked offline checking" {
			command = step.Run
		}
	}
	if command == "" {
		t.Fatal("installation verification step missing")
	}
	// Execute the YAML-decoded script with deterministic command substitutes.
	// This checks shell arguments, quoting, receipt redirection and fail-fast
	// behavior without contacting the registry or running a published binary.
	script := `
go() { test "$*" = "env GOPATH"; printf '/test go path'; }
python3() {
  test "$#" -eq 8
  test "$1" = "-B"
  test "$2" = "scripts/verify_installation.py"
  test "$3" = "--actionlint"
  test "$4" = "/test go path/bin/actionlint"
  test "$5" = "--version"
  test "$6" = "v0.1.1"
  test "$7" = "--sha256"
  test "$8" = "test-digest"
  if test "$PROBE_FAIL" = "yes"; then return 7; fi
  printf '{"verified":true}\n'
}
RELEASE_TAG=v0.1.1
EXPECTED_SHA256=test-digest
`
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "verification_failure"}[fail], func(t *testing.T) {
			directory := t.TempDir()
			probe := "PROBE_FAIL=no\n"
			if fail {
				probe = "PROBE_FAIL=yes\n"
			}
			cmd := exec.CommandContext(t.Context(), "bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", probe+script+command)
			cmd.Dir = directory
			output, err := cmd.CombinedOutput()
			if fail {
				if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 7 || len(output) != 0 {
					t.Fatalf("failed verifier did not stop receipt display: %q, %v", output, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("installation script: %v\n%s", err, output)
			}
			receipt, err := os.ReadFile(filepath.Join(directory, "installation.json"))
			if err != nil || strings.TrimSpace(string(receipt)) != `{"verified":true}` || string(receipt) != string(output) {
				t.Fatalf("receipt was not written and displayed: %q, %q, %v", receipt, output, err)
			}
		})
	}
}
