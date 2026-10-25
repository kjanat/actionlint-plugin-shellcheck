package host_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"actionlint.kjanat.dev/v2/diagnostic"
	"actionlint.kjanat.dev/v2/plugin"
)

// Exercise workspace grants, escape rejection and source overwrite protection
// through the real CLI and packaged component.
func TestManagedSourceGrantsThroughCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "actionlint")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-mod=readonly", "-o", binary, "actionlint.kjanat.dev/v2/cmd/actionlint")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build host: %v\n%s", err, output)
	}
	artifact, err := filepath.Abs(pluginPath())
	if err != nil {
		t.Fatal(err)
	}
	root, outside := t.TempDir(), t.TempDir()
	cache := t.TempDir()
	t.Setenv("LOCALAPPDATA", cache)
	t.Setenv("XDG_CACHE_HOME", cache)
	t.Setenv("HOME", cache)
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} {
		t.Setenv(name, "http://127.0.0.1:1")
	}
	t.Setenv("NO_PROXY", "")
	info, err := plugin.Inspect(t.Context(), artifact, plugin.ArtifactOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		Version   string `json:"plugin_version"`
		Interface string `json:"interface"`
		Contract  string `json:"contract_sha256"`
	}
	if err := json.Unmarshal(info.Metadata, &metadata); err != nil {
		t.Fatal(err)
	}
	version := "v" + metadata.Version
	const repository = "github.com/kjanat/actionlint-plugin-shellcheck"
	lock, err := json.Marshal(struct {
		SchemaVersion int                 `json:"schema_version"`
		Plugins       []map[string]string `json:"plugins"`
	}{1, []map[string]string{{
		"registry": "https://plugins.actionlint.kjanat.dev/", "name": repository,
		"repository_id": "1", "owner_id": "1", "plugin_id": "shellcheck",
		"selector": version, "version": version, "kind": "component", "asset": "plugin.wasm",
		"url":    "https://" + repository + "/releases/download/" + version + "/plugin.wasm",
		"sha256": info.SHA256, "contract": metadata.Interface + "#sha256=" + metadata.Contract,
	}}})
	if err != nil {
		t.Fatal(err)
	}
	cacheBase, err := os.UserCacheDir()
	if err != nil {
		t.Fatal(err)
	}
	artifactCache := filepath.Join(cacheBase, "actionlint", "artifacts")
	inside := filepath.Join(root, "sources")
	for _, directory := range []string{filepath.Join(root, ".git"), filepath.Join(inside, "sub"), filepath.Join(outside, "sub"), artifactCache} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "actionlint.plugins.lock.json"), lock, 0o600); err != nil {
		t.Fatal(err)
	}
	artifactBytes, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactCache, info.SHA256), artifactBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	const original = "FLAGS='one two'\nSTABLE=one\n"
	file, outsideFile := filepath.Join(inside, "values.sh"), filepath.Join(outside, "values.sh")
	for _, name := range []string{file, outsideFile} {
		if err := os.WriteFile(name, []byte(original), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	alias, link := filepath.Join(root, "shared"), filepath.Join(root, "link")
	escape, escapeLink := filepath.Join(root, "escape"), filepath.Join(root, "escape-link")
	for name, target := range map[string]string{
		alias: inside, link: filepath.Join(inside, "sub"),
		escape: outside, escapeLink: filepath.Join(outside, "sub"),
	} {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, grant string
		allowed     bool
	}{
		{"workspace-symlink", alias, true},
		{"workspace-symlink-parent", link + string(os.PathSeparator) + "..", true},
		{"outside-directory", outside, false},
		{"outside-symlink", escape, false},
		{"outside-symlink-parent", escapeLink + string(os.PathSeparator) + "..", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configuration := filepath.Join(root, "actionlint.yaml")
			settings := fmt.Sprintf(`plugins: [%s]
tools:
  ruff: false
  shellcheck:
    config:
      external-sources: true
      source-path: [%s]
`, strconv.Quote(repository+"@"+version), strconv.Quote(tc.grant))
			if err := os.WriteFile(configuration, []byte(settings), 0o600); err != nil {
				t.Fatal(err)
			}
			workflow := filepath.Join(root, "ci.yml")
			content := fmt.Sprintf(`on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          . %s
          echo $FLAGS
          echo $STABLE
        working-directory: shared
`, strconv.Quote(filepath.ToSlash(tc.grant)+"/values.sh"))
			if err := os.WriteFile(workflow, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), binary, "check", "--json", "--no-ruff", "--config", configuration, workflow)
			command.Dir = root
			var stderr bytes.Buffer
			command.Stderr = &stderr
			output, err := command.Output()
			exitCode := 3
			if tc.allowed {
				exitCode = 1
			}
			if err == nil || command.ProcessState == nil || command.ProcessState.ExitCode() != exitCode {
				t.Fatalf("expected exit %d: %v\n%s\n%s", exitCode, err, output, &stderr)
			}
			if !tc.allowed {
				if len(output) != 0 {
					t.Fatalf("failed analysis wrote findings to stdout: %s", output)
				}
				output = stderr.Bytes()
			}
			var result struct {
				Completed   bool                    `json:"completed"`
				Diagnostics []diagnostic.Diagnostic `json:"diagnostics"`
				Error       string                  `json:"error"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("decode host result: %v\n%s", err, output)
			}
			if !tc.allowed {
				if result.Completed || len(result.Diagnostics) != 0 || !strings.Contains(result.Error, "outside workspace root") {
					t.Fatalf("workspace escape not rejected: %+v", result)
				}
				return
			}
			if !result.Completed || len(result.Diagnostics) != 1 || result.Diagnostics[0].Code != "SC2086" {
				t.Fatalf("source not analyzed: %+v", result)
			}
			protect := exec.CommandContext(t.Context(), binary, "check", "--no-ruff", "--config", configuration, "--output-file", file, "--yes", workflow)
			protect.Dir = root
			output, err = protect.CombinedOutput()
			if err == nil || protect.ProcessState == nil || protect.ProcessState.ExitCode() != 3 || !strings.Contains(string(output), "also an input") {
				t.Fatalf("source overwrite not blocked: %v\n%s", err, output)
			}
			source, err := os.ReadFile(file)
			if err != nil || string(source) != original {
				t.Fatalf("source changed: %q, %v", source, err)
			}
		})
	}
	if source, err := os.ReadFile(outsideFile); err != nil || string(source) != original {
		t.Fatalf("outside source changed: %q, %v", source, err)
	}
}
