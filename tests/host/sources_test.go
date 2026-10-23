package host_test

import (
	"encoding/json"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"actionlint.kjanat.dev/v2/analyzer"
	"actionlint.kjanat.dev/v2/diagnostic"
	"github.com/kjanat/wacogo/wasi/filesystem/preopens"
)

type sourceFiles struct {
	fs.FS
	opened []string
}

func (s *sourceFiles) Open(name string) (fs.File, error) {
	f, err := s.FS.Open(name)
	if err == nil && name != "." {
		s.opened = append(s.opened, name)
	}
	return f, err
}

func sourceScript(text string) analyzer.Script {
	script := analyzer.Script{Text: text, Path: "ci.yml", Start: diagnostic.Position{Line: 1, Column: 1}, Runtime: &analyzer.Runtime{Shell: "bash", ShellKnown: true, Directory: "/workspace", DirectoryKnown: true}}
	for i, line := range strings.Split(text, "\n") {
		script.Spans = append(script.Spans, analyzer.Span{Line: i + 1, Start: 1, End: len(line) + 1, Document: diagnostic.Position{Line: i + 1, Column: 1}})
	}
	return script
}

func TestGrantedSourcesIncludeCleanNestedAndExternalFiles(t *testing.T) {
	component := load(t)
	files := &sourceFiles{FS: fstest.MapFS{
		"lib/clean.sh": &fstest.MapFile{Data: []byte(`# shellcheck source-path=SCRIPTDIR/lib
. ./nested.sh
VALUE=clean
`)},
		"lib/nested.sh": &fstest.MapFile{Data: []byte("FLAGS=one\n")},
	}}
	external := &sourceFiles{FS: fstest.MapFS{"shared.sh": &fstest.MapFile{Data: []byte("SHARED=two\n")}}}
	input := analyzer.Input{
		Options: json.RawMessage(`{"external-sources":true,"source-path":["/sources/0"],"source-roots":[{"host":"/actual/repo","guest":"/workspace"}]}`),
		Scripts: []analyzer.Script{sourceScript(`. shared.sh
# shellcheck source=/actual/repo/lib/clean.sh
. dynamic-name
printf '%s\n' "$VALUE" "$FLAGS" "$SHARED"
`)},
		Files: []analyzer.FileSystem{
			{Path: "/workspace", FS: preopens.ImmutableFS{FS: files}},
			{Path: "/sources/0", FS: preopens.ImmutableFS{FS: external}},
		},
	}
	findings, err := component.Analyze(t.Context(), input)
	if err != nil || len(findings) != 0 {
		t.Fatalf("findings=%+v error=%v", findings, err)
	}
	for _, name := range []string{"lib/clean.sh", "lib/nested.sh"} {
		if !slices.Contains(files.opened, name) {
			t.Fatalf("%s was not read: %v", name, files.opened)
		}
	}
	if !slices.Contains(external.opened, "shared.sh") {
		t.Fatalf("external file was not read: %v", external.opened)
	}
}

func TestSourceEditChangesSubsequentAnalysis(t *testing.T) {
	component := load(t)
	for _, tc := range []struct {
		content  string
		warnings int
	}{{"FLAGS=one\n", 0}, {"FLAGS='one two'\n", 1}} {
		input := analyzer.Input{
			Options: json.RawMessage(`{"external-sources":true}`),
			Scripts: []analyzer.Script{sourceScript(". ./values.sh\necho $FLAGS\n")},
			Files:   []analyzer.FileSystem{{Path: "/workspace", FS: preopens.ImmutableFS{FS: fstest.MapFS{"values.sh": &fstest.MapFile{Data: []byte(tc.content)}}}}},
		}
		findings, err := component.Analyze(t.Context(), input)
		if err != nil || len(findings) != tc.warnings {
			t.Fatalf("source=%q findings=%+v error=%v", tc.content, findings, err)
		}
		if len(findings) != 0 && findings[0].Code != "SC2086" {
			t.Fatalf("unexpected warning: %+v", findings)
		}
	}
}

func TestSourcedParseFailureIsReportedAtInvocation(t *testing.T) {
	component := load(t)
	findings, err := component.Analyze(t.Context(), analyzer.Input{
		Options: json.RawMessage(`{"external-sources":true}`),
		Scripts: []analyzer.Script{sourceScript(". ./broken.sh\nprintf 'ok\\n'\n")},
		Files: []analyzer.FileSystem{{Path: "/workspace", FS: preopens.ImmutableFS{FS: fstest.MapFS{
			"broken.sh": &fstest.MapFile{Data: []byte("if then\n")},
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.Code == "SC1094" {
			if finding.Path != "ci.yml" || finding.Reference == nil || finding.Start.Line != 1 || finding.Start.Column != 3 {
				t.Fatalf("source failure detached from invocation: %+v", finding)
			}
			return
		}
	}
	t.Fatalf("source parse failure lost: %+v", findings)
}

func TestUnknownDirectoryUsesOnlyIndependentSourcePaths(t *testing.T) {
	component := load(t)
	for _, tc := range []struct {
		name, script, options string
		noRuntime, read       bool
	}{
		{"absolute", ". /sources/0/values.sh\necho $FLAGS\n", `{"external-sources":true}`, false, true},
		{"absolute search path", ". values.sh\necho $FLAGS\n", `{"external-sources":true,"source-path":["/sources/0"]}`, false, true},
		{"mapped host path", ". /repo/values.sh\necho $FLAGS\n", `{"external-sources":true,"source-roots":[{"host":"/repo","guest":"/sources/0"}]}`, false, true},
		{"no runtime", ". /sources/0/values.sh\necho $FLAGS\n", `{"external-sources":true}`, true, true},
		{"relative without base", ". values.sh\necho $FLAGS\n", `{"external-sources":true}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			files := &sourceFiles{FS: fstest.MapFS{"values.sh": &fstest.MapFile{Data: []byte("FLAGS=one\n")}}}
			script := sourceScript(tc.script)
			if tc.noRuntime {
				script.Runtime = nil
			} else {
				script.Runtime.DirectoryKnown = false
			}
			findings, err := component.Analyze(t.Context(), analyzer.Input{
				Options: json.RawMessage(tc.options), Scripts: []analyzer.Script{script},
				Files: []analyzer.FileSystem{{Path: "/sources/0", FS: preopens.ImmutableFS{FS: files}}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(files.opened, "values.sh") != tc.read || tc.read && len(findings) != 0 {
				t.Fatalf("read=%v files=%v findings=%+v", tc.read, files.opened, findings)
			}
		})
	}
}

func TestAbsoluteSourceSearchOrderMatchesShellCheck(t *testing.T) {
	component := load(t)
	for _, shadow := range []bool{true, false} {
		workspace := fstest.MapFS{}
		if shadow {
			workspace["sources/0/values.sh"] = &fstest.MapFile{Data: []byte("FLAGS='one two'\n")}
		}
		findings, err := component.Analyze(t.Context(), analyzer.Input{
			Options: json.RawMessage(`{"external-sources":true}`),
			Scripts: []analyzer.Script{sourceScript(". /sources/0/values.sh\necho $FLAGS\n")},
			Files: []analyzer.FileSystem{
				{Path: "/workspace", FS: preopens.ImmutableFS{FS: workspace}},
				{Path: "/sources/0", FS: preopens.ImmutableFS{FS: fstest.MapFS{"values.sh": &fstest.MapFile{Data: []byte("FLAGS=one\n")}}}},
			},
		})
		if err != nil || (len(findings) == 1 && findings[0].Code == "SC2086") != shadow || !shadow && len(findings) != 0 {
			t.Fatalf("relative candidate=%v findings=%+v error=%v", shadow, findings, err)
		}
	}
}
