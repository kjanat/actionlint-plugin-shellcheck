package host_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"actionlint.kjanat.dev/v2/internal/checking/executor"
	rule "actionlint.kjanat.dev/v2/internal/checking/rules"
	scriptmodel "actionlint.kjanat.dev/v2/internal/model/scripts"

	checkinputs "actionlint.kjanat.dev/v2/internal/checking/inputs"
	sourcepos "actionlint.kjanat.dev/v2/internal/input/source"
	"actionlint.kjanat.dev/v2/internal/results"
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

// Register one workflow-owned script in the invocation graph so the host accepts
// its occurrence for shell preparation.
var (
	sourceEntry      = checkinputs.OccurrenceID(strings.Repeat("a", 64))
	sourceOccurrence = checkinputs.OccurrenceID(strings.Repeat("b", 64))
	sourceDocument   = sourcepos.Reference{Document: "ci.yml", Node: "document"}
)

func sourceScript(text string) checkinputs.Script {
	reference := sourcepos.Reference{Document: "ci.yml", Node: "run"}
	script := checkinputs.Script{
		Reference: reference, Text: text, Path: "ci.yml", Start: sourcepos.Position{Line: 1, Column: 1},
		Occurrence: checkinputs.ScriptOccurrence{ID: sourceOccurrence, Owner: sourceEntry, Ancestry: []checkinputs.OccurrenceID{sourceEntry}, Declaration: reference, Kind: checkinputs.RunScript},
		Runtime:    &scriptmodel.Execution{Shell: "bash", ShellKnown: true, Directory: "/workspace", DirectoryKnown: true},
	}
	for i, line := range strings.Split(text, "\n") {
		script.Spans = append(script.Spans, scriptmodel.Span{Line: i + 1, Start: 1, End: len(line) + 1, Document: sourcepos.Position{Line: i + 1, Column: 1}})
	}
	return script
}

// These filesystem tests use identity-mapped shell fixtures. The application and
// packaged-engine tests cover shell preparation.
func analyzeSources(t *testing.T, component checkinputs.Checker, input checkinputs.Input) ([]results.Diagnostic, error) {
	t.Helper()
	script := input.Scripts[0]
	graph, err := checkinputs.NewCallGraph(checkinputs.CallGraphData{
		Entry:    checkinputs.InvocationEntry{ID: sourceEntry, Kind: checkinputs.WorkflowEntry, Reference: sourceDocument},
		Budget:   checkinputs.InvocationBudget{MaxDepth: 1, MaxCalls: 1, MaxScripts: 1},
		Scripts:  []checkinputs.ScriptOccurrence{script.Occurrence},
		Complete: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	input.Reference, input.CallGraph = sourceDocument, graph
	input.AvailableInputs = []rule.InputKind{rule.Scripts, rule.Invocations, rule.Execution}
	input.BuildShellScriptInput = func(_ context.Context, occurrence checkinputs.OccurrenceID, _ *string) (*checkinputs.ShellScriptInput, error) {
		if occurrence != script.Occurrence.ID {
			t.Fatalf("unexpected script occurrence: %v", occurrence)
		}
		dialect := "bash"
		prepared := &checkinputs.ShellScriptInput{Text: script.Text, MaskedText: script.Text, Dialect: &dialect, Shell: "bash", Excluded: []uint32{1091}}
		for index := range strings.Split(script.Text, "\n") {
			prepared.Lines = append(prepared.Lines, checkinputs.ShellScriptLine{Kind: checkinputs.ShellScriptSourceLine, Line: index + 1})
		}
		return prepared, nil
	}
	return executor.Run(t.Context(), input, []checkinputs.Registration{{Checker: component, Options: input.Options}})
}

// Record source reads through workspace and external mounts, including a nested
// source and an absolute host path. Files without findings must still be dependencies.
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
	input := checkinputs.Input{
		Options:     json.RawMessage(`{"external-sources":true,"source-path":["/sources/0"]}`),
		SourceRoots: []checkinputs.SourceRoot{{Host: "/actual/repo", Guest: "/workspace"}},
		Scripts: []checkinputs.Script{sourceScript(`. shared.sh
# shellcheck source=/actual/repo/lib/clean.sh
. dynamic-name
printf '%s\n' "$VALUE" "$FLAGS" "$SHARED"
`)},
		Files: []checkinputs.FileSystem{
			{Path: "/workspace", FS: preopens.ImmutableFS{FS: files}},
			{Path: "/sources/0", FS: preopens.ImmutableFS{FS: external}},
		},
	}
	findings, err := analyzeSources(t, component, input)
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

// Analyze the same script twice, changing a sourced value from one word to two.
// The SC2086 warning must reflect the updated source on the second call.
func TestSourceEditChangesSubsequentAnalysis(t *testing.T) {
	component := load(t)
	for _, tc := range []struct {
		content  string
		warnings int
	}{{"FLAGS=one\n", 0}, {"FLAGS='one two'\n", 1}} {
		input := checkinputs.Input{
			Options: json.RawMessage(`{"external-sources":true}`),
			Scripts: []checkinputs.Script{sourceScript(". ./values.sh\necho $FLAGS\n")},
			Files:   []checkinputs.FileSystem{{Path: "/workspace", FS: preopens.ImmutableFS{FS: fstest.MapFS{"values.sh": &fstest.MapFile{Data: []byte(tc.content)}}}}},
		}
		findings, err := analyzeSources(t, component, input)
		if err != nil || len(findings) != tc.warnings {
			t.Fatalf("source=%q findings=%+v error=%v", tc.content, findings, err)
		}
		if len(findings) != 0 && findings[0].Code != "SC2086" {
			t.Fatalf("unexpected warning: %+v", findings)
		}
	}
}

// Check that SC1094 maps a syntax error in a sourced file to the workflow's
// source invocation, including its path, reference and position.
func TestSourcedParseFailureIsReportedAtInvocation(t *testing.T) {
	component := load(t)
	findings, err := analyzeSources(t, component, checkinputs.Input{
		Options: json.RawMessage(`{"external-sources":true}`),
		Scripts: []checkinputs.Script{sourceScript(". ./broken.sh\nprintf 'ok\\n'\n")},
		Files: []checkinputs.FileSystem{{Path: "/workspace", FS: preopens.ImmutableFS{FS: fstest.MapFS{
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

// Record guest reads when the working directory is unknown. Absolute paths must
// remain readable, and relative paths must not resolve against an invented base.
func TestUnknownDirectoryUsesOnlyIndependentSourcePaths(t *testing.T) {
	component := load(t)
	for _, tc := range []struct {
		name, script, options string
		noRuntime, read       bool
	}{
		{"absolute", ". /sources/0/values.sh\necho $FLAGS\n", `{"external-sources":true}`, false, true},
		{"absolute search path", ". values.sh\necho $FLAGS\n", `{"external-sources":true,"source-path":["/sources/0"]}`, false, true},
		{"mapped host path", ". /repo/values.sh\necho $FLAGS\n", `{"external-sources":true}`, false, true},
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
			findings, err := analyzeSources(t, component, checkinputs.Input{
				Options: json.RawMessage(tc.options), Scripts: []checkinputs.Script{script},
				SourceRoots: []checkinputs.SourceRoot{{Host: "/repo", Guest: "/sources/0"}},
				Files:       []checkinputs.FileSystem{{Path: "/sources/0", FS: preopens.ImmutableFS{FS: files}}},
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

// Supply conflicting source values to check that ShellCheck searches relative
// candidates first. Remove the relative candidate to check the absolute fallback.
func TestAbsoluteSourceSearchOrderMatchesShellCheck(t *testing.T) {
	component := load(t)
	for _, shadow := range []bool{true, false} {
		workspace := fstest.MapFS{}
		if shadow {
			workspace["sources/0/values.sh"] = &fstest.MapFile{Data: []byte("FLAGS='one two'\n")}
		}
		findings, err := analyzeSources(t, component, checkinputs.Input{
			Options: json.RawMessage(`{"external-sources":true}`),
			Scripts: []checkinputs.Script{sourceScript(". /sources/0/values.sh\necho $FLAGS\n")},
			Files: []checkinputs.FileSystem{
				{Path: "/workspace", FS: preopens.ImmutableFS{FS: workspace}},
				{Path: "/sources/0", FS: preopens.ImmutableFS{FS: fstest.MapFS{"values.sh": &fstest.MapFile{Data: []byte("FLAGS=one\n")}}}},
			},
		})
		if err != nil || (len(findings) == 1 && findings[0].Code == "SC2086") != shadow || !shadow && len(findings) != 0 {
			t.Fatalf("relative candidate=%v findings=%+v error=%v", shadow, findings, err)
		}
	}
}
