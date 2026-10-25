package host_test

import (
	"encoding/json"
	"errors"
	"testing"

	"actionlint.kjanat.dev/v2/analyzer"
)

func TestToolIntegrationNegotiatesConfigurationAndGrants(t *testing.T) {
	component := load(t)
	descriptor := component.ToolIntegration()
	if descriptor == nil || descriptor.Tool != "shellcheck" || descriptor.Contract != "kjanat:actionlint/shellcheck-config@0.1.0" {
		t.Fatalf("integration: %+v", descriptor)
	}
	negotiated, err := component.NegotiateTool(t.Context(), json.RawMessage(`{"external-sources":true,"source-path":["/repo/lib"]}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(negotiated.Resources) != 2 || negotiated.Resources[0].Kind != analyzer.ToolWorkspace || negotiated.Resources[1].Kind != analyzer.ToolDirectory || negotiated.Resources[1].Path != "/repo/lib" {
		t.Fatalf("resource requests: %+v", negotiated.Resources)
	}
	var options struct {
		External bool     `json:"external-sources"`
		Paths    []string `json:"source-path"`
	}
	if err := json.Unmarshal(negotiated.Options, &options); err != nil {
		t.Fatal(err)
	}
	if !options.External || len(options.Paths) != 1 || options.Paths[0] != "/repo/lib" {
		t.Fatalf("negotiated options: %s", negotiated.Options)
	}
	for _, config := range []string{`{"rc-file":".shellcheckrc"}`, `{"disable":["all"]}`, `{"disable":["SC2000-SC3000"]}`} {
		_, err := component.NegotiateTool(t.Context(), json.RawMessage(config), nil)
		var unsupported *analyzer.UnsupportedToolConfiguration
		if !errors.As(err, &unsupported) {
			t.Fatalf("%s: expected negotiated refusal, got %v", config, err)
		}
	}
}
