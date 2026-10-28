package aegis

import (
	"reflect"
	"testing"

	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/model"
)

func TestSecurityPluginConfig_CallbackInspectionAndDrift(t *testing.T) {
	rt := NewRuntime(RuntimeConfig{})
	cfg := rt.securityPluginConfig()
	got := activePluginCallbacksFromConfig(cfg)
	want := CanonicalSecurityPluginCallbacks()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("activePluginCallbacksFromConfig(rt.securityPluginConfig()) = %v, want %v", got, want)
	}

	// Nilling a callback on plugin.Config must diverge from CanonicalSecurityPluginCallbacks
	cfgMissing := cfg
	cfgMissing.AfterToolCallback = nil
	if reflect.DeepEqual(activePluginCallbacksFromConfig(cfgMissing), want) {
		t.Fatalf("expected activePluginCallbacksFromConfig to detect nil AfterToolCallback")
	}

	// Registering an extra callback on plugin.Config must also diverge
	cfgExtra := cfg
	cfgExtra.OnModelErrorCallback = func(_ agent.Context, _ *model.LLMRequest, _ error) (*model.LLMResponse, error) {
		return nil, nil
	}
	if reflect.DeepEqual(activePluginCallbacksFromConfig(cfgExtra), want) {
		t.Fatalf("expected activePluginCallbacksFromConfig to detect newly added OnModelErrorCallback")
	}
}
