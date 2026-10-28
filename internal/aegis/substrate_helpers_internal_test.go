package aegis

import (
	"reflect"
	"testing"
)

func TestParseEgressPolicySummary_DeduplicatesTopLevelAndSpecRules(t *testing.T) {
	payload := []byte(`{
		"defaultAction": "ALLOW",
		"rules": [
			{
				"https": {"hostnames": [" api.github.com ", "oauth2.googleapis.com"]},
				"destinations": [{"host": "api.github.com"}, {"host": "logging.googleapis.com"}]
			}
		],
		"spec": {
			"defaultAction": "DENY",
			"rules": [
				{
					"https": {"hostnames": ["logging.googleapis.com", "container.googleapis.com"]},
					"destinations": [{"host": " modelarmor.us-central1.rep.googleapis.com "}, {"host": ""}]
				}
			]
		}
	}`)

	defaultAction, hosts := parseEgressPolicySummary(payload)
	if defaultAction != "DENY" {
		t.Errorf("defaultAction = %q, want DENY", defaultAction)
	}
	wantHosts := []string{
		"api.github.com",
		"oauth2.googleapis.com",
		"logging.googleapis.com",
		"container.googleapis.com",
		"modelarmor.us-central1.rep.googleapis.com",
	}
	if !reflect.DeepEqual(hosts, wantHosts) {
		t.Errorf("allowedHosts = %v, want %v", hosts, wantHosts)
	}

	if da, badHosts := parseEgressPolicySummary([]byte("{invalid-json")); da != "" || badHosts != nil {
		t.Errorf("invalid JSON parseEgressPolicySummary = (%q, %v), want (\"\", nil)", da, badHosts)
	}
}

func TestPopulateSandboxMetadata_Scenario04AndScenario05SharedContract(t *testing.T) {
	// 1. Fixture mode (resp == nil): populates baseline gVisor + caller meta, omits live-only targetActor
	s4FixtureFields := map[string]string{}
	populateSandboxMetadata(s4FixtureFields, map[string]string{
		"Provenance":            string(ProvenanceFixture),
		"a2aCredentialScrub":    "withoutCredentialParts (upstream 3LO stripped)",
		"peerResponseScreening": "PASS: clean summary",
		"targetActor":           "aegis-system/remediator-1",
	}, nil)

	if s4FixtureFields["sandboxClass"] != "gvisor" ||
		s4FixtureFields["preferredFidelity"] != "SNAPSHOT_FIDELITY_MEMORY" ||
		s4FixtureFields["containerEnvSecrets"] != "0" ||
		s4FixtureFields["Provenance"] != string(ProvenanceFixture) ||
		s4FixtureFields["a2aCredentialScrub"] == "" ||
		s4FixtureFields["peerResponseScreening"] != "PASS: clean summary" {
		t.Fatalf("unexpected fixture sandbox fields: %+v", s4FixtureFields)
	}
	if _, exists := s4FixtureFields["targetActor"]; exists {
		t.Errorf("expected targetActor omitted when live SandboxExecutionResponse is nil, got %+v", s4FixtureFields)
	}

	// 2. Live mode (resp != nil): promotes Provenance=LIVE, stamps targetActor, and merges live proof metadata
	s5LiveFields := map[string]string{}
	liveResp := &SandboxExecutionResponse{
		Verified:   true,
		TestOutput: "=== RUN TestCheckoutHotfix\n--- PASS: TestCheckoutHotfix (0.01s)",
		Metadata: map[string]string{
			"kernelSignature":        "Linux version 4.19.0-gvisor",
			"zeroEnvSecretsVerified": "true",
			"githubAllowedProbe":     "http:200",
			"evilExfilProbe":         "blocked:403",
			"actorName":              "remediator-1",
			"sandboxPod":             "aegis-remediator-pool-xyz",
		},
	}
	populateSandboxMetadata(s5LiveFields, map[string]string{
		"peerResponseScreening": "PASS: clean summary",
		"targetActor":           "aegis-system/remediator-1",
	}, liveResp)

	if s5LiveFields["Provenance"] != string(ProvenanceLive) {
		t.Errorf("Provenance = %q, want LIVE", s5LiveFields["Provenance"])
	}
	if s5LiveFields["targetActor"] != "aegis-system/remediator-1" {
		t.Errorf("targetActor = %q, want aegis-system/remediator-1", s5LiveFields["targetActor"])
	}
	if s5LiveFields["kernelSignature"] != "Linux version 4.19.0-gvisor" ||
		s5LiveFields["zeroEnvSecretsVerified"] != "true" ||
		s5LiveFields["githubAllowedProbe"] != "http:200" ||
		s5LiveFields["evilExfilProbe"] != "blocked:403" ||
		s5LiveFields["actorName"] != "remediator-1" ||
		s5LiveFields["sandboxPod"] != "aegis-remediator-pool-xyz" ||
		s5LiveFields["testOutput"] == "" {
		t.Errorf("live sandbox proof fields incomplete: %+v", s5LiveFields)
	}
}
