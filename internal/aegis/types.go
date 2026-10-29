package aegis

import (
	"context"
	"net/http"
	"time"
)

// PersonaID identifies a named Operator identity profile in GLOSSARY.md.
type PersonaID string

const (
	PersonaAlice PersonaID = "alice" // SecOps Lead (privileged: SEC-101, private GitHub, Gmail)
	PersonaBob   PersonaID = "bob"   // External Contractor (restricted: PUB-202, public GitHub only)
)

// ProviderID identifies an external connected identity provider.
type ProviderID string

const (
	ProviderGoogleGmail   ProviderID = "google_gmail"
	ProviderAtlassianJira ProviderID = "atlassian_jira"
	ProviderGitHub        ProviderID = "github"
	ProviderGCPIAM        ProviderID = "gcp_iam"
)

// ScenarioID identifies one of the 5 canonical Red-vs-Blue Security Scenarios.
type ScenarioID string

const (
	Scenario01PromptInjectionAndPII ScenarioID = "SCENARIO-01"
	Scenario02ConfusedDeputy3LO     ScenarioID = "SCENARIO-02"
	Scenario03AgentGatewayAndStepUp ScenarioID = "SCENARIO-03"
	Scenario04AttenuatedA2ASandbox  ScenarioID = "SCENARIO-04"
	Scenario05FullChainZeroTrust    ScenarioID = "SCENARIO-05"
)

// BoundaryID names one of the 6 core security boundaries.
type BoundaryID string

const (
	BoundaryGenerativeUI       BoundaryID = "B1_A2UI_STEP_UP"
	BoundaryReasoningGuard     BoundaryID = "B2_MODEL_ARMOR_SDP"
	BoundaryIdentity3LO        BoundaryID = "B3_TOKEN_BROKER_3LO"
	BoundaryPlatformGovernance BoundaryID = "B4_AGENT_REGISTRY_GATEWAY"
	BoundaryCrossAgentA2A      BoundaryID = "B5_ATTENUATED_A2A"
	BoundarySandboxEgress      BoundaryID = "B6_SUBSTRATE_GVISOR_MITM"
)

// BoundaryVerdict records what a boundary did during a turn.
type BoundaryVerdict string

const (
	VerdictAllowed     BoundaryVerdict = "ALLOWED"
	VerdictRedacted    BoundaryVerdict = "REDACTED"
	VerdictBlocked     BoundaryVerdict = "BLOCKED"
	VerdictChallenge   BoundaryVerdict = "CHALLENGE"
	VerdictBypassedRed BoundaryVerdict = "BYPASSED_RED"
)

// SourceProvenance records whether a tool call or boundary trace event executed against a
// live External Source ("LIVE") or the deterministic local fixture fallback ("FIXTURE").
type SourceProvenance string

const (
	ProvenanceFixture SourceProvenance = "FIXTURE"
	ProvenanceLive    SourceProvenance = "LIVE"
)

// ExternalSourceID identifies one of the 8 External Sources in GLOSSARY.md / ADR-0007.
type ExternalSourceID string

const (
	SourceAgentPlatformGemini ExternalSourceID = "agent_platform_gemini"
	SourceModelArmorSDP       ExternalSourceID = "model_armor_sdp"
	SourceGCPObservability    ExternalSourceID = "gcp_observability"
	SourceAgentRegistry       ExternalSourceID = "agent_registry"
	SourceGitHub              ExternalSourceID = "github"
	SourceGoogleGmail         ExternalSourceID = "google_gmail"
	SourceAtlassianJira       ExternalSourceID = "atlassian_jira"
	SourceSubstrateSandbox    ExternalSourceID = "substrate_sandbox"
)

// SourceStatus reports the connection mode and endpoint of an External Source.
type SourceStatus struct {
	ID         ExternalSourceID `json:"id"`
	Name       string           `json:"name"`
	Boundary   BoundaryID       `json:"boundary"`
	Provenance SourceProvenance `json:"provenance"`
	Endpoint   string           `json:"endpoint"`
	Detail     string           `json:"detail"`
}

// TurnOutcome summarizes the end-to-end result of a turn.
type TurnOutcome string

const (
	OutcomeDefendedSuccess  TurnOutcome = "DEFENDED_SUCCESS"
	OutcomeBlocked          TurnOutcome = "BLOCKED"
	OutcomeConsentRequired  TurnOutcome = "CONSENT_REQUIRED"
	OutcomeApprovalRequired TurnOutcome = "APPROVAL_REQUIRED"
	OutcomeExploitedRed     TurnOutcome = "EXPLOITED_RED"
)

// A2UICardType identifies one of the 6 schema-validated Declarative UI Cards in the catalog.
type A2UICardType string

const (
	CardIncidentSummary    A2UICardType = "IncidentSummaryCard"
	CardConsentChallenge   A2UICardType = "ConsentChallengeCard"
	CardStepUpConfirmation A2UICardType = "StepUpConfirmationCard"
	CardThreatIntercept    A2UICardType = "ThreatInterceptCard"
	CardAclDenial          A2UICardType = "AclDenialCard"
	CardSandboxExecution   A2UICardType = "SandboxExecutionCard"
)

// SecurityPosture holds the 5 independently toggleable Security Shields (ADR-0002).
type SecurityPosture struct {
	PromptScreenEnabled         bool `json:"promptScreenEnabled"`
	PIIRedactorEnabled          bool `json:"piiRedactorEnabled"`
	TokenBrokerEnabled          bool `json:"tokenBrokerEnabled"`
	StepUpAndA2UICatalogEnabled bool `json:"stepUpAndA2UICatalogEnabled"`
	SandboxEgressMITMEnabled    bool `json:"sandboxEgressMitmEnabled"`
}

// AllBluePosture returns a SecurityPosture with all 5 Security Shields active.
func AllBluePosture() SecurityPosture {
	return SecurityPosture{
		PromptScreenEnabled:         true,
		PIIRedactorEnabled:          true,
		TokenBrokerEnabled:          true,
		StepUpAndA2UICatalogEnabled: true,
		SandboxEgressMITMEnabled:    true,
	}
}

// AllRedPosture returns a SecurityPosture with all 5 Security Shields disabled.
func AllRedPosture() SecurityPosture {
	return SecurityPosture{}
}

// BoundaryTraceEvent is a single entry in the Boundary Trace Waterfall.
type BoundaryTraceEvent struct {
	Order      int               `json:"order"`
	Boundary   BoundaryID        `json:"boundary"`
	Shield     string            `json:"shield"`
	Component  string            `json:"component"`
	Action     string            `json:"action"`
	Verdict    BoundaryVerdict   `json:"verdict"`
	Provenance SourceProvenance  `json:"provenance"`
	Detail     string            `json:"detail"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
}

// A2UICard is a schema-validated Declarative UI Card (application/json+a2ui).
type A2UICard struct {
	SurfaceID string            `json:"surfaceId"`
	MimeType  string            `json:"mimeType"`
	Version   string            `json:"version"`
	Type      A2UICardType      `json:"type"`
	Title     string            `json:"title"`
	Subtitle  string            `json:"subtitle,omitempty"`
	Severity  string            `json:"severity"`
	Body      string            `json:"body"`
	Fields    map[string]string `json:"fields,omitempty"`
	Actions   []A2UICardAction  `json:"actions,omitempty"`
}

// A2UICardAction represents an interactive button on an A2UI card.
type A2UICardAction struct {
	ID       string            `json:"id"`
	Label    string            `json:"label"`
	Kind     string            `json:"kind"` // "oauth_consent" | "step_up_approve" | "step_up_reject"
	Endpoint string            `json:"endpoint,omitempty"`
	Payload  map[string]string `json:"payload,omitempty"`
}

// ConsentChallenge represents an adk_request_credential 3LO interrupt.
type ConsentChallenge struct {
	Provider            ProviderID `json:"provider"`
	Persona             PersonaID  `json:"persona"`
	Scopes              []string   `json:"scopes"`
	AuthURI             string     `json:"authUri"`
	Nonce               string     `json:"nonce"`
	ResourceRef         string     `json:"resourceRef"`
	CodeChallenge       string     `json:"codeChallenge,omitempty"`
	CodeChallengeMethod string     `json:"codeChallengeMethod,omitempty"`
	ExpiresInSeconds    int        `json:"expiresInSeconds,omitempty"`
}

// StepUpConfirmation represents an adk_request_confirmation HITL interrupt.
type StepUpConfirmation struct {
	ConfirmationID string            `json:"confirmationId"`
	CallID         string            `json:"callId,omitempty"`
	ADKSessionID   string            `json:"adkSessionId,omitempty"`
	FunctionCall   string            `json:"functionCall"` // "adk_request_confirmation"
	TargetTool     string            `json:"targetTool"`
	TargetResource string            `json:"targetResource"`
	Hint           string            `json:"hint"`
	Arguments      map[string]string `json:"arguments"`
	Pending        bool              `json:"pending"`
}

// OutboundWireRecord captures an outbound tool HTTP request for audit and test verification.
type OutboundWireRecord struct {
	Provider          ProviderID        `json:"provider"`
	ToolName          string            `json:"toolName"`
	Method            string            `json:"method"`
	URL               string            `json:"url"`
	AuthHeaderPresent bool              `json:"authHeaderPresent"`
	AuthPrincipal     string            `json:"authPrincipal"`
	StatusCode        int               `json:"statusCode"`
	Provenance        SourceProvenance  `json:"provenance"`
	Headers           map[string]string `json:"headers,omitempty"`
}

// TurnRequest is the input to AegisRuntime.ExecuteTurn.
type TurnRequest struct {
	SessionID             string          `json:"sessionId"`
	Persona               PersonaID       `json:"persona"`
	ScenarioID            ScenarioID      `json:"scenarioId"`
	Posture               SecurityPosture `json:"posture"`
	Prompt                string          `json:"prompt"`
	CleanPIIOnly          bool            `json:"cleanPiiOnly,omitempty"`
	RequireCold3LOConsent bool            `json:"requireCold3loConsent,omitempty"`
	ForwardedBearerToken  string          `json:"-"`
}

// TurnResult is the output of AegisRuntime.ExecuteTurn.
type TurnResult struct {
	SessionID              string               `json:"sessionId"`
	ADKSessionID           string               `json:"adkSessionId,omitempty"`
	Persona                PersonaID            `json:"persona"`
	ScenarioID             ScenarioID           `json:"scenarioId"`
	Posture                SecurityPosture      `json:"posture"`
	Outcome                TurnOutcome          `json:"outcome"`
	AssistantText          string               `json:"assistantText"`
	SanitizedInputPreview  string               `json:"sanitizedInputPreview"`
	OutboundCommentPreview string               `json:"outboundCommentPreview,omitempty"`
	Cards                  []A2UICard           `json:"cards"`
	BoundaryTrace          []BoundaryTraceEvent `json:"boundaryTrace"`
	ConsentChallenge       *ConsentChallenge    `json:"consentChallenge,omitempty"`
	StepUpConfirmation     *StepUpConfirmation  `json:"stepUpConfirmation,omitempty"`
	WireRecords            []OutboundWireRecord `json:"wireRecords,omitempty"`
	ModelCallCount         int                  `json:"modelCallCount,omitempty"`
	PluginCallbacks        []string             `json:"pluginCallbacks,omitempty"`
	ExecutedTools          []string             `json:"executedTools,omitempty"`
}

// ConfirmationResolution resolves a pending StepUpConfirmation.
type ConfirmationResolution struct {
	SessionID      string `json:"sessionId"`
	ConfirmationID string `json:"confirmationId"`
	Confirmed      bool   `json:"confirmed"`
}

// OAuthGrantRequest grants or completes a 3LO token for a Persona and Provider.
type OAuthGrantRequest struct {
	SessionID    string     `json:"sessionId"`
	Persona      PersonaID  `json:"persona"`
	Provider     ProviderID `json:"provider"`
	Scopes       []string   `json:"scopes,omitempty"`
	Token        string     `json:"token,omitempty"`
	AccessToken  string     `json:"accessToken,omitempty"`
	Nonce        string     `json:"nonce,omitempty"`
	CodeVerifier string     `json:"codeVerifier,omitempty"`
	AuthMethod   string     `json:"authMethod,omitempty"`
	TTLSeconds   int        `json:"ttlSeconds,omitempty"`
}

// OAuthCallback carries parameters to complete an OAuth 2.0 3LO grant or callback.
type OAuthCallback = OAuthGrantRequest

// ConsentResult captures the updated session state after completing an OAuth 2.0 3LO grant.
type ConsentResult struct {
	SessionID string           `json:"sessionId"`
	Persona   PersonaID        `json:"persona"`
	Provider  ProviderID       `json:"provider"`
	Granted   bool             `json:"granted"`
	Session   *SessionSnapshot `json:"session,omitempty"`
}

// TurnStreamEventType identifies one of the 6 real-time SSE frames in ADR-0009.
type TurnStreamEventType string

const (
	TurnStreamEventStarted      TurnStreamEventType = "turn.started"
	TurnStreamEventBoundaryStep TurnStreamEventType = "boundary.step"
	TurnStreamEventWireRecord   TurnStreamEventType = "wire.record"
	TurnStreamEventTextDelta    TurnStreamEventType = "text.delta"
	TurnStreamEventA2UICard     TurnStreamEventType = "a2ui.card"
	TurnStreamEventCompleted    TurnStreamEventType = "turn.completed"
)

// TurnStreamEvent is a single frame emitted over the Turn Event Stream (SSE) during a turn.
type TurnStreamEvent struct {
	Type       TurnStreamEventType `json:"type"`
	SessionID  string              `json:"sessionId"`
	Persona    PersonaID           `json:"persona"`
	ScenarioID ScenarioID          `json:"scenarioId,omitempty"`
	Step       *BoundaryTraceEvent `json:"step,omitempty"`
	Record     *OutboundWireRecord `json:"record,omitempty"`
	Delta      string              `json:"delta,omitempty"`
	Card       *A2UICard           `json:"card,omitempty"`
	Turn       *TurnResult         `json:"turn,omitempty"`
}

// TurnEventSink receives real-time TurnStreamEvent frames as a turn executes.
type TurnEventSink func(TurnStreamEvent)

// AegisRuntime defines the primary in-process seam for executing turns, resolving HITL
// confirmations, completing 3LO OAuth callbacks, and inspecting session state.
type AegisRuntime interface {
	ExecuteTurn(ctx context.Context, req TurnRequest) (*TurnResult, error)
	ExecuteTurnStream(ctx context.Context, req TurnRequest, sink TurnEventSink) (*TurnResult, error)
	ResolveConfirmation(ctx context.Context, res ConfirmationResolution) (*TurnResult, error)
	ResolveConfirmationStream(ctx context.Context, res ConfirmationResolution, sink TurnEventSink) (*TurnResult, error)
	CompleteOAuthConsent(ctx context.Context, cb OAuthCallback) (*ConsentResult, error)
	GetSessionState(ctx context.Context, sessionID string) (*SessionSnapshot, error)
	GetSourcesStatus(ctx context.Context) ([]SourceStatus, error)
}

// EphemeralPKCEGrant exposes non-secret metadata for an active OAuth 2.0 + S256 PKCE
// grant held in the TokenBroker in-memory vault. Raw bearer tokens are never included.
type EphemeralPKCEGrant struct {
	Provider            ProviderID `json:"provider"`
	Persona             PersonaID  `json:"persona"`
	Scopes              []string   `json:"scopes"`
	AuthMethod          string     `json:"authMethod"`
	PKCEVerified        bool       `json:"pkceVerified"`
	CodeChallengeMethod string     `json:"codeChallengeMethod"`
	IssuedAt            time.Time  `json:"issuedAt"`
	ExpiresAt           time.Time  `json:"expiresAt"`
	TTLRemainingSeconds int        `json:"ttlRemainingSeconds"`
}

// SessionSnapshot holds the current state of an Operator session.
type SessionSnapshot struct {
	SessionID           string                             `json:"sessionId"`
	ActivePersona       PersonaID                          `json:"activePersona"`
	Posture             SecurityPosture                    `json:"posture"`
	GrantedProviders    map[PersonaID][]ProviderID         `json:"grantedProviders"`
	EphemeralGrants     map[PersonaID][]EphemeralPKCEGrant `json:"ephemeralGrants,omitempty"`
	PendingConfirmation *StepUpConfirmation                `json:"pendingConfirmation,omitempty"`
	LastTurn            *TurnResult                        `json:"lastTurn,omitempty"`
}

// RuntimeConfig configures NewRuntime.
type RuntimeConfig struct {
	ModelArmorEndpoint         string
	DLPEndpoint                string
	AgentRegistryURL           string
	GCPProjectID               string
	GCPLocation                string
	GKEClusterName             string
	AgentPlatformLiveLLM       bool
	GeminiEndpoint             string
	GitHubAPIURL               string
	GitHubTargetRepo           string
	GmailAPIURL                string
	JiraBaseURL                string
	JiraRestrictedKey          string
	JiraPublicKey              string
	SubstrateGatewayURL        string
	SubstrateTargetActor       string
	LiveSubstrate              bool
	AliceGitHubToken           string
	BobGitHubToken             string
	AliceGmailToken            string
	BobGmailToken              string
	AliceJiraToken             string
	BobJiraToken               string
	GitHubOAuthClientID        string
	GitHubOAuthClientSecret    string
	GoogleOAuthClientID        string
	GoogleOAuthClientSecret    string
	JiraOAuthClientID          string
	JiraOAuthClientSecret      string
	OAuthTokenEndpointOverride string
	SPIFFECredentialBundlePath string
	GCPAuthProviderID          string
	AgentGatewayIngressURL     string
	AgentGatewayEgressProxyURL string
	HTTPClient                 *http.Client
}

// HTTPRouteRegistrar registers additional HTTP routes onto the Aegis server mux.
type HTTPRouteRegistrar func(mux *http.ServeMux, rt *Runtime)
