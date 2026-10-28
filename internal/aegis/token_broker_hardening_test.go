package aegis

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"google.golang.org/adk/v2/auth"
)

func TestTokenBroker_StoreEnforcementAndBoundedNonceState(t *testing.T) {
	ctx := context.Background()
	rt := NewRuntime(RuntimeConfig{})
	tb := rt.TokenBroker()

	// 1. Verify write-only nonces map was removed from TokenBroker struct
	tbType := reflect.TypeOf(*tb)
	if _, hasDeadNoncesField := tbType.FieldByName("nonces"); hasDeadNoncesField {
		t.Fatalf("TokenBroker still contains dead write-only 'nonces' field; b.pkceChallenges must be the sole pending challenge store")
	}

	// 2. Verify seedWarmSessionGrants populates BOTH b.store and b.grantMeta with warm_session_seed & PKCEVerified=false
	const sessionID = "store-enforced-sess"
	snap := rt.GetOrCreateSession(sessionID)
	if len(snap.GrantedProviders[PersonaAlice]) == 0 {
		t.Fatalf("expected warm GrantedProviders for alice")
	}
	defJiraKey := tb.credentialKey(sessionID, PersonaAlice, ProviderAtlassianJira, defaultScopesForProvider(ProviderAtlassianJira))
	if _, hit, err := tb.store.Get(ctx, defJiraKey); err != nil || !hit {
		t.Fatalf("seedWarmSessionGrants must populate b.store for default scopes; got hit=%v err=%v", hit, err)
	}
	if !tb.hasActiveGrant(ctx, sessionID, PersonaAlice, ProviderAtlassianJira) {
		t.Fatalf("expected hasActiveGrant == true when both grantMeta and b.store have active credential")
	}

	// 3. Evicting credential directly from b.store MUST cause hasActiveGrant and pruneExpiredGrants to return false
	// and prune grantMeta, GrantedProviders, and EphemeralGrants!
	if err := tb.store.Delete(ctx, defJiraKey); err != nil {
		t.Fatalf("store.Delete: %v", err)
	}
	if tb.hasActiveGrant(ctx, sessionID, PersonaAlice, ProviderAtlassianJira) {
		t.Fatalf("hasActiveGrant returned true after credential was deleted from b.store!")
	}
	prunedSnap := tb.pruneExpiredGrants(ctx, sessionID)
	for _, p := range prunedSnap.GrantedProviders[PersonaAlice] {
		if p == ProviderAtlassianJira {
			t.Fatalf("expected atlassian_jira pruned from GrantedProviders after b.store deletion, got %v", prunedSnap.GrantedProviders[PersonaAlice])
		}
	}
	for _, g := range prunedSnap.EphemeralGrants[PersonaAlice] {
		if g.Provider == ProviderAtlassianJira {
			t.Fatalf("expected atlassian_jira pruned from EphemeralGrants after b.store deletion, got %+v", prunedSnap.EphemeralGrants[PersonaAlice])
		}
	}

	// Verify Credential() now emits ConsentRequiredError for the store-evicted provider
	invCtx := WithAuthInvocation(ctx, AuthInvocation{
		SessionID: sessionID,
		Persona:   PersonaAlice,
		Provider:  ProviderAtlassianJira,
	})
	if _, err := tb.Credential(invCtx); err == nil {
		t.Fatalf("expected ConsentRequiredError from Credential() after b.store eviction, got nil")
	} else {
		var consentErr *auth.ConsentRequiredError
		if !errors.As(err, &consentErr) {
			t.Fatalf("expected *auth.ConsentRequiredError, got %v", err)
		}
	}

	// 4. Verify Credential() reuses grantMeta.ExpiresAt (+ auth.ExpirySkew) when caching custom scope keys
	// rather than detaching with a fresh 15m TTL!
	tb.Grant(ctx, OAuthGrantRequest{
		SessionID:   sessionID,
		Persona:     PersonaAlice,
		Provider:    ProviderGitHub,
		AccessToken: "gho-short-ttl-reuse-check",
		TTLSeconds:  1,
	})
	customScopes := []string{"repo"}
	customCtx := WithAuthInvocation(ctx, AuthInvocation{
		SessionID: sessionID,
		Persona:   PersonaAlice,
		Provider:  ProviderGitHub,
		Scopes:    customScopes,
	})
	cred, err := tb.Credential(customCtx)
	if err != nil {
		t.Fatalf("Credential(customScopes) while 1s grant active: %v", err)
	}
	hdr := http.Header{}
	_ = cred.Apply(hdr)
	if got := hdr.Get("Authorization"); got != "Bearer gho-short-ttl-reuse-check" {
		t.Fatalf("Credential(customScopes) Authorization = %q, want Bearer gho-short-ttl-reuse-check", got)
	}

	time.Sleep(1150 * time.Millisecond)
	customKey := tb.credentialKey(sessionID, PersonaAlice, ProviderGitHub, customScopes)
	if _, hit, _ := tb.store.Get(ctx, customKey); hit {
		t.Fatalf("custom scope cache entry in b.store outlived grantMeta.ExpiresAt (+1s TTL)!")
	}
	if _, err := tb.Credential(customCtx); err == nil {
		t.Fatalf("expected Credential(customScopes) to fail after 1s grantMeta TTL expired")
	}

	// 5. Verify issueConsentChallengeWithPKCE supersedes older pending challenge for same (sessionID, persona, provider)
	// and pruneExpiredPKCEChallengesLocked prunes expired consumedNonces (15m TTL)
	chOld := tb.issueConsentChallengeWithPKCE("nonce-sess", PersonaAlice, ProviderGoogleGmail, defaultScopesForProvider(ProviderGoogleGmail), "")
	chNew := tb.issueConsentChallengeWithPKCE("nonce-sess", PersonaAlice, ProviderGoogleGmail, defaultScopesForProvider(ProviderGoogleGmail), "")
	tb.mu.RLock()
	_, oldStillPending := tb.pkceChallenges[chOld.Nonce]
	_, newPending := tb.pkceChallenges[chNew.Nonce]
	tb.mu.RUnlock()
	if oldStillPending {
		t.Fatalf("expected older pending PKCE challenge %q for (nonce-sess, alice, google_gmail) to be superseded", chOld.Nonce)
	}
	if !newPending {
		t.Fatalf("expected newest PKCE challenge %q to remain pending", chNew.Nonce)
	}

	if _, verified, err := tb.verifyAndConsumePKCE(chNew.Nonce, ""); err != nil || !verified {
		t.Fatalf("verifyAndConsumePKCE(chNew) = (verified=%v, err=%v), want (true, nil)", verified, err)
	}

	// Simulate consumedNonce past 15m TTL and verify pruneExpiredPKCEChallengesLocked evicts it
	tb.mu.Lock()
	if _, exists := tb.consumedNonces[chNew.Nonce]; !exists {
		tb.mu.Unlock()
		t.Fatalf("expected consumed nonce %q recorded in consumedNonces", chNew.Nonce)
	}
	tb.pruneExpiredPKCEChallengesLocked(time.Now().UTC().Add(16 * time.Minute))
	_, stillConsumedAfterTTL := tb.consumedNonces[chNew.Nonce]
	tb.mu.Unlock()
	if stillConsumedAfterTTL {
		t.Fatalf("expected consumed nonce %q to be pruned after 15m TTL", chNew.Nonce)
	}
}
