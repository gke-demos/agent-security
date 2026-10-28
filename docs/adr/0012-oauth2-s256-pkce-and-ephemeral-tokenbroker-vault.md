# 12. OAuth 2.0 + S256 PKCE Login Flows and Ephemeral In-Memory TokenBroker Vault

Date: 2026-10-28

## Status

Accepted

## Context

In earlier phases of **AegisSRE**, [`TokenBroker.issueConsentChallenge`](../../internal/aegis/token_broker.go) generated an OAuth 2.0 authorization URL using only a `state` nonce (`response_type=code`) without an RFC 7636 Proof Key for Code Exchange (`PKCE`) `code_verifier` or `code_challenge`. In addition:

1. `defaultCredentialTTL` was set to `1h`, and `TokenBroker.hasActiveGrant` checked `SessionSnapshot.GrantedProviders` without verifying whether the underlying credential in `b.store` (`auth.InMemoryCredentialStore`) had expired.
2. `ProviderGoogleGmail` requested only `gmail.readonly` rather than a unified Google Workspace SSO scope bundle (`openid`, `email`, `gmail.readonly`, `drive.readonly`, `calendar.readonly`).
3. For external service connections in web applications, **AegisSRE** must never prompt for or store long-lived Personal Access Tokens (PATs) in browser storage (`localStorage` / `sessionStorage`) or databases; all 3LO grants must use OAuth 2.0 + S256 PKCE flows storing short-lived access tokens strictly in the backend gateway's ephemeral in-memory vault with automatic TTL expiry.

## Decision

1. **RFC 7636 S256 PKCE Handshake (`CodeVerifier` & `CodeChallenge`)**:
   - When `issueConsentChallenge` (or `GET /oauth/{provider}/authorize`) executes, `TokenBroker` generates a cryptographic 32-byte random `code_verifier` (base64url-encoded without padding), computes `code_challenge = BASE64URL(SHA256(code_verifier))` with `code_challenge_method = "S256"`, and stores a one-time `PKCEChallengeState` (`Nonce`, `CodeVerifier`, `CodeChallenge`, `CodeChallengeMethod: "S256"`, `SessionID`, `Persona`, `Provider`, `Scopes`, `ExpiresAt: +5m`) in memory.
   - `ConsentChallenge` includes `CodeChallenge`, `CodeChallengeMethod` (`"S256"`), and `ExpiresInSeconds` (`900`), and appends `code_challenge` and `code_challenge_method=S256` to `AuthURI`.
   - On `GET /oauth/{provider}/callback` and `POST /api/sessions/{sessionId}/oauth/grant`, when a `nonce`/`state` or `code_verifier` is supplied, `TokenBroker` verifies `BASE64URL(SHA256(code_verifier)) == CodeChallenge`, includes `code_verifier` in the `authorization_code` token exchange POST (`exchangeOAuthCode`), and deletes the consumed `PKCEChallengeState`.

2. **Unified Google Workspace SSO Scope Bundle**:
   - Upgrade `defaultScopesForProvider(ProviderGoogleGmail)` to request unified Google Workspace SSO scopes:
     - `openid`
     - `email`
     - `https://www.googleapis.com/auth/gmail.readonly`
     - `https://www.googleapis.com/auth/drive.readonly`
     - `https://www.googleapis.com/auth/calendar.readonly`

3. **Strict `15m` Ephemeral In-Memory Vault TTL & Automatic Expiry Pruning**:
   - Set `defaultCredentialTTL = 15 * time.Minute` (overridable per grant via `OAuthGrantRequest.TTLSeconds` for deterministic sub-second expiry tests).
   - Store access tokens strictly inside `TokenBroker`'s in-memory `auth.CredentialStore` — never in `SessionSnapshot`, browser storage (`localStorage`/`sessionStorage`), or persistent databases.
   - Add `EphemeralGrants map[PersonaID][]EphemeralPKCEGrant` to `SessionSnapshot` containing only non-secret grant metadata (`provider`, `persona`, `scopes`, `authMethod: "oauth2_pkce_s256"`, `pkceVerified: true`, `codeChallengeMethod: "S256"`, `issuedAt`, `expiresAt`, `ttlRemainingSeconds`).
   - Update `hasActiveGrant` and session snapshot reads (`GetOrCreateSession` / `pruneExpiredGrants`) to verify that the grant exists and is unexpired in `b.store`; expired grants are automatically pruned from `GrantedProviders` and `EphemeralGrants`, causing the next tool call to emit a fresh cold 3LO `ConsentChallengeCard` (`adk_request_credential`).

4. **Zero-PAT Browser PKCE UX & Hygiene Guardrails**:
   - Clicking `Authorize <Provider> as <Persona> (OAuth 2.0 + PKCE)` on a `ConsentChallengeCard` or clicking `Connect (PKCE)` in the `⌘K` `3LO OAuth Token Vault` initiates the S256 PKCE flow (`/oauth/{provider}/authorize` → `/oauth/{provider}/callback`) and renders `PKCE · S256 · <TTL>` badges on each active provider chip.
   - Automated tests verify that `static/index.html` and `static/app.js` contain zero PAT `<input>` prompts and never write tokens to `localStorage` or `sessionStorage`.

## Consequences

- **Positive**: Eliminates long-lived browser PATs, enforces RFC 7636 S256 PKCE across Google Workspace SSO, GitHub, and Atlassian Jira Cloud, and guarantees automatic in-memory TTL expiration and pruning.
- **Negative**: Requires operators or automated tests with custom short TTLs (`TTLSeconds`) to re-authorize via PKCE once the ephemeral grant expires.
