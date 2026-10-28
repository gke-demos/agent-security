(function () {
  "use strict";

  const SESSION_ID = "arena-live-session";

  const CARD_CATALOG_ICONS = {
    IncidentSummaryCard:
      '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>',
    ConsentChallengeCard:
      '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="5.5"/><path d="m21 2-9.6 9.6"/><path d="m15.5 7.5 3 3L22 7l-3-3"/></svg>',
    StepUpConfirmationCard:
      '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    ThreatInterceptCard:
      '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    AclDenialCard:
      '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
    SandboxExecutionCard:
      '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>',
  };

  const VERDICT_ICONS = {
    ALLOWED:
      '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>',
    REDACTED:
      '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    BLOCKED:
      '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
    CHALLENGE:
      '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    EXPLOITED_RED:
      '<svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
  };

  const ALL_BOUNDARIES = [
    "B1_A2UI_STEP_UP",
    "B2_MODEL_ARMOR_SDP",
    "B3_TOKEN_BROKER_3LO",
    "B4_AGENT_REGISTRY_GATEWAY",
    "B5_ATTENUATED_A2A",
    "B6_SUBSTRATE_GVISOR_MITM",
  ];

  const state = {
    sessionId: SESSION_ID,
    persona: "alice",
    scenarioId: "SCENARIO-01",
    posture: {
      promptScreenEnabled: true,
      piiRedactorEnabled: true,
      tokenBrokerEnabled: true,
      stepUpAndA2UICatalogEnabled: true,
      sandboxEgressMitmEnabled: true,
    },
    grantedProviders: {
      alice: ["google_gmail", "atlassian_jira", "github", "gcp_iam"],
      bob: ["google_gmail", "atlassian_jira", "github", "gcp_iam"],
    },
    ephemeralGrants: {
      alice: [],
      bob: [],
    },
    scenarios: {},
  };

  function base64UrlEncodeBytes(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  async function generateBrowserPKCEPair() {
    const verifierBytes = new Uint8Array(32);
    window.crypto.getRandomValues(verifierBytes);
    const codeVerifier = base64UrlEncodeBytes(verifierBytes);
    const encoded = new TextEncoder().encode(codeVerifier);
    const digest = await window.crypto.subtle.digest("SHA-256", encoded);
    const codeChallenge = base64UrlEncodeBytes(new Uint8Array(digest));
    return {
      codeVerifier: codeVerifier,
      codeChallenge: codeChallenge,
      codeChallengeMethod: "S256",
    };
  }

  function applySessionSnapshot(snap) {
    if (!snap) return;
    if (snap.activePersona) state.persona = snap.activePersona;
    if (snap.posture) state.posture = snap.posture;
    if (snap.grantedProviders) state.grantedProviders = snap.grantedProviders;
    if (snap.ephemeralGrants) state.ephemeralGrants = snap.ephemeralGrants;
  }

  function formatGrantTTL(ttlRemainingSeconds) {
    const sec = Number(ttlRemainingSeconds) || 0;
    if (sec <= 0) return "Expired";
    if (sec >= 60) return Math.ceil(sec / 60) + "m";
    return sec + "s";
  }

  async function authorizeProviderWithPKCE(provider, persona) {
    const targetPersona = persona || state.persona;
    const targetProvider = provider || "atlassian_jira";
    const pkce = await generateBrowserPKCEPair();

    const authURL =
      "/oauth/" +
      encodeURIComponent(targetProvider) +
      "/authorize?session_id=" +
      encodeURIComponent(state.sessionId) +
      "&persona=" +
      encodeURIComponent(targetPersona) +
      "&code_challenge=" +
      encodeURIComponent(pkce.codeChallenge) +
      "&code_challenge_method=S256";

    const authResp = await fetch(authURL);
    if (!authResp.ok) return false;
    const challenge = await authResp.json();

    const grantResp = await fetch(
      "/api/sessions/" + encodeURIComponent(state.sessionId) + "/oauth/grant",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          persona: targetPersona,
          provider: targetProvider,
          nonce: challenge.nonce || "",
          codeVerifier: pkce.codeVerifier,
        }),
      }
    );
    if (!grantResp.ok) return false;
    const snap = await grantResp.json();
    applySessionSnapshot(snap);
    syncPersonaAndVaultUI();
    return true;
  }

  async function refreshSessionVaultSnapshot() {
    try {
      const resp = await fetch("/api/sessions/" + encodeURIComponent(state.sessionId));
      if (resp.ok) {
        const snap = await resp.json();
        applySessionSnapshot(snap);
        syncPersonaAndVaultUI();
      }
    } catch (err) {
      console.error("refreshSessionVaultSnapshot failed:", err);
    }
  }

  function parseStaticSVG(svgMarkup) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(svgMarkup, "image/svg+xml");
    return doc.documentElement ? doc.documentElement.cloneNode(true) : document.createTextNode("");
  }

  function initThemeToggle() {
    const saved = localStorage.getItem("aegis_theme") || "dark";
    document.documentElement.setAttribute("data-theme", saved);

    const btn = document.getElementById("btn-theme-toggle");
    if (!btn) return;
    btn.addEventListener("click", function () {
      const current = document.documentElement.getAttribute("data-theme") || "dark";
      const next = current === "light" ? "dark" : "light";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("aegis_theme", next);
    });
  }

  function closePersonaDropdown() {
    const menu = document.getElementById("persona-dropdown");
    const trigger = document.getElementById("btn-persona-dropdown");
    if (menu) menu.hidden = true;
    if (trigger) trigger.setAttribute("aria-expanded", "false");
  }

  function togglePersonaDropdown() {
    const menu = document.getElementById("persona-dropdown");
    const trigger = document.getElementById("btn-persona-dropdown");
    if (!menu) return;
    const nextHidden = !menu.hidden;
    menu.hidden = nextHidden;
    if (trigger) trigger.setAttribute("aria-expanded", nextHidden ? "false" : "true");
  }

  function openDemoModal() {
    closePersonaDropdown();
    const modal = document.getElementById("demo-controls-modal");
    if (!modal) return;
    modal.hidden = false;
    modal.setAttribute("aria-hidden", "false");
    refreshSessionVaultSnapshot();
    loadSourcesStatus();
  }

  function closeDemoModal() {
    const modal = document.getElementById("demo-controls-modal");
    if (!modal) return;
    modal.hidden = true;
    modal.setAttribute("aria-hidden", "true");
  }

  function toggleDemoModal() {
    const modal = document.getElementById("demo-controls-modal");
    if (!modal) return;
    if (modal.hidden) openDemoModal();
    else closeDemoModal();
  }

  function syncShieldUI() {
    const pills = document.querySelectorAll(".shield-pill");
    let enabledCount = 0;

    pills.forEach(function (pill) {
      const key = pill.getAttribute("data-shield");
      const input = pill.querySelector("input[type='checkbox']");
      const enabled = Boolean(state.posture[key]);
      if (input) input.checked = enabled;
      pill.classList.toggle("active", enabled);
      if (enabled) enabledCount += 1;
    });

    const allBlue = enabledCount === 5;
    const allRed = enabledCount === 0;

    const btnBlue = document.getElementById("btn-all-blue");
    const btnRed = document.getElementById("btn-all-red");
    if (btnBlue) btnBlue.classList.toggle("active", allBlue);
    if (btnRed) btnRed.classList.toggle("active", allRed);

    const dot = document.getElementById("topbar-posture-dot");
    const text = document.getElementById("topbar-posture-text");
    if (dot) {
      dot.className = "status-dot";
      if (allBlue) dot.classList.add("status-blue");
      else if (allRed) dot.classList.add("status-red");
      else dot.classList.add("status-amber");
    }
    if (text) {
      if (allBlue) text.textContent = "5/5 Shields Active";
      else if (allRed) text.textContent = "0/5 Shields Active";
      else text.textContent = enabledCount + "/5 Shields Active";
    }
  }

  function syncPersonaAndVaultUI() {
    const btnAlice = document.getElementById("btn-persona-alice");
    const btnBob = document.getElementById("btn-persona-bob");
    if (btnAlice) btnAlice.classList.toggle("active", state.persona === "alice");
    if (btnBob) btnBob.classList.toggle("active", state.persona === "bob");

    const personaLabel = document.getElementById("active-persona-label");
    if (personaLabel) personaLabel.textContent = state.persona;

    const topbarPersona = document.getElementById("topbar-persona-text");
    if (topbarPersona) {
      topbarPersona.textContent =
        state.persona === "alice" ? "Alice (SecOps Lead)" : "Bob (External Contractor)";
    }

    const grantedList = (state.grantedProviders && state.grantedProviders[state.persona]) || [];
    const personaGrants = (state.ephemeralGrants && state.ephemeralGrants[state.persona]) || [];
    const grantByProvider = {};
    personaGrants.forEach(function (g) {
      if (g && g.provider) {
        grantByProvider[g.provider] = g;
      }
    });

    const chips = document.querySelectorAll(".provider-chip");
    chips.forEach(function (chip) {
      const prov = chip.getAttribute("data-provider");
      const dot = chip.querySelector(".provider-dot");
      const pkceMeta = chip.querySelector(".provider-pkce-meta");
      const btn = chip.querySelector(".btn-revoke-provider");
      const isGranted = grantedList.indexOf(prov) !== -1;
      const meta = grantByProvider[prov];
      if (dot) dot.classList.toggle("granted", isGranted);
      if (pkceMeta) {
        if (isGranted) {
          const ttlLabel = meta ? formatGrantTTL(meta.ttlRemainingSeconds) : "15m";
          pkceMeta.textContent = "PKCE · S256 · " + ttlLabel;
          pkceMeta.classList.remove("expired");
        } else {
          pkceMeta.textContent = "PKCE · S256 · Required";
          pkceMeta.classList.add("expired");
        }
      }
      if (btn) {
        btn.textContent = isGranted ? "Test Revoke 3LO" : "Connect (OAuth + PKCE)";
        btn.setAttribute("data-mode", isGranted ? "revoke" : "grant");
      }
    });
  }

  function selectScenarioAndFillPrompt(scenId, focusInput) {
    if (scenId) {
      state.scenarioId = scenId;
    }

    document.querySelectorAll(".scenario-tab").forEach(function (tab) {
      tab.classList.toggle("active", tab.getAttribute("data-scenario") === state.scenarioId);
    });

    document.querySelectorAll(".starter-card").forEach(function (card) {
      card.classList.toggle("active", card.getAttribute("data-starter-scenario") === state.scenarioId);
    });

    const badge = document.getElementById("active-scenario-badge");
    if (badge) badge.textContent = state.scenarioId;

    const meta = state.scenarios[state.scenarioId];
    const promptInput = document.getElementById("input-prompt");

    if (meta) {
      const title = document.getElementById("active-scenario-title");
      const subtitle = document.getElementById("active-scenario-subtitle");
      if (title) title.textContent = meta.title;
      if (subtitle) subtitle.textContent = meta.subtitle;
      if (promptInput && meta.defaultPrompt) {
        promptInput.value = meta.defaultPrompt;
      }
    }

    syncComposerFlagsIndicator();

    if (focusInput && promptInput) {
      promptInput.focus();
      const len = promptInput.value.length;
      if (typeof promptInput.setSelectionRange === "function") {
        promptInput.setSelectionRange(len, len);
      }
    }
  }

  function syncComposerFlagsIndicator() {
    const cleanPiiCheck = document.getElementById("chk-clean-pii");
    const cold3loCheck = document.getElementById("chk-cold-3lo");
    const ind = document.getElementById("composer-flags-indicator");
    if (!ind) return;

    const flags = [];
    if (cleanPiiCheck && cleanPiiCheck.checked) flags.push("SDP-Only Clean PII");
    if (cold3loCheck && cold3loCheck.checked) flags.push("Cold 3LO Challenge");
    if (flags.length > 0) {
      ind.textContent = flags.join(" · ");
      ind.hidden = false;
    } else {
      ind.textContent = "";
      ind.hidden = true;
    }
  }

  async function persistPosture() {
    try {
      const resp = await fetch("/api/sessions/" + encodeURIComponent(state.sessionId) + "/posture", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          persona: state.persona,
          posture: state.posture,
        }),
      });
      if (resp.ok) {
        const snap = await resp.json();
        applySessionSnapshot(snap);
        syncPersonaAndVaultUI();
      }
    } catch (err) {
      console.error("persistPosture failed:", err);
    }
  }

  function buildA2UICardElement(card) {
    const cardType = card.type || "IncidentSummaryCard";
    const el = document.createElement("article");
    el.className = "a2ui-card severity-" + (card.severity || "INFO");
    el.setAttribute("data-card-type", cardType);

    const topRow = document.createElement("div");
    topRow.className = "a2ui-card-top";

    const typeBadge = document.createElement("span");
    typeBadge.className = "a2ui-card-type";
    typeBadge.appendChild(
      parseStaticSVG(CARD_CATALOG_ICONS[cardType] || CARD_CATALOG_ICONS.IncidentSummaryCard)
    );
    typeBadge.appendChild(document.createTextNode(" "));
    const typeLabel = document.createElement("span");
    typeLabel.textContent = cardType;
    typeBadge.appendChild(typeLabel);

    const sevBadge = document.createElement("span");
    sevBadge.className = "mime-tag";
    sevBadge.textContent = (card.severity || "INFO") + " · A2UI v" + (card.version || "0.9");

    topRow.appendChild(typeBadge);
    topRow.appendChild(sevBadge);
    el.appendChild(topRow);

    const titleEl = document.createElement("h4");
    titleEl.className = "a2ui-card-title";
    titleEl.textContent = card.title || "";
    el.appendChild(titleEl);

    if (card.subtitle) {
      const subEl = document.createElement("div");
      subEl.className = "a2ui-card-subtitle";
      subEl.textContent = card.subtitle;
      el.appendChild(subEl);
    }

    const bodyEl = document.createElement("p");
    bodyEl.className = "a2ui-card-body";
    bodyEl.textContent = card.body || "";
    el.appendChild(bodyEl);

    if (card.fields && Object.keys(card.fields).length > 0) {
      const grid = document.createElement("div");
      grid.className = "a2ui-fields-grid";
      Object.keys(card.fields).forEach(function (k) {
        const item = document.createElement("div");
        item.className = "a2ui-field-item";
        const kEl = document.createElement("div");
        kEl.className = "a2ui-field-key";
        kEl.textContent = k;
        const vEl = document.createElement("div");
        vEl.className = "a2ui-field-val";
        vEl.textContent = card.fields[k];
        item.appendChild(kEl);
        item.appendChild(vEl);
        grid.appendChild(item);
      });
      el.appendChild(grid);
    }

    if (Array.isArray(card.actions) && card.actions.length > 0) {
      const actionsRow = document.createElement("div");
      actionsRow.className = "a2ui-actions-row";
      card.actions.forEach(function (act) {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "a2ui-action-btn kind-" + (act.kind || "default");
        btn.textContent = act.label || act.id;
        btn.addEventListener("click", function () {
          actionsRow.querySelectorAll("button").forEach(function (b) {
            b.disabled = true;
          });
          handleA2UIAction(act, btn);
        });
        actionsRow.appendChild(btn);
      });
      el.appendChild(actionsRow);
    }

    return el;
  }

  async function handleA2UIAction(act, btnEl) {
    if (!act) return;
    if (act.kind === "oauth_consent") {
      const payload = act.payload || {};
      if (btnEl) btnEl.textContent = "Verifying OAuth 2.0 + S256 PKCE...";
      const ok = await authorizeProviderWithPKCE(
        payload.provider || "atlassian_jira",
        payload.persona || state.persona
      );
      if (ok) {
        const coldCheck = document.getElementById("chk-cold-3lo");
        if (coldCheck) coldCheck.checked = false;
        syncComposerFlagsIndicator();
        if (btnEl) btnEl.textContent = "OAuth 2.0 + PKCE Authorized (15m TTL)";
        await executeTurn({
          forceCold3LO: false,
          userLabelOverride:
            "Completed OAuth 2.0 + S256 PKCE consent for " +
            (payload.provider || "provider") +
            " — resuming request",
        });
      } else if (btnEl) {
        btnEl.disabled = false;
        btnEl.textContent = act.label || "Retry OAuth 2.0 + PKCE";
      }
      return;
    }

    if (act.kind === "step_up_approve" || act.kind === "step_up_reject") {
      const payload = act.payload || {};
      const confirmed = act.kind === "step_up_approve" || payload.confirmed === "true";
      if (btnEl) {
        btnEl.textContent = confirmed ? "Approved" : "Rejected";
      }
      const userLabel = confirmed
        ? "Approved step-up confirmation: proceed with remediation PR"
        : "Rejected step-up confirmation: abort state-mutating action";
      const resp = await fetch(
        "/api/sessions/" + encodeURIComponent(state.sessionId) + "/confirmations/stream",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "text/event-stream",
          },
          body: JSON.stringify({
            confirmationId: payload.confirmationId || "",
            confirmed: confirmed,
          }),
        }
      );
      if (resp.ok) {
        await consumeTurnSSEStream(resp, userLabel, state.persona, state.scenarioId);
      }
    }
  }

  function updateReferenceContainers(turn) {
    const outcomeBadge = document.getElementById("outcome-badge");
    const personaMeta = document.getElementById("outcome-persona-meta");
    const assistantText = document.getElementById("assistant-text");
    const previewEl = document.getElementById("sanitized-preview");
    const wireList = document.getElementById("wire-records-list");
    const cardsContainer = document.getElementById("a2ui-cards-container");
    const traceList = document.getElementById("boundary-trace-list");

    if (outcomeBadge) outcomeBadge.textContent = turn.outcome || "COMPLETED";
    if (personaMeta) personaMeta.textContent = "Persona: " + turn.persona;
    if (assistantText) assistantText.textContent = turn.assistantText || "";
    if (previewEl) {
      previewEl.textContent =
        turn.sanitizedInputPreview || turn.outboundCommentPreview || turn.assistantText || "";
    }
    if (wireList) {
      wireList.replaceChildren();
      (turn.wireRecords || []).forEach(function (rec) {
        const row = document.createElement("div");
        row.textContent = rec.method + " " + rec.url;
        wireList.appendChild(row);
      });
    }
    if (cardsContainer) {
      cardsContainer.replaceChildren();
      (turn.cards || []).forEach(function (c) {
        cardsContainer.appendChild(buildA2UICardElement(c));
      });
    }
    ALL_BOUNDARIES.forEach(function (bId) {
      const badge = document.getElementById("b-status-" + bId);
      if (badge) badge.textContent = "STANDBY";
    });
    if (traceList) {
      traceList.replaceChildren();
      (turn.boundaryTrace || []).forEach(function (ev) {
        const badge = document.getElementById("b-status-" + ev.boundary);
        if (badge) badge.textContent = ev.verdict;
      });
    }
  }

  function getOutcomePresentation(outcome) {
    if (outcome === "DEFENDED_SUCCESS") {
      return { label: "Defended", cls: "outcome-defended" };
    }
    if (outcome === "BLOCKED") {
      return { label: "Blocked by Security Policy", cls: "outcome-blocked" };
    }
    if (outcome === "CONSENT_REQUIRED") {
      return { label: "3LO OAuth Consent Required", cls: "outcome-challenge" };
    }
    if (outcome === "APPROVAL_REQUIRED") {
      return { label: "Human Step-Up Approval Required", cls: "outcome-challenge" };
    }
    return { label: "Exploited (Shield Disabled)", cls: "outcome-exploited" };
  }

  function buildProvenanceBadge(provenance) {
    const prov = provenance === "LIVE" ? "LIVE" : "FIXTURE";
    const badge = document.createElement("span");
    badge.className = "provenance-badge provenance-" + prov;
    badge.textContent = prov;
    return badge;
  }

  function createStreamingTurnDOM(userPromptText, persona, scenarioId) {
    const welcomeEl = document.getElementById("chat-welcome");
    if (welcomeEl) welcomeEl.hidden = true;

    const messagesEl = document.getElementById("chat-messages");
    const streamEl = document.getElementById("chat-stream");
    if (!messagesEl) return null;

    const turnWrap = document.createElement("div");
    turnWrap.className = "chat-turn";

    // 1. User Message Bubble
    const userRow = document.createElement("div");
    userRow.className = "user-msg-row";

    const userMeta = document.createElement("div");
    userMeta.className = "user-msg-meta";
    userMeta.textContent =
      (persona === "bob" ? "Bob (External Contractor)" : "Alice (SecOps Lead)") +
      " · " +
      (scenarioId || state.scenarioId);

    const userBubble = document.createElement("div");
    userBubble.className = "user-msg-bubble";
    userBubble.textContent = userPromptText;

    userRow.appendChild(userMeta);
    userRow.appendChild(userBubble);
    turnWrap.appendChild(userRow);

    // 2. Assistant Message Row
    const asstRow = document.createElement("div");
    asstRow.className = "assistant-msg-row";

    const avatar = document.createElement("div");
    avatar.className = "assistant-avatar";
    avatar.appendChild(
      parseStaticSVG(
        '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>'
      )
    );

    const contentCol = document.createElement("div");
    contentCol.className = "assistant-content";

    const headerRow = document.createElement("div");
    headerRow.className = "assistant-header";
    const nameSpan = document.createElement("span");
    nameSpan.className = "assistant-name";
    nameSpan.textContent = "AegisSRE";
    headerRow.appendChild(nameSpan);
    contentCol.appendChild(headerRow);

    const stepFeed = document.createElement("div");
    stepFeed.className = "step-feed";

    const liveStatus = document.createElement("div");
    liveStatus.className = "step-live-status";
    const pulseDot = document.createElement("span");
    pulseDot.className = "step-live-pulse";
    const statusText = document.createElement("span");
    statusText.textContent = "Evaluating security boundaries...";
    liveStatus.appendChild(pulseDot);
    liveStatus.appendChild(statusText);
    stepFeed.appendChild(liveStatus);

    contentCol.appendChild(stepFeed);

    asstRow.appendChild(avatar);
    asstRow.appendChild(contentCol);
    turnWrap.appendChild(asstRow);
    messagesEl.appendChild(turnWrap);

    if (streamEl) streamEl.scrollTop = streamEl.scrollHeight;

    return {
      turnWrap: turnWrap,
      contentCol: contentCol,
      headerRow: headerRow,
      stepFeed: stepFeed,
      liveStatus: liveStatus,
      proseEl: null,
      cardsWrap: null,
      streamEl: streamEl,
      renderedStepCount: 0,
      renderedCardCount: 0,
    };
  }

  function appendStepRowToFeed(dom, ev) {
    if (!dom || !dom.stepFeed || !ev) return;
    const stepRow = document.createElement("div");
    stepRow.className = "step-row";

    const left = document.createElement("div");
    left.className = "step-row-left";

    const iconSpan = document.createElement("span");
    iconSpan.className = "step-icon verdict-" + ev.verdict;
    iconSpan.appendChild(parseStaticSVG(VERDICT_ICONS[ev.verdict] || VERDICT_ICONS.ALLOWED));

    const labelSpan = document.createElement("span");
    labelSpan.className = "step-label";
    labelSpan.textContent = ev.shield;

    const detailSpan = document.createElement("span");
    detailSpan.className = "step-detail-short";
    detailSpan.textContent = "— " + ev.detail;

    left.appendChild(iconSpan);
    left.appendChild(labelSpan);
    left.appendChild(detailSpan);

    const right = document.createElement("div");
    right.className = "step-row-right";

    const pBadge = buildProvenanceBadge(ev.provenance || "FIXTURE");

    const vBadge = document.createElement("span");
    vBadge.className = "b-verdict verdict-" + ev.verdict;
    vBadge.textContent = ev.verdict;

    right.appendChild(pBadge);
    right.appendChild(vBadge);

    stepRow.appendChild(left);
    stepRow.appendChild(right);
    if (dom.liveStatus && dom.liveStatus.parentNode === dom.stepFeed) {
      dom.stepFeed.insertBefore(stepRow, dom.liveStatus);
    } else {
      dom.stepFeed.appendChild(stepRow);
    }
    dom.renderedStepCount += 1;

    const bBadge = document.getElementById("b-status-" + ev.boundary);
    if (bBadge) bBadge.textContent = ev.verdict;

    if (dom.streamEl) dom.streamEl.scrollTop = dom.streamEl.scrollHeight;
  }

  function updateStreamingProse(dom, text) {
    if (!dom || !text) return;
    if (!dom.proseEl) {
      dom.proseEl = document.createElement("p");
      dom.proseEl.className = "assistant-prose";
      dom.contentCol.appendChild(dom.proseEl);
    }
    dom.proseEl.textContent = text;
    if (dom.streamEl) dom.streamEl.scrollTop = dom.streamEl.scrollHeight;
  }

  function appendStreamingCard(dom, card) {
    if (!dom || !card) return;
    if (!dom.cardsWrap) {
      dom.cardsWrap = document.createElement("div");
      dom.cardsWrap.className = "a2ui-cards-container";
      dom.contentCol.appendChild(dom.cardsWrap);
    }
    dom.cardsWrap.appendChild(buildA2UICardElement(card));
    dom.renderedCardCount += 1;
    if (dom.streamEl) dom.streamEl.scrollTop = dom.streamEl.scrollHeight;
  }

  function buildTraceDrawer(turn) {
    const traceEvents = turn.boundaryTrace || [];
    const details = document.createElement("details");
    details.className = "turn-trace-drawer";

    const summary = document.createElement("summary");
    summary.className = "turn-trace-summary";
    const wireCount = (turn.wireRecords || []).length;
    const summaryLeft = document.createElement("span");
    summaryLeft.textContent =
      "Inspect security trace & HTTP wire audit (" +
      traceEvents.length +
      " boundary checks, " +
      wireCount +
      " outbound calls)";
    const summaryRight = document.createElement("span");
    summaryRight.textContent = "Expand";
    summary.appendChild(summaryLeft);
    summary.appendChild(summaryRight);
    details.appendChild(summary);

    const drawerBody = document.createElement("div");
    drawerBody.className = "turn-trace-body";

    traceEvents.forEach(function (ev) {
      const item = document.createElement("div");
      item.className = "trace-event-card";

      const top = document.createElement("div");
      top.className = "trace-event-top";

      const title = document.createElement("span");
      title.className = "trace-step-title";
      title.textContent = "#" + ev.order + " · " + ev.shield + " (" + ev.boundary + ")";

      const badges = document.createElement("div");
      badges.className = "trace-event-badges";

      const pBadge = buildProvenanceBadge(ev.provenance || "FIXTURE");

      const vBadge = document.createElement("span");
      vBadge.className = "b-verdict verdict-" + ev.verdict;
      vBadge.textContent = ev.verdict;

      badges.appendChild(pBadge);
      badges.appendChild(vBadge);

      top.appendChild(title);
      top.appendChild(badges);

      const comp = document.createElement("div");
      comp.className = "trace-component";
      comp.textContent = ev.component + " -> " + ev.action;

      const detail = document.createElement("div");
      detail.className = "trace-detail";
      detail.textContent = ev.detail;

      item.appendChild(top);
      item.appendChild(comp);
      item.appendChild(detail);
      drawerBody.appendChild(item);
    });

    if (turn.sanitizedInputPreview || turn.outboundCommentPreview) {
      const previewBox = document.createElement("div");
      previewBox.className = "wire-box";
      const lbl = document.createElement("div");
      lbl.className = "wire-box-label";
      lbl.textContent = "Sanitized In-Flight Payload / Outbound Comment Preview";
      const pre = document.createElement("pre");
      pre.className = "code-preview";
      pre.textContent = turn.sanitizedInputPreview || turn.outboundCommentPreview;
      previewBox.appendChild(lbl);
      previewBox.appendChild(pre);
      drawerBody.appendChild(previewBox);
    }

    if (Array.isArray(turn.wireRecords) && turn.wireRecords.length > 0) {
      const wireBox = document.createElement("div");
      wireBox.className = "wire-box";
      const lbl = document.createElement("div");
      lbl.className = "wire-box-label";
      lbl.textContent = "Outbound Tool Transport Wire Audit (auth.Transport / atenet MITM)";
      wireBox.appendChild(lbl);

      turn.wireRecords.forEach(function (rec) {
        const row = document.createElement("div");
        row.className = "wire-record-item";
        row.textContent =
          "[" +
          rec.statusCode +
          "] " +
          rec.method +
          " " +
          rec.url +
          " | tool=" +
          rec.toolName +
          " | principal=" +
          rec.authPrincipal;
        wireBox.appendChild(row);
      });
      drawerBody.appendChild(wireBox);
    }

    details.appendChild(drawerBody);
    return details;
  }

  function finalizeTurnDOM(dom, turn) {
    if (!dom || !turn) return;
    if (dom.liveStatus && dom.liveStatus.parentNode) {
      dom.liveStatus.parentNode.removeChild(dom.liveStatus);
    }

    const traceEvents = turn.boundaryTrace || [];
    if (dom.renderedStepCount === 0 && traceEvents.length > 0) {
      traceEvents.forEach(function (ev) {
        appendStepRowToFeed(dom, ev);
      });
    }
    if (dom.renderedStepCount === 0 && dom.stepFeed && dom.stepFeed.parentNode) {
      dom.stepFeed.parentNode.removeChild(dom.stepFeed);
    }

    const outPres = getOutcomePresentation(turn.outcome);
    const outPill = document.createElement("span");
    outPill.className = "outcome-pill " + outPres.cls;
    outPill.textContent = outPres.label;
    dom.headerRow.appendChild(outPill);

    if (turn.assistantText) {
      updateStreamingProse(dom, turn.assistantText);
    }

    if (dom.renderedCardCount === 0 && Array.isArray(turn.cards) && turn.cards.length > 0) {
      turn.cards.forEach(function (card) {
        appendStreamingCard(dom, card);
      });
    }

    dom.contentCol.appendChild(buildTraceDrawer(turn));
    updateReferenceContainers(turn);

    if (dom.streamEl) dom.streamEl.scrollTop = dom.streamEl.scrollHeight;
  }

  async function renderTurnInChat(userPromptText, turn) {
    if (!turn) return;
    const dom = createStreamingTurnDOM(
      userPromptText,
      turn.persona || state.persona,
      turn.scenarioId || state.scenarioId
    );
    if (!dom) return;
    finalizeTurnDOM(dom, turn);
  }

  async function consumeTurnSSEStream(resp, userPromptText, persona, scenarioId) {
    const contentType = (resp.headers && resp.headers.get && resp.headers.get("content-type")) || "";
    if (!resp.body || typeof resp.body.getReader !== "function" || contentType.indexOf("application/json") !== -1) {
      const turn = await resp.json();
      await renderTurnInChat(userPromptText, turn);
      return;
    }

    let dom = createStreamingTurnDOM(userPromptText, persona, scenarioId);
    const reader = resp.body.getReader();
    const decoder = new TextDecoder("utf-8");
    let buffer = "";

    function processSSEBlock(block) {
      const trimmed = block.trim();
      if (!trimmed) return;
      let eventType = "";
      let dataLine = "";
      trimmed.split("\n").forEach(function (line) {
        if (line.indexOf("event:") === 0) {
          eventType = line.slice(6).trim();
        } else if (line.indexOf("data:") === 0) {
          dataLine = line.slice(5).trim();
        }
      });
      if (!dataLine) return;
      let payload = null;
      try {
        payload = JSON.parse(dataLine);
      } catch (err) {
        console.error("Failed to parse SSE JSON frame:", err);
        return;
      }
      const type = eventType || payload.type;
      if (type === "turn.started") {
        if (!dom) {
          dom = createStreamingTurnDOM(
            userPromptText,
            payload.persona || persona,
            payload.scenarioId || scenarioId
          );
        }
      } else if (type === "boundary.step" && payload.step) {
        appendStepRowToFeed(dom, payload.step);
      } else if (type === "text.delta" && payload.delta) {
        updateStreamingProse(dom, payload.delta);
      } else if (type === "a2ui.card" && payload.card) {
        appendStreamingCard(dom, payload.card);
      } else if (type === "turn.completed" && payload.turn) {
        finalizeTurnDOM(dom, payload.turn);
      }
    }

    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      buffer += decoder.decode(chunk.value, { stream: true });
      const parts = buffer.split("\n\n");
      buffer = parts.pop() || "";
      parts.forEach(processSSEBlock);
    }
    buffer += decoder.decode();
    if (buffer.trim()) {
      buffer.split("\n\n").forEach(processSSEBlock);
    }
  }

  async function executeTurn(opts) {
    const options = opts || {};
    const promptInput = document.getElementById("input-prompt");
    const cleanPiiCheck = document.getElementById("chk-clean-pii");
    const cold3loCheck = document.getElementById("chk-cold-3lo");

    const promptText =
      options.promptOverride ||
      (promptInput && promptInput.value.trim()) ||
      "Triage customer P0 checkout 502 escalation email and post sanitized summary to Jira.";

    const reqBody = {
      sessionId: state.sessionId,
      persona: state.persona,
      scenarioId: state.scenarioId,
      posture: state.posture,
      prompt: promptText,
      cleanPiiOnly: Boolean(cleanPiiCheck && cleanPiiCheck.checked),
      requireCold3loConsent:
        options.forceCold3LO !== undefined
          ? Boolean(options.forceCold3LO)
          : Boolean(cold3loCheck && cold3loCheck.checked),
    };

    try {
      const resp = await fetch(
        "/api/sessions/" + encodeURIComponent(state.sessionId) + "/turns/stream",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Accept: "text/event-stream",
          },
          body: JSON.stringify(reqBody),
        }
      );
      if (!resp.ok) return;
      await consumeTurnSSEStream(
        resp,
        options.userLabelOverride || promptText,
        state.persona,
        state.scenarioId
      );
    } catch (err) {
      console.error("executeTurn failed:", err);
    }
  }

  function clearChatToWelcome() {
    const messagesEl = document.getElementById("chat-messages");
    const welcomeEl = document.getElementById("chat-welcome");
    if (messagesEl) messagesEl.replaceChildren();
    if (welcomeEl) welcomeEl.hidden = false;
  }

  async function seedFixtures() {
    try {
      const resp = await fetch("/api/fixtures/seed", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId: state.sessionId }),
      });
      if (!resp.ok) return;
      const data = await resp.json();
      if (data.session) {
        applySessionSnapshot(data.session);
      }
      const coldCheck = document.getElementById("chk-cold-3lo");
      if (coldCheck) coldCheck.checked = false;
      const cleanCheck = document.getElementById("chk-clean-pii");
      if (cleanCheck) cleanCheck.checked = false;
      syncShieldUI();
      syncPersonaAndVaultUI();
      selectScenarioAndFillPrompt(state.scenarioId, false);
      clearChatToWelcome();
      closeDemoModal();
    } catch (err) {
      console.error("seedFixtures failed:", err);
    }
  }

  async function loadSourcesStatus() {
    const grid = document.getElementById("sources-status-grid");
    if (!grid) return;
    try {
      const resp = await fetch("/api/sources/status");
      if (!resp.ok) return;
      const data = await resp.json();
      grid.replaceChildren();
      (data.sources || []).forEach(function (src) {
        const chip = document.createElement("div");
        chip.className = "source-status-chip";
        chip.setAttribute("data-source-id", src.id || "");
        if (src.detail) chip.title = src.detail;

        const nameSpan = document.createElement("span");
        nameSpan.className = "source-status-name";
        nameSpan.textContent = src.name || src.id || "";

        chip.appendChild(nameSpan);
        chip.appendChild(buildProvenanceBadge(src.provenance || "FIXTURE"));
        grid.appendChild(chip);
      });
    } catch (err) {
      console.error("loadSourcesStatus failed:", err);
    }
  }

  async function loadScenariosAndInitialState() {
    try {
      const scenResp = await fetch("/api/scenarios");
      if (scenResp.ok) {
        const data = await scenResp.json();
        (data.scenarios || []).forEach(function (s) {
          state.scenarios[s.id] = s;
        });
      }
      const sessResp = await fetch("/api/sessions/" + encodeURIComponent(state.sessionId));
      if (sessResp.ok) {
        const snap = await sessResp.json();
        applySessionSnapshot(snap);
      }
      await loadSourcesStatus();
    } catch (err) {
      console.error("initial load failed:", err);
    }
    syncShieldUI();
    syncPersonaAndVaultUI();
    selectScenarioAndFillPrompt(state.scenarioId, false);
  }

  function bindEvents() {
    // 1. ONLY open Demo Controls modal via Cmd+K / Ctrl+K or the "5/5 Shields Active" button
    const btnDemo = document.getElementById("btn-demo-controls");
    if (btnDemo) btnDemo.addEventListener("click", openDemoModal);

    const btnCloseModal = document.getElementById("btn-close-modal");
    if (btnCloseModal) btnCloseModal.addEventListener("click", closeDemoModal);

    const btnModalDone = document.getElementById("btn-modal-done");
    if (btnModalDone) btnModalDone.addEventListener("click", closeDemoModal);

    const modalBackdrop = document.getElementById("demo-controls-modal");
    if (modalBackdrop) {
      modalBackdrop.addEventListener("click", function (ev) {
        if (ev.target === modalBackdrop) closeDemoModal();
      });
    }

    // 2. Topbar Persona Dropdown (Quick switch between Alice and Bob without opening modal)
    const btnPersonaDropdown = document.getElementById("btn-persona-dropdown");
    if (btnPersonaDropdown) {
      btnPersonaDropdown.addEventListener("click", function (ev) {
        ev.stopPropagation();
        togglePersonaDropdown();
      });
    }

    document.querySelectorAll(".persona-option").forEach(function (opt) {
      opt.addEventListener("click", async function (ev) {
        ev.stopPropagation();
        const p = opt.getAttribute("data-persona");
        if (!p) return;
        state.persona = p;
        syncPersonaAndVaultUI();
        closePersonaDropdown();
        await persistPosture();
      });
    });

    // Close persona dropdown when clicking outside
    document.addEventListener("click", function (ev) {
      const wrap = document.querySelector(".persona-dropdown-wrap");
      if (wrap && !wrap.contains(ev.target)) {
        closePersonaDropdown();
      }
    });

    // Keyboard shortcut Cmd+K / Ctrl+K & Escape
    document.addEventListener("keydown", function (ev) {
      if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === "k") {
        ev.preventDefault();
        toggleDemoModal();
      } else if (ev.key === "Escape") {
        closePersonaDropdown();
        closeDemoModal();
      }
    });

    // New Chat button
    const btnNewChat = document.getElementById("btn-new-chat");
    if (btnNewChat) {
      btnNewChat.addEventListener("click", function () {
        clearChatToWelcome();
      });
    }

    // 3. Starter prompt cards on welcome screen ONLY fill the input box & focus it (no auto-send)
    document.querySelectorAll(".starter-card").forEach(function (card) {
      card.addEventListener("click", function () {
        const scenId = card.getAttribute("data-starter-scenario");
        selectScenarioAndFillPrompt(scenId, true);
      });
    });

    // Shield toggles inside modal
    document.querySelectorAll(".shield-pill").forEach(function (pill) {
      const key = pill.getAttribute("data-shield");
      const input = pill.querySelector("input[type='checkbox']");
      if (!input || !key) return;
      input.addEventListener("change", async function () {
        state.posture[key] = Boolean(input.checked);
        syncShieldUI();
        await persistPosture();
      });
    });

    const btnAllBlue = document.getElementById("btn-all-blue");
    if (btnAllBlue) {
      btnAllBlue.addEventListener("click", async function () {
        state.posture = {
          promptScreenEnabled: true,
          piiRedactorEnabled: true,
          tokenBrokerEnabled: true,
          stepUpAndA2UICatalogEnabled: true,
          sandboxEgressMitmEnabled: true,
        };
        syncShieldUI();
        await persistPosture();
      });
    }

    const btnAllRed = document.getElementById("btn-all-red");
    if (btnAllRed) {
      btnAllRed.addEventListener("click", async function () {
        state.posture = {
          promptScreenEnabled: false,
          piiRedactorEnabled: false,
          tokenBrokerEnabled: false,
          stepUpAndA2UICatalogEnabled: false,
          sandboxEgressMitmEnabled: false,
        };
        syncShieldUI();
        await persistPosture();
      });
    }

    document.querySelectorAll(".btn-revoke-provider").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        const provider = btn.getAttribute("data-provider");
        const mode = btn.getAttribute("data-mode") || "revoke";
        if (mode === "grant") {
          await authorizeProviderWithPKCE(provider, state.persona);
          return;
        }
        const resp = await fetch(
          "/api/sessions/" + encodeURIComponent(state.sessionId) + "/oauth/revoke",
          {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              persona: state.persona,
              provider: provider,
            }),
          }
        );
        if (resp.ok) {
          const snap = await resp.json();
          applySessionSnapshot(snap);
          syncPersonaAndVaultUI();
        }
      });
    });

    // Scenario tabs inside modal also fill the prompt in the chat box
    document.querySelectorAll(".scenario-tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        const scenId = tab.getAttribute("data-scenario");
        selectScenarioAndFillPrompt(scenId, false);
      });
    });

    const chatForm = document.getElementById("chat-form");
    if (chatForm) {
      chatForm.addEventListener("submit", function (ev) {
        ev.preventDefault();
        executeTurn();
      });
    }

    const btnSeed = document.getElementById("btn-seed-fixtures");
    if (btnSeed) {
      btnSeed.addEventListener("click", function () {
        seedFixtures();
      });
    }

    const chkCleanPii = document.getElementById("chk-clean-pii");
    if (chkCleanPii) {
      chkCleanPii.addEventListener("change", syncComposerFlagsIndicator);
    }

    const chkCold3lo = document.getElementById("chk-cold-3lo");
    if (chkCold3lo) {
      chkCold3lo.addEventListener("change", syncComposerFlagsIndicator);
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    initThemeToggle();
    bindEvents();
    loadScenariosAndInitialState();
  });
})();
