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
    route: "/",
    about: {
      catalog: null,
      loading: false,
      simScenarioId: "SCENARIO-05",
      simPosture: "BLUE",
      selectedBoundaryId: "B3_TOKEN_BROKER_3LO",
      focusedEdgeId: "",
      selectedStageIndex: 3,
      adrBoundaryFilter: "ALL",
      highlightedAdrNum: "",
      rafId: 0,
      pulseRunToken: 0,
    },
  };

  const SVG_NS = "http://www.w3.org/2000/svg";

  function resolveRouteFromPathname(pathname) {
    if (pathname === "/about" || (pathname && pathname.indexOf("/about/") === 0)) {
      return "/about";
    }
    return "/";
  }

  function applyRouteView(route) {
    const normalized = route === "/about" ? "/about" : "/";
    state.route = normalized;

    const btnArena = document.getElementById("nav-route-arena");
    const btnAbout = document.getElementById("nav-route-about");
    const chatStream = document.getElementById("chat-stream");
    const composerBar = document.querySelector(".chat-composer-bar");
    const aboutView = document.getElementById("about-view");

    const isAbout = normalized === "/about";
    if (btnArena) {
      btnArena.classList.toggle("active", !isAbout);
      if (!isAbout) btnArena.setAttribute("aria-current", "page");
      else btnArena.removeAttribute("aria-current");
    }
    if (btnAbout) {
      btnAbout.classList.toggle("active", isAbout);
      if (isAbout) btnAbout.setAttribute("aria-current", "page");
      else btnAbout.removeAttribute("aria-current");
    }

    if (chatStream) chatStream.hidden = isAbout;
    if (composerBar) composerBar.hidden = isAbout;
    if (aboutView) aboutView.hidden = !isAbout;

    if (isAbout) {
      loadAboutCatalog(false);
    } else {
      cancelAboutPulseAnimation();
    }
  }

  function navigateToRoute(route, pushHistory) {
    const normalized = route === "/about" ? "/about" : "/";
    if (pushHistory && window.location.pathname !== normalized && window.history && typeof window.history.pushState === "function") {
      window.history.pushState({ route: normalized }, "", normalized);
    }
    applyRouteView(normalized);
  }

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

  // ============================================================================
  // Interactive Architecture Topology Catalog (/about)
  // ============================================================================

  function createSVGElement(tagName, attrs) {
    const el = document.createElementNS(SVG_NS, tagName);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        el.setAttribute(k, String(attrs[k]));
      });
    }
    return el;
  }

  function truncateSVGLabel(str, maxLen) {
    const s = String(str || "");
    if (s.length <= maxLen) return s;
    return s.slice(0, Math.max(0, maxLen - 3)) + "...";
  }

  function boundaryShortCode(boundaryId) {
    const s = String(boundaryId || "");
    const idx = s.indexOf("_");
    return idx > 0 ? s.slice(0, idx) : s;
  }

  function computeEdgeCurve(edge) {
    const x0 = Number(edge.fromX) || 0;
    const y0 = Number(edge.fromY) || 0;
    const x3 = Number(edge.toX) || 0;
    const y3 = Number(edge.toY) || 0;

    let cx1 = x0;
    let cy1 = y0;
    let cx2 = x3;
    let cy2 = y3;

    if (edge.id === "EDGE_B6_B2") {
      cx1 = 780;
      cy1 = 434;
      cx2 = 555;
      cy2 = 426;
    } else {
      const dx = Math.max(24, Math.abs(x3 - x0) * 0.48);
      cx1 = x0 + (x3 >= x0 ? dx : -dx);
      cy1 = y0;
      cx2 = x3 - (x3 >= x0 ? dx : -dx);
      cy2 = y3;
    }

    const d =
      "M " +
      x0 +
      " " +
      y0 +
      " C " +
      cx1 +
      " " +
      cy1 +
      ", " +
      cx2 +
      " " +
      cy2 +
      ", " +
      x3 +
      " " +
      y3;

    const mid = evalCubicBezierPoints(x0, y0, cx1, cy1, cx2, cy2, x3, y3, 0.5);
    return {
      d: d,
      x0: x0,
      y0: y0,
      cx1: cx1,
      cy1: cy1,
      cx2: cx2,
      cy2: cy2,
      x3: x3,
      y3: y3,
      midX: mid.x,
      midY: mid.y,
    };
  }

  function evalCubicBezierPoints(x0, y0, cx1, cy1, cx2, cy2, x3, y3, t) {
    const u = 1 - t;
    const tt = t * t;
    const uu = u * u;
    const uuu = uu * u;
    const ttt = tt * t;
    return {
      x: uuu * x0 + 3 * uu * t * cx1 + 3 * u * tt * cx2 + ttt * x3,
      y: uuu * y0 + 3 * uu * t * cy1 + 3 * u * tt * cy2 + ttt * y3,
    };
  }

  function cancelAboutPulseAnimation() {
    state.about.pulseRunToken += 1;
    if (state.about.rafId) {
      cancelAnimationFrame(state.about.rafId);
      state.about.rafId = 0;
    }
  }

  function getActiveAboutScenario() {
    const cat = state.about.catalog;
    if (!cat || !Array.isArray(cat.scenarios) || cat.scenarios.length === 0) return null;
    for (let i = 0; i < cat.scenarios.length; i += 1) {
      if (cat.scenarios[i].id === state.about.simScenarioId) {
        return cat.scenarios[i];
      }
    }
    return cat.scenarios[0];
  }

  function getActiveAboutTrajectory(scenarioSpec) {
    if (!scenarioSpec) return null;
    return state.about.simPosture === "RED" ? scenarioSpec.red : scenarioSpec.blue;
  }

  function buildPulseVerdictBadge(verdict) {
    const v = String(verdict || "PASS");
    const span = document.createElement("span");
    span.className = "pulse-verdict-badge verdict-" + v;
    span.textContent = v;
    return span;
  }

  async function loadAboutCatalog(forceRefresh) {
    if (state.about.loading) return;
    if (state.about.catalog && !forceRefresh) {
      renderAboutAll(true);
      return;
    }
    state.about.loading = true;
    try {
      const resp = await fetch("/api/about/catalog");
      if (resp.ok) {
        state.about.catalog = await resp.json();
        renderAboutAll(true);
      }
    } catch (err) {
      console.error("loadAboutCatalog failed:", err);
    } finally {
      state.about.loading = false;
    }
  }

  function renderAboutAll(runPulse) {
    if (!state.about.catalog) return;
    renderAboutTopologyModule(Boolean(runPulse));
    renderAboutLifecycleModule();
    renderAboutGovernanceModule();
  }

  function selectAboutBoundary(boundaryId) {
    if (!boundaryId) return;
    state.about.selectedBoundaryId = boundaryId;
    document.querySelectorAll(".topo-boundary-node").forEach(function (nodeEl) {
      nodeEl.classList.toggle(
        "selected",
        nodeEl.getAttribute("data-boundary-id") === state.about.selectedBoundaryId
      );
    });
    renderAboutBoundaryInspector();
  }

  function jumpToAboutADR(adrNumber) {
    if (!adrNumber) return;
    state.about.adrBoundaryFilter = "ALL";
    state.about.highlightedAdrNum = adrNumber;
    renderAboutADRs();
    const targetCard = document.querySelector('[data-adr-number="' + adrNumber + '"]');
    if (targetCard && typeof targetCard.scrollIntoView === "function") {
      targetCard.scrollIntoView({ behavior: "smooth", block: "center" });
    }
  }

  function renderAboutTopologyModule(runPulse) {
    const cat = state.about.catalog;
    if (!cat) return;

    const btnBlue = document.getElementById("btn-sim-posture-blue");
    const btnRed = document.getElementById("btn-sim-posture-red");
    const isRed = state.about.simPosture === "RED";
    if (btnBlue) btnBlue.classList.toggle("active", !isRed);
    if (btnRed) btnRed.classList.toggle("active", isRed);

    const pillsWrap = document.getElementById("topology-scenario-pills");
    const activeScen = getActiveAboutScenario();
    if (pillsWrap) {
      pillsWrap.replaceChildren();
      (cat.scenarios || []).forEach(function (sc) {
        const pill = document.createElement("button");
        pill.type = "button";
        pill.className =
          "topo-scenario-pill" + (activeScen && activeScen.id === sc.id ? " active" : "");
        pill.setAttribute("role", "tab");
        pill.setAttribute(
          "aria-selected",
          activeScen && activeScen.id === sc.id ? "true" : "false"
        );
        pill.setAttribute("data-sim-scenario", sc.id);

        const codeSpan = document.createElement("span");
        codeSpan.className = "topo-scenario-code";
        codeSpan.textContent = sc.id;

        const labelSpan = document.createElement("span");
        labelSpan.className = "topo-scenario-label";
        labelSpan.textContent = sc.title;

        pill.appendChild(codeSpan);
        pill.appendChild(labelSpan);
        pill.addEventListener("click", function () {
          state.about.simScenarioId = sc.id;
          state.about.focusedEdgeId = "";
          if (Array.isArray(sc.primaryBoundaries) && sc.primaryBoundaries.length > 0) {
            state.about.selectedBoundaryId = sc.primaryBoundaries[0];
          }
          renderAboutTopologyModule(true);
        });
        pillsWrap.appendChild(pill);
      });
    }

    const traj = getActiveAboutTrajectory(activeScen);
    const bannerEl = document.getElementById("topology-trajectory-banner");
    if (bannerEl && activeScen && traj) {
      bannerEl.className = "topology-trajectory-banner posture-" + state.about.simPosture;
      bannerEl.replaceChildren();

      const mainCol = document.createElement("div");
      mainCol.className = "trajectory-banner-main";

      const titleDiv = document.createElement("div");
      titleDiv.className = "trajectory-banner-title";
      titleDiv.textContent = activeScen.id + " — " + activeScen.title;

      const summaryDiv = document.createElement("div");
      summaryDiv.className = "trajectory-banner-summary";
      summaryDiv.textContent = traj.summary || activeScen.subtitle || "";

      mainCol.appendChild(titleDiv);
      mainCol.appendChild(summaryDiv);

      const badgesCol = document.createElement("div");
      badgesCol.className = "trajectory-banner-badges";

      const postureTag = document.createElement("span");
      postureTag.className =
        "outcome-pill " + (isRed ? "outcome-exploited" : "outcome-defended");
      postureTag.textContent = isRed ? "Red Posture (0/5 Shields)" : "Blue Posture (5/5 Shields)";

      badgesCol.appendChild(postureTag);
      badgesCol.appendChild(buildPulseVerdictBadge(traj.terminalVerdict));

      bannerEl.appendChild(mainCol);
      bannerEl.appendChild(badgesCol);
    }

    const svgRefs = renderAboutTopologySVG(cat, activeScen, traj);
    renderAboutPulseLog(traj);
    renderAboutBoundaryInspector();

    if (runPulse && traj) {
      startAboutPulseSimulation(svgRefs, traj);
    }
  }

  function renderAboutTopologySVG(cat, activeScen, traj) {
    const stageEl = document.getElementById("about-topology-svg-stage");
    if (!stageEl) return null;
    stageEl.replaceChildren();

    const vbWidth = Number(cat.viewBoxWidth) || 1120;
    const vbHeight = Math.max(Number(cat.viewBoxHeight) || 430, 448);

    const svg = createSVGElement("svg", {
      id: "about-topology-svg",
      class: "about-topology-svg",
      viewBox: "0 0 " + vbWidth + " " + vbHeight,
      role: "img",
      "aria-label": "AegisSRE 6-Boundary Defense-in-Depth Topology Diagram",
    });

    const defs = createSVGElement("defs");
    const markerSpecs = [
      { id: "marker-about-idle", colorVar: "var(--svg-edge-idle)" },
      { id: "marker-about-PASS", colorVar: "var(--accent-green)" },
      { id: "marker-about-REDACTED", colorVar: "var(--accent-blue)" },
      { id: "marker-about-BLOCKED", colorVar: "var(--accent-blue)" },
      { id: "marker-about-STEP-UP", colorVar: "var(--accent-amber)" },
      { id: "marker-about-EXFILTRATED", colorVar: "var(--accent-red)" },
    ];
    markerSpecs.forEach(function (ms) {
      const marker = createSVGElement("marker", {
        id: ms.id,
        viewBox: "0 0 10 10",
        refX: "8.5",
        refY: "5",
        markerWidth: "6",
        markerHeight: "6",
        orient: "auto-start-reverse",
      });
      const arrow = createSVGElement("path", {
        d: "M 0 1.5 L 9 5 L 0 8.5 z",
        fill: ms.colorVar,
      });
      marker.appendChild(arrow);
      defs.appendChild(marker);
    });
    svg.appendChild(defs);

    const edgesLayer = createSVGElement("g", { class: "topo-edges-layer" });
    const nodesLayer = createSVGElement("g", { class: "topo-nodes-layer" });
    const pulseLayer = createSVGElement("g", { class: "topo-pulse-layer" });

    const edgeRefs = {};
    (cat.edges || []).forEach(function (edge) {
      const curve = computeEdgeCurve(edge);
      const g = createSVGElement("g", { "data-edge-id": edge.id });

      const basePath = createSVGElement("path", {
        class: "topo-edge-base",
        d: curve.d,
        "marker-end": "url(#marker-about-idle)",
      });

      const signalPath = createSVGElement("path", {
        class: "topo-edge-signal",
        d: curve.d,
      });

      g.appendChild(basePath);
      g.appendChild(signalPath);

      if (edge.label) {
        const labelText = String(edge.label);
        const pillW = Math.max(66, labelText.length * 5.6 + 12);
        const pillH = 16;
        const labelOffsetY =
          edge.id === "EDGE_B2_B1" || edge.id === "EDGE_B1_BROWSER"
            ? 13
            : edge.id === "EDGE_BROWSER_B1" || edge.id === "EDGE_B1_B2"
              ? -13
              : 0;
        const lx = curve.midX - pillW / 2;
        const ly = curve.midY + labelOffsetY - pillH / 2;

        const lblBg = createSVGElement("rect", {
          class: "topo-edge-label-bg",
          x: lx.toFixed(1),
          y: ly.toFixed(1),
          width: pillW.toFixed(1),
          height: pillH,
          rx: 4,
          ry: 4,
        });
        const lblTxt = createSVGElement("text", {
          class: "topo-edge-label-text",
          x: curve.midX.toFixed(1),
          y: (ly + 11.2).toFixed(1),
          "text-anchor": "middle",
        });
        lblTxt.textContent = labelText;
        g.appendChild(lblBg);
        g.appendChild(lblTxt);
      }

      edgesLayer.appendChild(g);
      edgeRefs[edge.id] = {
        curve: curve,
        signalPath: signalPath,
      };
    });

    (cat.contextNodes || []).forEach(function (cn) {
      const g = createSVGElement("g", {
        class: "topo-context-node",
        "data-node-id": cn.id,
      });
      const rect = createSVGElement("rect", {
        class: "node-box",
        x: cn.x,
        y: cn.y,
        width: cn.width,
        height: cn.height,
        rx: 12,
        ry: 12,
      });
      const kicker = createSVGElement("text", {
        class: "node-kicker",
        x: cn.x + 12,
        y: cn.y + 24,
      });
      kicker.textContent = "CLIENT SURFACE";

      const title = createSVGElement("text", {
        class: "node-title",
        x: cn.x + 12,
        y: cn.y + 48,
      });
      title.textContent = cn.title;

      const sub = createSVGElement("text", {
        class: "node-sub",
        x: cn.x + 12,
        y: cn.y + 68,
      });
      sub.textContent = truncateSVGLabel(cn.subtitle, 25);

      g.appendChild(rect);
      g.appendChild(kicker);
      g.appendChild(title);
      g.appendChild(sub);
      nodesLayer.appendChild(g);
    });

    const activeSet = {};
    if (traj && Array.isArray(traj.activeBoundaries)) {
      traj.activeBoundaries.forEach(function (bId) {
        activeSet[bId] = true;
      });
    } else if (activeScen && Array.isArray(activeScen.primaryBoundaries)) {
      activeScen.primaryBoundaries.forEach(function (bId) {
        activeSet[bId] = true;
      });
    }

    (cat.boundaries || []).forEach(function (b) {
      const isSelected = b.id === state.about.selectedBoundaryId;
      const isActiveInScenario = Boolean(activeSet[b.id]);
      const cls =
        "topo-boundary-node" +
        (isActiveInScenario ? " active-scenario posture-" + state.about.simPosture : "") +
        (isSelected ? " selected" : "");

      const g = createSVGElement("g", {
        class: cls,
        role: "button",
        tabindex: "0",
        "data-boundary-id": b.id,
        "aria-label": b.code + " " + b.title,
      });

      const rect = createSVGElement("rect", {
        class: "node-box",
        x: b.x,
        y: b.y,
        width: b.width,
        height: b.height,
        rx: 12,
        ry: 12,
      });
      g.appendChild(rect);

      const codeBg = createSVGElement("rect", {
        class: "node-code-pill",
        x: b.x + 12,
        y: b.y + 11,
        width: 30,
        height: 19,
        rx: 5,
        ry: 5,
      });
      const codeTxt = createSVGElement("text", {
        class: "node-code-text",
        x: b.x + 27,
        y: b.y + 24,
        "text-anchor": "middle",
      });
      codeTxt.textContent = b.code;
      g.appendChild(codeBg);
      g.appendChild(codeTxt);

      const maxChars = Math.max(22, Math.floor((b.width - 24) / 6.6));
      const cleanShort = String(b.shortLabel || b.title).replace(/^B[1-6]\s*·\s*/, "");

      const shieldTxt = createSVGElement("text", {
        class: "node-shield-text",
        x: b.x + 48,
        y: b.y + 24,
      });
      shieldTxt.textContent = truncateSVGLabel(b.shieldName, Math.max(16, maxChars - 6));
      g.appendChild(shieldTxt);

      const titleTxt = createSVGElement("text", {
        class: "node-title",
        x: b.x + 12,
        y: b.y + 50,
      });
      titleTxt.textContent = truncateSVGLabel(cleanShort, maxChars);
      g.appendChild(titleTxt);

      const subTxt = createSVGElement("text", {
        class: "node-sub",
        x: b.x + 12,
        y: b.y + 70,
      });
      subTxt.textContent = truncateSVGLabel(b.subtitle, maxChars + 4);
      g.appendChild(subTxt);

      const metaTxt = createSVGElement("text", {
        class: "node-sub",
        x: b.x + 12,
        y: b.y + 88,
      });
      metaTxt.textContent =
        (b.governedTools || []).length +
        " tool" +
        ((b.governedTools || []).length === 1 ? "" : "s") +
        " · " +
        (b.adrNumbers || []).length +
        " ADRs";
      g.appendChild(metaTxt);

      g.addEventListener("click", function () {
        selectAboutBoundary(b.id);
      });
      g.addEventListener("keydown", function (ev) {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          selectAboutBoundary(b.id);
        }
      });

      nodesLayer.appendChild(g);
    });

    svg.appendChild(edgesLayer);
    svg.appendChild(nodesLayer);
    svg.appendChild(pulseLayer);
    stageEl.appendChild(svg);

    return {
      svg: svg,
      edgeRefs: edgeRefs,
      pulseLayer: pulseLayer,
    };
  }

  function renderAboutPulseLog(traj) {
    const logEl = document.getElementById("topology-pulse-log");
    if (!logEl) return;
    logEl.replaceChildren();
    if (!traj || !Array.isArray(traj.pulses)) return;

    traj.pulses.forEach(function (hop, idx) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "pulse-hop-item";
      btn.setAttribute("data-hop-index", String(idx));
      btn.setAttribute("data-edge-id", hop.edgeId || "");

      const left = document.createElement("div");
      left.className = "pulse-hop-left";

      const title = document.createElement("span");
      title.className = "pulse-hop-title";
      title.textContent =
        "#" +
        hop.step +
        " " +
        boundaryShortCode(hop.from) +
        " -> " +
        boundaryShortCode(hop.to) +
        " · " +
        hop.label;

      const detail = document.createElement("span");
      detail.className = "pulse-hop-detail";
      detail.textContent = hop.detail || "";

      left.appendChild(title);
      left.appendChild(detail);

      btn.appendChild(left);
      btn.appendChild(buildPulseVerdictBadge(hop.verdict));

      btn.addEventListener("click", function () {
        state.about.focusedEdgeId = hop.edgeId || "";
        document.querySelectorAll(".topo-edge-signal").forEach(function (p) {
          p.classList.remove("focused-hop");
        });
        const edgeGroup = document.querySelector('[data-edge-id="' + hop.edgeId + '"]');
        if (edgeGroup) {
          const sig = edgeGroup.querySelector(".topo-edge-signal");
          if (sig) {
            sig.setAttribute("class", "topo-edge-signal active focused-hop verdict-" + hop.verdict);
            sig.setAttribute("marker-end", "url(#marker-about-" + hop.verdict + ")");
          }
        }
        const targetBoundary =
          String(hop.to || "").indexOf("B") === 0
            ? hop.to
            : String(hop.from || "").indexOf("B") === 0
              ? hop.from
              : "";
        if (targetBoundary) {
          selectAboutBoundary(targetBoundary);
        }
      });

      logEl.appendChild(btn);
    });
  }

  function startAboutPulseSimulation(svgRefs, traj) {
    cancelAboutPulseAnimation();
    if (!svgRefs || !svgRefs.pulseLayer || !traj || !Array.isArray(traj.pulses) || traj.pulses.length === 0) {
      return;
    }

    const token = state.about.pulseRunToken;
    const pulses = traj.pulses;
    const pulseLayer = svgRefs.pulseLayer;
    pulseLayer.replaceChildren();

    const halo = createSVGElement("circle", {
      class: "topo-pulse-halo verdict-PASS",
      r: 13,
      cx: 0,
      cy: 0,
    });
    const core = createSVGElement("circle", {
      class: "topo-pulse-core verdict-PASS",
      r: 5.5,
      cx: 0,
      cy: 0,
    });
    const tagGroup = createSVGElement("g");
    const tagBg = createSVGElement("rect", {
      class: "topo-pulse-tag-bg",
      x: -44,
      y: -30,
      width: 88,
      height: 18,
      rx: 5,
      ry: 5,
    });
    const tagTxt = createSVGElement("text", {
      class: "topo-pulse-tag-text",
      x: 0,
      y: -17.5,
      "text-anchor": "middle",
    });
    tagGroup.appendChild(tagBg);
    tagGroup.appendChild(tagTxt);

    pulseLayer.appendChild(halo);
    pulseLayer.appendChild(core);
    pulseLayer.appendChild(tagGroup);

    const hopDurationMs = 540;
    const hopPauseMs = 95;
    const stepMs = hopDurationMs + hopPauseMs;
    const startTime = performance.now();
    let lastActivatedHop = -1;

    const counterEl = document.getElementById("pulse-step-counter");
    const hopRows = document.querySelectorAll("#topology-pulse-log .pulse-hop-item");

    function activateHopVisuals(hopIdx) {
      const hop = pulses[hopIdx];
      if (!hop) return;
      const edgeRef = svgRefs.edgeRefs[hop.edgeId];
      if (edgeRef && edgeRef.signalPath) {
        edgeRef.signalPath.setAttribute(
          "class",
          "topo-edge-signal active verdict-" + hop.verdict
        );
        edgeRef.signalPath.setAttribute("marker-end", "url(#marker-about-" + hop.verdict + ")");
      }
      halo.setAttribute("class", "topo-pulse-halo verdict-" + hop.verdict);
      core.setAttribute("class", "topo-pulse-core verdict-" + hop.verdict);

      const badgeLabel = "#" + hop.step + " " + hop.verdict;
      const w = Math.max(76, badgeLabel.length * 6.4 + 14);
      tagBg.setAttribute("x", String((-w / 2).toFixed(1)));
      tagBg.setAttribute("width", String(w.toFixed(1)));
      tagTxt.textContent = badgeLabel;

      hopRows.forEach(function (row, rIdx) {
        row.classList.toggle("reached", rIdx <= hopIdx);
        row.classList.toggle("current", rIdx === hopIdx);
      });

      if (counterEl) {
        counterEl.textContent =
          "Hop " + (hopIdx + 1) + "/" + pulses.length + " · " + hop.verdict;
      }
    }

    function stepFrame(now) {
      if (token !== state.about.pulseRunToken) return;
      const elapsed = Math.max(0, now - startTime);
      const hopIdx = Math.floor(elapsed / stepMs);

      if (hopIdx >= pulses.length) {
        for (let k = lastActivatedHop + 1; k < pulses.length; k += 1) {
          activateHopVisuals(k);
        }
        hopRows.forEach(function (row) {
          row.classList.add("reached");
          row.classList.remove("current");
        });
        pulseLayer.replaceChildren();
        if (counterEl) {
          counterEl.textContent =
            "Simulated " + pulses.length + "/" + pulses.length + " hops · " + traj.terminalVerdict;
        }
        state.about.rafId = 0;
        return;
      }

      if (hopIdx !== lastActivatedHop) {
        for (let k = lastActivatedHop + 1; k <= hopIdx; k += 1) {
          activateHopVisuals(k);
        }
        lastActivatedHop = hopIdx;
      }

      const hop = pulses[hopIdx];
      const edgeRef = svgRefs.edgeRefs[hop.edgeId];
      if (edgeRef && edgeRef.curve) {
        const localElapsed = elapsed - hopIdx * stepMs;
        const rawT = Math.min(1, Math.max(0, localElapsed / hopDurationMs));
        const easedT = rawT < 0.5 ? 2 * rawT * rawT : 1 - Math.pow(-2 * rawT + 2, 2) / 2;
        const c = edgeRef.curve;
        const pt = evalCubicBezierPoints(c.x0, c.y0, c.cx1, c.cy1, c.cx2, c.cy2, c.x3, c.y3, easedT);
        halo.setAttribute("cx", pt.x.toFixed(1));
        halo.setAttribute("cy", pt.y.toFixed(1));
        core.setAttribute("cx", pt.x.toFixed(1));
        core.setAttribute("cy", pt.y.toFixed(1));
        tagGroup.setAttribute("transform", "translate(" + pt.x.toFixed(1) + "," + pt.y.toFixed(1) + ")");
      }

      state.about.rafId = requestAnimationFrame(stepFrame);
    }

    state.about.rafId = requestAnimationFrame(stepFrame);
  }

  function renderAboutBoundaryInspector() {
    const cardEl = document.getElementById("boundary-inspector-card");
    const cat = state.about.catalog;
    if (!cardEl || !cat || !Array.isArray(cat.boundaries)) return;
    cardEl.replaceChildren();

    let boundary = cat.boundaries[0];
    cat.boundaries.forEach(function (b) {
      if (b.id === state.about.selectedBoundaryId) {
        boundary = b;
      }
    });
    if (!boundary) return;

    const topRow = document.createElement("div");
    topRow.className = "inspector-top-row";

    const codeGroup = document.createElement("div");
    codeGroup.className = "inspector-code-group";

    const codeBadge = document.createElement("span");
    codeBadge.className = "inspector-code-badge";
    codeBadge.textContent = boundary.code + " · " + boundary.id;

    const shieldChip = document.createElement("span");
    shieldChip.className = "about-tag-chip";
    shieldChip.textContent = "Shield: " + boundary.shieldName;

    codeGroup.appendChild(codeBadge);
    codeGroup.appendChild(shieldChip);
    topRow.appendChild(codeGroup);
    cardEl.appendChild(topRow);

    const titleEl = document.createElement("h3");
    titleEl.className = "inspector-title";
    titleEl.textContent = boundary.title;
    cardEl.appendChild(titleEl);

    const compBox = document.createElement("div");
    compBox.className = "inspector-component-box";
    compBox.textContent = boundary.componentName;
    cardEl.appendChild(compBox);

    const compareGrid = document.createElement("div");
    compareGrid.className = "inspector-compare-grid";

    const blueBox = document.createElement("div");
    blueBox.className = "inspector-posture-box box-blue";
    const blueLbl = document.createElement("span");
    blueLbl.className = "inspector-box-label";
    blueLbl.textContent = "Blue Defense Mechanism";
    const blueBody = document.createElement("p");
    blueBody.className = "inspector-box-body";
    blueBody.textContent = boundary.blueDefenseMechanism;
    blueBox.appendChild(blueLbl);
    blueBox.appendChild(blueBody);

    const redBox = document.createElement("div");
    redBox.className = "inspector-posture-box box-red";
    const redLbl = document.createElement("span");
    redLbl.className = "inspector-box-label";
    redLbl.textContent = "Red Exploit Mode (Shield Disabled)";
    const redBody = document.createElement("p");
    redBody.className = "inspector-box-body";
    redBody.textContent = boundary.redExploitMode;
    redBox.appendChild(redLbl);
    redBox.appendChild(redBody);

    compareGrid.appendChild(blueBox);
    compareGrid.appendChild(redBox);
    cardEl.appendChild(compareGrid);

    const toolsRow = document.createElement("div");
    toolsRow.className = "inspector-tags-row";
    const toolsLbl = document.createElement("span");
    toolsLbl.className = "meta-tag-label";
    toolsLbl.textContent = "Governed Tools:";
    toolsRow.appendChild(toolsLbl);
    (boundary.governedTools || []).forEach(function (tName) {
      const chip = document.createElement("span");
      chip.className = "about-tag-chip";
      chip.textContent = tName;
      toolsRow.appendChild(chip);
    });
    cardEl.appendChild(toolsRow);

    const adrsRow = document.createElement("div");
    adrsRow.className = "inspector-tags-row";
    const adrsLbl = document.createElement("span");
    adrsLbl.className = "meta-tag-label";
    adrsLbl.textContent = "Linked ADRs:";
    adrsRow.appendChild(adrsLbl);
    (boundary.adrNumbers || []).forEach(function (num) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "about-adr-jump-btn";
      btn.textContent = "ADR-" + num;
      btn.addEventListener("click", function () {
        jumpToAboutADR(num);
      });
      adrsRow.appendChild(btn);
    });
    cardEl.appendChild(adrsRow);
  }

  function renderAboutLifecycleModule() {
    const cat = state.about.catalog;
    const trackEl = document.getElementById("lifecycle-stage-track");
    const detailEl = document.getElementById("lifecycle-detail-panel");
    const ssePreEl = document.getElementById("lifecycle-sse-preview");
    const sseBadgeEl = document.getElementById("lifecycle-sse-event-badge");
    if (!cat || !trackEl || !detailEl || !ssePreEl) return;

    const callbacks = cat.pluginCallbacks || [];
    if (callbacks.length === 0) return;

    let selectedCB = callbacks[0];
    callbacks.forEach(function (cb) {
      if (cb.stageIndex === state.about.selectedStageIndex) {
        selectedCB = cb;
      }
    });

    trackEl.replaceChildren();
    callbacks.forEach(function (cb) {
      const btn = document.createElement("button");
      btn.type = "button";
      const isActive = cb.stageIndex === selectedCB.stageIndex;
      btn.className = "lifecycle-stage-btn" + (isActive ? " active" : "");
      btn.setAttribute("role", "tab");
      btn.setAttribute("aria-selected", isActive ? "true" : "false");
      btn.setAttribute("data-stage-index", String(cb.stageIndex));

      const top = document.createElement("div");
      top.className = "lifecycle-stage-top";

      const numSpan = document.createElement("span");
      numSpan.className = "lifecycle-stage-num";
      numSpan.textContent = "0" + cb.stageIndex;

      const bCount = document.createElement("span");
      bCount.className = "subpanel-meta";
      bCount.textContent = (cb.governedBoundaries || []).length + "B";

      top.appendChild(numSpan);
      top.appendChild(bCount);

      const nameSpan = document.createElement("span");
      nameSpan.className = "lifecycle-stage-name";
      nameSpan.textContent = cb.name;

      const subSpan = document.createElement("span");
      subSpan.className = "lifecycle-stage-sub";
      subSpan.textContent = String(cb.executionLabel || "").replace(cb.name + " -> ", "");

      btn.appendChild(top);
      btn.appendChild(nameSpan);
      btn.appendChild(subSpan);

      btn.addEventListener("click", function () {
        state.about.selectedStageIndex = cb.stageIndex;
        renderAboutLifecycleModule();
      });

      trackEl.appendChild(btn);
    });

    detailEl.replaceChildren();

    const headerRow = document.createElement("div");
    headerRow.className = "inspector-top-row";
    const stageBadge = document.createElement("span");
    stageBadge.className = "inspector-code-badge";
    stageBadge.textContent = "STAGE 0" + selectedCB.stageIndex + " · " + selectedCB.name;
    headerRow.appendChild(stageBadge);
    detailEl.appendChild(headerRow);

    const execTitle = document.createElement("h3");
    execTitle.className = "inspector-title";
    execTitle.textContent = selectedCB.executionLabel;
    detailEl.appendChild(execTitle);

    const roleBox = document.createElement("div");
    roleBox.className = "inspector-posture-box box-blue";
    const roleLbl = document.createElement("span");
    roleLbl.className = "inspector-box-label";
    roleLbl.textContent = "Plugin Lifecycle Responsibility";
    const roleBody = document.createElement("p");
    roleBody.className = "inspector-box-body";
    roleBody.textContent = selectedCB.roleSummary;
    roleBox.appendChild(roleLbl);
    roleBox.appendChild(roleBody);
    detailEl.appendChild(roleBox);

    const scBox = document.createElement("div");
    scBox.className = "inspector-posture-box";
    const scLbl = document.createElement("span");
    scLbl.className = "subpanel-title";
    scLbl.textContent = "Short-Circuit & Mutation Semantics";
    const scBody = document.createElement("p");
    scBody.className = "inspector-box-body";
    scBody.textContent = selectedCB.shortCircuitBehavior;
    scBox.appendChild(scLbl);
    scBox.appendChild(scBody);
    detailEl.appendChild(scBox);

    const bRow = document.createElement("div");
    bRow.className = "inspector-tags-row";
    const bLbl = document.createElement("span");
    bLbl.className = "meta-tag-label";
    bLbl.textContent = "Active Boundaries:";
    bRow.appendChild(bLbl);
    (selectedCB.governedBoundaries || []).forEach(function (bId) {
      const pill = document.createElement("button");
      pill.type = "button";
      pill.className = "boundary-jump-pill";
      pill.textContent = bId;
      pill.addEventListener("click", function () {
        selectAboutBoundary(bId);
        const topoMod = document.getElementById("about-topology-module");
        if (topoMod && typeof topoMod.scrollIntoView === "function") {
          topoMod.scrollIntoView({ behavior: "smooth", block: "start" });
        }
      });
      bRow.appendChild(pill);
    });
    detailEl.appendChild(bRow);

    const tRow = document.createElement("div");
    tRow.className = "inspector-tags-row";
    const tLbl = document.createElement("span");
    tLbl.className = "meta-tag-label";
    tLbl.textContent = "Governed Tools:";
    tRow.appendChild(tLbl);
    (selectedCB.governedTools || []).forEach(function (tName) {
      const chip = document.createElement("span");
      chip.className = "about-tag-chip";
      chip.textContent = tName;
      tRow.appendChild(chip);
    });
    detailEl.appendChild(tRow);

    const evRow = document.createElement("div");
    evRow.className = "inspector-tags-row";
    const evLbl = document.createElement("span");
    evLbl.className = "meta-tag-label";
    evLbl.textContent = "Emitted SSE Events:";
    evRow.appendChild(evLbl);
    (selectedCB.emittedStreamEventTypes || []).forEach(function (evType) {
      const chip = document.createElement("span");
      chip.className = "mime-tag";
      chip.textContent = evType;
      evRow.appendChild(chip);
    });
    detailEl.appendChild(evRow);

    let eventTypeHeader =
      (selectedCB.emittedStreamEventTypes && selectedCB.emittedStreamEventTypes[0]) || "boundary.step";
    try {
      const parsed = JSON.parse(selectedCB.sampleSSEFrame || "{}");
      if (parsed && parsed.type) {
        eventTypeHeader = parsed.type;
      }
    } catch (_err) {
      // Keep fallback eventTypeHeader
    }
    if (sseBadgeEl) {
      sseBadgeEl.textContent = "SSE · " + eventTypeHeader;
    }
    ssePreEl.textContent =
      "event: " + eventTypeHeader + "\ndata: " + (selectedCB.sampleSSEFrame || "{}");
  }

  function classifyToolPolicyClass(stepUpPolicy) {
    const p = String(stepUpPolicy || "");
    if (p.indexOf("Step-Up") !== -1) return "policy-stepup";
    if (p.indexOf("Hard-Blocked") !== -1) return "policy-blocked";
    if (p.indexOf("Attenuated") !== -1) return "policy-sandbox";
    if (p.indexOf("PKCE") !== -1) return "policy-pkce";
    return "policy-readonly";
  }

  function renderAboutGovernanceModule() {
    const cat = state.about.catalog;
    if (!cat) return;

    const sourcesGrid = document.getElementById("about-sources-grid");
    const sourcesSummary = document.getElementById("about-sources-summary");
    const heroSourcesPill = document.getElementById("about-live-sources-pill");
    const heroAdrPill = document.getElementById("about-adr-count-pill");

    const sources = cat.sources || [];
    let liveCount = 0;
    sources.forEach(function (s) {
      if (s.provenance === "LIVE") liveCount += 1;
    });
    const fixtureCount = Math.max(0, sources.length - liveCount);
    if (sourcesSummary) {
      sourcesSummary.textContent =
        liveCount + " LIVE · " + fixtureCount + " FIXTURE (" + sources.length + " total)";
    }
    if (heroSourcesPill) {
      heroSourcesPill.replaceChildren();
      const strong = document.createElement("strong");
      strong.textContent = liveCount + "/" + sources.length;
      heroSourcesPill.appendChild(strong);
      heroSourcesPill.appendChild(document.createTextNode(" Live Sources"));
    }
    if (heroAdrPill && Array.isArray(cat.adrs)) {
      heroAdrPill.replaceChildren();
      const strongAdr = document.createElement("strong");
      strongAdr.textContent = String(cat.adrs.length);
      heroAdrPill.appendChild(strongAdr);
      heroAdrPill.appendChild(document.createTextNode(" Accepted ADRs"));
    }

    if (sourcesGrid) {
      sourcesGrid.replaceChildren();
      sources.forEach(function (src) {
        const prov = src.provenance === "LIVE" ? "LIVE" : "FIXTURE";
        const card = document.createElement("article");
        card.className = "about-source-card source-" + prov;
        card.setAttribute("data-about-source-id", src.id || "");

        const top = document.createElement("div");
        top.className = "card-row-between";

        const nameSpan = document.createElement("span");
        nameSpan.className = "about-card-title";
        nameSpan.textContent = src.name || src.id || "";

        top.appendChild(nameSpan);
        top.appendChild(buildProvenanceBadge(prov));
        card.appendChild(top);

        const metaRow = document.createElement("div");
        metaRow.className = "inspector-tags-row";
        const bChip = document.createElement("span");
        bChip.className = "about-tag-chip";
        bChip.textContent = src.boundary || "";
        metaRow.appendChild(bChip);
        card.appendChild(metaRow);

        if (src.endpoint) {
          const ep = document.createElement("div");
          ep.className = "about-card-mono";
          ep.textContent = src.endpoint;
          card.appendChild(ep);
        }

        const desc = document.createElement("p");
        desc.className = "about-card-desc";
        desc.textContent = src.detail || "";
        card.appendChild(desc);

        sourcesGrid.appendChild(card);
      });
    }

    const toolsGrid = document.getElementById("about-tools-grid");
    if (toolsGrid) {
      toolsGrid.replaceChildren();
      (cat.tools || []).forEach(function (tool) {
        const card = document.createElement("article");
        card.className = "about-tool-card";
        card.setAttribute("data-about-tool-name", tool.name);

        const top = document.createElement("div");
        top.className = "card-row-between";

        const tName = document.createElement("span");
        tName.className = "about-card-title";
        tName.textContent = tool.name;

        const bPill = document.createElement("button");
        bPill.type = "button";
        bPill.className = "boundary-jump-pill";
        bPill.textContent = boundaryShortCode(tool.primaryBoundary);
        bPill.title = tool.primaryBoundary;
        bPill.addEventListener("click", function () {
          selectAboutBoundary(tool.primaryBoundary);
          const topoMod = document.getElementById("about-topology-module");
          if (topoMod && typeof topoMod.scrollIntoView === "function") {
            topoMod.scrollIntoView({ behavior: "smooth", block: "start" });
          }
        });

        top.appendChild(tName);
        top.appendChild(bPill);
        card.appendChild(top);

        const wire = document.createElement("div");
        wire.className = "about-card-mono";
        wire.textContent = tool.wireOperation + " · " + tool.provider;
        card.appendChild(wire);

        const policyBadge = document.createElement("span");
        policyBadge.className = "tool-policy-badge " + classifyToolPolicyClass(tool.stepUpPolicy);
        policyBadge.textContent = tool.stepUpPolicy;
        card.appendChild(policyBadge);

        const desc = document.createElement("p");
        desc.className = "about-card-desc";
        desc.textContent = tool.description;
        card.appendChild(desc);

        toolsGrid.appendChild(card);
      });
    }

    renderAboutADRs();
  }

  function renderAboutADRs() {
    const cat = state.about.catalog;
    const filterWrap = document.getElementById("adr-filter-pills");
    const adrGrid = document.getElementById("about-adr-grid");
    if (!cat || !filterWrap || !adrGrid) return;

    const adrs = cat.adrs || [];
    const filterOptions = [
      { key: "ALL", label: "All (" + adrs.length + ")" },
      { key: "B1_A2UI_STEP_UP", label: "B1" },
      { key: "B2_MODEL_ARMOR_SDP", label: "B2" },
      { key: "B3_TOKEN_BROKER_3LO", label: "B3" },
      { key: "B4_AGENT_REGISTRY_GATEWAY", label: "B4" },
      { key: "B5_ATTENUATED_A2A", label: "B5" },
      { key: "B6_SUBSTRATE_GVISOR_MITM", label: "B6" },
    ];

    filterWrap.replaceChildren();
    filterOptions.forEach(function (opt) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className =
        "adr-filter-btn" + (state.about.adrBoundaryFilter === opt.key ? " active" : "");
      btn.textContent = opt.label;
      btn.addEventListener("click", function () {
        state.about.adrBoundaryFilter = opt.key;
        state.about.highlightedAdrNum = "";
        renderAboutADRs();
      });
      filterWrap.appendChild(btn);
    });

    adrGrid.replaceChildren();
    adrs.forEach(function (adr) {
      if (
        state.about.adrBoundaryFilter !== "ALL" &&
        (adr.primaryBoundaries || []).indexOf(state.about.adrBoundaryFilter) === -1
      ) {
        return;
      }

      const card = document.createElement("article");
      card.className =
        "about-adr-card" +
        (state.about.highlightedAdrNum === adr.number ? " highlighted-adr" : "");
      card.setAttribute("data-adr-number", adr.number);

      const top = document.createElement("div");
      top.className = "card-row-between";

      const numBadge = document.createElement("span");
      numBadge.className = "adr-num-badge";
      numBadge.textContent = "ADR-" + adr.number;

      const fileSpan = document.createElement("span");
      fileSpan.className = "mime-tag";
      fileSpan.textContent = adr.fileName;

      top.appendChild(numBadge);
      top.appendChild(fileSpan);
      card.appendChild(top);

      const title = document.createElement("div");
      title.className = "about-card-title";
      title.textContent = adr.title;
      card.appendChild(title);

      const summary = document.createElement("p");
      summary.className = "about-card-desc";
      summary.textContent = adr.summary;
      card.appendChild(summary);

      const bRow = document.createElement("div");
      bRow.className = "inspector-tags-row";
      (adr.primaryBoundaries || []).forEach(function (bId) {
        const chip = document.createElement("span");
        chip.className = "about-tag-chip";
        chip.textContent = boundaryShortCode(bId);
        chip.title = bId;
        bRow.appendChild(chip);
      });
      card.appendChild(bRow);

      adrGrid.appendChild(card);
    });
  }

  function bindAboutControls() {
    const btnSimBlue = document.getElementById("btn-sim-posture-blue");
    if (btnSimBlue) {
      btnSimBlue.addEventListener("click", function () {
        state.about.simPosture = "BLUE";
        renderAboutTopologyModule(true);
      });
    }

    const btnSimRed = document.getElementById("btn-sim-posture-red");
    if (btnSimRed) {
      btnSimRed.addEventListener("click", function () {
        state.about.simPosture = "RED";
        renderAboutTopologyModule(true);
      });
    }

    const btnSimReplay = document.getElementById("btn-sim-replay");
    if (btnSimReplay) {
      btnSimReplay.addEventListener("click", function () {
        renderAboutTopologyModule(true);
      });
    }

    const btnRefreshAbout = document.getElementById("btn-refresh-about-catalog");
    if (btnRefreshAbout) {
      btnRefreshAbout.addEventListener("click", function () {
        loadAboutCatalog(true);
      });
    }
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
        if (state.route !== "/") {
          navigateToRoute("/", true);
        }
        clearChatToWelcome();
      });
    }

    // Path-based route switcher (Arena -> / and Architecture -> /about)
    const navArena = document.getElementById("nav-route-arena");
    if (navArena) {
      navArena.addEventListener("click", function () {
        navigateToRoute("/", true);
      });
    }
    const navAbout = document.getElementById("nav-route-about");
    if (navAbout) {
      navAbout.addEventListener("click", function () {
        navigateToRoute("/about", true);
      });
    }
    window.addEventListener("popstate", function () {
      applyRouteView(resolveRouteFromPathname(window.location.pathname));
    });

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
    bindAboutControls();
    applyRouteView(resolveRouteFromPathname(window.location.pathname));
    bindEvents();
    loadScenariosAndInitialState();
  });
})();
