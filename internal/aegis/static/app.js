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
    scenarios: {},
  };

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

  function syncShieldUI() {
    const pills = document.querySelectorAll(".shield-pill");
    let allBlue = true;
    let allRed = true;

    pills.forEach(function (pill) {
      const key = pill.getAttribute("data-shield");
      const input = pill.querySelector("input[type='checkbox']");
      const enabled = Boolean(state.posture[key]);
      if (input) input.checked = enabled;
      pill.classList.toggle("active", enabled);
      if (enabled) allRed = false;
      else allBlue = false;
    });

    const btnBlue = document.getElementById("btn-all-blue");
    const btnRed = document.getElementById("btn-all-red");
    if (btnBlue) btnBlue.classList.toggle("active", allBlue);
    if (btnRed) btnRed.classList.toggle("active", allRed);
  }

  function syncPersonaAndVaultUI() {
    const btnAlice = document.getElementById("btn-persona-alice");
    const btnBob = document.getElementById("btn-persona-bob");
    if (btnAlice) btnAlice.classList.toggle("active", state.persona === "alice");
    if (btnBob) btnBob.classList.toggle("active", state.persona === "bob");

    const personaLabel = document.getElementById("active-persona-label");
    if (personaLabel) personaLabel.textContent = state.persona;

    const grantedList = (state.grantedProviders && state.grantedProviders[state.persona]) || [];
    const chips = document.querySelectorAll(".provider-chip");
    chips.forEach(function (chip) {
      const prov = chip.getAttribute("data-provider");
      const dot = chip.querySelector(".provider-dot");
      const btn = chip.querySelector(".btn-revoke-provider");
      const isGranted = grantedList.indexOf(prov) !== -1;
      if (dot) dot.classList.toggle("granted", isGranted);
      if (btn) {
        btn.textContent = isGranted ? "Test Revoke 3LO" : "Grant 3LO";
        btn.setAttribute("data-mode", isGranted ? "revoke" : "grant");
      }
    });
  }

  function syncScenarioHeader() {
    const tabs = document.querySelectorAll(".scenario-tab");
    tabs.forEach(function (tab) {
      tab.classList.toggle("active", tab.getAttribute("data-scenario") === state.scenarioId);
    });

    const meta = state.scenarios[state.scenarioId];
    if (!meta) return;

    const badge = document.getElementById("active-scenario-badge");
    const title = document.getElementById("active-scenario-title");
    const subtitle = document.getElementById("active-scenario-subtitle");
    const promptInput = document.getElementById("input-prompt");

    if (badge) badge.textContent = meta.id;
    if (title) title.textContent = meta.title;
    if (subtitle) subtitle.textContent = meta.subtitle;
    if (promptInput && meta.defaultPrompt) {
      promptInput.value = meta.defaultPrompt;
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
        if (snap.grantedProviders) {
          state.grantedProviders = snap.grantedProviders;
        }
        syncPersonaAndVaultUI();
      }
    } catch (err) {
      console.error("persistPosture failed:", err);
    }
  }

  function renderA2UICards(cards) {
    const container = document.getElementById("a2ui-cards-container");
    if (!container) return;
    container.innerHTML = "";

    if (!Array.isArray(cards) || cards.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-hint";
      empty.textContent = "No A2UI v0.9 cards emitted for this turn.";
      container.appendChild(empty);
      return;
    }

    cards.forEach(function (card) {
      const cardType = card.type || "IncidentSummaryCard";
      const el = document.createElement("article");
      el.className = "a2ui-card severity-" + (card.severity || "INFO");
      el.setAttribute("data-card-type", cardType);

      const topRow = document.createElement("div");
      topRow.className = "a2ui-card-top";

      const typeBadge = document.createElement("span");
      typeBadge.className = "a2ui-card-type";
      typeBadge.innerHTML = (CARD_CATALOG_ICONS[cardType] || CARD_CATALOG_ICONS.IncidentSummaryCard) + " ";
      const typeLabel = document.createElement("span");
      typeLabel.textContent = cardType;
      typeBadge.appendChild(typeLabel);

      const sevBadge = document.createElement("span");
      sevBadge.className = "mime-tag";
      sevBadge.textContent = (card.severity || "INFO") + " · v" + (card.version || "0.9");

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
            handleA2UIAction(act);
          });
          actionsRow.appendChild(btn);
        });
        el.appendChild(actionsRow);
      }

      container.appendChild(el);
    });
  }

  async function handleA2UIAction(act) {
    if (!act) return;
    if (act.kind === "oauth_consent") {
      const payload = act.payload || {};
      const resp = await fetch("/api/sessions/" + encodeURIComponent(state.sessionId) + "/oauth/grant", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          persona: payload.persona || state.persona,
          provider: payload.provider || "atlassian_jira",
          nonce: payload.nonce || "",
        }),
      });
      if (resp.ok) {
        const snap = await resp.json();
        if (snap.grantedProviders) {
          state.grantedProviders = snap.grantedProviders;
        }
        const coldCheck = document.getElementById("chk-cold-3lo");
        if (coldCheck) coldCheck.checked = false;
        syncPersonaAndVaultUI();
        await executeTurn({ forceCold3LO: false });
      }
      return;
    }

    if (act.kind === "step_up_approve" || act.kind === "step_up_reject") {
      const payload = act.payload || {};
      const confirmed = act.kind === "step_up_approve" || payload.confirmed === "true";
      const resp = await fetch("/api/sessions/" + encodeURIComponent(state.sessionId) + "/confirmations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          confirmationId: payload.confirmationId || "",
          confirmed: confirmed,
        }),
      });
      if (resp.ok) {
        const turnResult = await resp.json();
        renderTurnResult(turnResult);
      }
    }
  }

  function renderBoundaryWaterfall(trace) {
    ALL_BOUNDARIES.forEach(function (bId) {
      const badge = document.getElementById("b-status-" + bId);
      if (badge) {
        badge.className = "b-verdict";
        badge.textContent = "STANDBY";
      }
    });

    const listEl = document.getElementById("boundary-trace-list");
    if (!listEl) return;
    listEl.innerHTML = "";

    if (!Array.isArray(trace) || trace.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-hint";
      empty.textContent = "No boundary trace events recorded yet.";
      listEl.appendChild(empty);
      return;
    }

    trace.forEach(function (ev) {
      const badge = document.getElementById("b-status-" + ev.boundary);
      if (badge) {
        badge.className = "b-verdict verdict-" + ev.verdict;
        badge.textContent = ev.verdict;
      }

      const item = document.createElement("div");
      item.className = "trace-event-card";

      const top = document.createElement("div");
      top.className = "trace-event-top";

      const title = document.createElement("span");
      title.className = "trace-step-title";
      title.textContent = "#" + ev.order + " · " + ev.shield + " (" + ev.boundary + ")";

      const vBadge = document.createElement("span");
      vBadge.className = "b-verdict verdict-" + ev.verdict;
      vBadge.textContent = ev.verdict;

      top.appendChild(title);
      top.appendChild(vBadge);

      const comp = document.createElement("div");
      comp.className = "trace-component";
      comp.textContent = ev.component + " -> " + ev.action;

      const detail = document.createElement("div");
      detail.className = "trace-detail";
      detail.textContent = ev.detail;

      item.appendChild(top);
      item.appendChild(comp);
      item.appendChild(detail);
      listEl.appendChild(item);
    });
  }

  function renderWireRecords(turn) {
    const previewEl = document.getElementById("sanitized-preview");
    if (previewEl) {
      previewEl.textContent =
        turn.sanitizedInputPreview ||
        turn.outboundCommentPreview ||
        turn.assistantText ||
        "No payload preview emitted.";
    }

    const wireList = document.getElementById("wire-records-list");
    if (!wireList) return;
    wireList.innerHTML = "";

    const records = turn.wireRecords || [];
    if (records.length === 0) {
      const empty = document.createElement("div");
      empty.className = "empty-hint";
      empty.textContent = "No outbound HTTP wire calls recorded on this turn.";
      wireList.appendChild(empty);
      return;
    }

    records.forEach(function (rec) {
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
      wireList.appendChild(row);
    });
  }

  function renderTurnResult(turn) {
    if (!turn) return;
    const outcomeBadge = document.getElementById("outcome-badge");
    const personaMeta = document.getElementById("outcome-persona-meta");
    const assistantText = document.getElementById("assistant-text");

    if (outcomeBadge) {
      outcomeBadge.textContent = turn.outcome || "COMPLETED";
      outcomeBadge.className = "outcome-pill";
      if (turn.outcome === "DEFENDED_SUCCESS") {
        outcomeBadge.classList.add("outcome-defended");
      } else if (turn.outcome === "BLOCKED") {
        outcomeBadge.classList.add("outcome-blocked");
      } else if (turn.outcome === "CONSENT_REQUIRED" || turn.outcome === "APPROVAL_REQUIRED") {
        outcomeBadge.classList.add("outcome-challenge");
      } else {
        outcomeBadge.classList.add("outcome-exploited");
      }
    }

    if (personaMeta) {
      personaMeta.textContent =
        "Persona: " +
        turn.persona +
        " (" +
        (turn.persona === "alice" ? "SecOps Lead" : "External Contractor") +
        ") · Scenario: " +
        turn.scenarioId;
    }

    if (assistantText) {
      assistantText.textContent = turn.assistantText || "";
    }

    renderA2UICards(turn.cards || []);
    renderBoundaryWaterfall(turn.boundaryTrace || []);
    renderWireRecords(turn);
  }

  async function executeTurn(opts) {
    const options = opts || {};
    const promptInput = document.getElementById("input-prompt");
    const cleanPiiCheck = document.getElementById("chk-clean-pii");
    const cold3loCheck = document.getElementById("chk-cold-3lo");

    const reqBody = {
      sessionId: state.sessionId,
      persona: state.persona,
      scenarioId: state.scenarioId,
      posture: state.posture,
      prompt: promptInput ? promptInput.value : "Triage incident",
      cleanPiiOnly: Boolean(cleanPiiCheck && cleanPiiCheck.checked),
      requireCold3loConsent:
        options.forceCold3LO !== undefined
          ? Boolean(options.forceCold3LO)
          : Boolean(cold3loCheck && cold3loCheck.checked),
    };

    try {
      const resp = await fetch("/api/sessions/" + encodeURIComponent(state.sessionId) + "/turns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqBody),
      });
      if (!resp.ok) return;
      const turn = await resp.json();
      renderTurnResult(turn);
    } catch (err) {
      console.error("executeTurn failed:", err);
    }
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
        state.persona = data.session.activePersona || "alice";
        state.posture = data.session.posture || state.posture;
        state.grantedProviders = data.session.grantedProviders || state.grantedProviders;
      }
      const coldCheck = document.getElementById("chk-cold-3lo");
      if (coldCheck) coldCheck.checked = false;
      syncShieldUI();
      syncPersonaAndVaultUI();
      await executeTurn();
    } catch (err) {
      console.error("seedFixtures failed:", err);
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
        if (snap.activePersona) state.persona = snap.activePersona;
        if (snap.posture) state.posture = snap.posture;
        if (snap.grantedProviders) state.grantedProviders = snap.grantedProviders;
      }
    } catch (err) {
      console.error("initial load failed:", err);
    }
    syncShieldUI();
    syncPersonaAndVaultUI();
    syncScenarioHeader();
    await executeTurn();
  }

  function bindEvents() {
    document.querySelectorAll(".shield-pill").forEach(function (pill) {
      const key = pill.getAttribute("data-shield");
      const input = pill.querySelector("input[type='checkbox']");
      if (!input || !key) return;
      input.addEventListener("change", async function () {
        state.posture[key] = Boolean(input.checked);
        syncShieldUI();
        await persistPosture();
        await executeTurn();
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
        await executeTurn();
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
        await executeTurn();
      });
    }

    document.querySelectorAll(".persona-btn").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        const p = btn.getAttribute("data-persona");
        if (!p) return;
        state.persona = p;
        syncPersonaAndVaultUI();
        await persistPosture();
        await executeTurn();
      });
    });

    document.querySelectorAll(".btn-revoke-provider").forEach(function (btn) {
      btn.addEventListener("click", async function () {
        const provider = btn.getAttribute("data-provider");
        const mode = btn.getAttribute("data-mode") || "revoke";
        const endpoint =
          mode === "grant"
            ? "/api/sessions/" + encodeURIComponent(state.sessionId) + "/oauth/grant"
            : "/api/sessions/" + encodeURIComponent(state.sessionId) + "/oauth/revoke";
        const resp = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            persona: state.persona,
            provider: provider,
          }),
        });
        if (resp.ok) {
          const snap = await resp.json();
          if (snap.grantedProviders) {
            state.grantedProviders = snap.grantedProviders;
          }
          syncPersonaAndVaultUI();
          await executeTurn();
        }
      });
    });

    document.querySelectorAll(".scenario-tab").forEach(function (tab) {
      tab.addEventListener("click", async function () {
        const scenId = tab.getAttribute("data-scenario");
        if (!scenId) return;
        state.scenarioId = scenId;
        syncScenarioHeader();
        await executeTurn();
      });
    });

    const btnRun = document.getElementById("btn-run-turn");
    if (btnRun) {
      btnRun.addEventListener("click", function () {
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
      chkCleanPii.addEventListener("change", function () {
        executeTurn();
      });
    }

    const chkCold3lo = document.getElementById("chk-cold-3lo");
    if (chkCold3lo) {
      chkCold3lo.addEventListener("change", function () {
        executeTurn();
      });
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    initThemeToggle();
    bindEvents();
    loadScenariosAndInitialState();
  });
})();
