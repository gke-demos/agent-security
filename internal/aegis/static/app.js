(function () {
  "use strict";

  const SESSION_ID = "arena-live-session";
  const STEP_DELAY_MS = 220;

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
    scenarios: {},
  };

  function sleep(ms) {
    return new Promise(function (resolve) {
      setTimeout(resolve, ms);
    });
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
        if (snap.grantedProviders) {
          state.grantedProviders = snap.grantedProviders;
        }
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
    typeBadge.innerHTML = (CARD_CATALOG_ICONS[cardType] || CARD_CATALOG_ICONS.IncidentSummaryCard) + " ";
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
      if (btnEl) btnEl.textContent = "Granting OAuth Consent...";
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
        syncComposerFlagsIndicator();
        syncPersonaAndVaultUI();
        if (btnEl) btnEl.textContent = "3LO OAuth Granted";
        await executeTurn({
          forceCold3LO: false,
          userLabelOverride:
            "Completed 3LO OAuth consent for " + (payload.provider || "provider") + " — resuming request",
        });
      }
      return;
    }

    if (act.kind === "step_up_approve" || act.kind === "step_up_reject") {
      const payload = act.payload || {};
      const confirmed = act.kind === "step_up_approve" || payload.confirmed === "true";
      if (btnEl) {
        btnEl.textContent = confirmed ? "Approved" : "Rejected";
      }
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
        await renderTurnInChat(
          confirmed
            ? "Approved step-up confirmation: proceed with remediation PR"
            : "Rejected step-up confirmation: abort state-mutating action",
          turnResult
        );
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
      wireList.innerHTML = "";
      (turn.wireRecords || []).forEach(function (rec) {
        const row = document.createElement("div");
        row.textContent = rec.method + " " + rec.url;
        wireList.appendChild(row);
      });
    }
    if (cardsContainer) {
      cardsContainer.innerHTML = "";
      (turn.cards || []).forEach(function (c) {
        cardsContainer.appendChild(buildA2UICardElement(c));
      });
    }
    ALL_BOUNDARIES.forEach(function (bId) {
      const badge = document.getElementById("b-status-" + bId);
      if (badge) badge.textContent = "STANDBY";
    });
    if (traceList) {
      traceList.innerHTML = "";
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

  async function renderTurnInChat(userPromptText, turn) {
    if (!turn) return;
    updateReferenceContainers(turn);

    const welcomeEl = document.getElementById("chat-welcome");
    if (welcomeEl) welcomeEl.hidden = true;

    const messagesEl = document.getElementById("chat-messages");
    const streamEl = document.getElementById("chat-stream");
    if (!messagesEl) return;

    const turnWrap = document.createElement("div");
    turnWrap.className = "chat-turn";

    // 1. User Message Bubble
    const userRow = document.createElement("div");
    userRow.className = "user-msg-row";

    const userMeta = document.createElement("div");
    userMeta.className = "user-msg-meta";
    userMeta.textContent =
      (turn.persona === "bob" ? "Bob (External Contractor)" : "Alice (SecOps Lead)") +
      " · " +
      (turn.scenarioId || state.scenarioId);

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
    avatar.innerHTML =
      '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>';

    const contentCol = document.createElement("div");
    contentCol.className = "assistant-content";

    const headerRow = document.createElement("div");
    headerRow.className = "assistant-header";
    const nameSpan = document.createElement("span");
    nameSpan.className = "assistant-name";
    nameSpan.textContent = "AegisSRE";
    headerRow.appendChild(nameSpan);
    contentCol.appendChild(headerRow);

    // 2a. Progressive Step-by-Step Activity Feed
    const traceEvents = turn.boundaryTrace || [];
    if (traceEvents.length > 0) {
      const stepFeed = document.createElement("div");
      stepFeed.className = "step-feed";
      contentCol.appendChild(stepFeed);

      asstRow.appendChild(avatar);
      asstRow.appendChild(contentCol);
      turnWrap.appendChild(asstRow);
      messagesEl.appendChild(turnWrap);

      if (streamEl) streamEl.scrollTop = streamEl.scrollHeight;

      for (let i = 0; i < traceEvents.length; i++) {
        await sleep(STEP_DELAY_MS);
        const ev = traceEvents[i];
        const stepRow = document.createElement("div");
        stepRow.className = "step-row";

        const left = document.createElement("div");
        left.className = "step-row-left";

        const iconSpan = document.createElement("span");
        iconSpan.className = "step-icon verdict-" + ev.verdict;
        iconSpan.innerHTML = VERDICT_ICONS[ev.verdict] || VERDICT_ICONS.ALLOWED;

        const labelSpan = document.createElement("span");
        labelSpan.className = "step-label";
        labelSpan.textContent = ev.shield;

        const detailSpan = document.createElement("span");
        detailSpan.className = "step-detail-short";
        detailSpan.textContent = "— " + ev.detail;

        left.appendChild(iconSpan);
        left.appendChild(labelSpan);
        left.appendChild(detailSpan);

        const vBadge = document.createElement("span");
        vBadge.className = "b-verdict verdict-" + ev.verdict;
        vBadge.textContent = ev.verdict;

        stepRow.appendChild(left);
        stepRow.appendChild(vBadge);
        stepFeed.appendChild(stepRow);

        if (streamEl) streamEl.scrollTop = streamEl.scrollHeight;
      }
    } else {
      asstRow.appendChild(avatar);
      asstRow.appendChild(contentCol);
      turnWrap.appendChild(asstRow);
      messagesEl.appendChild(turnWrap);
    }

    await sleep(120);

    // 2b. Outcome Badge in Assistant Header
    const outPres = getOutcomePresentation(turn.outcome);
    const outPill = document.createElement("span");
    outPill.className = "outcome-pill " + outPres.cls;
    outPill.textContent = outPres.label;
    headerRow.appendChild(outPill);

    // 2c. Assistant Prose Summary
    if (turn.assistantText) {
      const prose = document.createElement("p");
      prose.className = "assistant-prose";
      prose.textContent = turn.assistantText;
      contentCol.appendChild(prose);
    }

    // 2d. Inline A2UI v0.9 Cards
    if (Array.isArray(turn.cards) && turn.cards.length > 0) {
      const cardsWrap = document.createElement("div");
      cardsWrap.className = "a2ui-cards-container";
      turn.cards.forEach(function (card) {
        cardsWrap.appendChild(buildA2UICardElement(card));
      });
      contentCol.appendChild(cardsWrap);
    }

    // 2e. Collapsible Inline Security Trace & Wire Audit Drawer
    const details = document.createElement("details");
    details.className = "turn-trace-drawer";

    const summary = document.createElement("summary");
    summary.className = "turn-trace-summary";
    const wireCount = (turn.wireRecords || []).length;
    summary.innerHTML =
      "<span>Inspect security trace &amp; HTTP wire audit (" +
      traceEvents.length +
      " boundary checks, " +
      wireCount +
      " outbound calls)</span><span>Expand</span>";
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
    contentCol.appendChild(details);

    if (streamEl) streamEl.scrollTop = streamEl.scrollHeight;
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
      const resp = await fetch("/api/sessions/" + encodeURIComponent(state.sessionId) + "/turns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(reqBody),
      });
      if (!resp.ok) return;
      const turn = await resp.json();
      await renderTurnInChat(options.userLabelOverride || promptText, turn);
    } catch (err) {
      console.error("executeTurn failed:", err);
    }
  }

  function clearChatToWelcome() {
    const messagesEl = document.getElementById("chat-messages");
    const welcomeEl = document.getElementById("chat-welcome");
    if (messagesEl) messagesEl.innerHTML = "";
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
        state.persona = data.session.activePersona || "alice";
        state.posture = data.session.posture || state.posture;
        state.grantedProviders = data.session.grantedProviders || state.grantedProviders;
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
