const $ = (selector) => document.querySelector(selector);
let incidents = [];
let toastTimer;

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[char]);
}

function showToast(message, error = false) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.toggle("error", error);
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 3600);
}

function formatTime(value) {
  return new Date(value).toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", timeZone: "UTC",
  }) + " UTC";
}

function riskClass(band) {
  return band.toLowerCase();
}

function renderIncidents() {
  $("#queue-count").textContent = incidents.length;
  $("#stat-open").textContent = incidents.length;
  $("#stat-high").textContent = incidents.filter((item) => item.risk_score >= 65).length;
  $("#stat-events").textContent = incidents.reduce((sum, item) => sum + item.event_count, 0);
  $("#last-updated").textContent = `UPDATED ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", timeZone: "UTC" })} UTC`;
  const body = $("#incident-rows");
  if (!incidents.length) {
    body.innerHTML = '<tr><td colspan="7" class="empty">No incidents yet. Ingest a synthetic event to get started.</td></tr>';
    return;
  }
  body.innerHTML = incidents.map((incident, index) => `
    <tr>
      <td><span class="incident-id">INC-${String(index + 1).padStart(3, "0")}</span></td>
      <td><span class="badge ${riskClass(incident.risk_band)}">${escapeHtml(incident.category)}</span></td>
      <td><span class="asset-name">${escapeHtml(incident.asset_ids.join(", "))}</span></td>
      <td><span class="event-pill">${incident.event_count} event${incident.event_count === 1 ? "" : "s"}</span></td>
      <td><span class="risk ${riskClass(incident.risk_band)}">${incident.risk_score}</span> <span class="badge ${riskClass(incident.risk_band)}">${escapeHtml(incident.risk_band)}</span></td>
      <td>${escapeHtml(formatTime(incident.last_seen))}</td>
      <td><button class="view-button" data-incident="${escapeHtml(incident.incident_id)}">Review →</button></td>
    </tr>`).join("");
  body.querySelectorAll("[data-incident]").forEach((button) => {
    button.addEventListener("click", () => openIncident(button.dataset.incident));
  });
}

function renderAssets(assets) {
  $("#stat-assets").textContent = assets.length;
  $("#asset-list").innerHTML = assets.map((asset) => `
    <div class="asset-row"><div><div class="asset-title">${escapeHtml(asset.display_name)}</div>
    <span class="asset-id">${escapeHtml(asset.asset_id)}</span></div>
    <span class="state ${asset.isolated ? "isolated" : ""}">${asset.isolated ? "ISOLATED · SIM" : "ONLINE · MOCK"}</span></div>`).join("");
}

function renderAudit(entries) {
  const list = $("#audit-list");
  if (!entries.length) {
    list.innerHTML = '<div class="empty">No response actions have been requested.</div>';
    return;
  }
  list.innerHTML = entries.slice(0, 5).map((entry) => `
    <div class="audit-row"><div><div class="audit-event">${escapeHtml(entry.event.replaceAll("_", " "))}</div>
    <span class="audit-meta">${escapeHtml(entry.details.action || "")} · ${escapeHtml(entry.details.target || "")}</span></div>
    <span class="audit-status ${entry.event === "simulation_applied" ? "approved" : ""}">${entry.event === "simulation_applied" ? "APPLIED · SIM" : "PENDING"}</span></div>`).join("");
}

async function loadDashboard() {
  const [incidentData, assetData, auditData] = await Promise.all([
    api("/api/incidents"), api("/api/assets"), api("/api/audit"),
  ]);
  incidents = incidentData.incidents;
  renderIncidents();
  renderAssets(assetData.assets);
  renderAudit(auditData.audit);
}

async function openIncident(id) {
  try {
    const incident = await api(`/api/incidents/${encodeURIComponent(id)}`);
    const ruleText = incident.rules_matched.length
      ? incident.rules_matched.map(escapeHtml).join(", ")
      : "No specific classification rule matched; shown as suspicious activity.";
    $("#dialog-content").innerHTML = `
      <div class="dialog-head"><div><div class="eyebrow">INCIDENT REVIEW · ${escapeHtml(incident.risk_band.toUpperCase())}</div>
      <h2>${escapeHtml(incident.category)}</h2><p>${escapeHtml(incident.incident_id)}</p></div>
      <button class="icon-button" id="close-dialog" aria-label="Close">×</button></div>
      <div class="dialog-body">
        <section class="detail-section"><h3>TRIAGE SUMMARY</h3>
          <div class="detail-copy">Heuristic risk score <strong>${incident.risk_score}/100 (${escapeHtml(incident.risk_band)})</strong>, based on ${incident.event_count} event(s) with maximum input severity ${Math.max(...incident.events.map((event) => event.severity))}/10. Classification: <strong>${escapeHtml(incident.category)}</strong>. Matched rules: ${ruleText}<br><br>Rule-match indicator: ${Math.round(incident.rule_confidence * 100)}% — ${escapeHtml(incident.confidence_note)} This is a deterministic triage aid, not an LLM conclusion or calibrated probability.</div>
        </section>
        <section class="detail-section"><h3>EVENT EVIDENCE · ${incident.events.length}</h3>
          ${incident.events.map((event) => `<div class="evidence-row"><div class="evidence-title"><span>${escapeHtml(event.event_id)} · ${escapeHtml(event.event_type)}</span><span>SEV ${event.severity}/10</span></div><p>${escapeHtml(event.description)} · ${escapeHtml(formatTime(event.timestamp))}</p></div>`).join("")}
        </section>
        <section class="detail-section"><h3>RETRIEVED DEFENSIVE CONTEXT</h3>
          ${incident.knowledge.length ? incident.knowledge.map((item) => `<div class="evidence-row"><a class="knowledge-link" href="${escapeHtml(item.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(item.title)} ↗</a><p>${escapeHtml(item.summary)} Source: MITRE ATT&CK.</p></div>`).join("") : '<div class="detail-copy">No directly matched local reference. Treat classification as uncertain.</div>'}
        </section>
        <section class="detail-section"><h3>ANALYST RESPONSE · SIMULATION ONLY</h3>
          <div class="response-actions"><button class="button" data-action="isolate_host">Request mock host isolation</button><button class="button" data-action="block_source">Request mock source block</button></div>
        </section>
        ${(incident.response_requests || []).map((request) => `<div class="pending-box">${escapeHtml(request.action)} · ${escapeHtml(request.status)} · ${escapeHtml(request.target)}. ${request.status === "pending" ? `<button class="button" data-approve="${escapeHtml(request.request_id)}">Approve simulation</button>` : "Simulation recorded; no real controls were changed."}</div>`).join("")}
      </div>
      <div class="dialog-footer"><span class="disclaimer">Approval writes mock state only. No OS or network actions.</span><button class="button" id="close-dialog-footer">Done</button></div>`;
    const dialog = $("#incident-dialog");
    dialog.showModal();
    $("#close-dialog").addEventListener("click", () => dialog.close());
    $("#close-dialog-footer").addEventListener("click", () => dialog.close());
    dialog.querySelectorAll("[data-action]").forEach((button) => {
      button.addEventListener("click", () => requestAction(incident.incident_id, button.dataset.action));
    });
    dialog.querySelectorAll("[data-approve]").forEach((button) => {
      button.addEventListener("click", () => approveRequest(button.dataset.approve));
    });
  } catch (error) {
    showToast(error.message, true);
  }
}

async function requestAction(incidentId, action) {
  if (!window.confirm(`Create a pending ${action.replaceAll("_", " ")} simulation request? It will not be applied until separately approved.`)) return;
  try {
    const request = await api(`/api/incidents/${encodeURIComponent(incidentId)}/response-requests`, {
      method: "POST", body: JSON.stringify({ action }),
    });
    const content = $("#dialog-content");
    const pending = document.createElement("div");
    pending.className = "pending-box";
    pending.textContent = `Request ${request.request_id} is pending. Approve this simulation?`;
    const approve = document.createElement("button");
    approve.className = "button";
    approve.textContent = "Approve simulation";
    approve.addEventListener("click", () => approveRequest(request.request_id));
    pending.append(" ", approve);
    content.querySelector(".dialog-body").append(pending);
    showToast("Request created. Analyst approval is required.");
    await loadDashboard();
  } catch (error) {
    showToast(error.message, true);
  }
}

async function approveRequest(requestId) {
  if (!window.confirm("Approve this action against mock state only? No real system or network control will be changed.")) return;
  try {
    const result = await api(`/api/response-requests/${encodeURIComponent(requestId)}/approve`, {
      method: "POST", body: "{}",
    });
    showToast(result.message);
    $("#incident-dialog").close();
    await loadDashboard();
  } catch (error) {
    showToast(error.message, true);
  }
}

function updateClock() {
  $("#clock").textContent = new Date().toLocaleTimeString([], {
    hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: "UTC",
  }) + " UTC";
}

$("#refresh-button").addEventListener("click", () => {
  loadDashboard().catch((error) => showToast(error.message, true));
});
$("#incident-dialog").addEventListener("click", (event) => {
  if (event.target === $("#incident-dialog")) $("#incident-dialog").close();
});
updateClock();
setInterval(updateClock, 1000);
loadDashboard().catch((error) => {
  $("#incident-rows").innerHTML = `<tr><td colspan="7" class="empty">Could not load the dashboard: ${escapeHtml(error.message)}</td></tr>`;
  showToast(error.message, true);
});
