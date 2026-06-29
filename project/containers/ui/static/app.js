"use strict";

const TRAFFIC_CAP = 100;
const ALERTS_CAP = 50;
let summaryTs = 0;
let bucketSeconds = 15;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// ---- traffic feed ----------------------------------------------------------
function addTrafficRows(rows) {
  const feed = $("traffic");
  for (const r of rows) {
    const div = document.createElement("div");
    const dir = r.is_response ? "resp" : "req";
    div.className = "row " + dir;
    div.innerHTML =
      `<span class="proto ${esc(r.proto)}">${esc(r.proto.toUpperCase())}</span>` +
      `<span class="dir ${dir}">${dir}</span>` +
      `<span class="src">${esc(r.src)}</span>` +
      `<span class="arrow">&rarr;</span>` +
      `<span class="dst">${esc(r.dst)}</span>` +
      `<span class="detail">${esc(r.detail)}</span>`;
    feed.appendChild(div);
  }
  while (feed.childElementCount > TRAFFIC_CAP) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;
}

// ---- analysis: counters + charts ------------------------------------------
function renderStats(s) {
  $("c-captures").textContent = s.total_captures;
  $("c-alerts").textContent = s.total_alerts;
  $("c-dns").textContent = s.by_proto.dns || 0;
  $("cap-count").textContent = s.total_captures + " events";
  $("alert-count").textContent = s.total_alerts;

  // alerts-over-time bars — full-height hoverable columns (tooltip shows value)
  bucketSeconds = s.bucket_seconds || bucketSeconds;
  const max = Math.max(1, ...s.alert_buckets);
  const n = s.alert_buckets.length;
  $("time-chart").innerHTML = s.alert_buckets
    .map((v, i) =>
      `<div class="bar-col" data-v="${v}" data-age="${Math.round((n - 1 - i) * bucketSeconds)}">` +
      `<div class="fill" style="height:${(v / max) * 100}%"></div></div>`)
    .join("");

  // top MITRE techniques horizontal bars
  const entries = Object.entries(s.technique_freq);
  const tmax = Math.max(1, ...entries.map(([, n]) => n));
  $("mitre-chart").innerHTML = entries
    .map(([t, n]) =>
      `<div class="hbar"><span class="lbl">${esc(t)}</span>` +
      `<span class="track"><span class="fill" style="width:${(n / tmax) * 100}%"></span></span>` +
      `<span class="n">${n}</span></div>`)
    .join("") || '<span class="muted">none yet</span>';
}

// ---- analysis: recent alerts ----------------------------------------------
function addAlerts(alerts) {
  const box = $("alerts");
  for (const a of alerts) {
    const div = document.createElement("div");
    div.className = "alert";
    div.innerHTML =
      `<div class="top"><span><span class="sev">${esc(a.proto.toUpperCase())}</span> ` +
      `${esc(a.src)} <span class="muted">score ${esc(a.score)}</span></span>` +
      `<span class="techs">${esc((a.techniques || []).join(", "))}</span></div>` +
      `<div class="muted">top: ${esc(a.top_feature)}</div>` +
      `<div class="report">${esc(a.report || "(no report yet)")}</div>`;
    div.querySelector(".top").addEventListener("click", () => div.classList.toggle("open"));
    box.insertBefore(div, box.firstChild);
  }
  while (box.childElementCount > ALERTS_CAP) box.removeChild(box.lastChild);
}

// ---- summary ---------------------------------------------------------------
function renderSummary(s) {
  $("summary").textContent = s.text;
  const t = $("summary-transient");
  if (s.transient) { t.textContent = "⏳ " + s.transient; t.style.display = ""; }
  else { t.style.display = "none"; }
  summaryTs = s.ts || 0;
  updateAge();
}

// ---- system panel (ops-agent health + LLM control) -------------------------
const RESTARTABLE = new Set(["soc-collector", "soc-defender", "soc-attacker", "soc-cti", "soc-ui"]);
const pendingRestart = {};   // container name -> epoch ms until which to show "restarting…"
let modelsLoaded = false;
let lastOps = null;

function markRestarting(name, ms) {
  pendingRestart[name] = Date.now() + ms;
  if (lastOps) renderOps(lastOps);   // instant feedback before the next health tick
}

async function postJSON(url, body) {
  try { await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }); }
  catch (e) { /* transient — ignore */ }
}

async function loadModels(selected) {
  if (modelsLoaded) return;
  modelsLoaded = true;
  try {
    const d = await (await fetch("/api/models")).json();
    const sel = $("llm-select");
    sel.innerHTML = d.models.map((m) => `<option value="${esc(m)}">${esc(m)}</option>`).join("");
    sel.value = selected || d.selected;
    sel.addEventListener("change", () => postJSON("/api/model", { model: sel.value }));
  } catch (e) { modelsLoaded = false; }
}

function renderOps(o) {
  lastOps = o;
  const llm = o.llm || {};
  loadModels(llm.model);
  if (modelsLoaded && llm.model) $("llm-select").value = llm.model;
  const st = $("llm-status");
  const ageTxt = (llm.age_s != null) ? ` · ${llm.age_s}s ago` : "";
  st.textContent = (llm.status || "—").replace("_", " ") + ageTxt;
  st.className = "chip " + (llm.status || "");
  const pct = llm.used_pct;
  $("llm-token-fill").style.width = (pct == null ? 0 : pct) + "%";
  $("llm-token-pct").textContent = pct == null ? "n/a" : Math.round(pct) + "%";

  const now = Date.now();
  const cs = o.containers || [];
  $("system-sub").textContent = cs.filter((c) => c.status === "running").length + "/" + cs.length + " running";
  const box = $("containers");
  box.innerHTML = cs.map((c) => {
    const can = RESTARTABLE.has(c.name);
    const pending = pendingRestart[c.name] && now < pendingRestart[c.name];
    const dot = pending ? "restarting" : (c.status === "running" ? "running" : "");
    const mid = pending
      ? `<span class="metric wide restarting">restarting…</span>`
      : `<span class="metric">${(c.cpu_pct ?? 0).toFixed(0)}%</span><span class="metric">${Math.round(c.mem_mb ?? 0)}MB</span>`;
    return `<div class="crow"><span class="dot ${dot}"></span>` +
      `<span class="cname">${esc(c.name.replace(/^soc-/, ""))}</span>` + mid +
      `<button class="restart" data-t="${esc(c.name)}" ${can && !pending ? "" : "disabled"} title="restart">⟳</button></div>`;
  }).join("");
  box.querySelectorAll("button.restart").forEach((b) => b.addEventListener("click", () => {
    postJSON("/api/restart", { target: b.dataset.t });
    markRestarting(b.dataset.t, 12000);
  }));
}
function updateAge() {
  if (!summaryTs) { $("summary-age").textContent = "—"; return; }
  const secs = Math.max(0, Math.floor(Date.now() / 1000 - summaryTs));
  $("summary-age").textContent = `updated ${secs}s ago`;
}
setInterval(updateAge, 1000);

// ---- detector model (multi-backend; live autoencoder view) -----------------
let modelCard = null;        // {active_backend, backends:{key:{type,label,available,models,note}}}
let detectorState = null;    // latest alert from the ACTIVE backend
let lastDetectorAt = 0;      // epoch ms of the last alert (for the IF "alerting" flash)
const lastAttr = {};         // protocol -> {attributions, score, ts} of its most recent alert
let selectedBackend = null;  // which backend's view is shown (default = active)
let currentProto = null;
let pinnedProto = null;      // when set, stop auto-following the latest alert's protocol

function mrow(k, v) { return `<span class="k">${esc(k)}</span><b>${esc(v)}</b>`; }
function setBackend(b) { if (modelCard && modelCard.backends[b]) { selectedBackend = b; renderModel(); } }
function setProto(p) { pinnedProto = p; currentProto = p; renderModel(); }
function setAuto() {
  pinnedProto = null;
  if (detectorState && detectorState.protocol) currentProto = detectorState.protocol;
  renderModel();
}

function renderBackendSwitch() {
  const el = $("backend-switch");
  let html = Object.entries(modelCard.backends).map(([key, b]) => {
    const cls = [key === selectedBackend ? "active" : "", b.available ? "" : "unavail"].join(" ").trim();
    const dot = key === modelCard.active_backend ? '<i class="live-dot"></i>' : "";
    return `<button data-b="${key}" class="${cls}">${dot}${esc(b.label)}</button>`;
  }).join("");
  // offer to make a viewed-but-inactive runnable backend the live one (restart defender)
  const canApply = selectedBackend !== modelCard.active_backend &&
    (selectedBackend === "local" || selectedBackend === "isolation_forest");
  if (canApply) html += `<button class="apply-backend" id="apply-backend">⟳ apply &amp; restart</button>`;
  el.innerHTML = html;
  el.querySelectorAll("button[data-b]").forEach((btn) => btn.addEventListener("click", () => setBackend(btn.dataset.b)));
  const ab = $("apply-backend");
  if (ab) ab.addEventListener("click", () => {
    ab.textContent = "restarting defender…"; ab.disabled = true;
    postJSON("/api/backend", { backend: selectedBackend });
    markRestarting("soc-defender", 15000);
  });
}

function renderProtoToggle(protos) {
  const toggle = $("model-toggle");
  if (!protos.length) { toggle.innerHTML = ""; return; }
  if (!protos.includes(currentProto)) currentProto = protos[0];
  toggle.innerHTML =
    `<button data-auto="1" class="${pinnedProto ? "" : "active"}">auto</button>` +
    protos.map((p) => `<button data-p="${p}" class="${pinnedProto === p ? "active" : ""}">${esc(p)}</button>`).join("");
  toggle.querySelectorAll("button").forEach((b) => b.addEventListener("click",
    () => (b.dataset.auto ? setAuto() : setProto(b.dataset.p))));
}

// per-feature error from this protocol's most recent alert (only for the ACTIVE backend)
function liveVals(feats, proto) {
  const la = (selectedBackend === modelCard.active_backend) ? lastAttr[proto] : null;
  const attr = la ? la.attributions : {};
  return feats.map((f) => attr[f] || 0);
}
function topDrivers(feats, vals) {
  return feats.map((f, j) => [f, vals[j]]).sort((a, b) => b[1] - a[1])
    .filter(([, v]) => v > 0).slice(0, 3).map(([f]) => f);
}
function activeTag(b) { return selectedBackend === modelCard.active_backend ? " (active)" : " (inspect)"; }

function renderAE(b) {
  $("ae-legend").style.display = "";
  const m = b.models[currentProto], layers = m.layers, feats = m.features || [];
  const vals = liveVals(feats, currentProto), maxv = Math.max(1e-9, ...vals);
  // spread the layers across more of the panel and use larger nodes for presence
  const W = 360, H = 200, padX = 14, padY = 13, nL = layers.length, minLayer = Math.min(...layers);
  const xs = layers.map((_, i) => padX + (W - 2 * padX) * (nL === 1 ? 0.5 : i / (nL - 1)));
  const ys = (c) => c === 1 ? [H / 2] : Array.from({ length: c }, (_, j) => padY + (H - 2 * padY) * j / (c - 1));
  const r = Math.max(2.2, Math.min(6, 95 / Math.max(...layers)));
  const parts = [];
  for (let i = 0; i < nL - 1; i++) {                   // sparse edges (avoid a hairball)
    const y1 = ys(layers[i]), y2 = ys(layers[i + 1]);
    const s1 = Math.ceil(layers[i] / 8), s2 = Math.ceil(layers[i + 1] / 8);
    for (let a = 0; a < y1.length; a += s1)
      for (let bb = 0; bb < y2.length; bb += s2)
        parts.push(`<line class="ae-edge" x1="${xs[i].toFixed(1)}" y1="${y1[a].toFixed(1)}" x2="${xs[i + 1].toFixed(1)}" y2="${y2[bb].toFixed(1)}"/>`);
  }
  for (let i = 0; i < nL; i++) {
    const y = ys(layers[i]);
    const isIO = (i === 0 || i === nL - 1) && feats.length === layers[i];
    const isBottleneck = layers[i] === minLayer;
    for (let j = 0; j < y.length; j++) {
      let fill = isBottleneck ? "#1f6feb" : "#3a4350";
      if (isIO) {
        const norm = vals[j] / maxv;                   // heatmap: dim grey -> amber -> red
        fill = norm < 0.02 ? "#3a4350" : `rgb(246,${Math.round(180 - 99 * norm)},${Math.round(40 + 33 * norm)})`;
      }
      parts.push(`<circle class="ae-node${isBottleneck ? " bottleneck" : ""}" cx="${xs[i].toFixed(1)}" cy="${y[j].toFixed(1)}" r="${r}" fill="${fill}"/>`);
    }
  }
  for (let i = 0; i < nL; i++)
    parts.push(`<text class="ae-label" x="${xs[i].toFixed(1)}" y="${H - 2}" text-anchor="middle">${layers[i]}</text>`);
  const role = (i) => i === 0 ? "input" : i === nL - 1 ? "output" : (layers[i] === minLayer ? "latent" : "");
  for (let i = 0; i < nL; i++) {
    const rl = role(i);
    if (rl) parts.push(`<text class="ae-role${rl === "latent" ? " latent" : ""}" x="${xs[i].toFixed(1)}" y="9" text-anchor="middle">${rl}</text>`);
  }
  $("ae-svg").innerHTML = parts.join("");
  const drivers = topDrivers(feats, vals);
  const la = (selectedBackend === modelCard.active_backend) ? lastAttr[currentProto] : null;
  $("model-sub").textContent = la
    ? `${currentProto.toUpperCase()} · nodes lit by last alert (${Math.round((Date.now() - la.ts) / 1000)}s ago)`
    : `${currentProto.toUpperCase()} · waiting for a ${currentProto.toUpperCase()} alert`;
  $("model-card").innerHTML =
    mrow("backend", b.label + activeTag(b)) +
    mrow("architecture", layers.join(" → ")) +
    mrow("parameters", (m.n_params || 0).toLocaleString()) +
    mrow("threshold", (+m.threshold).toPrecision(3)) +
    mrow("features", m.input_dim) +
    mrow("top drivers", drivers.length ? drivers.join(", ") : "—");
}

function renderIF(b) {
  $("ae-legend").style.display = "none";
  const m = b.models[currentProto], feats = m.features || [];
  const vals = liveVals(feats, currentProto);
  // the whole ensemble flashes red when it (the active backend) flags an anomaly
  const alerting = selectedBackend === modelCard.active_backend &&
    detectorState && detectorState.protocol === currentProto && (Date.now() - lastDetectorAt < 8000);
  const n = m.n_estimators || 0;
  const W = 360, H = 200, pad = 22, drawn = Math.min(n, 200), cols = 20;
  const rows = Math.max(1, Math.ceil(drawn / cols));
  const cw = (W - 2 * pad) / cols, ch = Math.min(18, (H - 2 * pad - 14) / rows);
  const cls = "if-tree" + (alerting ? " alert" : "");
  const parts = [];
  for (let k = 0; k < drawn; k++) {
    const cx = pad + cw * (k % cols + 0.5), cy = pad + 6 + ch * (Math.floor(k / cols) + 0.5);
    parts.push(`<polygon class="${cls}" points="${(cx-3).toFixed(1)},${(cy+3.5).toFixed(1)} ${(cx+3).toFixed(1)},${(cy+3.5).toFixed(1)} ${cx.toFixed(1)},${(cy-3.5).toFixed(1)}"/>`);
    parts.push(`<line class="if-trunk" x1="${cx.toFixed(1)}" y1="${(cy+3.5).toFixed(1)}" x2="${cx.toFixed(1)}" y2="${(cy+5).toFixed(1)}"/>`);
  }
  const shown = drawn < n ? ` (showing ${drawn})` : "";
  parts.push(`<text class="ae-label" x="${W / 2}" y="${H - 4}" text-anchor="middle">${n} isolation trees${shown}</text>`);
  $("ae-svg").innerHTML = parts.join("");
  const drivers = topDrivers(feats, vals);
  $("model-sub").textContent = alerting
    ? `${b.label} · ⚠ anomaly flagged (score ${(detectorState.score || 0).toFixed(2)})`
    : `${b.label}${activeTag(b)} · ${currentProto.toUpperCase()} · unsupervised baseline`;
  $("model-card").innerHTML =
    mrow("backend", b.label + activeTag(b)) +
    mrow("estimators", m.n_estimators) +
    mrow("contamination", m.contamination) +
    mrow("max samples", m.max_samples) +
    mrow("features", m.input_dim) +
    mrow("top drivers", drivers.length ? drivers.join(", ") : "—") +
    mrow("note", m.note || "");
}

function renderUnavailable(b) {
  $("model-toggle").innerHTML = "";
  $("ae-legend").style.display = "none";
  $("ae-svg").innerHTML =
    `<text x="180" y="92" text-anchor="middle" class="ae-role latent">${esc(b.label)}</text>` +
    `<text x="180" y="110" text-anchor="middle" class="ae-label">not available</text>`;
  $("model-sub").textContent = `${b.label} · not active`;
  $("model-card").innerHTML = mrow("backend", b.label) + mrow("status", "not available") + mrow("note", b.note || "");
}

function renderModel() {
  if (!modelCard || !modelCard.backends) { $("model-sub").textContent = "waiting for model…"; return; }
  if (!selectedBackend || !modelCard.backends[selectedBackend])
    selectedBackend = modelCard.active_backend || Object.keys(modelCard.backends)[0];
  renderBackendSwitch();
  const b = modelCard.backends[selectedBackend];
  const protos = Object.keys(b.models || {});
  if (b.available && protos.length && (b.type === "autoencoder" || b.type === "isolation_forest")) {
    renderProtoToggle(protos);
    (b.type === "autoencoder" ? renderAE : renderIF)(b);
  } else {
    renderUnavailable(b);
  }
}

// ---- SSE wiring ------------------------------------------------------------
function connect() {
  const es = new EventSource("/events");
  const conn = $("conn");

  es.onopen = () => { conn.textContent = "● live"; conn.className = "badge online"; };
  es.onerror = () => { conn.textContent = "reconnecting…"; conn.className = "badge offline"; };

  es.addEventListener("snapshot", (e) => {
    const d = JSON.parse(e.data);
    $("traffic").innerHTML = ""; addTrafficRows(d.traffic || []);
    $("alerts").innerHTML = ""; addAlerts(d.alerts || []);
    renderStats(d.stats);
  });
  es.addEventListener("traffic", (e) => addTrafficRows(JSON.parse(e.data)));
  es.addEventListener("alerts", (e) => addAlerts(JSON.parse(e.data)));
  es.addEventListener("stats", (e) => renderStats(JSON.parse(e.data)));
  es.addEventListener("summary", (e) => renderSummary(JSON.parse(e.data)));
  es.addEventListener("ops", (e) => renderOps(JSON.parse(e.data)));
  es.addEventListener("model", (e) => { modelCard = JSON.parse(e.data); renderModel(); });
  es.addEventListener("detector", (e) => {
    detectorState = JSON.parse(e.data);
    lastDetectorAt = Date.now();
    if (detectorState.protocol) {
      lastAttr[detectorState.protocol] = {
        attributions: detectorState.attributions || {}, score: detectorState.score, ts: Date.now(),
      };
    }
    // follow the latest alert's protocol only in AUTO mode (no manual pin)
    if (!pinnedProto && detectorState.protocol) currentProto = detectorState.protocol;
    renderModel();
  });
}

// ---- alerts-over-time tooltip (delegated, survives chart re-renders) --------
function initChartTooltip() {
  const chart = $("time-chart");
  // Attach to <body> with position:fixed so the panel's overflow:hidden can't crop it.
  const tip = document.createElement("div");
  tip.className = "chart-tip";
  tip.style.display = "none";
  document.body.appendChild(tip);

  chart.addEventListener("mousemove", (e) => {
    const col = e.target.closest(".bar-col");
    if (!col) { tip.style.display = "none"; return; }
    const v = col.dataset.v;
    const age = +col.dataset.age;
    const when = age <= 0 ? "now" : `~${age}s ago`;
    tip.textContent = `${v} alert${v === "1" ? "" : "s"} · ${when}`;
    // viewport coordinates (clamped so it never runs off the left/right edge)
    tip.style.left = Math.min(window.innerWidth - 60, Math.max(60, e.clientX)) + "px";
    tip.style.top = (e.clientY - 30) + "px";
    tip.style.display = "block";
  });
  chart.addEventListener("mouseleave", () => { tip.style.display = "none"; });
}

initChartTooltip();
connect();
