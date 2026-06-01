"use strict";

const TRAFFIC_CAP = 100;
const ALERTS_CAP = 50;
let summaryTs = 0;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// ---- traffic feed ----------------------------------------------------------
function addTrafficRows(rows) {
  const feed = $("traffic");
  for (const r of rows) {
    const div = document.createElement("div");
    div.className = "row";
    const arrow = r.is_response ? "&larr;" : "&rarr;";
    div.innerHTML =
      `<span class="proto ${esc(r.proto)}">${esc(r.proto.toUpperCase())}</span>` +
      `<span class="addr">${esc(r.src)} ${arrow} ${esc(r.dst)}</span> ` +
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
  $("c-snmp").textContent = s.by_proto.snmp || 0;
  $("cap-count").textContent = s.total_captures + " events";
  $("alert-count").textContent = s.total_alerts;

  // alerts-over-time vertical bars
  const max = Math.max(1, ...s.alert_buckets);
  $("time-chart").innerHTML = s.alert_buckets
    .map((v) => `<div class="bar" style="height:${(v / max) * 100}%" title="${v}"></div>`)
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
  summaryTs = s.ts || 0;
  updateAge();
}
function updateAge() {
  if (!summaryTs) { $("summary-age").textContent = "—"; return; }
  const secs = Math.max(0, Math.floor(Date.now() / 1000 - summaryTs));
  $("summary-age").textContent = `updated ${secs}s ago`;
}
setInterval(updateAge, 1000);

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
}

connect();
