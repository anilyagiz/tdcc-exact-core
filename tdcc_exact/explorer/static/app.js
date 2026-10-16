// TDCC Exact market explorer: vanilla JS over /api/snapshot and /api/events.
// Everything from the chain goes into the page through textContent (never innerHTML).
"use strict";

const SNAPSHOT_EVERY = 5000, EVENTS_EVERY = 15000, EVENTS_LIMIT = 50;
const AMOUNTS = new Set(["price", "amount", "stake", "refunded", "penalty", "host", "fee",
  "bond", "to_verifier", "to_tdcc", "rent"]);
const LIVE = new Set(["Open", "Committed", "Revealed", "Challenged"]);
const B58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const HEX32 = /^[0-9a-f]{64}$/;

let meta = { explorer_query: "?cluster=devnet", slot_seconds: 0.4 };
let snap = null;
let timers = [];

const $ = (id) => document.getElementById(id);

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "text") e.textContent = v; else if (k === "cls") e.className = v; else e.setAttribute(k, v);
  }
  for (const k of kids) if (k !== null && k !== undefined) e.append(k);
  return e;
}

const usdc = (x) => (x / 1e6).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 6 }) + " USDC";
const short = (k) => (k && k.length > 12 ? k.slice(0, 4) + "…" + k.slice(-4) : k);
const isZero = (h) => !h || /^0+$/.test(h);

function explorerUrl(kind, what) {
  return "https://explorer.solana.com/" + kind + "/" + encodeURIComponent(what) + (meta.explorer_query || "");
}

function addr(key, label) {
  if (!key || key === "11111111111111111111111111111111") return el("span", { cls: "muted", text: "—" });
  return el("a", { href: explorerUrl("address", key), title: key, cls: "mono",
    target: "_blank", rel: "noopener", "aria-label": (label ? label + " " : "") + key }, short(key));
}

function txLink(sig) {
  return el("a", { href: explorerUrl("tx", sig), title: sig, cls: "mono", target: "_blank",
    rel: "noopener", "aria-label": "transaction " + sig }, short(sig));
}

function ago(seconds) {
  const s = Math.abs(seconds);
  const v = s < 90 ? Math.round(s) + " s" : s < 5400 ? Math.round(s / 60) + " min"
    : s < 172800 ? (s / 3600).toFixed(1) + " h" : Math.round(s / 86400) + " d";
  return seconds >= 0 ? "in ~" + v : "~" + v + " ago";
}

// seconds from now until `slot`, from the snapshot's slot and when it was fetched
function secondsUntil(slot) {
  const elapsed = Date.now() / 1000 - (meta.fetched_at || Date.now() / 1000);
  return (slot - snap.slot) * (meta.slot_seconds || 0.4) - elapsed;
}

function td(label, cls, ...kids) { return el("td", { "data-label": label, cls }, ...kids); }

function emptyRow(tbody, cols, text) {
  tbody.replaceChildren(el("tr", null, el("td", { colspan: cols, cls: "empty", text })));
}

// ------------------------------------------------------------------------- summary
function renderSummary(s) {
  const by = s.jobs_by_state || {};
  const live = [...LIVE].reduce((n, k) => n + (by[k] || 0), 0);
  const tile = (name, value, note) => el("div", null, el("dt", { text: name }),
    el("dd", null, String(value), note ? el("small", { text: note }) : null));
  const states = Object.entries(by).map(([k, v]) => k + " " + v).join(", ") || "none";
  $("summary").replaceChildren(
    tile("Escrow locked", usdc(s.escrow), live + " live job" + (live === 1 ? "" : "s")),
    tile("Total stake", usdc(s.total_stake)),
    tile("Providers", s.providers.length),
    tile("Jobs", s.jobs, states),
    tile("Open challenges", s.open_challenges.length, s.open_challenges.length ? "awaiting the arbiter" : null),
    tile("Past a deadline", (s.late || []).length,
      (s.actionable || []).length ? s.actionable.length + " to settle or expire" : null),
    tile("Slot", s.slot.toLocaleString(), Object.keys(s.configs || {}).length + " market(s)"),
  );
}

// ------------------------------------------------------------------------- jobs
function deadlineCell(j) {
  const d = j.next_deadline;
  if (!d) return td("Next deadline", "muted", "—");
  const when = ago(secondsUntil(d.slot));
  const kids = [el("span", { text: d.label + " " }), el("span", { cls: "mono", text: d.slot.toLocaleString() }),
    el("br"), el("span", { cls: "small muted", text: when })];
  if (d.past) kids.push(" ", el("span", { cls: "chip late", text: "past: " + d.then }));
  const all = el("details", null, el("summary", { cls: "small", text: "all deadlines" }),
    el("div", { cls: "small mono", text: [["commit", j.commit_deadline], ["reveal", j.reveal_deadline],
      ["challenge", j.challenge_deadline], ["ruling", j.ruling_deadline]]
      .filter(([, v]) => v).map(([k, v]) => k + " " + v).join(" · ") }));   // 0: not set yet
  return td("Next deadline", null, ...kids, all);
}

function resultCell(j) {
  if (!j.revealed) return td("Result", "muted", "not revealed");
  const kids = [el("strong", { text: j.answer || "?" })];
  if (j.fingerprint && !isZero(j.fingerprint))
    kids.push(el("br"), el("code", { title: j.fingerprint, text: j.fingerprint.slice(0, 16) + "…" }));
  if (j.state === "Challenged" || j.state === "Slashed")
    kids.push(el("br"), el("span", { cls: "small" }, "verifier ", addr(j.verifier, "verifier")));
  return td("Result", null, ...kids);
}

function renderJobs() {
  const tbody = $("jobs").tBodies[0];
  if (!snap) return;
  const f = $("state-filter").value;
  const late = new Set(snap.late || []);
  const rows = snap.job_list.filter((j) => !f || (f === "live" ? LIVE.has(j.state)
    : f === "late" ? late.has(j.address) : j.state === f));
  if (!rows.length) return emptyRow(tbody, 7, snap.job_list.length ? "No jobs match this filter." : "No jobs yet.");
  tbody.replaceChildren(...rows.map((j) => el("tr", null,
    td("Job", null, addr(j.address, "job"), el("br"), el("span", { cls: "small muted", text: "#" + j.job_id })),
    td("State", null, el("span", { cls: "chip " + j.state, text: j.state })),
    td("Renter", null, addr(j.renter, "renter")),
    td("Provider", null, addr(j.provider, "provider")),
    td("Price", "num", usdc(j.price)),
    deadlineCell(j),
    resultCell(j),
  )));
}

// ------------------------------------------------------------------------- providers
function renderProviders(s) {
  const tbody = $("providers").tBodies[0];
  if (!s.providers.length) return emptyRow(tbody, 4, "No providers registered.");
  tbody.replaceChildren(...s.providers.map((p) => el("tr", null,
    td("Provider", null, addr(p.provider, "provider")),
    td("Stake", "num", usdc(p.stake)),
    td("Open jobs", "num", String(p.open_jobs)),
    td("Unstaking", p.unlock_slot ? null : "muted", p.unlock_slot
      ? "unlocks at " + p.unlock_slot.toLocaleString() + " (" + ago(secondsUntil(p.unlock_slot)) + ")" : "—"),
  )));
}

// ------------------------------------------------------------------------- events
function eventDetails(e) {
  const out = el("span");
  for (const [k, v] of Object.entries(e)) {
    if (["name", "sig", "slot", "index", "block_time"].includes(k)) continue;
    let val;
    if (typeof v === "string" && B58.test(v)) val = addr(v, k);
    else if (typeof v === "string" && HEX32.test(v)) val = el("code", { title: v, text: v.slice(0, 12) + "…" });
    else if (AMOUNTS.has(k) && typeof v === "number") val = usdc(v);
    else val = String(v);
    out.append(el("span", { cls: "small muted", text: k + " " }), val, " ");
  }
  return out;
}

function renderEvents(evs) {
  const tbody = $("events").tBodies[0];
  if (!evs.length) return emptyRow(tbody, 4, "No events in the recent transactions.");
  tbody.replaceChildren(...evs.map((e) => el("tr", null,
    td("Slot", "num", String(e.slot), e.block_time
      ? el("div", { cls: "small muted", text: new Date(e.block_time * 1000).toLocaleTimeString() }) : null),
    td("Event", null, el("strong", { text: e.name })),
    td("Details", null, eventDetails(e)),
    td("Transaction", null, txLink(e.sig)),
  )));
}

// ------------------------------------------------------------------------- fetching
function setStatus(text, error) {
  const s = $("status");
  s.textContent = text;
  s.classList.toggle("error", !!error);
}

async function getJSON(url) {
  const r = await fetch(url, { cache: "no-store" });
  const body = await r.json().catch(() => ({ error: "bad response (HTTP " + r.status + ")" }));
  if (!r.ok) throw new Error(body.error || "HTTP " + r.status);
  return body;
}

async function loadSnapshot() {
  try {
    const s = await getJSON("api/snapshot");
    snap = s;
    meta = s.meta || meta;
    $("slot-s").textContent = meta.slot_seconds;
    $("where").textContent = "Cluster " + meta.cluster + " · program " + short(meta.program) +
      (meta.admin ? " · admin " + short(meta.admin) : " · all markets");
    renderSummary(s); renderJobs(); renderProviders(s);
    setStatus("Updated " + new Date().toLocaleTimeString() + " at slot " + s.slot.toLocaleString() + ".");
  } catch (err) {
    setStatus("Snapshot failed: " + err.message + (snap ? " (showing the last one)" : ""), true);
  }
}

async function loadEvents() {
  try {
    const r = await getJSON("api/events?limit=" + EVENTS_LIMIT);
    renderEvents(r.events);
  } catch (err) {
    setStatus("Events failed: " + err.message, true);
  }
}

function schedule() {
  timers.forEach(clearInterval);
  timers = [];
  if (!$("auto").checked) return;
  timers.push(setInterval(() => { if (!document.hidden) loadSnapshot(); }, SNAPSHOT_EVERY));
  timers.push(setInterval(() => { if (!document.hidden) loadEvents(); }, EVENTS_EVERY));
}

document.addEventListener("DOMContentLoaded", () => {
  $("refresh").addEventListener("click", () => { loadSnapshot(); loadEvents(); });
  $("auto").addEventListener("change", schedule);
  $("state-filter").addEventListener("change", renderJobs);
  loadSnapshot(); loadEvents(); schedule();
});
