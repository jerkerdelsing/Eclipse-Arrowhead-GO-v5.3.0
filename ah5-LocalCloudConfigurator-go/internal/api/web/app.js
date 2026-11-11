"use strict";
const $ = (id) => document.getElementById(id);
let token = "";
try { token = sessionStorage.getItem("lccToken") || ""; } catch (e) {}
let catalog = null, states = {};

function el(tag, props, ...kids) {
  const e = document.createElement(tag);
  Object.assign(e, props || {});
  for (const k of kids) e.append(k);
  return e;
}

async function call(method, path, body) {
  const r = await fetch(path, { method, headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || r.statusText);
  return data;
}

function showError(e) { $("err").textContent = e ? String(e.message || e) : ""; }

async function connect() {
  showError();
  token = $("token").value || token;
  try {
    catalog = await call("GET", "/api/catalog");
    try { sessionStorage.setItem("lccToken", token); } catch (e) {}
    $("cloud").textContent = catalog.cloud + " — compose project " + catalog.composeProject;
    $("login").hidden = true; $("app").hidden = false;
    await refresh();
  } catch (e) { showError(e); }
}

async function refresh() {
  showError();
  try {
    const st = await call("GET", "/api/status");
    states = Object.fromEntries(st.systems.map((s) => [s.id, s]));
  } catch (e) { showError(e); }
  render();
}

function render() {
  const tb = $("systems"); tb.replaceChildren();
  for (const s of catalog.systems) {
    const st = states[s.id] || { state: "unknown" };
    const present = st.state === "running" || st.state === "alternate";
    const run = el("input", { type: "checkbox", checked: present, value: s.id, className: "sel" });
    const rm = el("input", { type: "checkbox", value: s.id, className: "rm", disabled: !(st.state === "running" || st.state === "partial") });
    run.onchange = () => { if (run.checked) rm.checked = false; };
    rm.onchange = () => { if (rm.checked) run.checked = false; };
    const label = st.state + (st.via ? " (" + st.via + ")" : "");
    tb.append(el("tr", {}, el("td", {}, run), el("td", {}, rm), el("td", {}, s.name),
      el("td", { className: "muted" }, s.kind), el("td", {}, el("span", { className: "state " + st.state, textContent: label }))));
  }
}

function request() {
  const pick = (cls) => [...document.querySelectorAll("input." + cls + ":checked")].map((i) => i.value);
  return { systems: pick("sel"), remove: pick("rm"), smoke: $("smoke").checked, reapply: $("reapply").checked };
}

function renderPlan(p) {
  const box = $("plan"); box.replaceChildren();
  if (!p.steps || p.steps.length === 0) box.append(el("div", { className: "muted", textContent: "Nothing to do." }));
  else {
    const t = el("table", {}, el("tr", {}, el("th", { textContent: "#" }), el("th", { textContent: "Step" }), el("th", { textContent: "Target" }), el("th", { textContent: "System" })));
    p.steps.forEach((s, i) => t.append(el("tr", {}, el("td", { textContent: i + 1 }), el("td", { textContent: s.kind }), el("td", { textContent: s.target }), el("td", { className: "muted", textContent: s.system || "" }))));
    box.append(t);
  }
  for (const n of p.notes || []) box.append(el("div", { className: "muted", textContent: "• " + n }));
}

async function preview() { showError(); try { renderPlan(await call("POST", "/api/plan", request())); } catch (e) { showError(e); } }

let timer = null;
async function apply() {
  showError();
  try {
    const res = await call("POST", "/api/deployments", request());
    renderPlan(res.plan);
    if (!res.id) { $("deployment").textContent = "Nothing to deploy."; return; }
    clearInterval(timer);
    const poll = async () => {
      try {
        const d = await call("GET", "/api/deployments/" + encodeURIComponent(res.id));
        renderDeployment(d);
        if (d.state === "success" || d.state === "failed") { clearInterval(timer); refresh(); }
      } catch (e) { showError(e); clearInterval(timer); }
    };
    timer = setInterval(poll, 2000); poll();
  } catch (e) { showError(e); }
}

function renderDeployment(d) {
  const box = $("deployment"); box.replaceChildren();
  box.append(el("div", {}, "Workflow ", el("code", { textContent: d.id }), " — ", el("span", { className: "state " + d.state, textContent: d.state })));
  const t = el("table");
  for (const s of d.steps || []) {
    const td = el("td", { textContent: s.kind + " " + s.target });
    if (s.errors && s.errors.length) td.append(el("pre", { className: "err", textContent: s.errors.join("\n") }));
    t.append(el("tr", {}, td, el("td", {}, el("span", { className: "state " + s.state, textContent: s.state }))));
  }
  box.append(t);
}

$("connect").onclick = connect;
$("token").onkeydown = (e) => { if (e.key === "Enter") connect(); };
$("refresh").onclick = refresh;
$("preview").onclick = preview;
$("apply").onclick = apply;
if (token) connect();
