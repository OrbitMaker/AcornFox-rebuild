// AcornFox web console. Framework-free ES2020. Everything is built with
// createElement + textContent so no user data ever reaches innerHTML (CSP:
// no inline scripts/styles, no eval, no external resources). Reproduces the
// prototype's recommended (R) variant, driven by the real /v1 API.

// ---------------------------------------------------------------------------
// Constants and small helpers
// ---------------------------------------------------------------------------

const POLL_MS = 3000;

// Deployment/desired -> visual status label used across tiles, pills and dots.
const STATUS = {
  running: { text: "运行中", dot: "", pill: "" },
  deploying: { text: "部署中", dot: "warn", pill: "warn" },
  failed: { text: "部署失败", dot: "bad", pill: "bad" },
  crashed: { text: "已崩溃", dot: "bad", pill: "bad" },
  stopped: { text: "已停止", dot: "idle", pill: "idle" },
};

const PENDING_STATUSES = new Set(["queued", "building", "starting", "checking", "routing"]);

// el creates an element with attributes and children. Text children are set as
// text nodes; never via innerHTML.
function el(tag, attrs, children) {
  const node = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "dataset") { for (const [dk, dv] of Object.entries(v)) node.dataset[dk] = dv; }
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
  }
  if (children) for (const c of [].concat(children)) { if (c != null) node.append(c); }
  return node;
}

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

// firstChar returns the first (grapheme-ish) character of a name for the tile.
function firstChar(name) {
  const chars = Array.from(name || "?");
  return chars.length ? chars[0].toUpperCase() : "?";
}


// timeAgo renders a coarse "N 分钟前" string from an ISO timestamp.
function timeAgo(iso) {
  if (!iso) return "";
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return "";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return "刚刚";
  const m = Math.floor(s / 60);
  if (m < 60) return m + " 分钟前";
  const h = Math.floor(m / 60);
  if (h < 24) return h + " 小时前";
  const d = Math.floor(h / 24);
  return d + " 天前";
}

// ---------------------------------------------------------------------------
// API client (fetch wrapper with CSRF + error classification)
// ---------------------------------------------------------------------------

const api = {
  csrf: null,

  async session() {
    const r = await fetch("/v1/console/session", { headers: { Accept: "application/json" } });
    if (!r.ok) throw await apiError(r);
    const body = await r.json();
    this.csrf = body.csrf || null;
    return body;
  },

  async get(path, signal) {
    const r = await fetch(path, { headers: { Accept: "application/json" }, signal });
    if (!r.ok) throw await apiError(r);
    return r.json();
  },

  async post(path, body) {
    const headers = { "Content-Type": "application/json" };
    if (this.csrf) headers["X-AcornFox-CSRF"] = this.csrf;
    const r = await fetch(path, { method: "POST", headers, body: body ? JSON.stringify(body) : null });
    if (!r.ok) throw await apiError(r);
    return r.status === 204 ? {} : r.json().catch(() => ({}));
  },
};

// apiError turns a non-OK Response into a classified error object with a code.
async function apiError(r) {
  let code = "server_error", message = "服务器错误";
  try {
    const body = await r.json();
    if (body && body.error) { code = body.error.code || code; message = body.error.message || message; }
    else if (body && body.code) { code = body.code; message = body.message || message; }
  } catch (_) { /* non-JSON body */ }
  const e = new Error(message);
  e.status = r.status;
  e.code = code;
  return e;
}

// ---------------------------------------------------------------------------
// App model derivation
// ---------------------------------------------------------------------------

// deriveStatus maps an app view (list form) to a visual status key.
// Rules (per contract):
//   live + observed running        -> running (green)
//   newest deployment pending       -> deploying (yellow pulsing)
//   newest deployment failed, or
//     desired running but not running -> failed/crashed (red)
//   desired stopped                 -> stopped (grey)
function deriveStatus(app) {
  if (app.desired === "stopped") return "stopped";
  // The newest deployment decides "deploying" and "failed"; a failed redeploy
  // leaves the previous version serving, which still counts as needing attention.
  const latest = app.latest || app.live;
  if (latest && PENDING_STATUSES.has(latest.status)) return "deploying";
  if (latest && latest.status === "failed") return "failed";
  if (app.observed_state === "running") return "running";
  // Desired running but the container is not running.
  if (app.observed_state === "stopped" || app.observed_state === "missing") return "crashed";
  return "running";
}

// appDiagnosis returns the failure diagnosis to surface for an app, if any.
function appDiagnosis(app) {
  const latest = app.latest || app.live;
  if (latest && latest.status === "failed" && latest.diagnosis) return latest.diagnosis;
  return null;
}

// failedDeploymentID is the deployment the diagnosis belongs to.
function failedDeploymentID(app) {
  const latest = app.latest || app.live;
  return latest ? latest.id : "";
}

// domainDiagnosis returns the first failed-domain diagnosis, if any.
function domainDiagnosis(app) {
  for (const d of app.domains || []) {
    if (d.status === "failed" && d.diagnosis) return { domain: d.name, diagnosis: d.diagnosis };
  }
  return null;
}

// copyForAI builds the exact clipboard text specified by the contract.
function copyForAI(diag, app, deploymentID) {
  const payload = {
    stage: diag.stage,
    code: diag.code,
    message: diag.message,
    log_excerpt: diag.log_excerpt || "",
    hint: diag.hint || "",
    app: app,
    deployment_id: deploymentID || "",
  };
  return "请根据以下 AcornFox 部署诊断修复项目，然后重新执行 acornfox deploy：\n" +
    JSON.stringify(payload, null, 2);
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

const state = {
  apps: [],          // list of appView
  host: null,        // host stats or {available:false}
  openApp: null,     // name of the app whose window is open
  openTool: null,    // "server" | "deploy" | "ai" | "settings" | null
  detail: null,      // detailed appView for openApp
  detailTab: "overview",
  logs: null,        // last fetched log lines for openApp
  logCursor: "", logFollow: false, logTail: 100, logError: null,
  logGeneration: 0, appMetrics: null,
  deployments: null, // deployments history for openApp
  fatal: null,       // {code,message} full-screen state
  connectionLost: false,
  loaded: false,
};

let pollTimer = null;
let logRequest = null;
let pollInFlight = false;

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);
const FOCUSABLE = "button, a, summary, select, input, [tabindex]";

function focusKey(node) {
  return node.tagName + ":" + (node.getAttribute("aria-label") || node.getAttribute("href") || node.id || node.textContent);
}

// selectionInside reports whether the user has a non-empty text selection
// inside node. Polling must not rebuild that node, or the selection is lost.
function selectionInside(node) {
  const sel = window.getSelection();
  if (!node || !sel || sel.isCollapsed || !sel.rangeCount) return false;
  return node.contains(sel.anchorNode) || node.contains(sel.focusNode);
}

// swapChildren replaces target's children with next's only when the markup
// differs. Unchanged regions keep their nodes, so selections, hover states and
// running animations survive the 3-second poll.
function sameChildren(a, b) {
  if (a.childNodes.length !== b.childNodes.length) return false;
  for (let i = 0; i < a.childNodes.length; i++) {
    if (!a.childNodes[i].isEqualNode(b.childNodes[i])) return false;
  }
  return true;
}

function swapChildren(target, next) {
  if (sameChildren(target, next)) return false;
  clear(target);
  while (next.firstChild) target.append(next.firstChild);
  return true;
}

function render() {
  const active = document.activeElement;
  const activeKey = active && active.matches(FOCUSABLE) ? focusKey(active) : null;
  const previousWindow = $("window");
  const activeInWindow = previousWindow?.contains(active);
  const previousScope = activeInWindow ? previousWindow : document;
  const activeIndex = activeKey ? Array.from(previousScope.querySelectorAll(FOCUSABLE)).filter((node) => focusKey(node) === activeKey).indexOf(active) : 0;
  const previousView = previousWindow?.dataset.viewKey || "";
  renderFatal();
  if (state.fatal) return;
  renderConnectionBanner();
  renderHealth();
  renderDesk();
  renderDock();
  renderWindow();
  const currentWindow = $("window");
  // Polling replaces controls. Preserve keyboard focus within the same view,
  // while a newly opened window still receives its initial focus.
  if (activeKey && !active.isConnected && previousView === (currentWindow?.dataset.viewKey || "")) {
    const scope = activeInWindow ? currentWindow : document;
    const replacement = Array.from(scope.querySelectorAll(FOCUSABLE)).filter((node) => focusKey(node) === activeKey)[activeIndex];
    if (replacement) replacement.focus({ preventScroll: true });
  }
}

function renderFatal() {
  const existing = $("fatal-state");
  if (!state.fatal) { if (existing) existing.remove(); return; }
  const { title, body, again } = state.fatal;
  const card = el("div", { class: "card" }, [
    el("h2", { text: title }),
    el("p", { text: body }),
    again ? el("p", { class: "faint", text: "请在终端重新执行 acornfox open。" }) : null,
  ]);
  if (existing) { clear(existing); existing.append(card); return; }
  const node = el("div", { id: "fatal-state", class: "state" }, card);
  document.body.append(node);
}

function renderConnectionBanner() {
  const existing = $("conn-banner");
  if (!state.connectionLost || state.fatal) { if (existing) existing.remove(); return; }
  if (existing) return;
  const node = el("div", { id: "conn-banner", class: "banner" },
    el("div", { class: "inner", text: "与服务器的连接中断，正在重试…" }));
  document.body.append(node);
}

function renderHealth() {
  const target = $("health");
  const health = document.createElement("div");
  buildHealth(health);
  swapChildren(target, health);
}

function buildHealth(health) {
  if (!state.loaded) return;
  const running = state.apps.filter((a) => deriveStatus(a) === "running").length;
  const attention = attentionItems().length;
  if (attention) {
    health.append(el("span", { class: "dot bad" }));
    health.append(document.createTextNode(`${running} 个运行中 · ${attention} 项需要处理`));
  } else {
    health.append(el("span", { class: "dot" }));
    health.append(document.createTextNode(`服务器正常 · ${running} 个应用运行中`));
  }
}

// attentionItems computes up to 3 attention rows (contract order):
// newest deployment failed, container not running, domain cert failed.
function attentionItems() {
  const items = [];
  for (const a of state.apps) {
    const st = deriveStatus(a);
    const diag = appDiagnosis(a);
    if (st === "failed" && diag) {
      items.push({ app: a.name, title: a.live ? "新版本部署失败（旧版本仍在服务）" : "部署失败", why: diag.message, kind: "deploy", diag, deploymentID: failedDeploymentID(a) });
    } else if (st === "crashed") {
      const d = diag || { stage: "start", code: "not_running", message: "容器未在运行，但期望状态为运行中。", hint: "查看日志排查启动失败原因，或重新部署。" };
      items.push({ app: a.name, title: "未在运行", why: d.message, kind: "crash", diag: d, deploymentID: a.live ? a.live.id : "" });
    }
  }
  for (const a of state.apps) {
    const dd = domainDiagnosis(a);
    if (dd) items.push({ app: a.name, title: "域名证书未就绪", why: dd.diagnosis.message, kind: "domain", diag: dd.diagnosis, deploymentID: "" });
  }
  return items.slice(0, 3);
}

function renderDesk() {
  const target = $("desk");
  if (selectionInside(target)) return;
  const desk = document.createElement("div");
  buildDesk(desk);
  // The ambient line (CPU / memory percentages) changes on almost every poll;
  // update it in place instead of rebuilding the whole desk.
  const curAmb = target.querySelector(".ambient");
  const nextAmb = desk.querySelector(".ambient");
  if (curAmb && nextAmb) {
    const a = target.cloneNode(true), b = desk.cloneNode(true);
    a.querySelector(".ambient").remove();
    b.querySelector(".ambient").remove();
    if (sameChildren(a, b)) {
      if (!curAmb.isEqualNode(nextAmb)) curAmb.replaceWith(nextAmb);
      return;
    }
  }
  swapChildren(target, desk);
}

function buildDesk(desk) {
  if (!state.loaded) {
    desk.append(el("div", { class: "state" }, el("div", { class: "card" }, [
      el("div", { class: "spinner" }), el("p", { text: "正在连接服务器…" }),
    ])));
    return;
  }
  if (state.apps.length === 0) { desk.append(emptyState()); return; }

  const wrap = el("div", { class: "deskwrap" });
  const inner = el("div");
  const strip = attentionStrip();
  if (strip) inner.append(strip);
  inner.append(appsGrid());
  inner.append(ambientLine());
  wrap.append(inner);
  desk.append(wrap);
}

function emptyState() {
  return el("div", { class: "empty" }, el("div", { class: "card" }, [
    el("div", { class: "tile", "aria-hidden": "true", text: "🚀" }),
    el("h2", { text: "还没有应用" }),
    el("p", { class: "muted", text: "在你的 AI 工作台里说「帮我部署」，或在项目目录运行 acornfox deploy ." }),
    el("div", { class: "row" }, [
      button("连接 AI 工作台", "btn primary", () => openTool("ai")),
      button("手动部署", "btn", () => openTool("deploy")),
    ]),
  ]));
}

function attentionStrip() {
  const items = attentionItems();
  if (!items.length) return null;
  const box = el("div", { class: "attention", role: "region", "aria-label": "需要处理" });
  for (const it of items) {
    const forAI = copyForAI(it.diag, it.app, it.deploymentID);
    box.append(el("div", { class: "item" }, [
      el("span", { class: "dot bad" }),
      el("div", { class: "what" }, [
        el("div", {}, [el("b", { text: it.app }), document.createTextNode(" · " + it.title)]),
        el("div", { class: "why", text: it.why }),
      ]),
      button("查看", "btn", () => openApp(it.app), "查看 " + it.app),
      button("复制给 AI", "btn primary", () => copyToClipboard(forAI, "已复制，粘贴给你的 AI 即可"), "复制 " + it.app + " 的诊断给 AI"),
    ]));
  }
  return box;
}

function appsGrid() {
  const grid = el("div", { class: "apps" });
  for (const a of state.apps) grid.append(appTile(a));
  grid.append(addTile());
  return grid;
}

function appTile(a) {
  const st = deriveStatus(a);
  const meta = STATUS[st];
  const tile = el("div", { class: "tile", "aria-hidden": "true", text: firstChar(a.name) });
  const badgeClass = "badge dot " + meta.dot + (st === "deploying" ? " live" : "");
  tile.append(el("span", { class: badgeClass.trim() }));
  return button(null, "app", () => openApp(a.name), "打开 " + a.name, [
    tile,
    el("div", { class: "name", text: a.name }),
    el("div", { class: "sub", text: meta.text }),
  ]);
}

function addTile() {
  return button(null, "app add", () => openTool("deploy"), "部署新应用", [
    el("div", { class: "tile", "aria-hidden": "true", text: "＋" }),
    el("div", { class: "name muted", text: "部署新应用" }),
  ]);
}

function ambientLine() {
  const running = state.apps.filter((a) => deriveStatus(a) === "running").length;
  const deploying = state.apps.filter((a) => deriveStatus(a) === "deploying").length;
  const line = el("div", { class: "ambient" });
  line.append(el("span", { text: `${running} 个运行中` }));
  if (deploying) line.append(el("span", { text: `${deploying} 个正在部署` }));
  const h = state.host;
  if (h && h.available !== false) {
    if (typeof h.cpu_percent === "number") line.append(el("span", { text: `CPU ${Math.round(h.cpu_percent)}%` }));
    if (h.memory_total) line.append(el("span", { text: `内存 ${pct(h.memory_used, h.memory_total)}%` }));
    if (h.disk_total) line.append(el("span", { text: `磁盘 ${pct(h.disk_used, h.disk_total)}%` }));
  }
  return line;
}

function pct(used, total) { return total ? Math.round((used / total) * 100) : 0; }

// button builds an accessible <button>.
function button(text, cls, onClick, ariaLabel, children) {
  const attrs = { class: cls, type: "button", onclick: onClick };
  if (ariaLabel) attrs["aria-label"] = ariaLabel;
  const b = el("button", attrs, children || null);
  if (text != null) b.append(document.createTextNode(text));
  return b;
}

// ---------------------------------------------------------------------------
// Dock
// ---------------------------------------------------------------------------

function renderDock() {
  const target = $("dock");
  const dock = document.createElement("div");
  buildDock(dock);
  swapChildren(target, dock);
}

function buildDock(dock) {
  if (!state.loaded || state.fatal) return;
  const items = [
    ["deploy", "＋ 部署"],
    ["server", "▤ 服务器"],
    ["sep"],
    ["ai", "✦ 让 AI 部署"],
    ["settings", "⚙ 设置"],
  ];
  for (const [k, label] of items) {
    if (k === "sep") { dock.append(el("span", { class: "sep" })); continue; }
    dock.append(button(label, state.openTool === k ? "on" : "", () => openTool(k), label));
  }
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

function renderWindow() {
  const existing = $("window");
  const viewKey = state.openApp ? "app:" + state.openApp : "tool:" + state.openTool;
  const sameView = existing?.dataset.viewKey === viewKey;
  const sameTab = sameView && existing.dataset.detailTab === state.detailTab;
  const scrollTop = sameTab ? existing.querySelector(".win-body")?.scrollTop || 0 : 0;
  const oldLog = sameTab ? existing.querySelector(".logbox") : null;
  const logScrollTop = oldLog?.scrollTop || 0;
  const logAtBottom = !oldLog || oldLog.scrollHeight - oldLog.scrollTop - oldLog.clientHeight < 24;
  const expandedDetails = sameTab ? Array.from(existing.querySelectorAll("details"), (node) => node.open) : [];
  if (sameTab && !state.fatal && selectionInside(existing)) return;

  let win = null;
  if (!state.fatal) {
    if (state.openApp) win = appWindow();
    else if (state.openTool) win = toolWindow();
  }
  if (win && sameTab) {
    win.querySelectorAll("details").forEach((node, index) => { node.open = expandedDetails[index] ?? node.open; });
    const probe = win.cloneNode(true);
    probe.id = "window"; probe.dataset.viewKey = viewKey; probe.dataset.detailTab = state.detailTab;
    probe.setAttribute("tabindex", "-1");
    if (probe.isEqualNode(existing)) return;
  }
  if (existing) existing.remove();
  const overlay = $("win-overlay");
  if (overlay) overlay.remove();
  if (!win) return;

  const ov = el("div", { id: "win-overlay", class: "overlay", onclick: closeWindow });
  document.body.append(ov);
  win.id = "window";
  win.dataset.viewKey = viewKey;
  win.dataset.detailTab = state.detailTab;
  win.setAttribute("tabindex", "-1");
  document.body.append(win);
  if (sameTab) {
    win.querySelector(".win-body").scrollTop = scrollTop;
    const logbox = win.querySelector(".logbox");
    if (logbox) logbox.scrollTop = state.logFollow && logAtBottom ? logbox.scrollHeight : logScrollTop;
  }
  // Only the initial open moves focus into the window. In particular, a poll
  // must not steal focus from the separate confirmation dialog.
  // Focus the window itself rather than its first control, so the close
  // button does not light up with a focus ring on every open; Tab moves in.
  if (!sameView) win.focus({ preventScroll: true });
}

function windowHead(title, tileText, tileColor, pill) {
  const head = el("div", { class: "win-head" });
  if (tileText != null) {
    const t = el("div", { class: "tile", "aria-hidden": "true", text: tileText });
    if (tileColor) t.style.background = tileColor;
    head.append(t);
  }
  head.append(el("h3", { text: title }));
  if (pill) head.append(pillNode(pill.text, pill.cls));
  head.append(el("div", { class: "grow" }));
  head.append(button("✕", "iconbtn", closeWindow, "关闭（Esc）"));
  return head;
}

function pillNode(text, cls) {
  const p = el("span", { class: "pill " + (cls || "") });
  if (cls === "" || cls == null) p.append(el("span", { class: "dot" }));
  p.append(document.createTextNode(text));
  return p;
}

function appWindow() {
  const listApp = state.apps.find((a) => a.name === state.openApp);
  const a = state.detail || listApp;
  if (!a) return null;
  const st = deriveStatus(a);
  const meta = STATUS[st];

  const win = el("section", { class: "win app-win", role: "dialog", "aria-modal": "true", "aria-label": a.name + " 应用窗口" });
  const t = el("div", { class: "tile", "aria-hidden": "true", text: firstChar(a.name) });
  const head = el("div", { class: "win-head" }, [
    t, el("h3", { text: a.name }), pillNode(meta.text, meta.pill),
    el("div", { class: "grow" }), button("✕", "iconbtn", closeWindow, "关闭（Esc）"),
  ]);
  win.append(head);

  const tabs = [["overview", "概览"], ["addons", "附加服务"], ["deploys", "部署记录"], ["logs", "日志"], ["domains", "域名"], ["settings", "设置"]];
  const tabsRow = el("div", { class: "tabs", role: "tablist" });
  for (const [k, label] of tabs) {
    tabsRow.append(button(label, state.detailTab === k ? "on" : "", () => setTab(k), label));
  }
  win.append(tabsRow);

  const body = el("div", { class: "win-body" });
  if (!state.detail) body.append(el("p", { class: "muted", text: "正在加载…" }));
  else if (state.detailTab === "overview") body.append(overviewTab(a, st, meta));
  else if (state.detailTab === "addons") body.append(addonsTab(a));
  else if (state.detailTab === "deploys") body.append(deploysTab(a));
  else if (state.detailTab === "logs") body.append(logsTab(a));
  else if (state.detailTab === "domains") body.append(domainsTab(a));
  else body.append(settingsTab(a));
  win.append(body);
  return win;
}

function overviewTab(a, st, meta) {
  const frag = document.createDocumentFragment();
  const diag = appDiagnosis(a);
  if (diag) frag.append(diagCard(diag, a.name, failedDeploymentID(a)));

  const dl = el("dl", { class: "kv" });
  const running = !!(a.observed && a.observed.running);
  dl.append(el("dt", { text: "网址" }));
  if (a.url && running) {
    dl.append(el("dd", {}, el("span", { class: "url" }, [
      el("a", { href: a.url, target: "_blank", rel: "noopener", text: a.url }),
      button("复制", "btn", () => copyToClipboard(a.url, "网址已复制"), "复制网址"),
    ])));
  } else if (a.url) {
    dl.append(el("dd", {}, el("span", { class: "muted", text: a.url + "（未运行，暂无法访问）" })));
  } else {
    dl.append(el("dd", {}, el("span", { class: "muted", text: "部署成功后显示" })));
  }

  dl.append(el("dt", { text: "当前版本" }));
  const live = a.live;
  const verText = live ? `第 ${live.seq} 版 · ${sourceLabel(live.source_kind)} · ${timeAgo(live.created_at)}` : "尚无版本";
  dl.append(el("dd", { text: verText }));

  dl.append(el("dt", { text: "资源" }));
  dl.append(el("dd", { text: `内存上限 ${a.memory_mb} MB · CPU ${(a.cpu_milli / 1000).toFixed(1)} 核` }));
  frag.append(dl);
  if (running) frag.append(appMetricsPanel(a));

  // Only offer actions that apply to the current state.
  const row = el("div", { class: "row" });
  if (a.desired === "stopped") {
    row.append(button("启动", "btn primary", () => actOnApp("start"), "启动应用"));
  } else if (running) {
    row.append(button("重启", "btn", () => actOnApp("restart"), "重启应用"));
    row.append(button("停止", "btn danger", confirmStop, "停止应用"));
  }
  if (live) row.append(button("重新部署", "btn", () => actOnApp("redeploy"), "用当前版本重新部署"));
  if (live && live.seq > 1) row.append(button("回退到上一版", "btn", () => actOnApp("rollback"), "回退到上一版"));
  if (row.childNodes.length) frag.append(row);

  frag.append(el("p", { class: "faint", text: "未备案域名无法使用 80/443 端口，当前通过 IP:端口 访问。绑定已备案域名后可自动开启 HTTPS。" }));
  return frag;
}

function sourceLabel(kind) {
  return kind === "image" ? "镜像" : kind === "git" ? "Git" : "上传";
}

function diagCard(diag, appName, deploymentID) {
  const card = el("div", { class: "diag", role: "alert" });
  card.append(el("h4", { text: "✕ " + (diag.message || "部署失败") }));
  if (diag.hint) card.append(el("p", { class: "muted", text: "建议：" + diag.hint }));
  const forAI = copyForAI(diag, appName, deploymentID);
  const row = el("div", { class: "row" }, [
    button("复制给 AI", "btn primary", () => copyToClipboard(forAI, "已复制，粘贴给你的 AI 即可"), "复制诊断给 AI"),
  ]);
  card.append(row);
  if (diag.log_excerpt) {
    const details = el("details", { open: "" });
    details.append(el("summary", { text: "日志片段" }));
    details.append(el("pre", { class: "mono", text: diag.log_excerpt }));
    card.append(details);
  }
  return card;
}

function deploysTab(a) {
  const list = state.deployments;
  if (!list) return el("p", { class: "muted", text: "正在加载…" });
  if (!list.length) return el("p", { class: "muted", text: "还没有部署记录。" });
  const ul = el("ul", { class: "timeline" });
  for (const d of list) {
    const dotCls = d.status === "live" ? "" : d.status === "failed" ? "bad" : PENDING_STATUSES.has(d.status) ? "warn" : "idle";
    const msg = d.diagnosis ? d.diagnosis.message : deployStatusText(d.status);
    ul.append(el("li", {}, [
      el("span", { class: "dot " + dotCls }),
      el("b", { text: "第 " + d.seq + " 版" }),
      el("span", { class: "grow", text: msg }),
      el("span", { class: "faint", text: timeAgo(d.created_at) }),
    ]));
  }
  return ul;
}

function deployStatusText(status) {
  return ({
    live: "正在服务", retired: "已被新版本替换", failed: "部署失败",
    superseded: "已被更新的提交取代", queued: "排队中", building: "构建中",
    starting: "启动中", checking: "健康检查中", routing: "切换路由中",
  })[status] || status;
}

function logsTab(a) {
  const frag = document.createDocumentFragment();
  const tail = el("select", { id: "logs-tail", "aria-label": "日志行数", onchange: (event) => {
    state.logTail = Number(event.target.value);
    refreshLogs(a.name, true);
  }});
  for (const value of [100, 500, 1000]) tail.append(el("option", { value, text: "最近 " + value + " 行" }));
  tail.value = String(state.logTail);
  const row = el("div", { class: "row log-controls" }, [
    button("刷新日志", "btn", () => refreshLogs(a.name, true), "刷新日志"),
    button(state.logFollow ? "暂停跟随" : "跟随新日志", "btn", () => toggleLogFollow(a.name), "日志跟随开关"),
    tail,
    el("span", { class: "faint", text: state.logFollow ? "每 3 秒跟随 · 最多保留 2000 行" : "已暂停跟随" }),
  ]);
  frag.append(row);
  if (state.logError) frag.append(el("p", { class: "muted", role: "status", text: state.logError }));
  const pre = el("pre", { class: "mono logbox", tabindex: "0", "aria-label": "应用日志" });
  if (state.logs === null) pre.textContent = "正在加载日志…";
  else if (state.logs.length === 0) pre.textContent = "暂无日志。";
  else pre.textContent = state.logs.join("\n");
  frag.append(pre);
  return frag;
}

function metricTile(label, value, detail) {
  return el("div", { class: "metric-tile" }, [
    el("span", { class: "muted", text: label }),
    el("strong", { text: value }),
    detail ? el("span", { class: "faint", text: detail }) : null,
  ]);
}

function appMetricsPanel(a) {
  const metrics = state.appMetrics;
  if (!metrics) return el("p", { class: "muted", text: "资源指标：正在采样…" });
  if (metrics.available === false) return el("p", { class: "muted", text: "资源指标暂不可用（" + observedMetricText(metrics.observed_state) + "）。" });
  const cpu = metrics.cpu_available === false ? "采样中" : numberText(metrics.cpu_percent, "%");
  const memory = numberText(metrics.memory_usage_mb, " MB");
  const limit = metrics.memory_limit_mb > 0 ? "上限 " + numberText(metrics.memory_limit_mb, " MB") : "未设置内存上限";
  return el("section", { class: "metric-tiles", "aria-label": a.name + " 当前资源指标" }, [
    metricTile("CPU 使用率", cpu, "1 核 = 100%"),
    metricTile("内存使用", memory, limit),
    metricTile("网络接收 / 发送", sizeText(metrics.network_rx_mb) + " / " + sizeText(metrics.network_tx_mb), "容器累计流量"),
    metricTile("进程数", Number.isFinite(metrics.pids) ? String(metrics.pids) : "不可用"),
  ]);
}

function observedMetricText(state) {
  return ({ stopped: "已停止", exited: "已停止", missing: "尚无容器", restarting: "正在重启", unavailable: "执行器不可用" })[state] || state || "不可用";
}

// sizeText formats a megabyte value with a unit that keeps small traffic visible.
function sizeText(mb) {
  if (!Number.isFinite(mb)) return "不可用";
  // A no-break space keeps "35 KB" together; lines may only wrap at " / ".
  if (mb >= 1024) return (mb / 1024).toFixed(1) + "\u00a0GB";
  if (mb >= 1) return mb.toFixed(1) + "\u00a0MB";
  return Math.round(mb * 1024) + "\u00a0KB";
}

function numberText(value, unit) {
  return Number.isFinite(value) ? value.toFixed(1) + (unit || "") : "不可用";
}

// Read-only view: render only the explicit public fields. Connection URLs,
// passwords and raw credentials never enter the DOM, even if an API regresses.
function addonsTab(a) {
  const frag = document.createDocumentFragment();
  const addons = Array.isArray(a.addons) ? a.addons : [];
  if (addons.length === 0) {
    frag.append(el("p", { class: "muted", text: "此应用还没有附加服务。" }));
    frag.append(el("p", { class: "mono", text: "acornfox add postgres --app " + a.name }));
    return frag;
  }
  const states = {
    running: ["运行中", ""], starting: ["初始化中", "warn"], unhealthy: ["未就绪", "bad"],
    stopped: ["已停止", "idle"], missing: ["等待创建", "warn"], unavailable: ["无法读取状态", "idle"],
  };
  const labels = { postgres: "PostgreSQL", mysql: "MySQL", redis: "Redis" };
  for (const addon of addons) {
    const [status, style] = states[addon.observed_state] || ["状态未知", "idle"];
    const card = el("article", { class: "addon-card", "aria-label": (labels[addon.kind] || addon.kind || "附加服务") + " 状态" });
    card.append(el("div", { class: "row" }, [
      el("h4", { text: labels[addon.kind] || addon.kind || "附加服务" }),
      pillNode(status, style),
    ]));
    const dl = el("dl", { class: "kv" });
    for (const [label, value] of [
      ["镜像", addon.image || "未知"],
      ["网络内地址", addon.host ? addon.host + ":" + addon.port : "暂不可用"],
      ["连接变量", addon.env_var || "未设置"],
      ["数据卷", addon.volume_name || "未知"],
    ]) {
      dl.append(el("dt", { text: label }));
      dl.append(el("dd", { class: "mono", text: value }));
    }
    card.append(dl);
    frag.append(card);
  }
  frag.append(el("p", { class: "faint", text: "端口仅在应用专用网络内可见。连接信息以密钥注入应用，控制台不显示密码。删除附加服务默认保留数据卷。" }));
  return frag;
}

function domainsTab(a) {
  const domains = a.domains || [];
  if (!domains.length) {
    return el("div", {}, [
      el("p", { class: "muted", text: "尚未绑定域名。" }),
      el("p", { class: "faint", text: "使用 acornfox domain add <域名> 绑定。中国大陆服务器的域名须已完成 ICP 备案，否则无法通过 80/443 访问。" }),
    ]);
  }
  const ul = el("ul", { class: "timeline" });
  for (const d of domains) {
    const cls = d.status === "ready" ? "" : d.status === "failed" ? "bad" : "warn";
    const txt = ({ ready: "已就绪", failed: "证书失败", pending: "等待证书" })[d.status] || d.status;
    const li = el("li", {}, [
      el("span", { class: "dot " + cls }),
      el("b", { text: d.name }),
      el("span", { class: "grow" }, pillNode(txt, cls)),
    ]);
    ul.append(li);
    if (d.status === "failed" && d.diagnosis) ul.append(el("li", {}, diagCard(d.diagnosis, a.name, "")));
  }
  return ul;
}

function settingsTab(a) {
  const frag = document.createDocumentFragment();
  const dl = el("dl", { class: "kv" });

  dl.append(el("dt", { text: "环境变量" }));
  const envDd = el("dd");
  const env = a.env || [];
  if (!env.length) envDd.append(el("span", { class: "muted", text: "无" }));
  else {
    const ul = el("ul", { class: "envlist" });
    for (const e of env) {
      ul.append(el("li", {}, [
        el("span", { class: "k", text: e.key }),
        el("span", { class: "grow" }),
        el("span", { class: e.secret ? "pill idle" : "muted", text: e.secret ? "已设置" : (e.value || "") }),
      ]));
    }
    envDd.append(ul);
  }
  dl.append(envDd);

  dl.append(el("dt", { text: "数据卷" }));
  const volDd = el("dd");
  const vols = a.volumes || [];
  if (!vols.length) volDd.append(el("span", { class: "muted", text: "无" }));
  else {
    const ul = el("ul", { class: "envlist" });
    for (const v of vols) {
      ul.append(el("li", {}, [
        el("span", { class: "k", text: v.path }),
        el("span", { class: "grow" }),
        el("span", { class: "faint", text: v.auto ? "自动" : "手动" }),
      ]));
    }
    volDd.append(ul);
  }
  dl.append(volDd);

  dl.append(el("dt", { text: "端口" }));
  dl.append(el("dd", { text: String(a.port || 0) }));
  frag.append(dl);
  frag.append(el("p", { class: "faint", text: "此处只读。修改请在 AI 工作台里说明，或用 acornfox env set / volume add / app set；改完点「重新部署」生效。密钥值不会显示或返回。" }));
  return frag;
}

// Tool windows: server (host stats), deploy, ai, settings.
function toolWindow() {
  const win = el("section", { class: "win", role: "dialog", "aria-modal": "true" });
  let title = "", body = null;
  if (state.openTool === "server") { title = "服务器"; body = serverTool(); }
  else if (state.openTool === "deploy") { title = "部署新应用"; body = deployTool(); }
  else if (state.openTool === "ai") { title = "让 AI 部署"; body = aiTool(); }
  else { title = "设置"; body = settingsTool(); }
  win.setAttribute("aria-label", title);
  win.append(el("div", { class: "win-head" }, [
    el("h3", { text: title }), el("div", { class: "grow" }),
    button("✕", "iconbtn", closeWindow, "关闭（Esc）"),
  ]));
  win.append(el("div", { class: "win-body" }, body));
  return win;
}

function serverTool() {
  const frag = document.createDocumentFragment();
  const h = state.host;
  if (!h || h.available === false) {
    frag.append(el("p", { class: "muted", text: "主机资源暂不可用。" }));
    return frag;
  }
  const memoryPct = h.memory_total > 0 ? pct(h.memory_used, h.memory_total) : null;
  const diskPct = h.disk_total > 0 ? pct(h.disk_used, h.disk_total) : null;
  frag.append(el("section", { class: "metric-tiles", "aria-label": "主机当前资源指标" }, [
    metricTile("CPU 使用率", typeof h.cpu_percent === "number" ? numberText(h.cpu_percent, "%") : "采样中", "最近几秒的平均值"),
    metricTile("内存使用率", memoryPct !== null ? numberText(memoryPct, "%") : "不可用", bytePair(h.memory_used, h.memory_total)),
    metricTile("磁盘使用率", diskPct !== null ? numberText(diskPct, "%") : "不可用", bytePair(h.disk_used, h.disk_total)),
  ]));
  const dl = el("dl", { class: "kv" });
  if (typeof h.load1 === "number") { dl.append(el("dt", { text: "负载" })); dl.append(el("dd", { text: h.load1.toFixed(2) })); }
  if (h.uptime_seconds) { dl.append(el("dt", { text: "运行时长" })); dl.append(el("dd", { text: uptimeText(h.uptime_seconds) })); }
  frag.append(dl);
  return frag;
}

function bytePair(used, total) {
  if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return "";
  return (used / (1024 ** 3)).toFixed(1) + " / " + (total / (1024 ** 3)).toFixed(1) + " GiB";
}

function uptimeText(s) {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  if (d) return `${d} 天 ${h} 小时`;
  const m = Math.floor((s % 3600) / 60);
  return h ? `${h} 小时 ${m} 分钟` : `${m} 分钟`;
}

const SKILL_PROMPT = "请安装 AcornFox Skill：下载 https://acornfox.com/skill/SKILL.md ，保存为你 skills 目录下的 acornfox/SKILL.md（Claude Code 是 ~/.claude/skills，Codex 是 ~/.codex/skills），然后按这个 Skill 把当前项目部署到我的服务器。";

function copyBlock(text, okMsg, label, mono) {
  return el("div", { class: "copyblock" }, [
    el("p", { class: mono ? "mono" : "", text }),
    button("复制", "btn", () => copyToClipboard(text, okMsg), label),
  ]);
}

function deployTool() {
  const frag = document.createDocumentFragment();
  frag.append(el("p", { class: "muted", text: "推荐：在 AI 工作台里说「帮我把这个项目部署到我的服务器」。没有安装 Skill 的话，先把下面这句话发给 AI：" }));
  frag.append(copyBlock(SKILL_PROMPT, "已复制，发给你的 AI 即可", "复制 Skill 安装提示"));
  frag.append(el("p", { class: "muted", text: "也可以在项目目录（含 Dockerfile）手动运行：" }));
  frag.append(copyBlock("acornfox deploy", "命令已复制", "复制部署命令", true));
  return frag;
}

function aiTool() {
  const frag = document.createDocumentFragment();
  frag.append(el("p", { text: "1. 把下面这句话发给你的 AI 工作台（Claude Code、Codex 等），它会安装 AcornFox Skill：" }));
  frag.append(copyBlock(SKILL_PROMPT, "已复制，发给你的 AI 即可", "复制 Skill 安装提示"));
  frag.append(el("p", { text: "2. 之后在项目里说「帮我把这个项目部署到我的服务器」。部署失败时，点诊断卡上的「复制给 AI」让它修复。" }));
  return frag;
}

function settingsTool() {
  const frag = document.createDocumentFragment();
  const dl = el("dl", { class: "kv" });
  dl.append(el("dt", { text: "外观" }));
  const dd = el("dd", { class: "row" }, [
    button("跟随系统", "btn", () => setTheme(null), "外观跟随系统"),
    button("深色", "btn", () => setTheme("dark"), "深色外观"),
    button("浅色", "btn", () => setTheme("light"), "浅色外观"),
  ]);
  dl.append(dd);
  dl.append(el("dt", { text: "会话" }));
  dl.append(el("dd", {}, button("退出登录", "btn", logout, "退出登录")));
  frag.append(dl);
  return frag;
}

// ---------------------------------------------------------------------------
// Interactions
// ---------------------------------------------------------------------------

function openApp(name) {
  state.openApp = name;
  state.openTool = null;
  state.detailTab = "overview";
  state.detail = null;
  resetLogReader();
  state.appMetrics = null;
  state.deployments = null;
  location.hash = "app=" + encodeURIComponent(name);
  render();
  loadDetail(name);
}

function openTool(tool) {
  resetLogReader();
  state.appMetrics = null;
  state.openTool = state.openTool === tool ? null : tool;
  state.openApp = null;
  state.detail = null;
  if (!state.openTool) location.hash = "";
  render();
}

function closeWindow() {
  resetLogReader();
  state.appMetrics = null;
  state.openApp = null;
  state.openTool = null;
  state.detail = null;
  location.hash = "";
  render();
}

function setTab(tab) {
  if (state.detailTab === "logs" && tab !== "logs") {
    state.logGeneration++;
    if (logRequest) logRequest.abort();
    logRequest = null;
  }
  state.detailTab = tab;
  render();
  if (tab === "deploys" && state.openApp) loadDeployments(state.openApp);
  if (tab === "logs" && state.openApp && state.logs === null) refreshLogs(state.openApp);
}

async function loadDetail(name) {
  try {
    const [d, metrics] = await Promise.all([
      api.get("/v1/apps/" + encodeURIComponent(name)),
      api.get("/v1/metrics/apps/" + encodeURIComponent(name)).catch(() => ({ available: false, observed_state: "unavailable" })),
    ]);
    if (state.openApp !== name) return;
    state.detail = d;
    state.appMetrics = metrics;
    render();
  } catch (e) { handleError(e); }
}

async function loadDeployments(name) {
  try {
    const body = await api.get("/v1/apps/" + encodeURIComponent(name) + "/deployments?limit=20");
    if (state.openApp !== name) return;
    state.deployments = body.deployments || body.items || [];
    render();
  } catch (e) { handleError(e); }
}

function resetLogReader() {
  state.logGeneration++;
  if (logRequest) logRequest.abort();
  logRequest = null;
  state.logs = null;
  state.logCursor = "";
  state.logFollow = false;
  state.logError = null;
}

function toggleLogFollow(name) {
  state.logFollow = !state.logFollow;
  if (!state.logFollow) {
    state.logGeneration++;
    if (logRequest) logRequest.abort();
    logRequest = null;
  } else refreshLogs(name);
  render();
}

async function refreshLogs(name, reset = false) {
  if (reset) {
    state.logGeneration++;
    if (logRequest) logRequest.abort();
    logRequest = null;
    state.logCursor = "";
    state.logs = null;
  }
  if (logRequest) return;
  const generation = state.logGeneration;
  const request = new AbortController();
  logRequest = request;
  try {
    const query = new URLSearchParams({ tail: String(state.logTail) });
    if (state.logCursor) query.set("cursor", state.logCursor);
    const body = await api.get("/v1/apps/" + encodeURIComponent(name) + "/log-batch?" + query.toString(), request.signal);
    if (state.openApp !== name || state.logGeneration !== generation) return;
    if (body.reset) state.logs = [];
    state.logs = (state.logs || []).concat(body.lines || []).slice(-2000);
    state.logCursor = body.cursor || "";
    state.logError = null;
    render();
    if (body.has_more && state.logFollow) setTimeout(() => refreshLogs(name), 0);
  } catch (e) {
    if (e.name === "AbortError" || state.openApp !== name || state.logGeneration !== generation) return;
    state.logError = e.message || "无法读取日志";
    if (e.code === "no_live_deployment") state.logs = [];
    if (e.status === 501 || e.status === 404) state.logFollow = false;
    if (e.status === 401) handleError(e);
    else render();
  } finally {
    if (logRequest === request) logRequest = null;
  }
}

async function actOnApp(action) {
  const name = state.openApp;
  if (!name) return;
  try {
    await api.post("/v1/apps/" + encodeURIComponent(name) + "/" + action, {});
    toast(({ start: "已提交启动", restart: "已提交重启", redeploy: "已提交重新部署", rollback: "已提交回退，正在部署" })[action] || "已提交停止");
    await poll();
    if (state.openApp === name) await loadDetail(name);
  } catch (e) { handleError(e); }
}

function confirmStop() {
  const name = state.openApp;
  showConfirm("停止应用", `确定要停止「${name}」吗？停止后用户将无法访问，直到重新启动。`, "停止", async () => {
    await actOnApp("stop");
  });
}

async function logout() {
  try { await api.post("/v1/console/logout", {}); } catch (_) { /* ignore */ }
  state.fatal = { title: "已退出登录", body: "你已退出控制台。", again: true };
  stopPolling();
  render();
}

// ---------------------------------------------------------------------------
// Confirm dialog
// ---------------------------------------------------------------------------

let confirmAction = null;

function showConfirm(title, body, okLabel, action) {
  $("confirm-title").textContent = title;
  $("confirm-body").textContent = body;
  const ok = $("confirm-ok");
  ok.textContent = okLabel;
  confirmAction = action;
  $("confirm-overlay").hidden = false;
  $("confirm-dialog").hidden = false;
  // Default focus on the safe choice: Enter must not stop or delete anything.
  $("confirm-cancel").focus();
}

function hideConfirm() {
  $("confirm-overlay").hidden = true;
  $("confirm-dialog").hidden = true;
  confirmAction = null;
}

// ---------------------------------------------------------------------------
// Clipboard
// ---------------------------------------------------------------------------

function copyToClipboard(text, okMsg) {
  const done = () => toast(okMsg || "已复制");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  } else {
    fallbackCopy(text, done);
  }
}

function fallbackCopy(text, done) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.opacity = "0";
  document.body.append(ta);
  ta.select();
  try {
    if (document.execCommand("copy")) done();
    else toast("复制失败，请手动复制");
  } catch (_) { toast("复制失败，请手动复制"); }
  ta.remove();
}

// ---------------------------------------------------------------------------
// Toast
// ---------------------------------------------------------------------------

let toastTimer = null;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 1800);
}

// ---------------------------------------------------------------------------
// Theme
// ---------------------------------------------------------------------------

function applyTheme() {
  const saved = localStorage.getItem("af-theme");
  if (saved === "dark" || saved === "light") document.documentElement.dataset.theme = saved;
  else delete document.documentElement.dataset.theme;
}

function setTheme(mode) {
  if (mode === "dark" || mode === "light") localStorage.setItem("af-theme", mode);
  else localStorage.removeItem("af-theme");
  applyTheme();
}

function toggleTheme() {
  const cur = document.documentElement.dataset.theme;
  const prefersLight = window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches;
  const effective = cur || (prefersLight ? "light" : "dark");
  setTheme(effective === "dark" ? "light" : "dark");
}

// ---------------------------------------------------------------------------
// Polling and errors
// ---------------------------------------------------------------------------

async function poll() {
  if (pollInFlight) return;
  pollInFlight = true;
  try {
    const [appsBody, hostBody] = await Promise.all([
      api.get("/v1/apps"),
      api.get("/v1/host").catch(() => ({ available: false })),
    ]);
    state.apps = appsBody.apps || [];
    state.host = hostBody;
    state.loaded = true;
    state.connectionLost = false;
    if (state.fatal && state.fatal.code === "connection") state.fatal = null;
    render();
    if (state.openApp) {
      await loadDetail(state.openApp);
      if (state.detailTab === "logs" && state.logFollow) await refreshLogs(state.openApp);
    }
  } catch (e) { handleError(e); }
  finally { pollInFlight = false; }
}

function handleError(e) {
  if (e.status === 401 && e.code === "session_expired") {
    state.fatal = { title: "会话已过期", body: "为了安全，登录会话已过期。", again: true };
    stopPolling();
    render();
    return;
  }
  if (e.status === 401) {
    state.fatal = { title: "需要重新登录", body: "登录状态已失效。", again: true };
    stopPolling();
    render();
    return;
  }
  if (typeof e.status === "undefined") {
    // Network failure: connection lost, keep retrying via the poll timer.
    state.connectionLost = true;
    render();
    return;
  }
  // Other server errors: show a transient toast; keep the console usable.
  toast("操作失败：" + (e.message || "服务器错误"));
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(() => { if (!document.hidden) poll(); }, POLL_MS);
}

function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

function readHash() {
  const h = location.hash.slice(1);
  if (h.startsWith("app=")) {
    const name = decodeURIComponent(h.slice(4));
    if (name) { state.openApp = name; state.detailTab = "overview"; }
  }
}

async function boot() {
  applyTheme();
  $("theme").addEventListener("click", () => { toggleTheme(); render(); });

  $("confirm-cancel").addEventListener("click", hideConfirm);
  $("confirm-overlay").addEventListener("click", hideConfirm);
  $("confirm-ok").addEventListener("click", async () => {
    const action = confirmAction;
    hideConfirm();
    if (action) await action();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (!$("confirm-dialog").hidden) { hideConfirm(); return; }
    if (state.openApp || state.openTool) closeWindow();
  });

  document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); });
  window.addEventListener("hashchange", () => {
    const h = location.hash.slice(1);
    if (h.startsWith("app=")) { const n = decodeURIComponent(h.slice(4)); if (n && n !== state.openApp) openApp(n); }
    else if (!h && (state.openApp || state.openTool)) closeWindow();
  });

  readHash();
  render();

  // Fetch the CSRF token, then start the data loop.
  try {
    const sess = await api.session();
    if (sess && sess.server) {
      $("server-label").textContent = sess.server;
      document.title = "AcornFox · " + sess.server;
    }
  } catch (e) {
    if (e.status === 401) { handleError(e); return; }
    // A missing session endpoint (e.g. dev) should not block read-only polling.
  }
  await poll();
  if (state.openApp) loadDetail(state.openApp);
  startPolling();
}

boot();
