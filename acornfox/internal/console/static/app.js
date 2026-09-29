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
const TILE_COLORS = [
  "#3ecf8e", "#f5a524", "#f0616d", "#5b8def", "#a855f7",
  "#e05d9e", "#14b8a6", "#f97316", "#0ea5e9", "#8b5cf6",
];

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

// hashColor picks a stable color from the app name.
function hashColor(name) {
  let h = 0;
  for (let i = 0; i < name.length; i++) h = (h * 31 + name.charCodeAt(i)) >>> 0;
  return TILE_COLORS[h % TILE_COLORS.length];
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

  async get(path) {
    const r = await fetch(path, { headers: { Accept: "application/json" } });
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
  deployments: null, // deployments history for openApp
  fatal: null,       // {code,message} full-screen state
  connectionLost: false,
  loaded: false,
};

let pollTimer = null;

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function render() {
  renderFatal();
  if (state.fatal) return;
  renderConnectionBanner();
  renderHealth();
  renderDesk();
  renderDock();
  renderWindow();
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
  const health = $("health");
  clear(health);
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
  const desk = $("desk");
  clear(desk);
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
  tile.style.background = hashColor(a.name);
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
  const dock = $("dock");
  clear(dock);
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
  if (existing) existing.remove();
  const overlay = $("win-overlay");
  if (overlay) overlay.remove();
  if (state.fatal) return;

  let win = null;
  if (state.openApp) win = appWindow();
  else if (state.openTool) win = toolWindow();
  if (!win) return;

  const ov = el("div", { id: "win-overlay", class: "overlay", onclick: closeWindow });
  document.body.append(ov);
  win.id = "window";
  document.body.append(win);
  // Move focus into the window for keyboard users.
  const focusable = win.querySelector("button, a, [tabindex]");
  if (focusable) focusable.focus();
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

  const win = el("section", { class: "win", role: "dialog", "aria-modal": "true", "aria-label": a.name + " 应用窗口" });
  const t = el("div", { class: "tile", "aria-hidden": "true", text: firstChar(a.name) });
  t.style.background = hashColor(a.name);
  const head = el("div", { class: "win-head" }, [
    t, el("h3", { text: a.name }), pillNode(meta.text, meta.pill),
    el("div", { class: "grow" }), button("✕", "iconbtn", closeWindow, "关闭（Esc）"),
  ]);
  win.append(head);

  const tabs = [["overview", "概览"], ["deploys", "部署记录"], ["logs", "日志"], ["domains", "域名"], ["settings", "设置"]];
  const tabsRow = el("div", { class: "tabs", role: "tablist" });
  for (const [k, label] of tabs) {
    tabsRow.append(button(label, state.detailTab === k ? "on" : "", () => setTab(k), label));
  }
  win.append(tabsRow);

  const body = el("div", { class: "win-body" });
  if (!state.detail) body.append(el("p", { class: "muted", text: "正在加载…" }));
  else if (state.detailTab === "overview") body.append(overviewTab(a, st, meta));
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
  dl.append(el("dt", { text: "状态" }));
  dl.append(el("dd", {}, pillNode(meta.text, meta.pill)));

  dl.append(el("dt", { text: "网址" }));
  if (a.url) {
    dl.append(el("dd", {}, el("span", { class: "url" }, [
      el("a", { href: a.url, target: "_blank", rel: "noopener", text: a.url }),
      button("复制", "btn", () => copyToClipboard(a.url, "网址已复制"), "复制网址"),
    ])));
  } else {
    dl.append(el("dd", {}, el("span", { class: "muted", text: "部署成功后显示" })));
  }

  dl.append(el("dt", { text: "当前版本" }));
  const live = a.live;
  const verText = live ? `第 ${live.seq} 版 · ${sourceLabel(live.source_kind)} · ${timeAgo(live.created_at)}` : "尚无版本";
  dl.append(el("dd", { text: verText }));

  dl.append(el("dt", { text: "资源" }));
  if (st === "running" && a.observed) {
    dl.append(el("dd", { text: `内存上限 ${a.memory_mb} MB · CPU ${(a.cpu_milli / 1000).toFixed(1)} 核` }));
  } else {
    dl.append(el("dd", {}, el("span", { class: "muted", text: "未运行" })));
  }
  frag.append(dl);

  const row = el("div", { class: "row" });
  if (a.desired === "stopped") {
    row.append(button("启动", "btn primary", () => actOnApp("start"), "启动应用"));
  } else {
    row.append(button("停止", "btn danger", confirmStop, "停止应用"));
  }
  row.append(button("回退到上一版", "btn", () => actOnApp("rollback"), "回退到上一版"));
  frag.append(row);

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
    const details = el("details");
    details.append(el("summary", { text: "查看日志" }));
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
  const row = el("div", { class: "row" }, [
    button("刷新日志", "btn", () => refreshLogs(a.name), "刷新日志"),
    el("span", { class: "faint", text: "最近 100 行" }),
  ]);
  frag.append(row);
  const pre = el("pre", { class: "mono logbox" });
  if (state.logs === null) pre.textContent = "点击「刷新日志」加载。";
  else if (state.logs.length === 0) pre.textContent = "暂无日志。";
  else pre.textContent = state.logs.join("\n");
  frag.append(pre);
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
  frag.append(el("p", { class: "faint", text: "环境变量与数据卷在下次部署时生效；密钥值不会显示或返回。" }));
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
  if (typeof h.cpu_percent === "number") frag.append(metric("CPU", Math.round(h.cpu_percent)));
  if (h.memory_total) frag.append(metric("内存", pct(h.memory_used, h.memory_total)));
  if (h.disk_total) frag.append(metric("磁盘", pct(h.disk_used, h.disk_total)));
  const dl = el("dl", { class: "kv" });
  if (typeof h.load1 === "number") { dl.append(el("dt", { text: "负载" })); dl.append(el("dd", { text: h.load1.toFixed(2) })); }
  if (h.uptime_seconds) { dl.append(el("dt", { text: "运行时长" })); dl.append(el("dd", { text: uptimeText(h.uptime_seconds) })); }
  frag.append(dl);
  return frag;
}

function metric(name, value) {
  const m = el("div", { class: "metric" }, [
    el("div", { class: "row" }, [el("span", { text: name }), el("span", { class: "muted", text: value + "%" })]),
    el("div", { class: "bar" }, el("i")),
  ]);
  m.querySelector("i").style.width = Math.max(0, Math.min(100, value)) + "%";
  return m;
}

function uptimeText(s) {
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600);
  if (d) return `${d} 天 ${h} 小时`;
  const m = Math.floor((s % 3600) / 60);
  return h ? `${h} 小时 ${m} 分钟` : `${m} 分钟`;
}

function deployTool() {
  const frag = document.createDocumentFragment();
  frag.append(el("p", { class: "muted", text: "推荐：在你的 AI 工作台里说「帮我部署」。也可以在项目目录运行：" }));
  frag.append(el("p", { class: "mono", text: "acornfox deploy ." }));
  return frag;
}

function aiTool() {
  const frag = document.createDocumentFragment();
  frag.append(el("p", { text: "1. 在你的电脑安装 AI 工作台技能（N6 提供）。" }));
  frag.append(el("p", { text: "2. 对 AI 说：「帮我把这个项目部署到我的服务器」。" }));
  frag.append(el("p", { text: "3. 或在项目目录手动运行：" }));
  frag.append(el("p", { class: "mono", text: "acornfox deploy" }));
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
  state.logs = null;
  state.deployments = null;
  location.hash = "app=" + encodeURIComponent(name);
  render();
  loadDetail(name);
}

function openTool(tool) {
  state.openTool = state.openTool === tool ? null : tool;
  state.openApp = null;
  state.detail = null;
  if (!state.openTool) location.hash = "";
  render();
}

function closeWindow() {
  state.openApp = null;
  state.openTool = null;
  state.detail = null;
  location.hash = "";
  render();
}

function setTab(tab) {
  state.detailTab = tab;
  render();
  if (tab === "deploys" && state.openApp) loadDeployments(state.openApp);
  if (tab === "logs" && state.openApp && state.logs === null) refreshLogs(state.openApp);
}

async function loadDetail(name) {
  try {
    const d = await api.get("/v1/apps/" + encodeURIComponent(name));
    if (state.openApp !== name) return;
    state.detail = d;
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

async function refreshLogs(name) {
  try {
    const body = await api.get("/v1/apps/" + encodeURIComponent(name) + "/logs?tail=100");
    if (state.openApp !== name) return;
    state.logs = body.lines || [];
    render();
  } catch (e) {
    if (e.code === "no_live_deployment") { state.logs = []; render(); return; }
    handleError(e);
  }
}

async function actOnApp(action) {
  const name = state.openApp;
  if (!name) return;
  try {
    await api.post("/v1/apps/" + encodeURIComponent(name) + "/" + action, {});
    toast(action === "start" ? "已启动" : action === "rollback" ? "已回退" : "已停止");
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
  ok.focus();
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
  try { document.execCommand("copy"); done(); } catch (_) { toast("复制失败，请手动复制"); }
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
    if (state.openApp) loadDetail(state.openApp);
  } catch (e) { handleError(e); }
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
    await api.session();
  } catch (e) {
    if (e.status === 401) { handleError(e); return; }
    // A missing session endpoint (e.g. dev) should not block read-only polling.
  }
  await poll();
  if (state.openApp) loadDetail(state.openApp);
  startPolling();
}

boot();
