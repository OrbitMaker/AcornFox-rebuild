// AcornFox 网页控制台 · 一拨即开（docs/console-design.md、docs/brand.md）。
// 不依赖框架，ES2020。所有内容用 createElement + textContent 生成，用户数据
// 永远不进 innerHTML（安全策略：不内联脚本 / 样式、不用 eval、不加载外部资源）。
// 结构：顶栏 + 四个页面（我的应用 / 应用中心 / 服务器 / 设置）+ 应用详情页。

// ---------------------------------------------------------------------------
// 常量与小工具
// ---------------------------------------------------------------------------

const POLL_MS = 3000;

// 应用的显示状态：卡片、标题和提醒共用。
const STATUS = {
  running: { text: "运行中", cls: "running" },
  deploying: { text: "部署中", cls: "deploying" },
  failed: { text: "部署失败", cls: "error" },
  crashed: { text: "未在运行", cls: "error" },
  stopped: { text: "已停止", cls: "stopped" },
};

const PENDING_STATUSES = new Set(["queued", "building", "starting", "checking", "routing"]);

// 部署流程的五步，与诊断的 stage 对应。
const STEPS = ["上传", "构建", "启动", "健康检查", "切换流量"];
const STEP_OF_STATUS = { queued: 0, building: 1, starting: 2, checking: 3, routing: 4 };
const STEP_OF_STAGE = { upload: 0, build: 1, runner: 1, start: 2, addon: 2, health: 3, data: 3, route: 4 };

const PAGES = [
  ["home", "我的应用", "#/"],
  ["store", "应用中心", "#/store"],
  ["server", "服务器", "#/server"],
  ["settings", "设置", "#/settings"],
];

const APP_TABS = [["overview", "概览"], ["logs", "日志"], ["versions", "版本记录"], ["config", "配置"], ["db", "数据库"], ["domains", "域名"]];

const ADDON_NAMES = { postgres: "PostgreSQL", mysql: "MySQL", redis: "Redis" };
const ADDON_KINDS = ["postgres", "mysql", "redis"];
const ADDON_DESC = {
  postgres: "关系型数据库，连接地址注入 DATABASE_URL。",
  mysql: "关系型数据库，连接地址注入 DATABASE_URL。",
  redis: "缓存与会话，连接地址注入 REDIS_URL。",
};

const SKILL_PROMPT = "请安装 AcornFox Skill：下载 https://acornfox.com/skill/SKILL.md ，保存为你 skills 目录下的 acornfox/SKILL.md（Claude Code 是 ~/.claude/skills，Codex 是 ~/.codex/skills），然后按这个 Skill 把当前项目部署到我的服务器。";
const UPGRADE_CN = "curl -fsSL https://gitee.com/VIP13390/AcornFox-rebuild/raw/main/scripts/install/upgrade.sh | sudo bash";
const UPGRADE_GLOBAL = "curl -fsSL https://github.com/OrbitMaker/AcornFox-rebuild/releases/latest/download/upgrade.sh | sudo bash";

// 应用中心首批预告（目录服务上线前只展示，不提供安装）。
const STORE_PREVIEW = [
  ["OpenClaw", "个人 AI 智能体，能替你执行任务。"],
  ["CowAgent", "接入微信、飞书、钉钉的 AI 助手。"],
  ["AstrBot", "多平台聊天机器人，插件丰富。"],
  ["LobeHub", "界面精致的 AI 对话助手。"],
  ["MaxKB", "企业知识库问答。"],
  ["New API", "把多家大模型合成一个接口。"],
  ["NextChat", "轻量的 AI 对话网页。"],
  ["Open WebUI", "功能全面的 AI 对话界面。"],
];

// el 创建元素：文字一律作为文本节点，绝不经过 innerHTML。
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

function text(s) { return document.createTextNode(s); }

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

// firstChar 取名字的第一个字，用作应用图标。
function firstChar(name) {
  const chars = Array.from(name || "?");
  return chars.length ? chars[0].toUpperCase() : "?";
}

// timeAgo 把时间戳显示成“N 分钟前”。
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
  return Math.floor(h / 24) + " 天前";
}

// tookText 显示一次部署的用时。
function tookText(d) {
  if (!d || !d.created_at || !d.finished_at) return "";
  const s = Math.round((Date.parse(d.finished_at) - Date.parse(d.created_at)) / 1000);
  if (!Number.isFinite(s) || s < 0) return "";
  return s < 60 ? `用时 ${s} 秒` : `用时 ${Math.floor(s / 60)} 分 ${s % 60} 秒`;
}

function pct(used, total) { return total ? Math.round((used / total) * 100) : 0; }

// ---------------------------------------------------------------------------
// 接口（CSRF + 错误分类）
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

  async send(method, path, body) {
    const headers = { "Content-Type": "application/json" };
    if (this.csrf) headers["X-AcornFox-CSRF"] = this.csrf;
    const r = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : null });
    if (!r.ok) throw await apiError(r);
    return r.status === 204 ? {} : r.json().catch(() => ({}));
  },

  post(path, body) { return this.send("POST", path, body); },
  del(path) { return this.send("DELETE", path, null); },
};

async function apiError(r) {
  let code = "server_error", message = "服务器错误";
  try {
    const body = await r.json();
    if (body && body.error) { code = body.error.code || code; message = body.error.message || message; }
    else if (body && body.code) { code = body.code; message = body.message || message; }
  } catch (_) { /* 非 JSON */ }
  const e = new Error(message);
  e.status = r.status;
  e.code = code;
  return e;
}

function appPath(name, rest) { return "/v1/apps/" + encodeURIComponent(name) + (rest || ""); }

// ---------------------------------------------------------------------------
// 应用状态推导
// ---------------------------------------------------------------------------

// deriveStatus：期望停止 → 已停止；最新部署进行中 → 部署中；最新部署失败 →
// 部署失败（旧版本可能仍在服务）；容器在跑 → 运行中；否则未在运行。
function deriveStatus(app) {
  if (app.desired === "stopped") return "stopped";
  const latest = app.latest || app.live;
  if (latest && PENDING_STATUSES.has(latest.status)) return "deploying";
  if (latest && latest.status === "failed") return "failed";
  if (app.observed_state === "running") return "running";
  if (app.observed_state === "stopped" || app.observed_state === "missing") return "crashed";
  return "running";
}

// oldVersionServing：最新一次部署没上线，但之前的版本仍在服务。
function oldVersionServing(app) {
  const latest = app.latest;
  if (!latest || latest.status !== "failed") return false;
  if (app.live) return app.live.id !== latest.id && app.live.status === "live";
  return !!app.current_deployment && app.current_deployment !== latest.id;
}

function isRunning(app) {
  if (app.observed) return !!app.observed.running;
  return app.observed_state === "running";
}

function appDiagnosis(app) {
  const latest = app.latest || app.live;
  if (latest && latest.status === "failed" && latest.diagnosis) return latest.diagnosis;
  return null;
}

function failedDeploymentID(app) {
  const latest = app.latest || app.live;
  return latest ? latest.id : "";
}

function domainDiagnosis(app) {
  for (const d of app.domains || []) {
    if (d.status === "failed" && d.diagnosis) return { domain: d.name, diagnosis: d.diagnosis };
  }
  return null;
}

// copyForAI 生成交给 AI 的诊断文本（格式与 CLI 一致）。
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
  return "请根据以下 AcornFox 部署诊断修复项目，然后重新执行 acornfox deploy：\n" + JSON.stringify(payload, null, 2);
}

// statusForAI 生成应用当前状态的摘要，供“复制状态给 AI”。
function statusForAI(a) {
  const st = STATUS[deriveStatus(a)].text;
  const lines = ["这是我在 AcornFox 上的应用「" + a.name + "」的当前状态，请帮我看看：", "状态：" + st];
  if (a.live) lines.push("当前版本：第 " + a.live.seq + " 版（" + deploymentSource(a.live) + "）");
  if (a.latest && a.live && a.latest.id !== a.live.id) lines.push("最新一次部署：第 " + a.latest.seq + " 版，" + deployStatusText(a.latest.status));
  if (a.url) lines.push("访问地址：" + a.url);
  const addons = (a.addons || []).map((x) => (ADDON_NAMES[x.kind] || x.kind) + "（" + addonStateText(x.observed_state) + "）");
  if (addons.length) lines.push("数据库：" + addons.join("、"));
  lines.push("资源上限：内存 " + a.memory_mb + " MB，CPU " + (a.cpu_milli / 1000).toFixed(1) + " 核");
  const diag = appDiagnosis(a);
  if (diag) lines.push("", copyForAI(diag, a.name, failedDeploymentID(a)));
  return lines.join("\n");
}

function sourceLabel(kind) {
  return kind === "image" ? "镜像" : kind === "git" ? "Git" : "上传";
}

// reasonText 说明复用镜像的部署为什么产生，如“添加 PostgreSQL（基于第 1 版）”。
function reasonText(d) {
  if (!d || !d.reason) return "";
  const [kind, addon] = d.reason.split(":");
  const what = ({
    redeploy: "重新部署",
    rollback: "回退",
    addon_add: "添加 " + (ADDON_NAMES[addon] || addon || "数据库"),
    addon_remove: "移除 " + (ADDON_NAMES[addon] || addon || "数据库"),
  })[kind] || d.reason;
  return d.based_on_seq ? `${what}（基于第 ${d.based_on_seq} 版）` : what;
}

// deploymentSource 显示代码的原始来源；重新部署一个上传的目录仍是“上传”。
function deploymentSource(d) {
  return sourceLabel(d.origin_kind || d.source_kind);
}

function deployStatusText(status) {
  return ({
    live: "正在服务", retired: "已被新版本替换", failed: "部署失败",
    superseded: "已被更新的提交取代", queued: "排队中", building: "构建中",
    starting: "启动中", checking: "健康检查中", routing: "切换流量中",
  })[status] || status;
}

function addonStateText(s) {
  return ({ running: "运行中", starting: "初始化中", unhealthy: "未就绪", stopped: "已停止", missing: "等待创建", unavailable: "无法读取状态" })[s] || "状态未知";
}

// ---------------------------------------------------------------------------
// 全局状态
// ---------------------------------------------------------------------------

const state = {
  apps: [],
  host: null,
  server: "",
  route: { page: "home" },
  openApp: null,       // 当前打开的应用名（应用详情页）
  detailTab: "overview",
  detail: null,
  logs: null,
  logCursor: "", logFollow: false, logTail: 100, logError: null,
  logGeneration: 0, appMetrics: null,
  deployments: null,
  fatal: null,
  connectionLost: false,
  loaded: false,
  busy: {},            // 正在提交的操作，避免重复点击
};

let pollTimer = null;
let logRequest = null;
let pollInFlight = false;

const $ = (id) => document.getElementById(id);
const FOCUSABLE = "button, a, summary, select, input, [tabindex]";

// ---------------------------------------------------------------------------
// 通用组件
// ---------------------------------------------------------------------------

function button(label, cls, onClick, ariaLabel, children) {
  const attrs = { class: cls, type: "button", onclick: onClick };
  if (ariaLabel) attrs["aria-label"] = ariaLabel;
  const b = el("button", attrs, children || null);
  if (label != null) b.append(text(label));
  return b;
}

function linkButton(label, cls, href, extra) {
  return el("a", Object.assign({ class: cls, href }, extra || {}), text(label));
}

// switchNode 是“一拨即开”开关：role=switch，开启时轨道内显示三个圆点。
function switchNode(checked, label, onToggle, opts) {
  const o = opts || {};
  return el("button", {
    class: "switch" + (o.sm ? " sm" : ""), type: "button", role: "switch",
    "aria-checked": checked ? "true" : "false", "aria-label": label,
    disabled: o.disabled ? "" : false, onclick: onToggle,
  }, [
    el("span", { class: "dots", "aria-hidden": "true" }, [el("span"), el("span"), el("span")]),
    el("span", { class: "knob", "aria-hidden": "true" }),
  ]);
}

function badge(cls, label) {
  return el("span", { class: "badge " + cls }, [el("span", { class: "dot " + cls, "aria-hidden": "true" }), text(label)]);
}

function statusBadge(st, label) {
  return badge(STATUS[st].cls, label || STATUS[st].text);
}

function card(children, cls, region) {
  return el("section", { class: "card" + (cls ? " " + cls : ""), dataset: region ? { region } : undefined }, children);
}

function cardHead(title, side) {
  return el("div", { class: "card-head" }, [el("h2", { class: "section-title", text: title }), side || null]);
}

function copyBlock(content, okMsg, label, mono) {
  return el("div", { class: "codebox" }, [
    el("span", { class: mono ? "mono" : "", text: content }),
    el("div", {}, button("复制", "btn sm", () => copyToClipboard(content, okMsg), label)),
  ]);
}

function progressNode(currentStep, failedStep, compact) {
  const ol = el("ol", { class: "progress" + (compact ? " compact" : ""), "aria-label": "部署进度" });
  STEPS.forEach((name, i) => {
    let cls = "";
    let label = name;
    if (failedStep != null) {
      if (i < failedStep) { cls = "done"; label = name + " ✓"; }
      else if (i === failedStep) { cls = "fail"; label = name + " ✕"; }
    } else if (currentStep != null) {
      if (i < currentStep) cls = "done";
      else if (i === currentStep) cls = "now";
    }
    ol.append(el("li", { class: cls, text: label }));
  });
  return ol;
}

function logoSVG() {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 120 60");
  svg.setAttribute("aria-hidden", "true");
  const p = document.createElementNS(ns, "path");
  p.setAttribute("class", "logo-track");
  p.setAttribute("fill-rule", "evenodd");
  p.setAttribute("d", "M30 0 H90 A30 30 0 0 1 90 60 H30 A30 30 0 0 1 30 0 Z M68 30 A22 22 0 1 0 112 30 A22 22 0 1 0 68 30 Z M16 30 A3.5 3.5 0 1 0 23 30 A3.5 3.5 0 1 0 16 30 Z M30.3 30 A5 5 0 1 0 40.3 30 A5 5 0 1 0 30.3 30 Z M47.7 30 A6.5 6.5 0 1 0 60.7 30 A6.5 6.5 0 1 0 47.7 30 Z");
  const c = document.createElementNS(ns, "circle");
  c.setAttribute("class", "logo-knob");
  c.setAttribute("cx", "90"); c.setAttribute("cy", "30"); c.setAttribute("r", "22");
  svg.append(p, c);
  return svg;
}

// 底部标签栏的四个小图标。
function tabIcon(id) {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  const add = (tag, attrs) => {
    const n = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    n.setAttribute("fill", attrs.fill || "none");
    if (!attrs.fill) { n.setAttribute("stroke", "currentColor"); n.setAttribute("stroke-width", "1.7"); }
    svg.append(n);
  };
  if (id === "home") { add("rect", { x: "2.5", y: "7", width: "19", height: "10", rx: "5" }); add("circle", { cx: "16.5", cy: "12", r: "3", fill: "currentColor" }); }
  else if (id === "store") { add("rect", { x: "4", y: "4", width: "7", height: "7", rx: "2" }); add("rect", { x: "13", y: "4", width: "7", height: "7", rx: "2" }); add("rect", { x: "4", y: "13", width: "7", height: "7", rx: "2" }); add("rect", { x: "13", y: "13", width: "7", height: "7", rx: "3.5" }); }
  else if (id === "server") { add("rect", { x: "4", y: "4", width: "16", height: "6.5", rx: "2" }); add("rect", { x: "4", y: "13.5", width: "16", height: "6.5", rx: "2" }); add("circle", { cx: "8", cy: "7.25", r: "1", fill: "currentColor" }); add("circle", { cx: "8", cy: "16.75", r: "1", fill: "currentColor" }); }
  else { add("path", { d: "M4 7h16M4 17h16" }); add("circle", { cx: "9", cy: "7", r: "2.4" }); add("circle", { cx: "15", cy: "17", r: "2.4" }); }
  return svg;
}

// ---------------------------------------------------------------------------
// 渲染：只替换有变化的区域，轮询不打断选择、焦点和滚动
// ---------------------------------------------------------------------------

function focusKey(node) {
  return node.tagName + ":" + (node.getAttribute("aria-label") || node.getAttribute("href") || node.id || node.textContent);
}

function selectionInside(node) {
  const sel = window.getSelection();
  if (!node || !sel || sel.isCollapsed || !sel.rangeCount) return false;
  return node.contains(sel.anchorNode) || node.contains(sel.focusNode);
}

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

function regionKey(node) {
  return node.nodeType === 1 ? node.nodeName + "|" + (node.dataset.region || "") : "#" + node.nodeType;
}

// patch 把 next 的内容合到 target：结构相同时逐个区域比较，只替换变化的；
// 日志框只更新文字并保留滚动位置；用户正在选择的区域本轮不动。
function patch(target, next) {
  const a = Array.from(target.childNodes), b = Array.from(next.childNodes);
  const sameShape = a.length === b.length && a.every((n, i) => regionKey(n) === regionKey(b[i]));
  if (!sameShape) { swapChildren(target, next); return; }
  for (let i = 0; i < a.length; i++) {
    const cur = a[i], nxt = b[i];
    if (cur.isEqualNode(nxt)) continue;
    if (cur.nodeType === 1 && cur.classList.contains("logbox") && nxt.classList.contains("logbox")) {
      if (selectionInside(cur)) continue;
      const atBottom = cur.scrollHeight - cur.scrollTop - cur.clientHeight < 24;
      const top = cur.scrollTop;
      cur.textContent = nxt.textContent;
      cur.scrollTop = state.logFollow && atBottom ? cur.scrollHeight : top;
      continue;
    }
    if (cur.nodeType === 1 && selectionInside(cur)) continue;
    if (cur.nodeType === 1 && cur.dataset.region && cur.nodeName === nxt.nodeName) {
      patch(cur, nxt);
      for (const attr of ["class", "aria-label", "aria-checked", "aria-selected"]) {
        const v = nxt.getAttribute(attr);
        if (v == null) cur.removeAttribute(attr); else if (cur.getAttribute(attr) !== v) cur.setAttribute(attr, v);
      }
      continue;
    }
    cur.replaceWith(nxt);
  }
}

function render() {
  const active = document.activeElement;
  const activeKey = active && active.matches && active.matches(FOCUSABLE) ? focusKey(active) : null;
  const scope = $("page");
  const activeIndex = activeKey ? Array.from(document.querySelectorAll(FOCUSABLE)).filter((n) => focusKey(n) === activeKey).indexOf(active) : 0;
  renderFatal();
  if (state.fatal) return;
  renderConnectionBanner();
  renderChrome();
  const next = document.createElement("div");
  buildPage(next);
  patch(scope, next);
  if (activeKey && !active.isConnected) {
    const replacement = Array.from(document.querySelectorAll(FOCUSABLE)).filter((n) => focusKey(n) === activeKey)[activeIndex];
    if (replacement) replacement.focus({ preventScroll: true });
  }
}

function renderFatal() {
  const existing = $("fatal-state");
  if (!state.fatal) { if (existing) existing.remove(); return; }
  const { title, body, again } = state.fatal;
  const box = el("div", { class: "card" }, [
    el("h2", { class: "section-title", text: title }),
    el("p", { class: "muted", text: body }),
    again ? el("p", { class: "faint", text: "请在你的电脑终端重新执行 acornfox open。" }) : null,
  ]);
  if (existing) { clear(existing); existing.append(box); return; }
  document.body.append(el("div", { id: "fatal-state", class: "state" }, box));
}

function renderConnectionBanner() {
  const existing = $("conn-banner");
  if (!state.connectionLost || state.fatal) { if (existing) existing.remove(); return; }
  if (existing) return;
  document.body.append(el("div", { id: "conn-banner", class: "banner", role: "status" }, el("div", { class: "inner", text: "与服务器的连接中断，正在重试…" })));
}

function currentPage() {
  return state.route.page === "app" || state.route.page === "new" ? "home" : state.route.page;
}

function renderChrome() {
  const label = $("server-label");
  const serverText = state.server || (state.loaded ? "服务器" : "正在连接…");
  if (label.textContent !== serverText) label.textContent = serverText;
  const dot = $("server-dot");
  const attention = attentionItems().length;
  const dotCls = !state.loaded ? "dot stopped" : attention ? "dot error" : "dot";
  if (dot.className !== dotCls) dot.className = dotCls;
  const chipTitle = !state.loaded ? "正在连接服务器" : attention ? `${attention} 项需要处理` : "服务器运行正常";
  $("server-chip").setAttribute("title", chipTitle);

  const page = currentPage();
  const nav = el("div");
  const bar = el("div");
  for (const [id, name, href] of PAGES) {
    nav.append(el("a", { href, "aria-current": id === page ? "page" : false, text: name }));
    bar.append(el("a", { href, "aria-current": id === page ? "page" : false }, [tabIcon(id), text(name)]));
  }
  swapChildren($("nav"), nav);
  swapChildren($("tabbar"), bar);
}

function buildPage(page) {
  if (!state.loaded) {
    page.append(el("div", { class: "state", dataset: { region: "loading" } }, el("div", { class: "card" }, [
      el("div", { class: "spinner", "aria-hidden": "true" }), el("p", { text: "正在连接服务器…" }),
    ])));
    return;
  }
  const r = state.route.page;
  if (r === "store") buildStore(page);
  else if (r === "server") buildServer(page);
  else if (r === "settings") buildSettings(page);
  else if (r === "new") buildStart(page, false);
  else if (r === "app") buildApp(page);
  else buildHome(page);
}

// ---------------------------------------------------------------------------
// 我的应用
// ---------------------------------------------------------------------------

function buildHome(page) {
  if (state.apps.length === 0) { buildStart(page, true); return; }
  const running = state.apps.filter((a) => deriveStatus(a) === "running").length;
  const items = attentionItems();
  const summary = [`${state.apps.length} 个应用`, `${running} 个运行中`];
  if (items.length) summary.push(`${items.length} 项需要处理`);
  page.append(el("div", { class: "page-head", dataset: { region: "head" } }, [
    el("div", {}, [el("h1", { text: "我的应用" }), el("p", { class: "sub", text: summary.join(" · ") })]),
    linkButton("新建应用", "btn primary knob", "#/new"),
  ]));
  if (items.length) page.append(attentionStrip(items));
  const grid = el("div", { class: "apps", dataset: { region: "apps" } });
  for (const a of state.apps) grid.append(appCard(a));
  grid.append(el("a", { class: "add-card", href: "#/new", "aria-label": "部署新应用" }, [
    el("b", { text: "＋ 部署新应用" }),
    el("span", { class: "faint", text: "让 AI 部署你的项目，或用命令行部署目录、Git 仓库、镜像。" }),
  ]));
  page.append(grid);
  page.append(ambientLine());
}

// attentionItems：最多三条，依次为部署失败、未在运行、域名证书失败。
function attentionItems() {
  const items = [];
  for (const a of state.apps) {
    const st = deriveStatus(a);
    const diag = appDiagnosis(a);
    const latest = a.latest || a.live;
    if (st === "failed" && diag) {
      const seq = latest ? `第 ${latest.seq} 版` : "新版本";
      const title = oldVersionServing(a) ? `「${a.name}」${seq}部署失败，旧版本仍在正常服务` : `「${a.name}」${seq}部署失败`;
      items.push({ app: a.name, title, why: stageName(diag.stage) + " · " + diag.message, diag, deploymentID: failedDeploymentID(a) });
    } else if (st === "crashed") {
      const d = diag || { stage: "start", code: "not_running", message: "容器未在运行，但期望状态为运行中。", hint: "查看日志排查启动失败原因，或重新部署。" };
      items.push({ app: a.name, title: `「${a.name}」未在运行`, why: d.message, diag: d, deploymentID: a.current_deployment || "" });
    }
  }
  for (const a of state.apps) {
    const dd = domainDiagnosis(a);
    if (dd) items.push({ app: a.name, title: `「${a.name}」域名 ${dd.domain} 证书未就绪`, why: dd.diagnosis.message, diag: dd.diagnosis, deploymentID: "" });
  }
  return items.slice(0, 3);
}

function stageName(stage) {
  const i = STEP_OF_STAGE[stage];
  return i == null ? "部署" : STEPS[i];
}

function attentionStrip(items) {
  const box = el("section", { class: "attention", "aria-label": "需要处理", dataset: { region: "attention" } });
  for (const it of items) {
    const forAI = copyForAI(it.diag, it.app, it.deploymentID);
    box.append(el("div", { class: "attention-item" }, [
      badge("error", "需要处理"),
      el("div", { class: "what" }, [el("b", { text: it.title }), el("span", { class: "why", text: it.why })]),
      el("div", { class: "row" }, [
        linkButton("查看", "btn sm", appHash(it.app), { "aria-label": "查看 " + it.app }),
        button("复制给 AI", "btn sm primary", () => copyToClipboard(forAI, "已复制，粘贴给你的 AI 即可"), "复制 " + it.app + " 的诊断给 AI"),
      ]),
    ]));
  }
  return box;
}

function appHash(name, tab) {
  return "#/app/" + encodeURIComponent(name) + (tab && tab !== "overview" ? "/" + tab : "");
}

function appSubLine(a) {
  const latest = a.latest;
  if (!latest) return "还没有版本";
  const st = deriveStatus(a);
  if (st === "deploying") return `第 ${latest.seq} 版 · ${deploymentSource(latest)} · ${deployStatusText(latest.status)}`;
  if (st === "failed") return oldVersionServing(a) ? `第 ${latest.seq} 版失败 · 旧版本仍在服务` : `第 ${latest.seq} 版部署失败`;
  return [`第 ${latest.seq} 版`, deploymentSource(latest), reasonText(latest), timeAgo(latest.created_at)].filter(Boolean).join(" · ");
}

function appCard(a) {
  const st = deriveStatus(a);
  const running = isRunning(a);
  const latest = a.latest;
  const art = el("article", { class: "app-card", dataset: { region: "app:" + a.name } });
  art.append(el("div", { class: "app-top" }, [
    el("span", { class: "app-icon", "aria-hidden": "true", text: firstChar(a.name) }),
    el("div", { class: "app-title" }, [
      el("a", { class: "app-name", href: appHash(a.name), text: a.name }),
      el("span", { class: "app-sub", text: appSubLine(a) }),
    ]),
    statusBadge(st),
  ]));
  if (st === "deploying" && latest) {
    art.append(progressNode(STEP_OF_STATUS[latest.status] ?? 0, null, true));
  } else {
    art.append(urlRow(a.url, running && st !== "stopped", a.name));
  }
  let foot;
  if (st === "failed") foot = el("a", { href: appHash(a.name), text: "查看诊断" });
  else if (st === "deploying") foot = el("span", { text: "上传 → 构建 → 启动 → 检查 → 上线" });
  else if (st === "crashed") foot = el("span", { text: "容器未在运行" });
  else foot = el("span", { text: `内存上限 ${a.memory_mb} MB` });
  const on = a.desired !== "stopped";
  art.append(el("div", { class: "app-foot" }, [
    foot,
    switchNode(on, a.name + " 运行开关", () => toggleRun(a.name, on), { disabled: st === "deploying" || !!state.busy[a.name] }),
  ]));
  return art;
}

function urlRow(url, live, name) {
  if (!url) return el("div", { class: "urlrow" }, el("span", { class: "u off", text: "部署成功后显示访问地址" }));
  if (!live) return el("div", { class: "urlrow" }, el("span", { class: "u off", text: url + "（未运行）" }));
  return el("div", { class: "urlrow" }, [
    el("a", { class: "u", href: url, target: "_blank", rel: "noopener", text: url }),
    button("复制", "copy-mini", () => copyToClipboard(url, "网址已复制"), "复制 " + (name || "") + " 的网址"),
  ]);
}

function ambientLine() {
  const parts = [];
  if (state.server) parts.push("服务器 " + state.server);
  const h = state.host;
  if (h && h.available !== false) {
    if (typeof h.cpu_percent === "number") parts.push(`CPU ${Math.round(h.cpu_percent)}%`);
    if (h.memory_total) parts.push(`内存 ${pct(h.memory_used, h.memory_total)}%`);
    if (h.disk_total) parts.push(`磁盘 ${pct(h.disk_used, h.disk_total)}%`);
  }
  parts.push("应用端口 18810–18899");
  return el("p", { class: "faint", dataset: { region: "ambient" }, text: parts.join(" · ") });
}

// buildStart：没有应用时的首页，也是“新建应用”页。
function buildStart(page, empty) {
  if (!empty) page.append(el("nav", { class: "crumbs", "aria-label": "位置", dataset: { region: "crumbs" } }, [el("a", { href: "#/", text: "我的应用" }), text(" / 新建应用")]));
  page.append(el("div", { class: "start-hero", dataset: { region: "hero" } }, [
    logoSVG(),
    el("h1", { text: empty ? "服务器已就绪，装第一个应用吧" : "新建应用" }),
    el("p", { text: "装好后，应用会出现在“我的应用”里，每个应用一个开关。" }),
  ]));
  const deployCmds = "acornfox deploy\nacornfox deploy --git <公开仓库地址>\nacornfox deploy --image <镜像> --port <端口>";
  page.append(el("div", { class: "cards-3", dataset: { region: "ways" } }, [
    el("section", { class: "way strong" }, [
      el("span", { class: "k", text: "推荐" }),
      el("h2", { text: "让 AI 部署你的项目" }),
      el("p", { text: "把这句话发给 Claude Code、Codex 等 AI 工作台，它会装好 Skill 并完成部署：" }),
      copyBlock(SKILL_PROMPT, "已复制，发给你的 AI 即可", "复制 Skill 安装提示"),
    ]),
    el("section", { class: "way" }, [
      el("span", { class: "k", text: "熟悉终端" }),
      el("h2", { text: "用命令行部署" }),
      el("p", { text: "在你电脑的项目目录里运行（目录需含 Dockerfile；也可以部署公开 Git 仓库或现成镜像）：" }),
      copyBlock(deployCmds, "命令已复制", "复制部署命令", true),
    ]),
    el("section", { class: "way" }, [
      el("span", { class: "k", text: "即将开放" }),
      el("h2", { text: "从应用中心安装" }),
      el("p", { text: "现成的应用选一个、点安装就能用，需要的数据库自动配好。首批是 8 个热门 AI 应用。" }),
      linkButton("看看有哪些", "btn", "#/store"),
    ]),
  ]));
  page.append(el("p", { class: "faint", dataset: { region: "ambient" }, text: "应用通过 http://服务器IP:18810–18899 访问，记得在云厂商安全组放行这些端口；绑定已备案域名再放行 80、443。" }));
}

// ---------------------------------------------------------------------------
// 应用中心（目录服务上线前只做预告）
// ---------------------------------------------------------------------------

function buildStore(page) {
  page.append(el("div", { class: "page-head", dataset: { region: "head" } }, [
    el("div", {}, [el("h1", { text: "应用中心" }), el("p", { class: "sub", text: "挑一个现成应用，点安装就能用。需要的数据库会一起装好。" })]),
  ]));
  page.append(el("div", { class: "notice", role: "note", dataset: { region: "notice" } }, [
    el("b", { text: "即将开放" }),
    el("span", { text: "应用中心正在准备首批应用，开放后在这里一键安装。现在可以先让 AI 部署你自己的项目。" }),
  ]));
  const grid = el("div", { class: "store-grid", dataset: { region: "preview" } });
  for (const [name, desc] of STORE_PREVIEW) {
    grid.append(el("article", { class: "store-card" }, [
      el("div", { class: "app-top" }, [
        el("span", { class: "app-icon", "aria-hidden": "true", text: firstChar(name) }),
        el("div", { class: "app-title" }, [el("span", { class: "app-name", text: name }), el("span", { class: "app-sub", text: "AI 助手 · 热门开源" })]),
      ]),
      el("p", { class: "desc", text: desc }),
      el("div", { class: "row" }, [el("span", { class: "tag", text: "即将上架" }), el("span", { class: "faint", text: "安装时填写大模型接口地址与密钥" })]),
    ]));
  }
  page.append(el("section", { class: "stack", dataset: { region: "first" } }, [el("h2", { class: "section-title", text: "首批上架：热门 AI 应用" }), grid]));
  page.append(el("a", { class: "more-link", href: "#/new", dataset: { region: "more" } }, [
    el("span", { class: "stack" }, [el("b", { text: "没有你要的？" }), el("span", { class: "faint", text: "任何带 Dockerfile 的项目都能部署，交给 AI 工作台一句话完成。" })]),
    el("span", { text: "让 AI 部署我的项目 →" }),
  ]));
}

// ---------------------------------------------------------------------------
// 服务器
// ---------------------------------------------------------------------------

function buildServer(page) {
  const h = state.host;
  const ok = h && h.available !== false;
  const sub = [];
  if (ok && h.uptime_seconds) sub.push("已运行 " + uptimeText(h.uptime_seconds));
  if (ok && typeof h.load1 === "number") sub.push("负载 " + h.load1.toFixed(2));
  sub.push("经 SSH 访问 · 控制台不对公网开放");
  page.append(el("div", { class: "page-head", dataset: { region: "head" } }, [
    el("div", {}, [
      el("div", { class: "row" }, [el("h1", { text: state.server || "服务器" }), ok ? badge("running", "运行正常") : badge("stopped", "资源暂不可用")]),
      el("p", { class: "sub", text: sub.join(" · ") }),
    ]),
  ]));
  if (ok) {
    const memoryPct = h.memory_total > 0 ? pct(h.memory_used, h.memory_total) : null;
    const diskPct = h.disk_total > 0 ? pct(h.disk_used, h.disk_total) : null;
    page.append(el("div", { class: "metric-tiles", "aria-label": "主机当前资源", dataset: { region: "tiles" } }, [
      hostTile("CPU", typeof h.cpu_percent === "number" ? numberText(h.cpu_percent, "%") : "采样中", typeof h.cpu_percent === "number" ? h.cpu_percent : null, "最近几秒的平均值"),
      hostTile("内存", memoryPct !== null ? memoryPct + "%" : "不可用", memoryPct, bytePair(h.memory_used, h.memory_total)),
      hostTile("磁盘", diskPct !== null ? diskPct + "%" : "不可用", diskPct, diskPct !== null && diskPct >= 80 ? "已超过 80%，请清理或扩容" : bytePair(h.disk_used, h.disk_total)),
    ]));
  }
  const rows = state.apps.map((a) => {
    const st = deriveStatus(a);
    return el("tr", {}, [
      el("td", {}, el("a", { href: appHash(a.name), text: a.name })),
      el("td", {}, statusBadge(st)),
      el("td", { class: "mono", text: a.memory_mb + " MB" }),
      el("td", { class: "mono", text: (a.cpu_milli / 1000).toFixed(1) + " 核" }),
      el("td", { class: "mono", text: a.public_port ? String(a.public_port) : "—" }),
    ]);
  });
  const table = el("table", { class: "usage" }, [
    el("thead", {}, el("tr", {}, ["应用", "状态", "内存上限", "CPU 上限", "访问端口"].map((t) => el("th", { text: t })))),
    el("tbody", {}, rows.length ? rows : el("tr", {}, el("td", { colspan: "5", class: "muted", text: "还没有应用。" }))),
  ]);
  page.append(card([cardHead("各应用"), el("div", { class: "scroll-x" }, table)], "", "usage"));
  page.append(el("div", { class: "cards-3", dataset: { region: "more" } }, [
    card([
      el("h2", { class: "section-title", text: "版本与升级" }),
      el("p", { class: "muted", text: "升级前自动备份程序和数据库，失败自动回退，运行中的应用不会中断。在服务器上执行：" }),
      el("span", { class: "faint", text: "中国大陆服务器" }),
      copyBlock(UPGRADE_CN, "升级命令已复制", "复制国内升级命令", true),
      el("span", { class: "faint", text: "其他地区" }),
      copyBlock(UPGRADE_GLOBAL, "升级命令已复制", "复制海外升级命令", true),
    ], "stack"),
    card([
      el("h2", { class: "section-title", text: "访问方式" }),
      el("p", { text: "控制台只经 SSH 隧道访问，不对公网开放。" }),
      el("p", { class: "muted", text: "在你的电脑上运行 acornfox open 打开本页面。应用端口 18810–18899，绑定域名还需放行 80 和 443。" }),
    ], "stack"),
    card([
      el("span", { class: "soon", text: "即将推出" }),
      el("h2", { class: "section-title", text: "不想自己管服务器？" }),
      el("p", { class: "faint", text: "把这台服务器上的应用一键搬到云上，备份、扩容由我们负责。" }),
    ], "stack dark-card"),
  ]));
}

function hostTile(label, value, percent, detail) {
  const fill = el("span");
  if (percent != null && Number.isFinite(percent)) fill.style.width = Math.min(100, Math.max(0, percent)) + "%";
  const bar = el("div", { class: "bar" + (percent != null && percent >= 80 ? " warn" : "") }, fill);
  return el("div", { class: "metric-tile" }, [el("span", { class: "muted", text: label }), el("strong", { text: value }), bar, detail ? el("span", { class: "faint", text: detail }) : null]);
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

// ---------------------------------------------------------------------------
// 设置
// ---------------------------------------------------------------------------

function buildSettings(page) {
  page.append(el("div", { class: "page-head", dataset: { region: "head" } }, el("h1", { text: "设置" })));
  const mode = themeMode();
  const seg = el("div", { class: "seg", role: "radiogroup", "aria-label": "外观" });
  for (const [id, label] of [["system", "跟随系统"], ["light", "浅色"], ["dark", "深色"]]) {
    seg.append(el("button", { type: "button", role: "radio", "aria-checked": mode === id ? "true" : "false", onclick: () => { setTheme(id === "system" ? null : id); render(); }, text: label }));
  }
  page.append(card(el("div", { class: "setting" }, [
    el("div", { class: "text" }, [el("h2", { text: "外观" }), el("span", { class: "faint", text: "只在这台电脑的浏览器里生效。" })]), seg,
  ]), "", "theme"));
  page.append(card([
    el("h2", { class: "section-title", text: "连接 AI 工作台" }),
    el("p", { class: "muted", text: "把这句话发给 Claude Code、Codex 等 AI 工作台，装好 Skill 后，部署、排错、加数据库都可以用一句话完成。" }),
    copyBlock(SKILL_PROMPT, "已复制，发给你的 AI 即可", "复制 Skill 安装提示"),
  ], "stack", "ai"));
  page.append(card([
    el("h2", { class: "section-title", text: "修改应用配置" }),
    el("p", { class: "muted", text: "环境变量、数据目录、资源上限在控制台里只读。请在 AI 工作台里说明要改什么，或在你的电脑上使用 acornfox env set、acornfox volume add、acornfox app set，改完点“重新部署”生效。密钥值在任何地方都不会显示。" }),
  ], "stack", "config"));
  page.append(card(el("div", { class: "setting" }, [
    el("div", { class: "text" }, [el("h2", { text: "登录会话" }), el("span", { class: "faint", text: "关闭浏览器后自动失效，再次使用请运行 acornfox open。" })]),
    button("退出登录", "btn", logout, "退出登录"),
  ]), "", "session"));
  page.append(el("div", { class: "footer-links", dataset: { region: "links" } }, [
    el("span", { text: "AcornFox · AGPL-3.0 开源" }),
    el("a", { href: "https://acornfox.com", target: "_blank", rel: "noopener", text: "官网" }),
    el("a", { href: "https://github.com/OrbitMaker/AcornFox-rebuild", target: "_blank", rel: "noopener", text: "GitHub" }),
    el("a", { href: "https://gitee.com/VIP13390/AcornFox-rebuild", target: "_blank", rel: "noopener", text: "Gitee" }),
    el("a", { href: "https://github.com/OrbitMaker/AcornFox-rebuild/issues", target: "_blank", rel: "noopener", text: "问题反馈" }),
  ]));
}

// ---------------------------------------------------------------------------
// 应用详情
// ---------------------------------------------------------------------------

function buildApp(page) {
  const name = state.openApp;
  const listApp = state.apps.find((x) => x.name === name);
  const a = state.detail || listApp;
  page.append(el("nav", { class: "crumbs", "aria-label": "位置", dataset: { region: "crumbs" } }, [el("a", { href: "#/", text: "我的应用" }), text(" / " + name)]));
  if (!a) {
    page.append(card([el("h2", { class: "section-title", text: "找不到应用「" + name + "」" }), el("p", { class: "muted", text: "它可能已被删除。" }), linkButton("回到我的应用", "btn", "#/")], "stack", "missing"));
    return;
  }
  const st = deriveStatus(a);
  const running = isRunning(a);
  const on = a.desired !== "stopped";
  const sub = [];
  if (a.live) sub.push(`第 ${a.live.seq} 版`, deploymentSource(a.live), reasonText(a.live), timeAgo(a.live.created_at));
  else if (a.latest) sub.push(`第 ${a.latest.seq} 版`, deployStatusText(a.latest.status));
  else sub.push("还没有版本");
  if (st === "failed" && oldVersionServing(a) && a.latest) sub.push(`第 ${a.latest.seq} 版未上线`);
  const side = el("div", { class: "row" });
  if (a.url && running) side.append(el("a", { class: "btn", href: a.url, target: "_blank", rel: "noopener", text: "打开网站" }));
  side.append(el("span", { class: "run-pill" + (on && running ? " on" : "") }, [
    el("span", { text: !on ? "已停止" : st === "deploying" ? "部署中" : running ? "运行中" : "未在运行" }),
    switchNode(on, a.name + " 运行开关", () => toggleRun(a.name, on), { disabled: st === "deploying" || !!state.busy[a.name] }),
  ]));
  page.append(el("div", { class: "detail-head", dataset: { region: "head" } }, [
    el("span", { class: "app-icon lg", "aria-hidden": "true", text: firstChar(a.name) }),
    el("div", { class: "title" }, [
      el("div", { class: "row" }, [el("h1", { text: a.name }), statusBadge(st, st === "failed" && oldVersionServing(a) ? "新版本部署失败" : null)]),
      el("span", { class: "muted", text: sub.filter(Boolean).join(" · ") }),
    ]),
    side,
  ]));
  const diag = appDiagnosis(a);
  if (diag && state.detailTab !== "logs") page.append(diagSection(diag, a));
  else if (st === "deploying" && a.latest) {
    page.append(card([
      cardHead(`第 ${a.latest.seq} 版正在部署`, el("span", { class: "faint", text: deployStatusText(a.latest.status) })),
      progressNode(STEP_OF_STATUS[a.latest.status] ?? 0, null, false),
    ], "", "progress"));
  }
  const tabs = el("div", { class: "tabs", role: "tablist", "aria-label": "应用详情", dataset: { region: "tabs" } });
  for (const [k, label] of APP_TABS) {
    tabs.append(el("button", { type: "button", role: "tab", "aria-selected": state.detailTab === k ? "true" : "false", onclick: () => go(appHash(a.name, k)), text: label }));
  }
  page.append(tabs);
  const body = el("div", { class: "stack", role: "tabpanel", dataset: { region: "tab:" + state.detailTab } });
  if (!state.detail) body.append(el("p", { class: "muted", text: "正在加载…" }));
  else if (state.detailTab === "logs") body.append(card(logsTab(a), "stack"));
  else if (state.detailTab === "versions") body.append(versionsTab(a));
  else if (state.detailTab === "config") body.append(configTab(a));
  else if (state.detailTab === "db") body.append(addonsTab(a));
  else if (state.detailTab === "domains") body.append(card(domainsTab(a), "stack"));
  else body.append(overviewTab(a));
  page.append(body);
}

// missingAddon：诊断里提到缺少数据库连接、而应用还没有对应数据库时，给出一键添加。
function missingAddon(diag, a) {
  const textAll = [diag.message, diag.log_excerpt, diag.hint].join("\n");
  const has = (k) => (a.addons || []).some((x) => x.kind === k);
  if (/REDIS_URL/.test(textAll) && !has("redis")) return "redis";
  if (/DATABASE_URL/.test(textAll) && !has("postgres") && !has("mysql")) return /mysql/i.test(textAll) ? "mysql" : "postgres";
  return null;
}

function diagSection(diag, a) {
  const latest = a.latest || a.live;
  const seq = latest ? `第 ${latest.seq} 版` : "这次部署";
  const serving = oldVersionServing(a);
  const sec = el("section", { class: "diag", role: "alert", "aria-label": "部署诊断", dataset: { region: "diag" } });
  sec.append(el("div", { class: "stack" }, [
    el("span", { class: "kicker", text: "诊断 · " + seq }),
    el("h2", { text: `${seq}没有上线：${diag.message || "部署失败"}` }),
    el("span", { class: "safe", text: serving ? "用户访问不受影响，旧版本一直在服务。" : "应用还没有上线的版本。" }),
  ]));
  const step = STEP_OF_STAGE[diag.stage];
  if (step != null) sec.append(progressNode(null, step, false));
  if (diag.log_excerpt) {
    const lines = diag.log_excerpt.split("\n");
    sec.append(el("div", { class: "stack" }, [
      el("b", { text: "关键日志" }),
      el("pre", { class: "excerpt", tabindex: "0", text: lines.slice(-14).join("\n") }),
    ]));
  }
  if (diag.hint) sec.append(el("div", { class: "hint" }, [el("b", { text: "建议" }), el("span", { text: diag.hint })]));
  const kind = missingAddon(diag, a);
  const forAI = copyForAI(diag, a.name, failedDeploymentID(a));
  const row = el("div", { class: "row" });
  if (kind) row.append(button(`添加 ${ADDON_NAMES[kind]} 并重新部署`, "btn primary knob", () => addAddon(a.name, kind), `添加 ${ADDON_NAMES[kind]} 并重新部署`));
  row.append(button("复制诊断给 AI", kind ? "btn" : "btn primary", () => copyToClipboard(forAI, "已复制，粘贴给你的 AI 即可"), "复制诊断给 AI"));
  row.append(linkButton("查看完整日志", "btn ghost", appHash(a.name, "logs")));
  sec.append(row);
  sec.append(el("span", { class: "faint", text: "复制给 AI 的内容包含阶段、错误码、日志片段和建议，可直接粘贴到 Claude Code 或 Codex。" }));
  return sec;
}

function overviewTab(a) {
  const running = isRunning(a);
  const left = el("div", { class: "stack" });
  const right = el("div", { class: "stack" });

  const urls = el("div", { class: "stack" });
  for (const d of a.domains || []) {
    if (d.status === "ready") urls.append(el("div", { class: "row" }, [urlRow("https://" + d.name, running, a.name), badge("running", "HTTPS 已生效")]));
  }
  urls.append(urlRow(a.url, running && a.desired !== "stopped", a.name));
  left.append(card([cardHead("访问地址"), urls], "", "urls"));

  left.append(card([
    cardHead("资源", el("span", { class: "faint", text: `上限 ${a.memory_mb} MB 内存 · ${(a.cpu_milli / 1000).toFixed(1)} 核` })),
    running ? appMetricsPanel(a) : el("p", { class: "muted", text: "应用未运行，没有资源数据。" }),
  ], "", "resources"));

  const recent = (state.deployments || []).slice(0, 3);
  const ul = el("ul", { class: "list" });
  if (!state.deployments) ul.append(el("li", { class: "muted", text: "正在加载…" }));
  else if (!recent.length) ul.append(el("li", { class: "muted", text: "还没有部署记录。" }));
  for (const d of recent) ul.append(versionRow(d, a, true));
  left.append(card([cardHead("版本记录", linkButton("全部 →", "btn ghost sm", appHash(a.name, "versions"))), ul], "", "recent"));

  const dbl = el("ul", { class: "list" });
  const addons = a.addons || [];
  if (!addons.length) dbl.append(el("li", { class: "muted", text: "未添加数据库。需要时在“数据库”标签里打开开关。" }));
  for (const x of addons) {
    dbl.append(el("li", {}, [
      el("span", { class: "v", text: ADDON_NAMES[x.kind] || x.kind }),
      el("span", { class: "meta", text: "本机 · 已注入 " + (x.env_var || "") }),
      badge(addonBadgeCls(x.observed_state), addonStateText(x.observed_state)),
    ]));
  }
  right.append(card([cardHead("数据库", linkButton("管理 →", "btn ghost sm", appHash(a.name, "db"))), dbl], "", "db"));

  const actions = el("div", { class: "row" });
  if (a.desired === "stopped") actions.append(button("启动", "btn primary", () => actOnApp("start"), "启动应用"));
  else if (running) actions.append(button("重启", "btn", () => actOnApp("restart"), "重启应用"));
  if (a.live) actions.append(button("重新部署", "btn", () => actOnApp("redeploy"), "用当前版本重新部署"));
  if (a.live && a.live.seq > 1) actions.append(button("回退到上一版", "btn", confirmRollback, "回退到上一版"));
  actions.append(button("复制状态给 AI", "btn", () => copyToClipboard(statusForAI(a), "已复制，粘贴给你的 AI 即可"), "复制状态给 AI"));
  right.append(card([cardHead("常用操作"), actions], "", "actions"));

  const env = a.env || [];
  const secrets = env.filter((e) => e.secret).length;
  const vols = a.volumes || [];
  const kv = el("dl", { class: "kv" }, [
    el("dt", { text: "环境变量" }), el("dd", { text: env.length ? `${env.length} 个（含密钥 ${secrets} 个）` : "无" }),
    el("dt", { text: "数据目录" }), el("dd", { class: "mono", text: vols.length ? vols.map((v) => v.path).join("、") : "无" }),
    el("dt", { text: "容器端口" }), el("dd", { class: "mono", text: String(a.port || 0) }),
  ]);
  right.append(card([cardHead("配置", linkButton("查看 →", "btn ghost sm", appHash(a.name, "config"))), kv], "", "config"));

  return el("div", { class: "grid-2" }, [left, right]);
}

function addonBadgeCls(s) {
  return ({ running: "running", starting: "warning", missing: "warning", unhealthy: "error" })[s] || "stopped";
}

function versionRow(d, a, compact) {
  const li = el("li");
  li.append(el("span", { class: "v", text: "第 " + d.seq + " 版" }));
  if (d.status === "live") li.append(badge("running", "正在服务"));
  else if (d.status === "failed") li.append(badge("error", "失败"));
  else if (PENDING_STATUSES.has(d.status)) li.append(badge("deploying", deployStatusText(d.status)));
  const meta = [deploymentSource(d), reasonText(d), timeAgo(d.created_at)];
  if (d.status === "live" || d.status === "retired") meta.push(tookText(d));
  if (d.status === "failed" && d.diagnosis) meta.push("停在" + stageName(d.diagnosis.stage) + "：" + d.diagnosis.message);
  else if (!compact && d.status !== "live") meta.push(deployStatusText(d.status));
  li.append(el("span", { class: "meta", text: meta.filter(Boolean).join(" · ") }));
  return li;
}

function versionsTab(a) {
  const list = state.deployments;
  const side = a.live && a.live.seq > 1 ? button("回退到上一版", "btn sm", confirmRollback, "回退到上一版") : null;
  const ul = el("ul", { class: "list" });
  if (!list) ul.append(el("li", { class: "muted", text: "正在加载…" }));
  else if (!list.length) ul.append(el("li", { class: "muted", text: "还没有部署记录。" }));
  else for (const d of list) ul.append(versionRow(d, a, false));
  return card([
    cardHead("版本记录", side),
    ul,
    el("p", { class: "faint", text: "保留最近的版本，可回退到上一版。回退不重新构建，直接用那一版的镜像。" }),
  ], "stack");
}

function configTab(a) {
  const frag = document.createDocumentFragment();
  const env = a.env || [];
  const envList = el("ul", { class: "list envlist" });
  if (!env.length) envList.append(el("li", { class: "muted", text: "没有环境变量。" }));
  for (const e of env) {
    envList.append(el("li", {}, [
      el("span", { class: "k", text: e.key }),
      el("span", { class: "grow" }),
      e.secret ? badge("stopped", "密钥 · 已设置") : el("span", { class: "mono muted", text: e.value || "" }),
    ]));
  }
  frag.append(card([cardHead("环境变量"), envList], "", "env"));
  const vols = a.volumes || [];
  const volList = el("ul", { class: "list envlist" });
  if (!vols.length) volList.append(el("li", { class: "muted", text: "没有数据目录。重新部署时，容器里未保存到数据目录的文件会丢失。" }));
  for (const v of vols) volList.append(el("li", {}, [el("span", { class: "k", text: v.path }), el("span", { class: "grow" }), el("span", { class: "faint", text: v.auto ? "自动识别" : "手动添加" })]));
  frag.append(card([cardHead("数据目录"), volList], "", "volumes"));
  frag.append(card([cardHead("运行参数"), el("dl", { class: "kv" }, [
    el("dt", { text: "容器端口" }), el("dd", { class: "mono", text: String(a.port || 0) }),
    el("dt", { text: "访问端口" }), el("dd", { class: "mono", text: a.public_port ? String(a.public_port) : "—" }),
    el("dt", { text: "健康检查" }), el("dd", { class: "mono", text: a.health_path || "/" }),
    el("dt", { text: "内存上限" }), el("dd", { class: "mono", text: a.memory_mb + " MB" }),
    el("dt", { text: "CPU 上限" }), el("dd", { class: "mono", text: (a.cpu_milli / 1000).toFixed(1) + " 核" }),
  ])], "", "params"));
  frag.append(card([
    cardHead("怎么修改"),
    el("p", { class: "muted", text: "此处只读。在 AI 工作台里说明要改什么，或在你的电脑上运行下面的命令，改完点“重新部署”生效。密钥值不会显示或返回。" }),
    copyBlock(`acornfox env set KEY=VALUE --app ${a.name}\nacornfox env set KEY=VALUE --secret --app ${a.name}\nacornfox volume add /容器内目录 --app ${a.name}`, "命令已复制", "复制配置命令", true),
  ], "stack", "how"));
  return frag;
}

// addonsTab 是“数据库”标签。只渲染公开字段：连接地址、密码等凭据永远不进页面。
function addonsTab(a) {
  const frag = document.createDocumentFragment();
  const addons = Array.isArray(a.addons) ? a.addons : [];
  frag.append(el("p", { class: "muted", text: "需要时自动装上：应用中心的应用按模板带上，自己的项目在诊断发现缺少数据库时一键添加。每个应用独立一套，只在应用内部网络可见，密码自动生成、不会显示。" }));
  if (addons.length === 0) {
    frag.append(el("p", { text: "此应用还没有附加服务（数据库）。需要时打开下面的开关，或在终端运行：" }));
    frag.append(el("p", { class: "mono", text: "acornfox add postgres --app " + a.name }));
  }
  const kinds = ADDON_KINDS.slice();
  for (const x of addons) if (!kinds.includes(x.kind)) kinds.push(x.kind);
  for (const kind of kinds) {
    const addon = addons.find((x) => x.kind === kind);
    const label = ADDON_NAMES[kind] || kind || "附加服务";
    const conflict = !addon && (kind === "postgres" || kind === "mysql") ? addons.find((x) => (x.kind === "postgres" || x.kind === "mysql") && x.kind !== kind) : null;
    const box = el("article", { class: "addon-card", "aria-label": label + " 状态" });
    let desc = ADDON_DESC[kind] || "";
    if (!addon) desc = conflict ? `已有 ${ADDON_NAMES[conflict.kind]} 提供 DATABASE_URL，同一应用只能有其一。` : "打开即添加，已上线的应用会自动重新部署。";
    box.append(el("div", { class: "head" }, [
      el("h4", { text: label }),
      addon ? badge(addonBadgeCls(addon.observed_state), addonStateText(addon.observed_state)) : null,
      el("span", { class: "desc", text: addon ? ADDON_DESC[kind] || "" : desc }),
      switchNode(!!addon, label, () => (addon ? confirmRemoveAddon(a.name, kind) : addAddon(a.name, kind)), { disabled: !!conflict || !!state.busy[a.name + ":" + kind] }),
    ]));
    if (addon) {
      const dl = el("dl", { class: "kv" });
      for (const [k, value] of [
        ["来源", "本机容器"],
        ["镜像", addon.image || "未知"],
        ["网络内地址", addon.host ? addon.host + ":" + addon.port : "暂不可用"],
        ["注入变量", addon.env_var || "未设置"],
        ["数据卷", addon.volume_name || "未知"],
      ]) {
        dl.append(el("dt", { text: k }));
        dl.append(el("dd", { text: value }));
      }
      box.append(dl);
    }
    frag.append(box);
  }
  frag.append(el("p", { class: "faint", text: "端口仅在应用专用网络内可见。连接信息以密钥注入应用，控制台不显示密码。关闭数据库时默认保留数据，确认框里可以选择一并删除。" }));
  frag.append(el("p", { class: "faint", text: "使用外部数据库（云数据库或另一台服务器）：acornfox env set DATABASE_URL=<连接地址> --secret --app " + a.name }));
  return frag;
}

function domainsTab(a) {
  const frag = document.createDocumentFragment();
  const domains = a.domains || [];
  frag.append(cardHead("域名"));
  if (!domains.length) {
    frag.append(el("p", { class: "muted", text: "还没有绑定域名，目前通过 IP:端口 访问。" }));
  } else {
    const ul = el("ul", { class: "list" });
    for (const d of domains) {
      const cls = d.status === "ready" ? "running" : d.status === "failed" ? "error" : "warning";
      const label = ({ ready: "HTTPS 已生效", failed: "证书失败", pending: "等待证书" })[d.status] || d.status;
      ul.append(el("li", {}, [el("span", { class: "v mono", text: d.name }), badge(cls, label), el("span", { class: "meta", text: d.diagnosis && d.status === "failed" ? d.diagnosis.message : "" })]));
    }
    frag.append(ul);
    const dd = domainDiagnosis(a);
    if (dd && dd.diagnosis.hint) frag.append(el("div", { class: "hint" }, [el("b", { text: "建议" }), el("span", { text: dd.diagnosis.hint })]));
  }
  frag.append(el("p", { class: "muted", text: "绑定域名：先把域名解析到这台服务器的公网 IP，再运行下面的命令，证书会自动申请。" }));
  frag.append(copyBlock("acornfox domain add 你的域名 --app " + a.name, "命令已复制", "复制绑定域名命令", true));
  frag.append(el("p", { class: "faint", text: "中国大陆服务器的域名须已完成 ICP 备案，否则无法通过 80/443 访问；未备案时仍可用 IP:端口 访问。需要在安全组放行 80 和 443。" }));
  return frag;
}

function logsTab(a) {
  const frag = document.createDocumentFragment();
  const tail = el("select", { id: "logs-tail", "aria-label": "日志行数", onchange: (event) => {
    state.logTail = Number(event.target.value);
    refreshLogs(a.name, true);
  } });
  for (const value of [100, 500, 1000]) tail.append(el("option", { value, text: "最近 " + value + " 行" }));
  tail.value = String(state.logTail);
  const title = a.live ? `应用日志 · 第 ${a.live.seq} 版` : "应用日志";
  frag.append(el("div", { class: "log-controls" }, [
    el("h2", { class: "section-title grow", text: title }),
    button(state.logFollow ? "暂停跟随" : "跟随新日志", "btn sm" + (state.logFollow ? " primary" : ""), () => toggleLogFollow(a.name), "日志跟随开关"),
    tail,
    button("刷新", "btn sm", () => refreshLogs(a.name, true), "刷新日志"),
    button("复制给 AI", "btn sm", () => copyToClipboard(logsForAI(a), "已复制，粘贴给你的 AI 即可"), "复制最近日志给 AI"),
  ]));
  frag.append(el("p", { class: "faint", text: (state.logFollow ? "每 3 秒跟随新日志" : "已暂停跟随") + " · 最多保留 2000 行" + (a.live && a.live.seq > 1 ? ` · 当前显示第 ${a.live.seq} 版的日志；更早版本的日志已随旧容器删除。` : "") }));
  if (state.logError) frag.append(el("p", { class: "muted", role: "status", text: state.logError }));
  const pre = el("pre", { class: "logbox", tabindex: "0", role: "log", "aria-label": "应用日志" });
  if (state.logs === null) pre.textContent = "正在加载日志…";
  else if (state.logs.length === 0) pre.textContent = "暂无日志。";
  else pre.textContent = state.logs.join("\n");
  frag.append(pre);
  return frag;
}

function logsForAI(a) {
  const lines = (state.logs || []).slice(-80);
  return `这是我在 AcornFox 上的应用「${a.name}」最近 ${lines.length} 行日志，请帮我分析：\n` + lines.join("\n");
}

function meterNode(label, valueText, percent) {
  const fill = el("span");
  if (percent != null && Number.isFinite(percent)) fill.style.width = Math.min(100, Math.max(0, percent)) + "%";
  const bar = el("div", { class: "bar" + (percent != null && percent >= 80 ? " warn" : "") }, fill);
  return el("div", { class: "meter" }, [el("div", { class: "top" }, [el("span", { text: label }), el("span", { text: valueText })]), bar]);
}

function appMetricsPanel(a) {
  const metrics = state.appMetrics;
  if (!metrics) return el("p", { class: "muted", text: "资源指标：正在采样…" });
  if (metrics.available === false) return el("p", { class: "muted", text: "资源指标暂不可用（" + observedMetricText(metrics.observed_state) + "）。" });
  const cpu = metrics.cpu_available === false ? "采样中" : numberText(metrics.cpu_percent, "%");
  const cpuPct = metrics.cpu_available === false ? null : metrics.cpu_percent;
  const memory = numberText(metrics.memory_usage_mb, " MB");
  const limit = metrics.memory_limit_mb > 0 ? numberText(metrics.memory_limit_mb, " MB") : "未设置内存上限";
  const memPct = metrics.memory_limit_mb > 0 && Number.isFinite(metrics.memory_usage_mb) ? (metrics.memory_usage_mb / metrics.memory_limit_mb) * 100 : null;
  return el("section", { class: "app-metrics", "aria-label": a.name + " 当前资源指标" }, [
    meterNode("CPU（1 核 = 100%）", cpu, cpuPct),
    meterNode("内存", memory + " / " + limit, memPct),
    el("div", { class: "meter" }, el("div", { class: "top" }, [el("span", { text: "网络 接收 / 发送" }), el("span", { text: sizeText(metrics.network_rx_mb) + " / " + sizeText(metrics.network_tx_mb) })])),
    el("div", { class: "meter" }, el("div", { class: "top" }, [el("span", { text: "进程数" }), el("span", { text: Number.isFinite(metrics.pids) ? String(metrics.pids) : "不可用" })])),
  ]);
}

function observedMetricText(s) {
  return ({ stopped: "已停止", exited: "已停止", missing: "尚无容器", restarting: "正在重启", unavailable: "执行器不可用" })[s] || s || "不可用";
}

// sizeText 按大小换单位，KB 级流量也能看见。
function sizeText(mb) {
  if (!Number.isFinite(mb)) return "不可用";
  if (mb >= 1024) return (mb / 1024).toFixed(1) + " GB";
  if (mb >= 1) return mb.toFixed(1) + " MB";
  return Math.round(mb * 1024) + " KB";
}

function numberText(value, unit) {
  return Number.isFinite(value) ? value.toFixed(1) + (unit || "") : "不可用";
}

// ---------------------------------------------------------------------------
// 路由
// ---------------------------------------------------------------------------

function parseHash(h) {
  const raw = (h || "").replace(/^#/, "");
  if (raw.startsWith("app=")) return { page: "app", app: decodeURIComponent(raw.slice(4)), tab: "overview" };
  const parts = raw.replace(/^\//, "").split("/");
  const head = parts[0] || "";
  if (head === "app" && parts[1]) {
    const tab = APP_TABS.some(([k]) => k === parts[2]) ? parts[2] : "overview";
    let name = parts[1];
    try { name = decodeURIComponent(parts[1]); } catch (_) { /* 原样使用 */ }
    return { page: "app", app: name, tab };
  }
  if (["store", "server", "settings", "new"].includes(head)) return { page: head };
  return { page: "home" };
}

function go(hash) {
  if (location.hash === hash) onRoute();
  else location.hash = hash;
}

function onRoute() {
  const r = parseHash(location.hash);
  const prevApp = state.openApp;
  const prevTab = state.detailTab;
  state.route = r;
  if (r.page === "app") {
    if (r.app !== prevApp) {
      resetLogReader();
      state.openApp = r.app;
      state.detail = null;
      state.appMetrics = null;
      state.deployments = null;
      state.detailTab = r.tab;
      loadDetail(r.app);
      loadDeployments(r.app);
    } else {
      state.detailTab = r.tab;
    }
    if (prevTab === "logs" && r.tab !== "logs") {
      state.logGeneration++;
      if (logRequest) logRequest.abort();
      logRequest = null;
    }
    if (r.tab === "logs" && state.logs === null) refreshLogs(r.app);
    if (r.tab === "versions" || r.tab === "overview") loadDeployments(r.app);
  } else {
    resetLogReader();
    state.openApp = null;
    state.detail = null;
    state.appMetrics = null;
    state.deployments = null;
  }
  render();
  const key = r.page + ":" + (r.app || "");
  if (key !== prevPageKey) window.scrollTo(0, 0);
  prevPageKey = key;
}

let prevPageKey = "";

// ---------------------------------------------------------------------------
// 交互
// ---------------------------------------------------------------------------

async function loadDetail(name) {
  try {
    const [d, metrics] = await Promise.all([
      api.get(appPath(name)),
      api.get("/v1/metrics/apps/" + encodeURIComponent(name)).catch(() => ({ available: false, observed_state: "unavailable" })),
    ]);
    if (state.openApp !== name) return;
    state.detail = d;
    state.appMetrics = metrics;
    render();
  } catch (e) {
    if (e.status === 404 && state.openApp === name) { state.detail = null; render(); return; }
    handleError(e);
  }
}

async function loadDeployments(name) {
  try {
    const body = await api.get(appPath(name, "/deployments?limit=20"));
    if (state.openApp !== name) return;
    state.deployments = body.deployments || body.items || [];
    render();
  } catch (e) { if (e.status !== 404) handleError(e); }
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
    const body = await api.get(appPath(name, "/log-batch?" + query.toString()), request.signal);
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

async function withBusy(key, fn) {
  if (state.busy[key]) return;
  state.busy[key] = true;
  render();
  try { await fn(); } catch (e) { handleError(e); } finally { delete state.busy[key]; render(); }
}

async function refreshAfterAction(name) {
  await poll();
  if (state.openApp === name) { await loadDetail(name); loadDeployments(name); }
}

async function actOnApp(action, nameArg) {
  const name = nameArg || state.openApp;
  if (!name) return;
  await withBusy(name, async () => {
    await api.post(appPath(name, "/" + action), {});
    toast(({ start: "已提交启动", restart: "已提交重启", redeploy: "已提交重新部署", rollback: "已提交回退，正在部署", stop: "已提交停止" })[action] || "已提交");
    await refreshAfterAction(name);
  });
}

// toggleRun：开关从开到关要确认（默认焦点在“取消”）；从关到开直接启动。
function toggleRun(name, on) {
  if (!on) { actOnApp("start", name); return; }
  showConfirm({
    title: "停止应用",
    body: `确定要停止「${name}」吗？停止后用户将无法访问，直到重新打开开关。数据不会丢失。`,
    ok: "停止",
    action: () => actOnApp("stop", name),
  });
}

function confirmRollback() {
  const name = state.openApp;
  showConfirm({
    title: "回退到上一版",
    body: `「${name}」将用上一版的镜像重新部署，不重新构建。健康检查通过后才切换流量，失败时当前版本继续服务。`,
    ok: "回退",
    action: () => actOnApp("rollback", name),
  });
}

function addAddon(name, kind) {
  withBusy(name + ":" + kind, async () => {
    await api.post(appPath(name, "/addons"), { kind });
    toast(`已添加 ${ADDON_NAMES[kind] || kind}，应用会自动重新部署`);
    await refreshAfterAction(name);
  });
}

function confirmRemoveAddon(name, kind) {
  const label = ADDON_NAMES[kind] || kind;
  showConfirm({
    title: `关闭 ${label}`,
    body: `「${name}」将不再连接 ${label}，应用会自动重新部署。默认保留数据卷，之后重新打开可恢复原来的数据。`,
    ok: "关闭",
    check: "同时删除数据（不可恢复）",
    action: (removeData) => withBusy(name + ":" + kind, async () => {
      await api.del(appPath(name, "/addons/" + encodeURIComponent(kind) + (removeData ? "?volumes=true" : "")));
      toast(removeData ? `已关闭 ${label} 并删除数据` : `已关闭 ${label}，数据已保留`);
      await refreshAfterAction(name);
    }),
  });
}

async function logout() {
  try { await api.post("/v1/console/logout", {}); } catch (_) { /* 忽略 */ }
  state.fatal = { title: "已退出登录", body: "你已退出控制台。", again: true };
  stopPolling();
  render();
}

// ---------------------------------------------------------------------------
// 确认框与“让 AI 帮忙”
// ---------------------------------------------------------------------------

let confirmAction = null;
let lastFocus = null;

function showConfirm(o) {
  lastFocus = document.activeElement;
  $("confirm-title").textContent = o.title;
  $("confirm-body").textContent = o.body;
  $("confirm-ok").textContent = o.ok;
  $("confirm-ok").className = "btn primary";
  const extra = $("confirm-extra");
  $("confirm-check").checked = false;
  if (o.check) { $("confirm-check-label").textContent = o.check; extra.hidden = false; } else extra.hidden = true;
  confirmAction = o.action;
  $("confirm-overlay").hidden = false;
  $("confirm-dialog").hidden = false;
  // 默认焦点放在安全选项上：回车不会停止或删除任何东西。
  $("confirm-cancel").focus();
}

function hideConfirm() {
  $("confirm-overlay").hidden = true;
  $("confirm-dialog").hidden = true;
  confirmAction = null;
  if (lastFocus && lastFocus.isConnected) lastFocus.focus({ preventScroll: true });
}

function openAskAI() {
  lastFocus = document.activeElement;
  const sheet = $("sheet");
  clear(sheet);
  const items = attentionItems();
  sheet.append(el("h3", { id: "sheet-title", text: "让 AI 帮忙" }));
  sheet.append(el("p", { text: "把这句话发给 Claude Code、Codex 等 AI 工作台，它会装好 AcornFox Skill，之后部署、排错、加数据库都可以一句话完成：" }));
  sheet.append(copyBlock(SKILL_PROMPT, "已复制，发给你的 AI 即可", "复制 Skill 安装提示"));
  if (items.length) {
    const all = items.map((it) => copyForAI(it.diag, it.app, it.deploymentID)).join("\n\n");
    sheet.append(el("p", { text: `现在有 ${items.length} 项需要处理，可以一起交给 AI：` }));
    sheet.append(el("div", {}, button("复制全部问题给 AI", "btn primary", () => copyToClipboard(all, "已复制，粘贴给你的 AI 即可"), "复制全部问题给 AI")));
  }
  sheet.append(el("div", { class: "actions" }, button("关闭", "btn", closeSheet, "关闭")));
  $("sheet-overlay").hidden = false;
  sheet.hidden = false;
  sheet.querySelector("button").focus();
}

function closeSheet() {
  $("sheet-overlay").hidden = true;
  $("sheet").hidden = true;
  if (lastFocus && lastFocus.isConnected) lastFocus.focus({ preventScroll: true });
}

// ---------------------------------------------------------------------------
// 剪贴板与提示
// ---------------------------------------------------------------------------

function copyToClipboard(content, okMsg) {
  const done = () => toast(okMsg || "已复制");
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(content).then(done).catch(() => fallbackCopy(content, done));
  } else {
    fallbackCopy(content, done);
  }
}

function fallbackCopy(content, done) {
  const ta = document.createElement("textarea");
  ta.value = content;
  ta.setAttribute("readonly", "");
  ta.className = "sr-only";
  document.body.append(ta);
  ta.select();
  try {
    if (document.execCommand("copy")) done();
    else toast("复制失败，请手动复制");
  } catch (_) { toast("复制失败，请手动复制"); }
  ta.remove();
}

let toastTimer = null;
function toast(msg) {
  const t = $("toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2200);
}

// ---------------------------------------------------------------------------
// 外观
// ---------------------------------------------------------------------------

function readTheme() {
  try { return localStorage.getItem("af-theme"); } catch (_) { return null; }
}

function themeMode() {
  const saved = readTheme();
  return saved === "dark" || saved === "light" ? saved : "system";
}

function applyTheme() {
  const saved = readTheme();
  if (saved === "dark" || saved === "light") document.documentElement.dataset.theme = saved;
  else delete document.documentElement.dataset.theme;
}

function setTheme(mode) {
  try {
    if (mode === "dark" || mode === "light") localStorage.setItem("af-theme", mode);
    else localStorage.removeItem("af-theme");
  } catch (_) { /* 隐私模式 */ }
  applyTheme();
}

function toggleTheme() {
  const cur = document.documentElement.dataset.theme;
  const prefersDark = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  const effective = cur || (prefersDark ? "dark" : "light");
  setTheme(effective === "dark" ? "light" : "dark");
}

// ---------------------------------------------------------------------------
// 轮询与错误
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
    // 记下应用名：等待详情返回期间用户可能已离开详情页，state.openApp 会变成 null。
    const name = state.openApp;
    if (name) {
      await loadDetail(name);
      if (state.openApp !== name) return;
      if (state.detailTab === "overview" || state.detailTab === "versions") loadDeployments(name);
      if (state.detailTab === "logs" && state.logFollow) await refreshLogs(name);
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
    state.connectionLost = true;
    render();
    return;
  }
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
// 启动
// ---------------------------------------------------------------------------

async function boot() {
  applyTheme();
  $("theme").addEventListener("click", () => { toggleTheme(); render(); });
  $("ask-ai").addEventListener("click", openAskAI);
  $("sheet-overlay").addEventListener("click", closeSheet);
  $("confirm-cancel").addEventListener("click", hideConfirm);
  $("confirm-overlay").addEventListener("click", hideConfirm);
  $("confirm-ok").addEventListener("click", async () => {
    const action = confirmAction;
    const checked = $("confirm-check").checked;
    hideConfirm();
    if (action) await action(checked);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    if (!$("confirm-dialog").hidden) { hideConfirm(); return; }
    if (!$("sheet").hidden) closeSheet();
  });
  document.addEventListener("visibilitychange", () => { if (!document.hidden) poll(); });
  window.addEventListener("hashchange", onRoute);
  if (window.matchMedia) {
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    if (mq.addEventListener) mq.addEventListener("change", () => render());
  }

  onRoute();

  try {
    const sess = await api.session();
    if (sess && sess.server) {
      state.server = sess.server;
      document.title = "AcornFox · " + sess.server;
    }
  } catch (e) {
    if (e.status === 401) { handleError(e); return; }
    // 开发环境没有会话接口时，不影响只读轮询。
  }
  await poll();
  startPolling();
}

boot();
