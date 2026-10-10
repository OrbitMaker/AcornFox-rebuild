// acornfox.com：复制按钮、地区切换、首屏开关演示。
(function () {
  "use strict";

  // 复制按钮：data-copy 指向要复制的元素。
  function copyText(text, btn) {
    function done() {
      var old = btn.textContent;
      btn.textContent = "已复制";
      btn.classList.add("done");
      setTimeout(function () { btn.textContent = old; btn.classList.remove("done"); }, 1600);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { fallback(text, done); });
    } else { fallback(text, done); }
  }
  function fallback(text, done) {
    var ta = document.createElement("textarea");
    ta.value = text; ta.setAttribute("readonly", ""); ta.className = "sr-only";
    document.body.appendChild(ta); ta.select();
    try { if (document.execCommand("copy")) done(); } catch (e) { /* 手动复制 */ }
    ta.remove();
  }
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var target = document.querySelector(btn.getAttribute("data-copy"));
      if (target) copyText(target.textContent.trim(), btn);
    });
  });

  // 地区切换。
  document.querySelectorAll(".tabs").forEach(function (tabs) {
    var scope = tabs.parentElement;
    tabs.querySelectorAll("[data-tab]").forEach(function (b) {
      b.addEventListener("click", function () {
        tabs.querySelectorAll("[data-tab]").forEach(function (x) { x.setAttribute("aria-selected", x === b ? "true" : "false"); });
        scope.querySelectorAll("[data-panel]").forEach(function (p) { p.hidden = p.getAttribute("data-panel") !== b.getAttribute("data-tab"); });
      });
    });
  });

  // 首屏演示：拨开开关，应用经过五步上线；再拨一下停止。
  var sw = document.getElementById("demo-switch");
  if (!sw) return;
  var badge = document.getElementById("demo-badge");
  var sub = document.getElementById("demo-sub");
  var hint = document.getElementById("demo-hint");
  var url = document.getElementById("demo-url");
  var steps = Array.prototype.slice.call(document.querySelectorAll("#demo-steps li"));
  var reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var timer = null;

  function setBadge(cls, text) { badge.className = "badge" + (cls ? " " + cls : ""); badge.textContent = text; }
  function paint(i) {
    steps.forEach(function (li, k) { li.className = k < i ? "done" : k === i ? "now" : ""; });
  }
  function stop() {
    clearTimeout(timer);
    sw.setAttribute("aria-checked", "false");
    sw.disabled = false;
    setBadge("", "已停止");
    sub.textContent = "从你的项目目录部署";
    hint.textContent = "拨一下试试";
    url.className = "demo-url";
    url.textContent = "部署成功后显示访问地址";
    paint(-1);
  }
  function run() {
    sw.setAttribute("aria-checked", "true");
    sw.disabled = true;
    setBadge("busy", "部署中");
    sub.textContent = "第 1 版 · 上传";
    hint.textContent = "正在部署…";
    var i = 0;
    var names = ["上传", "构建", "启动", "健康检查", "切换流量"];
    function next() {
      if (i < steps.length) {
        paint(i);
        sub.textContent = "第 1 版 · " + names[i];
        i++;
        timer = setTimeout(next, reduce ? 0 : 520);
        return;
      }
      paint(steps.length);
      setBadge("on", "运行中");
      sub.textContent = "第 1 版 · 上传 · 刚刚";
      hint.textContent = "再拨一下就停止";
      url.className = "demo-url live";
      url.textContent = "http://203.0.113.10:18810";
      sw.disabled = false;
    }
    next();
  }
  sw.addEventListener("click", function () {
    if (sw.getAttribute("aria-checked") === "true") stop(); else run();
  });
  // 打开页面时自动演示一次。
  if (!reduce) setTimeout(function () { if (sw.getAttribute("aria-checked") === "false") run(); }, 900);
})();
