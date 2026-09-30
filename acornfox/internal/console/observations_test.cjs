// Dependency-free DOM/model checks. Browser layout is verified separately.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Node {
  constructor(tag = '') { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.events = {}; this.dataset = {}; this.style = {}; this._text = ''; }
  setAttribute(key, value) { this.attrs[key] = String(value); }
  getAttribute(key) { return this.attrs[key]; }
  addEventListener(key, callback) { this.events[key] = callback; }
  append(...nodes) { this.children.push(...nodes); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(node => typeof node === 'string' ? node : node.textContent).join(''); }
}

function setup(fetcher = async () => ({ ok: true, json: async () => ({ lines: [], cursor: '' }) })) {
  const context = vm.createContext({
    document: { createElement: tag => new Node(tag), createTextNode: text => { const node = new Node(); node.textContent = text; return node; }, createDocumentFragment: () => new Node(), getElementById: () => null },
    fetch: fetcher, AbortController, URLSearchParams, setTimeout, clearTimeout, setInterval, clearInterval, console,
  });
  let source = fs.readFileSync(path.join(__dirname, 'static/app.js'), 'utf8');
  source = source.replace(/\nboot\(\);\s*$/, '\n');
  vm.runInContext(source, context);
  vm.runInContext('render = () => {}; state.openApp = "shop";', context);
  return expression => vm.runInContext(expression, context);
}

function plain(value) { return JSON.parse(JSON.stringify(value)); }

test('log batches preserve repeated content and carry cursor', async () => {
  const urls = [];
  const batches = [{ lines: ['same', 'same'], cursor: 'first' }, { lines: ['same'], cursor: 'second' }];
  const run = setup(async url => { urls.push(url); return { ok: true, json: async () => batches.shift() }; });
  await run('refreshLogs("shop")');
  await run('refreshLogs("shop")');
  assert.deepEqual(plain(run('state.logs')), ['same', 'same', 'same']);
  assert.ok(urls[1].includes('cursor=first'));
  assert.equal(run('state.logCursor'), 'second');
});

test('deployment reset replaces prior displayed logs', async () => {
  const run = setup(async () => ({ ok: true, json: async () => ({ lines: ['new'], cursor: 'new', reset: true }) }));
  run('state.logs = ["old"]; state.logCursor = "old";');
  await run('refreshLogs("shop")');
  assert.deepEqual(plain(run('state.logs')), ['new']);
});

test('pausing aborts in-flight polling without a false error', async () => {
  const run = setup((url, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => { const error = new Error('cancelled'); error.name = 'AbortError'; reject(error); });
  }));
  run('state.logFollow = true;');
  const request = run('refreshLogs("shop")');
  run('toggleLogFollow("shop")');
  await request;
  assert.equal(run('state.logFollow'), false);
  assert.equal(run('state.logError'), null);
});

test('log controls expose pause, tail and keyboard-accessible text', () => {
  const run = setup();
  run('state.logs = ["<script>not HTML</script>"]; state.logFollow = true;');
  const panel = run('logsTab({name:"shop"})');
  assert.ok(panel.textContent.includes('暂停跟随'));
  assert.ok(panel.textContent.includes('最近 1000 行'));
  assert.ok(panel.textContent.includes('<script>not HTML</script>'));
  assert.equal(panel.children.at(-1).attrs.tabindex, '0');
});

test('metrics report unavailable, sampling and unlimited accurately', () => {
  const run = setup();
  run('state.appMetrics = {available:false, observed_state:"stopped"};');
  assert.ok(run('appMetricsPanel({name:"shop"}).textContent').includes('已停止'));
  run('state.appMetrics = {available:true, cpu_available:false, memory_usage_mb:64, memory_limit_mb:0, network_rx_mb:0, network_tx_mb:0, pids:1};');
  const panel = run('appMetricsPanel({name:"shop"}).textContent');
  assert.ok(panel.includes('采样中'));
  assert.ok(panel.includes('未设置内存上限'));
  assert.ok(!panel.includes('NaN') && !panel.includes('Infinity'));
});
