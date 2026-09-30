const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

class Node {
  constructor(tag = '') { this.tagName = tag.toUpperCase(); this.children = []; this.attrs = {}; this.events = {}; this.dataset = {}; this.style = {}; this._text = ''; }
  setAttribute(key, value) { this.attrs[key] = String(value); }
  addEventListener(key, callback) { this.events[key] = callback; }
  append(...nodes) { this.children.push(...nodes); }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(node => typeof node === 'string' ? node : node.textContent).join(''); }
}
function renderAddon(addons) {
  const context = vm.createContext({ document: { createElement: tag => new Node(tag), createTextNode: text => { const node = new Node(); node.textContent = text; return node; }, createDocumentFragment: () => new Node(), getElementById: () => null } });
  vm.runInContext(fs.readFileSync(path.join(__dirname, 'static/app.js'), 'utf8').replace(/\nboot\(\);\s*$/, '\n'), context);
  context.input = { name: 'shop', addons };
  return vm.runInContext('addonsTab(input)', context);
}

test('empty addons provide accurate CLI hint', () => {
  const panel = renderAddon([]);
  assert.ok(panel.textContent.includes('还没有附加服务'));
  assert.ok(panel.textContent.includes('acornfox add postgres --app shop'));
});

test('addon status and public metadata are present without credentials', () => {
  const panel = renderAddon([{ kind: 'postgres', observed_state: 'starting', image: 'postgres:16-alpine', host: 'af-shop-addon-postgres', port: 5432, env_var: 'DATABASE_URL', volume_name: 'af-shop-addon-postgres-data', credentials: 'must-never-render', password: 'secret-password', url: 'postgres://secret@host/db' }]);
  for (const text of ['PostgreSQL', '初始化中', 'postgres:16-alpine', 'af-shop-addon-postgres:5432', 'DATABASE_URL', 'af-shop-addon-postgres-data']) assert.ok(panel.textContent.includes(text), text);
  for (const secret of ['must-never-render', 'secret-password', 'postgres://secret']) assert.ok(!panel.textContent.includes(secret), secret);
});

test('all six observed states render as explicit text', () => {
  const states = { running: '运行中', starting: '初始化中', unhealthy: '未就绪', stopped: '已停止', missing: '等待创建', unavailable: '无法读取状态' };
  for (const [state, text] of Object.entries(states)) assert.ok(renderAddon([{kind:'redis',observed_state:state}]).textContent.includes(text), state);
});

test('malicious public metadata remains literal text', () => {
  const literal = '<img src=x onerror=alert(1)>';
  const panel = renderAddon([{kind:'mysql',observed_state:'unavailable',image:literal,host:literal,port:3306,env_var:'DATABASE_URL',volume_name:literal}]);
  assert.ok(panel.textContent.includes(literal));
  function allTags(node) { return [node.tagName, ...node.children.flatMap(child => typeof child === 'string' ? [] : allTags(child))]; }
  assert.ok(!allTags(panel).includes('IMG'));
});
