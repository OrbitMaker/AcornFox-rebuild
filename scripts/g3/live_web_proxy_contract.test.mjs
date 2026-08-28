import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { resolve } from 'node:path';

const proxy = resolve('scripts/g3/live_web_proxy.mjs');

function runWithApi(api) {
  return spawnSync(process.execPath, [proxy, '--listen', '127.0.0.1:58084', '--api', api, '--web-root', '/tmp/gate3-web-root', '--cert', '/tmp/gate3-cert', '--key', '/tmp/gate3-key'], { encoding: 'utf8' });
}

test('rejects an API origin without an explicit high port', () => {
  const result = runWithApi('http://127.0.0.1:80');
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /explicit high port/);
});

test('rejects API origins outside the task-local loopback boundary', () => {
  const result = runWithApi('https://example.test:58083');
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /loopback HTTP origin/);
});
