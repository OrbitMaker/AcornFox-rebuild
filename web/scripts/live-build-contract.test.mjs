import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const webRoot = new URL('..', import.meta.url);
const webPath = fileURLToPath(webRoot);
const npmCommand = process.platform === 'win32' ? 'npm.cmd' : 'npm';

function runNpmScript(script, variables = {}) {
  const env = { ...process.env };
  for (const [key, value] of Object.entries(variables)) {
    if (value === undefined) {
      delete env[key];
    } else {
      env[key] = value;
    }
  }

  return spawnSync(npmCommand, ['run', script], {
    cwd: webPath,
    encoding: 'utf8',
    env,
  });
}

async function readMetadata(directory) {
  const content = await readFile(join(webPath, directory, 'build-metadata.json'), 'utf8');
  return JSON.parse(content);
}

function assertFailed(result, label) {
  assert.notEqual(result.status, 0, `${label} unexpectedly succeeded\n${result.stdout}\n${result.stderr}`);
}

test('production build succeeds only with the Live same-origin contract', async () => {
  const result = runNpmScript('build', {
    VITE_API_MODE: 'live',
    VITE_API_BASE_URL: '/api/v1',
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);

  const metadata = await readMetadata('dist');
  assert.deepEqual(metadata, {
    mode: 'live',
    apiBaseUrl: '/api/v1',
    schemaVersion: 'open-card-build-attestation.v1',
  });
});

test('production build fails when VITE_API_MODE is missing', () => {
  const result = runNpmScript('build', {
    VITE_API_MODE: undefined,
    VITE_API_BASE_URL: '/api/v1',
  });
  assertFailed(result, 'missing mode production build');
});

test('production build fails when VITE_API_BASE_URL is missing', () => {
  const result = runNpmScript('build', {
    VITE_API_MODE: 'live',
    VITE_API_BASE_URL: undefined,
  });
  assertFailed(result, 'missing API base production build');
});

test('production build fails for Stub mode', () => {
  const result = runNpmScript('build', {
    VITE_API_MODE: 'stub',
    VITE_API_BASE_URL: '/api/v1',
  });
  assertFailed(result, 'stub production build');
});

test('production build fails for an unsupported mode', () => {
  const result = runNpmScript('build', {
    VITE_API_MODE: 'preview',
    VITE_API_BASE_URL: '/api/v1',
  });
  assertFailed(result, 'unsupported mode production build');
});

for (const apiBaseUrl of ['http://api.example.test/api/v1', 'https://api.example.test/api/v1']) {
  test(`production build fails for an external API URL (${apiBaseUrl.split(':', 1)[0]})`, () => {
    const result = runNpmScript('build', {
      VITE_API_MODE: 'live',
      VITE_API_BASE_URL: apiBaseUrl,
    });
    assertFailed(result, 'external API production build');
  });
}

test('production build fails for an unsupported VITE environment variable', () => {
  const result = runNpmScript('build', {
    VITE_API_MODE: 'live',
    VITE_API_BASE_URL: '/api/v1',
    VITE_API_TOKEN: 'redacted-test-value',
  });
  assertFailed(result, 'unsupported VITE environment variable production build');
});

test('explicit Stub build succeeds in an isolated output with a Stub attestation', async () => {
  const result = runNpmScript('build:stub');
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);

  const metadata = await readMetadata('dist-stub');
  assert.deepEqual(metadata, {
    mode: 'stub',
    apiBaseUrl: '/api/v1',
    schemaVersion: 'open-card-build-attestation.v1',
  });
});
