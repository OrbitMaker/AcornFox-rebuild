import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { test } from "node:test";

const webRoot = fileURLToPath(new URL("..", import.meta.url));
const node = process.execPath;
const vite = join(webRoot, "node_modules", "vite", "bin", "vite.js");
const source = {
  ACORNFOX_RELEASE_VERSION: "1.2.3-rc.1",
  ACORNFOX_SOURCE_REPOSITORY: "https://github.com/acme/acornfox-fixture",
  ACORNFOX_SOURCE_COMMIT: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  VITE_API_MODE: "live",
  VITE_API_BASE_URL: "/api/v1",
};

function run(overrides = {}) {
  return spawnSync(node, [vite, "build", "--mode", "acornfox-release"], {
    cwd: webRoot,
    encoding: "utf8",
    env: { ...process.env, ...source, ...overrides },
  });
}
function failed(result) { assert.notEqual(result.status, 0, `${result.stdout}\n${result.stderr}`); }

test("release mode emits exact release metadata", async () => {
  const result = run();
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  const metadata = JSON.parse(await readFile(join(webRoot, "dist", "build-metadata.json"), "utf8"));
  assert.deepEqual(metadata, {
    apiBaseUrl: "/api/v1",
    mode: "acornfox-release",
    releaseId: "release-1.2.3-rc.1",
    schemaVersion: "acornfox-release-build-attestation.v1",
    sourceCommit: source.ACORNFOX_SOURCE_COMMIT,
    sourceRepository: source.ACORNFOX_SOURCE_REPOSITORY,
    version: source.ACORNFOX_RELEASE_VERSION,
  });
});

for (const overrides of [
  { ACORNFOX_RELEASE_VERSION: "bad" },
  { ACORNFOX_SOURCE_REPOSITORY: "https://example.test/acme/repo" },
  { ACORNFOX_SOURCE_COMMIT: "A".repeat(40) },
  { ACORNFOX_RELEASE_EXTRA: "x" },
  { VITE_API_MODE: "stub" },
]) {
  test(`release mode rejects invalid identity ${Object.keys(overrides)[0]}`, () => failed(run(overrides)));
}
