import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../dist/", import.meta.url));
const forbidden = [
  /open[ -]?card/i,
  /m0-m7/i,
  /m2-m6/i,
  /rollback/i,
  /\bscale\b/i,
  /rolling/i,
  /\brequired\b/i,
  /\boptional\b/i,
  /\bai\b/i,
  /\busage\b/i,
  /\bwebhook\b/i,
  /\bvolume\b/i,
  /\bdatabase\b/i,
  /\bcompose\b/i,
  /\barchive\b/i,
  /private[ -]?git/i,
  /deferred/i,
];

async function files(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) =>
      entry.isDirectory()
        ? files(join(directory, entry.name))
        : [join(directory, entry.name)],
    ),
  );
  return nested.flat();
}

test("production artifact contains only AcornFox identity and no deferred navigation", async () => {
  const output = await files(root);
  assert.ok(output.length > 0, "build output is missing");
  const content = await Promise.all(
    output
      .filter((file) => !file.endsWith(".map"))
      .map((file) => readFile(file, "utf8")),
  );
  const combined = content.join("\n");
  assert.match(combined, /AcornFox/);
  for (const pattern of forbidden.slice(0, 4))
    assert.doesNotMatch(
      combined,
      pattern,
      `production artifact leaked ${pattern}`,
    );
  const maps = output.filter((file) => file.endsWith(".map"));
  assert.equal(
    maps.length,
    1,
    "clean entry should produce one traceable bundle map",
  );
  const map = JSON.parse(await readFile(maps[0], "utf8"));
  const projectSources = map.sources.filter((source) =>
    source.includes("/src/"),
  );
  assert.ok(projectSources.includes("../../src/main.tsx"));
  assert.ok(
    projectSources.every(
      (source) =>
        source.includes("/src/acornfox/") || source.endsWith("/src/main.tsx"),
    ),
    `legacy project source entered artifact: ${projectSources.join(", ")}`,
  );
  for (const source of projectSources)
    assert.doesNotMatch(
      source,
      /\/src\/App\.tsx$|styles\/global|\/src\/api\/client/,
      `legacy project source entered artifact: ${source}`,
    );
  const projectContent = map.sourcesContent
    .filter((_, index) => map.sources[index].includes("/src/"))
    .join("\n");
  for (const pattern of forbidden)
    assert.doesNotMatch(
      projectContent,
      pattern,
      `clean product source leaked ${pattern}`,
    );
});
