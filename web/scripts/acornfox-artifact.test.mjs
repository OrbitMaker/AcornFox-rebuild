import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../dist/", import.meta.url));

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

test("production artifact contains only AcornFox identity and no retired entrypoints or features", async () => {
  const output = await files(root);
  assert.ok(output.length > 0, "build output is missing");
  const content = await Promise.all(
    output
      .filter((file) => !file.endsWith(".map"))
      .map((file) => readFile(file, "utf8")),
  );
  const combined = content.join("\n");

  // Positive AcornFox branding check
  assert.match(combined, /AcornFox/);

  // User-visible branding check (distinguish legitimate repository URLs from visible branding)
  const nonUrlCombined = combined.replace(/https?:\/\/[^\s"'`<>]+/g, "");
  assert.doesNotMatch(
    nonUrlCombined,
    /open[ -]?card/i,
    "production artifact leaked old-product identity (Open Card)",
  );
  assert.doesNotMatch(
    combined,
    /m0-m7|m2-m6/i,
    "production artifact leaked retired milestone references",
  );
  assert.doesNotMatch(
    combined,
    /\brollback\b/i,
    "production artifact leaked retired rollback navigation",
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

  // Exact entrypoint requirement
  assert.ok(projectSources.includes("../../src/main.tsx"), "main.tsx must be included");

  // Exact approved project-module allowlist (acornfox entry + reviewed shared modules)
  const allowedSharedSources = new Set([
    "../../src/shared/Account.tsx",
    "../../src/shared/HelpDialog.tsx",
    "../../src/shared/Login.tsx",
    "../../src/shared/MenuBar.tsx",
    "../../src/shared/ReleaseSourceLink.tsx",
    "../../src/shared/Setup.tsx",
    "../../src/shared/Toast.tsx",
    "../../src/shared/auth-transport.ts",
    "../../src/shared/useDesktopPresentation.ts",
  ]);

  const unapproved = projectSources.filter(
    (source) =>
      !source.includes("/src/acornfox/") &&
      !source.endsWith("/src/main.tsx") &&
      !allowedSharedSources.has(source),
  );
  assert.equal(
    unapproved.length,
    0,
    `unapproved project source entered artifact: ${unapproved.join(", ")}`,
  );

  // Explicit exclusion of retired entrypoints and legacy business packages
  const retiredModulePatterns = [
    /\/src\/App\.tsx$/,
    /styles\/global/,
    /\/src\/api\/client/,
    /\/src\/api\/generated-schema/,
    /\/src\/features\//,
    /\/src\/components\//,
    /\/src\/domain\//,
    /\/src\/core\//,
    /Assistant/,
    /ai-interventions/,
    /AIServiceSettings/,
    /action-polling/,
    /stream-recovery/,
  ];

  for (const source of projectSources) {
    for (const pattern of retiredModulePatterns) {
      assert.doesNotMatch(
        source,
        pattern,
        `retired entrypoint or module entered artifact: ${source}`,
      );
    }
  }

  // Precise checks in source content for retired assistant/simulator features
  const projectContent = map.sourcesContent
    .filter((_, index) => map.sources[index].includes("/src/"))
    .join("\n");

  const retiredContentPatterns = [
    /import.*Assistant/,
    /ai-floating-container/,
    /ai-chat-window/,
    /chat-send-btn/,
    /assistantScope/,
    /assistantAppNames/,
  ];

  for (const pattern of retiredContentPatterns) {
    assert.doesNotMatch(
      projectContent,
      pattern,
      `clean product source leaked retired assistant/simulator feature: ${pattern}`,
    );
  }
});
