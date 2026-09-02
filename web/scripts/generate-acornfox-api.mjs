import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createConfig, lint } from '@redocly/openapi-core';

const webRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const schemaPath = resolve(webRoot, '../api/openapi/acornfox.yaml');
const outputPath = resolve(webRoot, 'src/api/acornfox-generated-schema.ts');
const binary = resolve(webRoot, 'node_modules/.bin/openapi-typescript');
const check = process.argv.slice(2).includes('--check');

if (!existsSync(schemaPath)) {
  console.error(`AcornFox OpenAPI source not found at ${schemaPath}.`);
  process.exit(1);
}

async function lintOpenAPI() {
  // The minimal ruleset still validates the OpenAPI 3.0 structural schema,
  // without turning documentation preferences into a release blocker.
  const config = await createConfig({ extends: ['minimal'] });
  const problems = await lint({ ref: schemaPath, config });
  const errors = problems.filter((problem) => problem.severity === 'error');
  if (errors.length === 0) return;
  for (const problem of errors) {
    const pointer = problem.location?.[0]?.pointer ?? '#';
    console.error(`AcornFox OpenAPI ${problem.ruleId} at ${pointer}: ${problem.message}`);
  }
  process.exit(1);
}

await lintOpenAPI();
mkdirSync(resolve(webRoot, 'src/api'), { recursive: true });
const temporaryDirectory = check ? mkdtempSync(resolve(tmpdir(), 'acornfox-openapi-')) : null;
const generatedPath = check ? resolve(temporaryDirectory, 'acornfox-generated-schema.ts') : outputPath;
const result = spawnSync(binary, [schemaPath, '-o', generatedPath], { cwd: webRoot, stdio: 'inherit' });
if (result.error) {
  console.error(`Unable to run openapi-typescript: ${result.error.message}`);
  process.exit(1);
}
if (result.status !== 0) process.exit(result.status ?? 1);
if (check) {
  try {
    if (!existsSync(outputPath) || readFileSync(outputPath, 'utf8') !== readFileSync(generatedPath, 'utf8')) {
      console.error('Generated AcornFox OpenAPI schema is stale. Run npm --prefix web run generate:acornfox-api.');
      process.exitCode = 1;
    }
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}
