import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const webRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const schemaPath = resolve(
  process.env.OPEN_CARD_OPENAPI ?? `${webRoot}/../api/openapi/openapi.yaml`,
);
const outputPath = resolve(webRoot, 'src/api/generated-schema.ts');
const check = process.argv.slice(2).includes('--check');

if (!existsSync(schemaPath)) {
  console.error(`OpenAPI source not found at ${schemaPath}.`);
  process.exit(1);
}

mkdirSync(resolve(webRoot, 'src/api'), { recursive: true });
const binary = resolve(webRoot, 'node_modules/.bin/openapi-typescript');
const temporaryDirectory = check ? mkdtempSync(resolve(tmpdir(), 'open-card-openapi-')) : null;
const generatedPath = check ? resolve(temporaryDirectory, 'generated-schema.ts') : outputPath;
const result = spawnSync(binary, [schemaPath, '-o', generatedPath], {
  cwd: webRoot,
  stdio: 'inherit',
});

if (result.error) {
  console.error(`Unable to run openapi-typescript: ${result.error.message}`);
  process.exit(1);
}
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
if (check) {
  try {
    if (!existsSync(outputPath) || readFileSync(outputPath, 'utf8') !== readFileSync(generatedPath, 'utf8')) {
      console.error('Generated OpenAPI schema is stale. Run npm --prefix web run generate:api.');
      process.exitCode = 1;
    }
  } finally {
    rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}
