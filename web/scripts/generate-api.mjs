import { existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const webRoot = resolve(fileURLToPath(new URL('..', import.meta.url)));
const schemaPath = resolve(
  process.env.OPEN_CARD_OPENAPI ?? `${webRoot}/../api/openapi/openapi.yaml`,
);
const outputPath = resolve(webRoot, 'src/api/generated-schema.ts');

if (!existsSync(schemaPath)) {
  console.log(`OpenAPI source not found at ${schemaPath}. Keeping the checked-in typed API stub.`);
  console.log('Provide api/openapi/openapi.yaml (or OPEN_CARD_OPENAPI) before generating the live client.');
  process.exit(0);
}

mkdirSync(resolve(webRoot, 'src/api'), { recursive: true });
const binary = resolve(webRoot, 'node_modules/.bin/openapi-typescript');
const result = spawnSync(binary, [schemaPath, '-o', outputPath], {
  cwd: webRoot,
  stdio: 'inherit',
});

if (result.error) {
  console.error(`Unable to run openapi-typescript: ${result.error.message}`);
  process.exit(1);
}
process.exit(result.status ?? 1);
