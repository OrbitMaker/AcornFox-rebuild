import { loadEnv, defineConfig, type Plugin } from 'vite';

const LIVE_API_MODE = 'live';
const STUB_API_MODE = 'stub';
const API_BASE_URL = '/api/v1';
const BUILD_SCHEMA_VERSION = 'open-card-build-attestation.v1';
const ALLOWED_CLIENT_ENV = new Set(['VITE_API_MODE', 'VITE_API_BASE_URL']);

export type BuildContract = {
  apiBaseUrl: string;
  apiMode: typeof LIVE_API_MODE | typeof STUB_API_MODE;
};

export function resolveBuildContract(mode: string, env: Record<string, string | undefined>): BuildContract {
  const localMode = mode === 'development' || mode === 'test';
  const apiMode = env.VITE_API_MODE?.trim() || (localMode ? STUB_API_MODE : undefined);
  const apiBaseUrl = env.VITE_API_BASE_URL?.trim() || (localMode ? API_BASE_URL : undefined);
  const unexpectedEnv = Object.keys(env).filter((key) => !ALLOWED_CLIENT_ENV.has(key));

  if (unexpectedEnv.length > 0) {
    throw new Error(`Unsupported VITE_* build variables: ${unexpectedEnv.join(', ')}.`);
  }

  if (mode === 'production' && apiMode !== LIVE_API_MODE) {
    throw new Error('Production build requires VITE_API_MODE=live. Stub builds must use npm run build:stub.');
  }
  if (apiMode !== LIVE_API_MODE && apiMode !== STUB_API_MODE) {
    throw new Error('VITE_API_MODE must be exactly live or stub.');
  }
  if (apiBaseUrl !== API_BASE_URL) {
    throw new Error(`VITE_API_BASE_URL must be the same-origin path ${API_BASE_URL}.`);
  }

  return { apiMode, apiBaseUrl };
}

function buildAttestationPlugin(contract: BuildContract): Plugin {
  return {
    name: 'open-card-build-attestation',
    apply: 'build',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'build-metadata.json',
        source: `${JSON.stringify(
          {
            mode: contract.apiMode,
            apiBaseUrl: contract.apiBaseUrl,
            schemaVersion: BUILD_SCHEMA_VERSION,
          },
          null,
          2,
        )}\n`,
      });
    },
  };
}

export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_');
  const contract = resolveBuildContract(mode, env);

  return {
    plugins: command === 'build' ? [buildAttestationPlugin(contract)] : [],
    build: {
      emptyOutDir: true,
      outDir: contract.apiMode === STUB_API_MODE ? 'dist-stub' : 'dist',
      sourcemap: true,
      target: 'es2022',
    },
  };
});
