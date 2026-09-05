import { loadEnv, defineConfig, type Plugin } from "vite";

const LIVE_API_MODE = "live";
const STUB_API_MODE = "stub";
const API_BASE_URL = "/api/v1";
const BUILD_SCHEMA_VERSION = "acornfox-build-attestation.v1";
const RELEASE_SCHEMA_VERSION = "acornfox-release-build-attestation.v1";
const RELEASE_MODE = "acornfox-release";
const ALLOWED_CLIENT_ENV = new Set(["VITE_API_MODE", "VITE_API_BASE_URL"]);
const RELEASE_ENV_KEYS = new Set([
  "ACORNFOX_RELEASE_VERSION",
  "ACORNFOX_SOURCE_REPOSITORY",
  "ACORNFOX_SOURCE_COMMIT",
]);
const SEMVER = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?(\+[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$/;
const COMMIT = /^[a-f0-9]{40}$/;
const REPOSITORY = /^https:\/\/github\.com\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/;

export type BuildContract = {
  apiBaseUrl: string;
  apiMode: typeof LIVE_API_MODE | typeof STUB_API_MODE;
};
export type ReleaseContract = {
  releaseId: string;
  sourceCommit: string;
  sourceRepository: string;
  version: string;
};

export function resolveReleaseContract(
  mode: string,
  env: Record<string, string | undefined>,
): ReleaseContract | undefined {
  const supplied = Object.keys(env).filter(
    (key) => key.startsWith("ACORNFOX_RELEASE_") || key.startsWith("ACORNFOX_SOURCE_"),
  );
  const unknown = supplied.filter((key) => !RELEASE_ENV_KEYS.has(key));
  if (unknown.length > 0) {
    throw new Error(`Unsupported AcornFox release variables: ${unknown.join(", ")}.`);
  }
  if (mode !== RELEASE_MODE) {
    if (supplied.length > 0) {
      throw new Error("AcornFox release/source variables are valid only in acornfox-release mode.");
    }
    return undefined;
  }
  const version = env.ACORNFOX_RELEASE_VERSION;
  const sourceRepository = env.ACORNFOX_SOURCE_REPOSITORY;
  const sourceCommit = env.ACORNFOX_SOURCE_COMMIT;
  if (!version || !sourceRepository || !sourceCommit || !SEMVER.test(version) || !REPOSITORY.test(sourceRepository) || !COMMIT.test(sourceCommit)) {
    throw new Error("acornfox-release requires canonical version, GitHub repository, and lowercase 40-hex source commit.");
  }
  return { version, releaseId: `release-${version}`, sourceRepository, sourceCommit };
}

export function resolveBuildContract(
  mode: string,
  env: Record<string, string | undefined>,
): BuildContract {
  const localMode = mode === "development" || mode === "test";
  const apiMode =
    env.VITE_API_MODE?.trim() || (localMode ? STUB_API_MODE : undefined);
  const apiBaseUrl =
    env.VITE_API_BASE_URL?.trim() || (localMode ? API_BASE_URL : undefined);
  const unexpectedEnv = Object.keys(env).filter(
    (key) => !ALLOWED_CLIENT_ENV.has(key),
  );

  if (unexpectedEnv.length > 0) {
    throw new Error(
      `Unsupported VITE_* build variables: ${unexpectedEnv.join(", ")}.`,
    );
  }

  if (mode === "production" && apiMode !== LIVE_API_MODE) {
    throw new Error(
      "Production build requires VITE_API_MODE=live. Stub builds must use npm run build:stub.",
    );
  }
  if (apiMode !== LIVE_API_MODE && apiMode !== STUB_API_MODE) {
    throw new Error("VITE_API_MODE must be exactly live or stub.");
  }
  if (apiBaseUrl !== API_BASE_URL) {
    throw new Error(
      `VITE_API_BASE_URL must be the same-origin path ${API_BASE_URL}.`,
    );
  }

  return { apiMode, apiBaseUrl };
}

function buildAttestationPlugin(contract: BuildContract, release?: ReleaseContract): Plugin {
  return {
    name: "acornfox-build-attestation",
    apply: "build",
    generateBundle() {
      this.emitFile({
        type: "asset",
        fileName: "build-metadata.json",
        source: `${JSON.stringify(
          release
            ? {
                apiBaseUrl: contract.apiBaseUrl,
                mode: RELEASE_MODE,
                releaseId: release.releaseId,
                schemaVersion: RELEASE_SCHEMA_VERSION,
                sourceCommit: release.sourceCommit,
                sourceRepository: release.sourceRepository,
                version: release.version,
              }
            : {
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
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const contract = resolveBuildContract(mode, env);
  const release = resolveReleaseContract(mode, process.env);
  if (release && (contract.apiMode !== LIVE_API_MODE || contract.apiBaseUrl !== API_BASE_URL)) {
    throw new Error("acornfox-release requires the Live same-origin API contract.");
  }

  return {
    plugins: command === "build" ? [buildAttestationPlugin(contract, release)] : [],
    build: {
      emptyOutDir: true,
      outDir: contract.apiMode === STUB_API_MODE ? "dist-stub" : "dist",
      sourcemap: true,
      target: "es2022",
    },
  };
});
