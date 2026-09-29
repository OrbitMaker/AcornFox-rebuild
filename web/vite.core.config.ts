import { loadEnv, defineConfig, type Plugin } from "vite";
import { resolve } from "node:path";
import {
  resolveBuildContract,
  resolveReleaseContract,
  type BuildContract,
  type ReleaseContract,
} from "./vite.config";

const LIVE_API_MODE = "live";
const STUB_API_MODE = "stub";
const API_BASE_URL = "/api/v1";
const CORE_BUILD_SCHEMA_VERSION = "acornfox-core-build-attestation.v1";
const CORE_RELEASE_SCHEMA_VERSION = "acornfox-core-release-build-attestation.v1";

function coreBuildAttestationPlugin(
  contract: BuildContract,
  release?: ReleaseContract,
): Plugin {
  return {
    name: "acornfox-core-build-attestation",
    apply: "build",
    generateBundle() {
      this.emitFile({
        type: "asset",
        fileName: "build-metadata.json",
        source: `${JSON.stringify(
          release
            ? {
                apiBaseUrl: contract.apiBaseUrl,
                mode: LIVE_API_MODE,
                product: "acornfox-core",
                releaseId: release.releaseId,
                schemaVersion: CORE_RELEASE_SCHEMA_VERSION,
                sourceCommit: release.sourceCommit,
                sourceRepository: release.sourceRepository,
                version: release.version,
              }
            : {
                mode: contract.apiMode,
                product: "acornfox-core",
                apiBaseUrl: contract.apiBaseUrl,
                schemaVersion: CORE_BUILD_SCHEMA_VERSION,
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
  if (
    release &&
    (contract.apiMode !== LIVE_API_MODE || contract.apiBaseUrl !== API_BASE_URL)
  ) {
    throw new Error(
      "acornfox-release requires the Live same-origin API contract.",
    );
  }

  return {
    cacheDir: resolve(import.meta.dirname, ".vite-cache"),
    define: {
      __ACORNFOX_RELEASE_SOURCE__: JSON.stringify(
        release
          ? {
              version: release.version,
              url: `${release.sourceRepository}/tree/${release.sourceCommit}`,
            }
          : null,
      ),
    },
    plugins:
      command === "build"
        ? [coreBuildAttestationPlugin(contract, release)]
        : [],
    build: {
      emptyOutDir: true,
      outDir: contract.apiMode === STUB_API_MODE ? "dist-core-stub" : "dist-core",
      sourcemap: true,
      target: "es2022",
      rollupOptions: {
        input: {
          core: resolve(import.meta.dirname, "core.html"),
        },
      },
    },
  };
});
