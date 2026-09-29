declare const __ACORNFOX_RELEASE_SOURCE__: { version: string; url: string } | null | undefined;

export function ReleaseSourceLink() {
  const release = typeof __ACORNFOX_RELEASE_SOURCE__ === "undefined" ? null : __ACORNFOX_RELEASE_SOURCE__;
  return release ? (
    <a className="af-source-link" href={release.url} target="_blank" rel="noopener noreferrer">
      v{release.version} · 对应源码
    </a>
  ) : null;
}
