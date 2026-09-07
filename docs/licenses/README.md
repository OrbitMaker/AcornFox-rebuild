# AcornFox dependency notices

AcornFox source is licensed under AGPL-3.0-only. The complete license text is
`AGPL-3.0-only.txt`. Bundled dependencies retain their own terms.

`licenses-manifest.json` contains the version, public source URL, complete
upstream license/notice material, and its SHA-256 for each recorded component.
`LicenseRef-<sha256>` preserves an exact upstream notice set without inferring a
single license expression for mixed material. The same text is embedded in the
release SPDX document's extracted licensing information.

`THIRD_PARTY_NOTICES.md` indexes those materials. The manifest covers Go and
frontend dependencies and modules from the bundled BuildKit, RootlessKit,
Caddy, and rebuilt runc binaries. An inventory entry is not an assertion that
every source file in that module is present in the compiled output.

The Ubuntu 24.04 runc build uses the host's shared libseccomp and libc. Those
shared libraries are not copied into the AcornFox archive. Their package
versions and the runc source/build recipe are documented in the source
repository's `docs/acornfox/runtime-build.md`. Original static buildkit-runc is
not included in this release payload.

The Pi coding-agent entry records the pinned v0.85.1 upstream MIT license.
Its standalone archive checksum and exact runtime file inventory are pinned
separately by `internal/pibundle`. Bundled Pi dependencies still require their
own applicable notice audit before RC-SUPPLY-001 can pass.
