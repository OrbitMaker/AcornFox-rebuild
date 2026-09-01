# AcornFox root Dockerfile definition — AFB-DEF-02

Status: local module and workspace-fixture evidence only. It does not claim a
build, container runtime, internal response, public access, host, external or
customer acceptance.

## Result

For one immutable `SourceRevision`, AcornFox reads exactly
`WorkspaceRef/Dockerfile` (capital D, repository root), verifies the workspace
content digest before and after the read, and returns a deterministic read-only
definition. It never executes Docker, BuildKit, Compose, AI or source code, and
does not persist a second canonical store.

The result is one of:

- `ready`: root Dockerfile was safely parsed; explicit gaps can still describe
  unobserved external base configuration, variable expansion or sensitive ENV.
- `waiting_later`: no root Dockerfile; the only result gap is
  `root_dockerfile_missing`.
- `unsupported`: symlink/non-regular/oversized Dockerfile, heredoc or syntax
  that cannot be safely parsed, or malformed projected instruction.

## Projected facts

The definition carries source revision/content digest, Dockerfile and canonical
definition digests, stage count/final stage/platform, final effective WORKDIR,
ENTRYPOINT/CMD form, sorted TCP/UDP EXPOSE declarations, ordinary ENV defaults,
redacted sensitive ENV names, HEALTHCHECK (including `NONE`), SHELL, and sorted
gaps/warnings. EXPOSE declarations are candidates only: this leaf never chooses
an internal or public/default port.

The final stage is selected from a multi-stage Dockerfile. If its `FROM` names
an earlier stage, effective configuration is inherited deterministically. A
base image remains unobserved configuration; no image pull or metadata lookup
happens here. RUN/COPY/ADD/USER/LABEL/VOLUME/STOPSIGNAL and other non-projected
instructions become deterministic warnings rather than silently disappearing.
An ENTRYPOINT set in a child stage clears an inherited CMD unless that child
stage supplies its own CMD. Relative WORKDIR is resolved with POSIX path
semantics only when the inherited workdir is known; otherwise it is omitted
with `workdir_external_base_unresolved`.

Before the first `FROM`, only a syntactically safe global `ARG` is accepted.
FROM expansion becomes an explicit gap rather than an inferred base. The only
leading directives accepted are default-safe syntax/escape directives (with
whitespace/case normalized); duplicate, `check`, custom frontend, non-default
escape and unknown directives are unsupported. If no local/inherited health
exists, a scratch ancestry yields `healthcheck_missing`; an external base yields
`healthcheck_external_base_unobserved` instead. HEALTHCHECK duration/retry
options, when specified, must be positive and bounded.

## Safety boundary and exclusions

- The root Dockerfile must be regular, non-symlink and at most 1 MiB.
- Workspace hash mismatch fails closed; the importer does not write or change
  modes in the source tree.
- Sensitive ENV values never enter JSON or errors when the ENV name matches the
  conservative name policy (`TOKEN`, `PASSWORD`/`PASS`, `SECRET`, `KEY`,
  `CREDENTIAL`, `ACCESS`, `SESSION`, `SSH`, `CERT`, `DSN`, `DATABASE_URL` and
  related underscore forms). This is name-policy redaction, not content-based
  secret detection. Unresolved `$` expansions become named gaps, not invented
  values.
- Non-default parser directives, unsupported FROM flags, quoted ENV forms,
  heredocs and unknown Dockerfile instructions are unsupported rather than
  partially interpreted. The default `# syntax=docker/dockerfile:1` and
  `# escape=\` directives are the only accepted leading directives.
- Root Dockerfile only. Nested Dockerfiles, Compose, private source inputs,
  archives/OCI, BuildKit, runtime, probes, database persistence, API/Web/CLI,
  DNS/cloud and AI are outside this leaf.

## Local verification

```bash
go test -count=1 ./internal/contracts ./internal/importers/dockerfile
go test -race -count=1 ./internal/contracts ./internal/importers/dockerfile
go vet ./internal/contracts ./internal/importers/dockerfile
```

The fixture tests prove deterministic canonical JSON/digest, multi-stage
inheritance, JSON/shell commands, continuation/comments, EXPOSE ordering,
sensitive redaction, HEALTHCHECK variants, missing/symlink/oversized/mutated
workspaces and unsupported heredoc handling. They are not external acceptance.
