# Task-scoped OCI registry fixture

`registry_fixture.py` implements the minimum OCI Distribution read path needed
by the M2 ImageResolver test:

* `GET /v2/` returns `200`.
* `GET /v2/<repository>/manifests/<tag-or-digest>` returns an OCI manifest.
* `GET /v2/<repository>/blobs/<digest>` returns the config or layer blob.
* public repositories are readable without authentication.
* private repositories require `Authorization: Basic ...`; a wrong token is
  rejected before any manifest is returned.
* `POST /__control/move-tag` is loopback-only and requires a separate
  task-local control token;
  it changes a tag mapping but never changes an existing digest.

The server creates four small scratch images from the canonical static-server
binary supplied by the clean-worker bundle.  It emits its repository and
digest map as JSON to the runner's evidence directory.  It never logs the
Basic-auth token.  The runner removes the server data and token file before
the VM is reclaimed.

The registry is an acceptance fixture, not a production registry.  It must
remain task-prefixed, loopback-only, and stopped after the run.
