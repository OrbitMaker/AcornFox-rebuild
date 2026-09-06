# AcornFox final host acceptance in progress

This report distinguishes the internal candidate, installed behavior, public behavior and final publication. Evidence is under `.omx/evidence/aliyun-mvp-20260905/`; no credentials belong in this report.

## Verified internal artifacts and installed substrate

The source snapshot `803832f6ddbe6824205bd8ef74c7e1bc6abe015c` produced an installer-verified bootstrap `0.1.0-beta.0` and successor `0.1.0-beta.1` on the dedicated Alibaba Ubuntu 24.04 amd64 host.

- Bootstrap binding: `6ea1b0d6222ac64ee8291ec1ab81b4b35a4cedd619729f0658b71708fc45b923`; offline build 94.92 seconds.
- Successor binding: `ede6d70f28694e0c5e834b2433cad5b883fb4bafa7dc1c36e38ee10b6959f830`; offline build 93.22 seconds, exact predecessor bound.
- First installation completed all 34 migrations, runtime generation, service enable/start and the installer local health gate. An old task-owned `/run/acornfox-runtime-network` witness was separately identified against its archived owner record and retired; no validator was weakened to accept it.
- The bundled dynamically linked runc executed a real Dockerfile RUN inside the installed rootless BuildKit worker and exported an OCI archive. This isolated runtime proof does not substitute for the application API chain.

## Actual upgrade interruption and boot recovery

The upgrade was interrupted at the persisted `SWITCHED` phase. MainPID ended with SIGKILL (status 9); the journal and ingress marker remained. A systemd auxiliary-process signal error in the test harness did not negate the observed main-process termination.

After an actual host reboot, the prepare and finalize units succeeded, the journal reached `ROLLED_BACK`, the marker was removed, and the old binding was restored. Application ID/name rows and all five runtime certificate/key digests matched the pre-upgrade snapshot. A subsequent explicit retry of the same candidate returned `UPGRADED` and the expected successor binding.

This round had retained application records but no running application container. It is not the final application-continuity acceptance. The final public bootstrap will be tested with a running application and a private successor before publication.

## Failures caught before publication

- Actual public TLS succeeded, but a browser received an empty HTTP 200. The edge retained the public Host while the internal Caddy site matched only `127.0.0.1`. The console-only Host rewrite was fixed in `a596c459`; Origin/CSRF and application Host are preserved.
- The runtime publisher still counted seven files after HTTPS added an eighth file. `9dc0f17d` derives the exact count from the validated intent; missing or unknown files remain rejected.
- A test client's 240-second timeout cancelled a slow Docker Hub build. The old API left its build row `running`; `d6de8e1a` gives terminal failure persistence its own bounded context and retains safe diagnostic categories. The production CLI already had a ten-minute deploy budget.
- Identical public Git transport inputs sometimes succeeded in about two seconds and sometimes exceeded the original limit. `987af14a` keeps DNS/TLS/object/process limits and sets a two-minute Git phase plus a three-minute create-app client budget.
- A literal control-character range in `ContainsAny` accidentally rejected hyphenated Git refs. `da808a69` accepts normal hyphens while rejecting leading options and all existing unsafe characters. This API resolves named branches/tags to immutable commits; a raw commit was not a supported lookup in the tested version.
- Source extraction discarded executable bits, and private build-context modes leaked into image COPY permissions. `b8c07add` preserves executable semantics, keeps snapshots read-only, strips special bits, and normalizes only the subtree beneath the private run root for Docker COPY. Existing bad snapshots are not rewritten.
- Git archive parsing stopped at logical tar EOF before draining record padding. A real producer regression timed out after two seconds; `5dc807d5` drains only bounded zero padding before waiting and terminates the process group on errors/cancellation. This proven pipe defect is not asserted to explain every network timeout.

The published repository contains reviewed application-example branches and the exact earlier candidate source e54f981e on a candidate-only branch. No platform main, beta tag or final release assets have been published. The official static runc was replaced by an independently built dynamic candidate; 605 exact notices and native build/copyright materials are recorded in source.

## Verification scope

The R3/R4 integrated Linux suite passed, including 120.631 seconds of targeted install/upgrade tests, frontend lint/typecheck, 177 Vitest tests and six Node release-build tests. Subsequent source/application/CLI integration tests and vet passed after the permission, cancellation and archive changes. Independent GPT-6 reviews approved the changes.

An earlier full install suite reached its 900-second total budget while constructing an existing runtime-configuration fault fixture. It was not counted as a passing full suite, and the old matrix was not repeatedly rerun. Final package installation, running-app continuity, full public enable/disable/restart, final source URL readback and immutable beta publication remain separate gates.

## Later exact beta1 application acceptance and new failures

The e54f981e source bootstrap binding cc750c53c49ed6f31560b4708cd68668fe06b1a7ed0935143cd7f2c206d69dc4 installed normally. A temporary read-only HTTPS smart Git fixture on the same host supplied reviewed source f78b7df2922b7af805a398a3e108bed1828928ae. Product DNS/pinning/TLS/source bounds were unchanged. Import took 0.58 seconds, the real Dockerfile RUN/build 0.86 seconds, and the application returned internal HTTP200. Exact Caddy baseline was restored after import.

A normal Agent HTTP probe then wrote a real responded200 observation; public application TLS, original Host, enable/disable404/re-enable and container restart passed. The missing probe prerequisite originally surfaced as a misleading404. The source now supplies an explicit UI/CLI response-check action and a409 readiness error while keeping foreign-resource404 and endpoint checks.

Recreate produced a new running container but reallocated its loopback port37869to43267. The existing owned route retained the old port and returned502. This is an unresolved release gate until the same-deployment replacement preserves its port lease and passes real public readback.

The exact beta1/privatebeta2 transaction was killed at persisted SWITCHED with the application still running and DB/key facts unchanged. After a real reboot (boot0c9c1a7d-af49-4774-baf0-bfeb7bf9c29d), recovery/finalize both succeeded and journal reached ROLLED_BACK; the original application container was stopped and its internal HTTP port refused connections. Guard-ordered restoration has since been implemented and independently reviewed, but only a newly built exact package and another real reboot can close that gate.
