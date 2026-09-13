# macOS Verified-FD Native Launch Layer

## 1. Overview & Architectural Role

The Darwin native launch layer (`internal/darwinlaunch`) provides a secure, verified execution bridge on macOS for launching AcornFox Host Controllers and Host Launchers without introducing pathname races (TOCTOU) or depending on external helper processes.

On Darwin, unlike Linux `/proc/self/fd/3`, file descriptors cannot be executed directly via `fexecve`. Executing an executable requires a filesystem path. However, passing or reopening raw filesystem paths breaks verified inode continuity and exposes the system to symlink/path-swap attacks.

The Darwin native launch layer solves this by:
1. Receiving an already verified open file descriptor (`verifiedFD`) from trusted controller/slot callbacks.
2. Materializing those exact bytes into a private, unpredictable current-user runtime directory.
3. Building an exact public `SecRequirement` binding Apple anchor, Team ID, child identifier, and exact dynamic `CDHash`.
4. Launching the materialized binary suspended (`POSIX_SPAWN_START_SUSPENDED`), strictly checking return codes of all attributes and file actions before spawn, validating raw `p_stat == SSTOP (4)` and dynamic guest code signature before releasing the suspended process.
5. Establishing a single lifecycle owner (`ChildRegistry`) that manages process reaping, capped pipe drains, cooperative EOF stops, and fallback termination.
6. Supporting a compile-time test distribution build variant (`acornfox_test_distribution`) for real test commands, while production builds remain strictly locked to Developer ID / Team ID / `CS_RUNTIME`.

## 2. Verified FD Authority & Continuity

Native execution consumes pre-verified file descriptors live during callback execution:
- **Controller Launch**: Consumed from `desktopupdate.OpenActiveControllerReadOnly(ctx, opts, func(ctx, target, fd))`. The slot lock and root pins remain live throughout the callback. The verified FD is consumed inside the callback and never reopened afterward.
- **Launcher Lifecycle**: Consumed via `HostSlotView.WithLauncherFD(ctx, func(fd, id))`. The view opens the launcher through `v.root`, checks asset permissions, verifies the signed SHA256 and size against the bundle manifest, checks Mach-O arm64 headers, and closes the FD when the callback returns. Reopening `LauncherPath` is forbidden.

Any path replacement, symlink insertion, mode drift, hard link creation, or content tampering causes immediate failure closed.

## 3. Private Runtime Materialization

Because Darwin requires a path for `posix_spawn`, the native launcher materializes an exact copy into:
```
~/Library/Application Support/AcornFox/native-launch/session-<unpredictable-hex>/acornfox-guest
```
(In the test distribution build variant, an isolated directory is used: `~/Library/Application Support/AcornFox/test-distribution-launch`).

Materialization sequence:
1. Source FD is read via `ReadAt` starting at offset zero in 64 KiB chunks, checking context cancellation on each iteration.
2. Bytes are streamed into an exclusively created destination file (`O_RDWR|O_CREAT|O_EXCL`, initially `0600`).
3. SHA256 digest and byte count are computed on the fly and verified against source stats.
4. `destFD.Sync()` fsyncs destination FD, `destFD.Chmod(0500)` sets permissions, and session directory is opened, fsynced, and closed with strict error propagation.
5. Destination stat checks enforce regular file, current UID ownership (`st.Uid == geteuid()`), mode `0500`, and single link (`st.Nlink == 1`).
6. Pinned destination FD is re-read from offset zero to verify hash equality against `SourceIdentity`, checking cancellation on each iteration.
7. Immediate pre-spawn `SameFile` and stat recheck guarantees no race occurred prior to spawn.

The materialized file and session directory are kept private and pinned until the child process is confirmed reaped. Upon confirmed exit, the session directory and executable are removed.

## 4. Public Apple Security & posix_spawn Pipeline

The implementation uses exclusively standard, public Apple SDK APIs:
- `<spawn.h>`: `posix_spawn`, `posix_spawnattr_*`, `posix_spawn_file_actions_*` with `POSIX_SPAWN_START_SUSPENDED`, `POSIX_SPAWN_SETPGROUP`, explicit signal defaults/masks, and file actions mapping `/dev/null` (STDIN), pipes (STDOUT/STDERR), and lifecycle socket (FD 3).
  - Every single attribute setter and file action call is checked; any failure immediately destroys allocated structures and aborts before `posix_spawn`.
- `<sys/sysctl.h>`: `sysctl(KERN_PROC_PID)` strictly checking raw `p_stat == SSTOP (4)`.
- `<Security/Security.h>` & `<CoreFoundation/CoreFoundation.h>`:
  - `SecCodeCopySelf` / `SecCodeCopySigningInformation`: Extracts host Team ID and enforces `CS_RUNTIME` without ad-hoc flags.
  - `SecStaticCodeCreateWithPath` / `SecStaticCodeCheckValidity`: Strict static validation with `kSecCSCheckAllArchitectures | kSecCSStrictValidate`.
  - `SecRequirementCreateWithString`: Compiles exact public requirement (`anchor apple generic and certificate leaf[subject.OU] = "<TeamID>" and identifier "<id>" and cdhash H"<cdhash>"`). There is no designated-requirement fallback.
  - `SecCodeCopyGuestWithAttributes` / `SecCodeCheckValidity`: Dynamic validation of suspended guest against the exact compiled requirement.
- Zero private symbols, zero `csops` syscalls, and zero external Swift helpers.

## 5. Child Ownership & Lifecycle Boundary

Every child process spawned by `internal/darwinlaunch` is owned exclusively by `ChildRegistry`:
- **Single Waiter Goroutine**: Exactly one goroutine executes `waitpid` per PID, handling `EINTR` retries and non-ECHILD error supervision.
- **Two-Phase Spawn**: `PrepareController` / `PrepareSlotLauncher` returns a truly suspended child (`*PreparedChild`). Admission is written to `ParentLifecycle()`, and `Resume()` re-verifies registry ownership, raw `SSTOP (4)`, destination inode/uid/nlink/mode status, and dynamic validity before sending `SIGCONT`.
- **Retryable Abort & Retained Child Errors**: If `Abort()` fails or is interrupted by SIGKILL denial/timeout, `p.aborted` is not marked terminal; the live owner is preserved in `ChildRetainedError`, enabling caller retries.
- **Capped Concurrent Pipe Drains**: STDOUT and STDERR have concurrent drains capped at 64 KiB, preventing long-running child processes from blocking on full OS pipe buffers. `Wait()` synchronizes drains before reading buffers, and `ExitResult` explicitly exposes `StdoutTruncated` and `StderrTruncated`.
- **Cooperative EOF Stop**: Calling `Stop(ctx)` closes the parent lifecycle socket endpoint, signaling cooperative shutdown to the child. If the child does not exit within bounded timeouts, direct-child `SIGTERM` and `SIGKILL` fallbacks are applied. Unrelated process groups are never signaled.
- **Durable Retention on Fault**: If kernel kill or wait operations fail, the child is retained in `ChildRegistry` with a typed error; cleanup is only executed upon confirmed reap.

## 6. Compile-Time Test Distribution Variant

Per user authorization (`MAC-TEST-DISTRIBUTION-AUTHORIZATION.md`), Mac acceptance proceeds with an explicit test distribution build variant rather than production certificates:
- Build tag: `acornfox_test_distribution`.
- In default production build:
  - `DistributionMode = "production"`
  - `PrepareController` and `PrepareSlotLauncher` strictly reject ad-hoc code signatures and require verified Team ID / Developer ID / `CS_RUNTIME`.
  - `PrepareTestDistributionController` and `PrepareTestDistributionSlotLauncher` return `ErrTestDistributionUnavailable`.
- In test distribution build (`-tags acornfox_test_distribution`):
  - `DistributionMode = "test-distribution"`
  - `PrepareTestDistributionController` and `PrepareTestDistributionSlotLauncher` are compiled in, utilizing fixed test identifiers (`com.acornfox.test.host-update`, `com.acornfox.test.host-launcher`) and an isolated test directory.
  - Ad-hoc code signatures are permitted only in this compile-time variant.
  - Zero CLI, environment, or JSON downgrade switches exist for the production constructors.
  - Both variants share the exact same underlying verified-FD streaming, SSTOP verification, exact CDHash requirement, ChildRegistry ownership, and EOF stop logic.

## 7. Acceptance Verification Matrix

| Acceptance Item | Description | Status | Evidence |
| :--- | :--- | :--- | :--- |
| **P1. Spawn Attributes/Actions Check** | posix_spawn attribute & dup2 return codes checked before spawn; 8 injected failure paths fail closed without spawning | Verified | `TestDarwinLaunch_P1_PosixSpawnAttributeAndActionFailures` |
| **P1. PreparedChild Retryable Abort** | Abort terminal only after confirmed reap; SIGKILL failure preserves retryable owner via `ChildRetainedError` | Verified | `TestDarwinLaunch_P1_PreparedChildAbortRetryAndRetainedError` |
| **P1. Post-Spawn Failure Owner Preservation** | Inode drift during Resume with kill denial preserves owner; subsequent retry reaps cleanly | Verified | `TestDarwinLaunch_P1_ResumePostSpawnFailurePreservesOwner` |
| **P1. Real Path Swap Matrix (Case 5)** | Valid replacement binary validated against original CDHash requirement fails (-67050); corrupted binary fails; registry empty | Verified | `TestDarwinLaunch_Case5_PathSwapAndReplacementMatrix` |
| **P1. Real Lock & Admission (Case 7)** | `OpenActiveControllerReadOnly` holds slot lock during callback; admission written only AFTER callback returns and unlock | Verified | `TestDarwinLaunch_Case7_AdmissionOrderingWithSlotLock` |
| **P2. Context Cancellation Boundaries** | Copy and rehash loops check ctx; pre-cancelled context fails closed with zero files/PIDs left behind | Verified | `TestDarwinLaunch_P2_ContextCancellationDuringMaterialization` |
| **P2. Pipe Drain Join & Truncation** | Concurrent pipe drains joined before buffer read; 256 KiB flood capped at 64 KiB with `StdoutTruncated == true` | Verified | `TestDarwinLaunch_Case9_FaultInjectionAndStalledStdout` |
| **1. Controller FD Continuity** | `OpenActiveControllerReadOnly` consumes live FD; path replacement during callback cannot alter executed bytes | Verified | `TestOpenActiveControllerReadOnly_FDContinuity` |
| **2. WithLauncherFD Verification** | `WithLauncherFD` validates signed identity, mode, owner, nlink, CPU; path/inode/content drift rejected | Verified | `TestHostSlotExecutableWithLauncherFD_ContinuityAndIdentity`, `TestHostSlotExecutableWithLauncherFD_FailClosedOnDrift` |
| **3. Path Isolation** | No source path passed into `darwinlaunch` or retained across callbacks | Verified | Design & API signature verification |
| **4. Correct Fixture Lifecycle** | Benign arm64 fixture: raw `p_stat=4`, exact requirement passes, zero marker before `Resume`, exits cleanly and reaped | Verified | `TestDarwinLaunch_Case4_CorrectFixtureLifecycle` |
| **6. Production Rejection of Ad-Hoc** | Default production constructors reject ad-hoc, empty Team ID, and missing `CS_RUNTIME` | Verified | `TestDarwinLaunch_Case6_ProductionRejectionOfAdHocAndMismatchedTeamID` |
| **8. Lifecycle EOF Cooperative Stop** | Parent EOF on lifecycle socket triggers child cooperative stop; child cleanly reaped | Verified | `TestDarwinLaunch_Case8_LifecycleEOFCooperativeStop` |
| **9. Fault Injection & Bounded Pipes** | Injected SIGKILL denial and waitpid failure retain child; retry reaps cleanly; 256 KiB stdout drain does not stall | Verified | `TestDarwinLaunch_Case9_FaultInjectionAndStalledStdout` |
| **10. Parallel Prepare Independence** | Concurrent prepare operations maintain separate PIDs, unique session directories, and independent owners | Verified | `TestDarwinLaunch_Case10_ParallelPrepareIndependentOwnership` |
| **11. Public Security APIs (No csops)** | `go tool nm` and source scan prove public Security/posix_spawn APIs only; zero `csops` symbols | Verified | `TestDarwinLaunch_Case11_SymbolScanNoCsops` |
| **Distribution Variant** | Production build rejects test constructors; `acornfox_test_distribution` tag enables test constructors | Verified | `TestDarwinLaunch_DistributionVariant` |
| **12. Production Developer ID** | Real Developer ID code signing, hardened runtime, and production Team ID validation | Pending | User authorized test-distribution acceptance first (`security find-identity` returns 0) |
| **13. Real Controller Selection** | Production bootstrap controller selection wiring on signed Darwin binaries | Pending | Blocked on Developer ID signed release binaries |
| **14. Native VM / GUI Integration** | Full HostSlots VM startup and GUI handoff | Pending | Future integration phase (out of scope for packet41) |

## 8. Threat Boundary & Same-UID Peer Limitations

Suspended spawn, private 0700 runtime directories, and exact `SecRequirement` validation provide strong protection against ordinary filesystem races, symlink substitution, and unprivileged tampering.

However, as demonstrated in Packet 36 Case 4:
- On macOS, any process running under the **exact same UID** possesses the POSIX capability to send signals (including `SIGCONT`) to peer processes.
- While `Resume()` re-checks raw `p_stat == 4` and dynamic guest validity immediately before sending `SIGCONT`, a compromised same-UID adversary can theoretically send `SIGCONT` during the microsecond window between spawn and validation.
- Therefore, suspended-spawn is not an OS capability boundary against same-UID peers. True isolation against compromised peer processes on the host requires distinct user accounts (separate UIDs) or App Sandbox / virtualization boundaries.
