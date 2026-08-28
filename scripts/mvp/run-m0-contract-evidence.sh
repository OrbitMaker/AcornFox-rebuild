#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

go_cache="${OPEN_CARD_M0_GOCACHE:-/tmp/opencard-m0-evidence-go-cache}"

record_go_test() {
  local test_id="$1"
  local package="$2"
  local test_name="$3"
  local description="$4"

  python3 tools/evidence/record_command.py \
    --milestone m0 \
    --test-id "$test_id" \
    --description "$description" \
    --evidence-type unit_test \
    --evidence-type deterministic_result \
    -- \
    env GOCACHE="$go_cache" go test -count=1 "$package" -run "^${test_name}$" -v
}

record_go_test UNIT-SRC-001 ./internal/foundation TestUnitSRC001NormalizeGitLocatorAndRef \
  "Normalize HTTPS and SSH Git locators and refs; reject unsafe schemes."
record_go_test UNIT-SRC-002 ./internal/foundation TestUnitSRC002DigestUploadTree \
  "Create stable upload-tree digests and detect content changes."
record_go_test UNIT-ARCHIVE-001 ./internal/foundation TestUnitARCHIVE001SafetyClassification \
  "Reject archive traversal, links, special files, count and size excess without extraction."
record_go_test UNIT-REDACT-001 ./internal/foundation TestUnitREDACT001SecretsAndEncodedVariants \
  "Redact tokens, passwords, cookies, known secrets, and encoded variants."
record_go_test UNIT-WEBHOOK-001 ./internal/foundation TestUnitWEBHOOK001SignatureVectorAndReplay \
  "Verify deterministic HMAC, timestamp, event ID, and replay-window behavior."
record_go_test UNIT-USAGE-001 ./internal/foundation TestUnitUSAGE001AggregateAveragePeakTrend \
  "Aggregate fixed usage samples into exact average, peak, and trend values."
record_go_test UNIT-AI-001 ./internal/foundation TestUnitAI001FingerprintCacheAndVersionKeys \
  "Keep AI problem, cache, and version keys stable and version-separated."
record_go_test UNIT-STATE-001 ./internal/domain TestUNIT_STATE_001_StateMachinesRejectIllegalTransitions \
  "Reject illegal Release, Deployment, and Operation transitions including lease and cancellation states."
record_go_test UNIT-DAG-001 ./internal/domain TestUNIT_DAG_001_And_002_ServiceDependencyOrderRejectsCycles \
  "Produce stable dependency order for an acyclic ServiceGroup."
record_go_test UNIT-DAG-002 ./internal/domain TestUNIT_DAG_001_And_002_ServiceDependencyOrderRejectsCycles \
  "Reject cyclic ServiceGroup dependencies."

record_go_test SCHEMA-DEF-001 ./internal/domain TestSCHEMA_DEF_001_DefinitionRejectsAutomaticFactWithoutMetadata \
  "Reject automatic definition facts without source evidence metadata."
record_go_test SCHEMA-DEF-002 ./internal/domain TestSCHEMA_DEF_002_DefinitionSeparatesFactsObservationsAndRecommendations \
  "Keep configuration facts, observations, and recommendations separate."
record_go_test SCHEMA-RELEASE-001 ./internal/domain TestSCHEMA_RELEASE_001_ReleaseIsImmutableAndDigestSetIsCopied \
  "Keep complete Release digest sets immutable and alias-safe."
record_go_test SCHEMA-SERVICE-001 ./internal/domain TestSCHEMA_SERVICE_001_ServiceSourceIsAnExactTaggedUnion \
  "Require exactly one matching static, Dockerfile, or prebuilt service source."
record_go_test SCHEMA-COMP-001 ./internal/domain TestSCHEMA_COMP_001_ComposeSupportedSubsetMapsToControlledServiceGroup \
  "Map the supported Compose subset into the controlled ServiceGroup model."
record_go_test SCHEMA-COMP-002 ./internal/domain TestSCHEMA_COMP_002_ComposeUnknownFieldsFailClosedWithPath \
  "Reject unknown and unsafe Compose fields with exact source paths."
record_go_test SCHEMA-OP-001 ./internal/domain TestSCHEMA_OP_001_OneActiveOperationPerEnvironment \
  "Reject more than one active Operation for the same environment at the domain boundary."
record_go_test SCHEMA-ROUTE-001 ./internal/domain TestSCHEMA_ROUTE_001_RouteUniquenessAndIngressTarget \
  "Reject duplicate host/path routes and non-ingress route targets."
record_go_test SCHEMA-AI-001 ./internal/domain TestSCHEMA_AI_001_AIActionPlanRequiresBoundedActionSchema \
  "Require bounded tool, version, risk, validation, and rollback fields in AIActionPlan."
record_go_test SCHEMA-AI-002 ./internal/domain TestSCHEMA_AI_002_RuleCandidateRequiresReviewTestsAndVersionedPromotion \
  "Prevent RuleCandidate promotion without review, tests, versioning, and evaluation evidence."

record_go_test CT-BUILD-001 ./internal/contracts TestCT_BUILD_001_FakeBuildIsIdempotentAndEvidenceBacked \
  "Exercise fake BuildProvider success, classified failure, cancellation, timeout, cleanup, and evidence."
record_go_test CT-IMAGE-001 ./internal/contracts TestCT_IMAGE_001_FakeImagePinsDigestAndProtectsDeletion \
  "Exercise fake ImageStore digest pinning, retention, and protected deletion."
record_go_test CT-RUNTIME-001 ./internal/contracts TestCT_RUNTIME_001_FakeRuntimeLifecycleIsIdempotent \
  "Exercise fake RuntimeDriver deploy, observe, logs, restart, scale, rollback, destroy, and idempotency."
record_go_test CT-VOLUME-001 ./internal/contracts TestCT_VOLUME_001_FakeVolumeRetainsByDefaultAndRequiresConfirmation \
  "Exercise fake VolumeProvider retain-by-default and confirmed destructive deletion."
record_go_test CT-ROUTE-001 ./internal/contracts TestCT_ROUTE_001_FakeRouteHasDesiredActualEvidenceAndIdempotency \
  "Exercise fake RouteProvider apply, observe, remove, rebuild, and desired/actual evidence."
record_go_test CT-SECRET-001 ./internal/contracts TestCT_SECRET_001_FakeSecretNeverReturnsPlaintextAndMountsAreRevocable \
  "Exercise fake SecretProvider reference-only API, idempotent mount, and revoke behavior."
record_go_test CT-METER-001 ./internal/contracts TestCT_METER_001_FakeMeterDeduplicatesAndQueriesWindow \
  "Exercise fake MeterProvider duplicate, late-sample, window, and conflict behavior."
record_go_test CT-NOTIFY-001 ./internal/contracts TestCT_NOTIFY_001_FakeNotificationRetriesOnceAndDeduplicatesEvent \
  "Exercise fake NotificationProvider bounded retry, event dedupe, and payload redaction."
record_go_test CT-AI-001 ./internal/contracts TestCT_AI_001_FakeAIIsStructuredBoundedAndDisableable \
  "Exercise fake AIProvider structured output, bounds, timeout, and disabled fallback."
record_go_test CT-SOURCE-001 ./internal/contracts TestCT_SOURCE_001_FakeSourceProviderIsIdempotent \
  "Exercise fake SourceProvider immutable idempotent preparation."
record_go_test CT-OBJECT-001 ./internal/contracts TestCT_OBJECT_001_ObjectStorageCapabilityFailsClosed \
  "Reject disabled ObjectStorage capability without false success."

record_go_test AGENT-CT-001 ./cmd/open-card-agent TestAGENT_CT_001_RequiresTrustedValidClientCertificate \
  "Reject missing and expired client certificates while accepting the trusted mTLS identity."
record_go_test AGENT-CT-002 ./cmd/open-card-agent TestAGENT_CT_002_RejectUnknownTask \
  "Reject a non-allowlisted shell task before any executor side effect."
record_go_test AGENT-CT-003 ./cmd/open-card-agent TestAGENT_CT_003_DeduplicateAllowedTask100Times \
  "Acknowledge one allowed task and replay duplicate acknowledgement for 99 retries."
record_go_test SPIKE-S0-AGENT-TASK-LIFECYCLE ./cmd/open-card-agent TestAgentTaskCancellationAndReplayableStreams \
  "Cancel a running allowlisted task and replay its bounded log and observation streams."
record_go_test SPIKE-S0-SSE-REPLAY ./cmd/open-card-server TestAPI_CONTRACT_002_SSEReplaysFromRepositoryAfterServerRestart \
  "Replay persisted control-plane events using Last-Event-ID after a server restart."
record_go_test SPIKE-S1-APPLICATION-CONTROLLER ./internal/application TestControllerCreateIsIdempotentAndReplayable \
  "Keep application creation idempotent and its event replayable through the repository contract."

python3 tools/evidence/record_command.py \
  --milestone m0 \
  --test-id SPIKE-S1-CONTROLLER-WORKER-UNIT \
  --description "Exercise worker ordering, renewal, retry, panic recovery, resume cursor and idle cancellation." \
  --evidence-type controller_state_machine \
  --evidence-type lease_renewal \
  --evidence-type retry_recovery \
  -- env GOCACHE="$go_cache" go test -count=1 ./internal/controllers -run '^TestWorker' -v

python3 tools/evidence/record_command.py \
  --milestone m0 \
  --test-id SPIKE-S0-AGENT-OUTBOUND \
  --description "Exercise strict mTLS identity, Agent-initiated polling, reconnect replay, heartbeat and message idempotency." \
  --evidence-type mtls_transport \
  --evidence-type reconnect_replay \
  --evidence-type heartbeat \
  -- env GOCACHE="$go_cache" go test -count=1 ./internal/agenttransport -v

python3 tools/evidence/record_command.py \
  --milestone m0 \
  --test-id SPIKE-S4-LOG-STORE \
  --description "Exercise bounded metric aggregation and local log rotation, redaction, restart recovery and audit retention." \
  --evidence-type metric_aggregation \
  --evidence-type log_rotation \
  --evidence-type secret_redaction \
  --evidence-type restart_recovery \
  -- env GOCACHE="$go_cache" go test -count=1 ./internal/observability -v

python3 tools/evidence/record_command.py \
  --milestone m0 \
  --test-id SPIKE-S0-API-AGENT-COMPATIBILITY \
  --description "Verify API and Agent N/N-1 negotiation, explicit capability degradation, mTLS session ownership, unknown security-field rejection, major rejection, fixture compatibility and SSE schema projection." \
  --evidence-type api_n_minus_one \
  --evidence-type agent_n_minus_one \
  --evidence-type version_negotiation \
  --evidence-type mtls_session_binding \
  --evidence-type security_field_rejection \
  --evidence-type sse_replay \
  --evidence-type schema_fixtures \
  -- env GOCACHE="$go_cache" go test -count=1 ./internal/compatibility ./api/agent/v1 ./internal/agenttransport ./cmd/open-card-server -v

python3 tools/evidence/record_command.py \
  --milestone m0 \
  --test-id SPIKE-S5-INSTALL-UPGRADE-UNIT \
  --description "Verify strict manifest archive/file-set/mode/checksum contracts, N-1 compatibility, path safety, staged systemd boundaries, backup consistency, atomic activation, failure rollback and preserve-by-default uninstall." \
  --evidence-type install_contract \
  --evidence-type checksum_guard \
  --evidence-type archive_safety \
  --evidence-type file_set_guard \
  --evidence-type upgrade_rollback \
  --evidence-type backup_restore \
  --evidence-type systemd_boundary \
  -- env GOCACHE="$go_cache" go test -count=1 ./internal/install -v

python3 tools/evidence/record_command.py \
  --milestone m0 \
  --test-id SPIKE-S2-CLEAN-WORKER-SPEC \
  --description "Validate the task-scoped clean worker resource/isolation contract, image and bundle checksum gates, tamper rejection, acceptance dry-run and non-mutating reclaim plan." \
  --evidence-type worker_spec \
  --evidence-type checksum_guard \
  --evidence-type network_isolation \
  --evidence-type resource_limits \
  --evidence-type dry_run_reclaim \
  -- bash tests/spikes/clean_worker_spec.sh

if [[ "${OPEN_CARD_RUN_DEVBOX_G7_EVIDENCE:-0}" == 1 ]]; then
  python3 tools/evidence/record_command.py \
    --milestone m0 \
    --test-id SPIKE-S5-INSTALL-UPGRADE-USER-FIXTURE \
    --description "Run task-scoped user-space install, N-1 upgrade, rollback, backup/restore and uninstall fixtures on the physical development host without activating systemd or changing host policy." \
    --evidence-type devbox_user_fixture \
    --evidence-type install_upgrade \
    --evidence-type failure_rollback \
    --evidence-type isolation_snapshot \
    -- bash tests/spikes/devbox_g7_user_fixture.sh
fi

python3 tools/evidence/validate_mvp_evidence.py --require-pass-conclusion artifacts/mvp/m0/*/ \
  --junit artifacts/mvp/m0/all-evidence-junit.xml
