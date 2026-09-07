export const candidateFixture = {
  candidate_id: `candidate_${"a".repeat(32)}`, application_id: "app-1", base_source_revision_id: "src-base", status: "validated",
  created_at: "2030-01-01T00:00:00Z", expires_at: "2030-01-01T01:00:00Z", base_repository_url: "https://github.com/example/public.git", base_commit: "b".repeat(40),
  base_tree_digest: `sha256:${"c".repeat(64)}`, patch_digest: `sha256:${"d".repeat(64)}`, result_tree_digest: `sha256:${"e".repeat(64)}`,
  container_port: 8000, changed_paths: ["Dockerfile"], canonical_diff: "--- a/Dockerfile\n+++ b/Dockerfile\n-<script>bad</script>\n+<img src=x onerror=bad()>",
  validated_image: { repository: "test/app", digest: `sha256:${"f".repeat(64)}` }, build_log_ref: "build-log", build_evidence_digest: `sha256:${"1".repeat(64)}`,
  runtime: { task_id: "task-1", image: { repository: "test/app", digest: `sha256:${"f".repeat(64)}` }, runtime_state: "stopped", probe_outcome: "responded", http_status: 200, cleanup_confirmed: true, evidence_digest: `sha256:${"2".repeat(64)}` },
};
