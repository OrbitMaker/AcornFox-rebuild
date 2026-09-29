package sqlite

// Registered after 0011 in the finite Native SQLite migration sequence.
const version0012_source_build = "0012_source_build"

const sourceBuildSchemaSQL = `
CREATE TABLE source_prepare_intents (
 id TEXT PRIMARY KEY, admin_id TEXT NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT, application_id TEXT NOT NULL REFERENCES applications(id),
 environment_id TEXT NOT NULL REFERENCES environments(id), operation_id TEXT NOT NULL UNIQUE REFERENCES operations(id),
 task_id TEXT NOT NULL UNIQUE REFERENCES task_leases(task_id), request TEXT NOT NULL CHECK(json_valid(request)),
 state TEXT NOT NULL CHECK(state IN ('pending','running','waiting','prepared','failed')),
 deadline TEXT, command_sha TEXT, bound_core_generation INTEGER, bound_lease_generation INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE native_source_revisions (
 id TEXT PRIMARY KEY, intent_id TEXT NOT NULL UNIQUE REFERENCES source_prepare_intents(id),
 application_id TEXT NOT NULL REFERENCES applications(id), revision TEXT NOT NULL CHECK(json_valid(revision)),
 evidence TEXT NOT NULL CHECK(json_valid(evidence)), definition TEXT NOT NULL CHECK(json_valid(definition)), created_at TEXT NOT NULL
);
CREATE TABLE source_build_intents (
 id TEXT PRIMARY KEY, prepare_intent_id TEXT NOT NULL REFERENCES source_prepare_intents(id),
 source_revision_id TEXT NOT NULL REFERENCES native_source_revisions(id), admin_id TEXT NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
 application_id TEXT NOT NULL REFERENCES applications(id), environment_id TEXT NOT NULL REFERENCES environments(id),
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(id), task_id TEXT NOT NULL UNIQUE REFERENCES task_leases(task_id),
 build_id TEXT NOT NULL UNIQUE, plan_id TEXT NOT NULL UNIQUE,
 plan TEXT NOT NULL CHECK(json_valid(plan)), policy TEXT NOT NULL CHECK(json_valid(policy)),
 state TEXT NOT NULL CHECK(state IN ('pending','running','waiting','succeeded','failed')),
 deadline TEXT, command_sha TEXT,
 bound_core_generation INTEGER, bound_lease_generation INTEGER, created_at TEXT NOT NULL
);
CREATE TABLE source_build_results (
 intent_id TEXT PRIMARY KEY REFERENCES source_build_intents(id), build_id TEXT NOT NULL UNIQUE, artifact_id TEXT NOT NULL UNIQUE,
 build TEXT NOT NULL CHECK(json_valid(build)), artifact TEXT NOT NULL CHECK(json_valid(artifact)),
 log_ref TEXT NOT NULL CHECK(length(trim(log_ref))>0), evidence TEXT NOT NULL CHECK(json_valid(evidence)), created_at TEXT NOT NULL
);
CREATE TRIGGER native_source_revisions_immutable BEFORE UPDATE ON native_source_revisions
 BEGIN SELECT RAISE(ABORT,'source revision is immutable'); END;
CREATE TRIGGER source_build_results_immutable BEFORE UPDATE ON source_build_results
 BEGIN SELECT RAISE(ABORT,'build result is immutable'); END;
CREATE TRIGGER source_prepare_identity_frozen BEFORE UPDATE ON source_prepare_intents
 WHEN NEW.id<>OLD.id OR NEW.admin_id<>OLD.admin_id OR NEW.application_id<>OLD.application_id
 OR NEW.environment_id<>OLD.environment_id OR NEW.operation_id<>OLD.operation_id OR NEW.task_id<>OLD.task_id
 OR NEW.request<>OLD.request OR NEW.created_at<>OLD.created_at
 BEGIN SELECT RAISE(ABORT,'prepare intent identity is immutable'); END;
CREATE TRIGGER source_build_identity_frozen BEFORE UPDATE ON source_build_intents
 WHEN NEW.id<>OLD.id OR NEW.prepare_intent_id<>OLD.prepare_intent_id OR NEW.source_revision_id<>OLD.source_revision_id
 OR NEW.admin_id<>OLD.admin_id OR NEW.application_id<>OLD.application_id OR NEW.environment_id<>OLD.environment_id
 OR NEW.operation_id<>OLD.operation_id OR NEW.task_id<>OLD.task_id OR NEW.build_id<>OLD.build_id
 OR NEW.plan_id<>OLD.plan_id OR NEW.plan<>OLD.plan OR NEW.policy<>OLD.policy OR NEW.created_at<>OLD.created_at
 BEGIN SELECT RAISE(ABORT,'build intent identity is immutable'); END;
CREATE TRIGGER source_prepare_no_delete BEFORE DELETE ON source_prepare_intents
 BEGIN SELECT RAISE(ABORT,'prepare intent cannot be deleted'); END;
CREATE TRIGGER native_source_revisions_no_delete BEFORE DELETE ON native_source_revisions
 BEGIN SELECT RAISE(ABORT,'source revision cannot be deleted'); END;
CREATE TRIGGER source_build_intents_no_delete BEFORE DELETE ON source_build_intents
 BEGIN SELECT RAISE(ABORT,'build intent cannot be deleted'); END;
CREATE TRIGGER source_build_results_no_delete BEFORE DELETE ON source_build_results
 BEGIN SELECT RAISE(ABORT,'build result cannot be deleted'); END;
`
