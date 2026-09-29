package sqlite

// Registered after Source-owned 0012 in the finite Native SQLite sequence.
const version0009_image_public_access = "0009_image_public_access"

const imagePublicAccessSchemaSQL = `
CREATE TABLE image_public_access (
 id TEXT PRIMARY KEY NOT NULL,
 deployment_id TEXT NOT NULL UNIQUE REFERENCES image_deployments(id) ON DELETE RESTRICT,
 application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE RESTRICT,
 environment_id TEXT NOT NULL REFERENCES environments(id) ON DELETE RESTRICT,
 release_id TEXT NOT NULL REFERENCES image_releases(id) ON DELETE RESTRICT,
 admin_id TEXT NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
 hostname TEXT NOT NULL UNIQUE,
 endpoint_id TEXT NOT NULL,
 endpoint_version TEXT NOT NULL CHECK(length(endpoint_version)=71 AND endpoint_version GLOB 'sha256:[0-9a-f]*'),
 container_id TEXT NOT NULL,
 host_port INTEGER NOT NULL CHECK(host_port BETWEEN 1 AND 65535),
 container_port INTEGER NOT NULL CHECK(container_port BETWEEN 1 AND 65535),
 desired_public INTEGER NOT NULL CHECK(desired_public IN (0,1)),
 local_route_state TEXT NOT NULL CHECK(local_route_state IN ('desired','reconcile_required','configured','disabled')),
 operation_id TEXT NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
 certificate_fingerprint TEXT CHECK(certificate_fingerprint IS NULL OR (length(certificate_fingerprint)=71 AND certificate_fingerprint GLOB 'sha256:[0-9a-f]*')),
 certificate_expires_at TEXT CHECK(certificate_expires_at IS NULL OR certificate_expires_at GLOB '` + timePattern + `'),
 observed_at TEXT CHECK(observed_at IS NULL OR observed_at GLOB '` + timePattern + `'),
 created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `'),
 updated_at TEXT NOT NULL CHECK(updated_at GLOB '` + timePattern + `')
);
CREATE TABLE image_public_access_commands (
 operation_id TEXT PRIMARY KEY NOT NULL REFERENCES operations(id) ON DELETE RESTRICT,
 task_id TEXT NOT NULL UNIQUE REFERENCES task_leases(task_id) ON DELETE RESTRICT,
 approval_id TEXT NOT NULL REFERENCES image_public_access(id) ON DELETE RESTRICT,
 deployment_id TEXT NOT NULL REFERENCES image_deployments(id) ON DELETE RESTRICT,
 admin_id TEXT NOT NULL REFERENCES admin_credentials(id) ON DELETE RESTRICT,
 action TEXT NOT NULL CHECK(action IN ('ensure','remove')),
 binding TEXT NOT NULL CHECK(json_valid(binding)),
 created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `')
);
CREATE INDEX image_public_access_commands_approval_idx ON image_public_access_commands(approval_id);
CREATE TABLE image_public_access_results (
 operation_id TEXT PRIMARY KEY NOT NULL REFERENCES image_public_access_commands(operation_id) ON DELETE RESTRICT,
 observed_at TEXT NOT NULL CHECK(observed_at GLOB '` + timePattern + `'),
 certificate_fingerprint TEXT CHECK(certificate_fingerprint IS NULL OR (length(certificate_fingerprint)=71 AND certificate_fingerprint GLOB 'sha256:[0-9a-f]*')),
 certificate_expires_at TEXT CHECK(certificate_expires_at IS NULL OR certificate_expires_at GLOB '` + timePattern + `'),
 created_at TEXT NOT NULL CHECK(created_at GLOB '` + timePattern + `')
);
CREATE TRIGGER image_public_access_commands_frozen BEFORE UPDATE ON image_public_access_commands
 BEGIN SELECT RAISE(ABORT,'public access command immutable'); END;
CREATE TRIGGER image_public_access_commands_no_delete BEFORE DELETE ON image_public_access_commands
 BEGIN SELECT RAISE(ABORT,'public access command immutable'); END;
CREATE TRIGGER image_public_access_results_frozen BEFORE UPDATE ON image_public_access_results
 BEGIN SELECT RAISE(ABORT,'public access result immutable'); END;
CREATE TRIGGER image_public_access_results_no_delete BEFORE DELETE ON image_public_access_results
 BEGIN SELECT RAISE(ABORT,'public access result immutable'); END;
CREATE TRIGGER image_public_access_identity_frozen BEFORE UPDATE ON image_public_access
 WHEN NEW.id<>OLD.id OR NEW.deployment_id<>OLD.deployment_id OR NEW.application_id<>OLD.application_id
 OR NEW.environment_id<>OLD.environment_id OR NEW.release_id<>OLD.release_id OR NEW.admin_id<>OLD.admin_id
 OR NEW.hostname<>OLD.hostname OR NEW.created_at<>OLD.created_at
 BEGIN SELECT RAISE(ABORT,'public access identity immutable'); END;
CREATE TRIGGER image_endpoint_public_access_no_delete BEFORE DELETE ON image_endpoints
 WHEN EXISTS(SELECT 1 FROM image_public_access a WHERE a.endpoint_id=OLD.id AND a.local_route_state<>'disabled')
 BEGIN SELECT RAISE(ABORT,'remove public route before releasing endpoint'); END;
CREATE TRIGGER image_endpoint_public_access_no_rebind BEFORE UPDATE OF host_ip,host_port,container_port,deployment_id ON image_endpoints
 WHEN EXISTS(SELECT 1 FROM image_public_access a WHERE a.endpoint_id=OLD.id AND a.local_route_state<>'disabled')
 BEGIN SELECT RAISE(ABORT,'remove public route before rebinding endpoint'); END;
CREATE TRIGGER image_deployment_public_access_no_rebind BEFORE UPDATE OF container_id,image_id ON image_deployments
 WHEN EXISTS(SELECT 1 FROM image_public_access a WHERE a.deployment_id=OLD.id AND a.local_route_state<>'disabled')
 BEGIN SELECT RAISE(ABORT,'remove public route before replacing container'); END;
`
