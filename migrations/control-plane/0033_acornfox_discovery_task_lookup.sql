-- AcornFox discovery proves runtime and source facts from bounded task
-- evidence. These indexes make each candidate-scoped lookup avoid historical
-- operation/task scans while preserving the existing ledger schema.

CREATE INDEX IF NOT EXISTS operations_acornfox_discovery_deployment_type_idx
    ON operations (deployment_id, operation_type, id)
    WHERE deployment_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS task_leases_acornfox_discovery_operation_order_idx
    ON task_leases (operation_id, created_at, task_id);

CREATE INDEX IF NOT EXISTS operations_acornfox_discovery_source_proof_idx
    ON operations (application_id, operation_type, target_ref, id);
