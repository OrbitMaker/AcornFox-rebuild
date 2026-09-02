-- Provider-neutral DNS ownership ledger for AcornFox public access.
-- Existing DNSPod facts remain readable as installation_id=legacy-dnspod.
-- This schema records identifiers and desired DNS facts only; it never stores
-- provider credentials, authorization material, or raw provider responses.

ALTER TABLE dns_change_owned_records
    ADD COLUMN IF NOT EXISTS installation_id text;

UPDATE dns_change_owned_records
SET installation_id = 'legacy-dnspod'
WHERE installation_id IS NULL OR length(trim(installation_id)) = 0;

ALTER TABLE dns_change_owned_records
    ALTER COLUMN installation_id SET NOT NULL;

-- Drop the old numeric/type-specific guards before changing the identifier
-- columns. PostgreSQL otherwise evaluates `zone_id > 0` while converting the
-- column to text and rejects the forward migration.
ALTER TABLE dns_change_owned_records
    DROP CONSTRAINT IF EXISTS dns_change_owned_records_pkey,
    DROP CONSTRAINT IF EXISTS dns_change_owned_records_provider_check,
    DROP CONSTRAINT IF EXISTS dns_change_owned_records_domain_id_check,
    DROP CONSTRAINT IF EXISTS dns_change_owned_records_zone_id_check,
    DROP CONSTRAINT IF EXISTS dns_change_owned_records_record_id_check,
    DROP CONSTRAINT IF EXISTS dns_change_owned_records_record_type_check,
    DROP CONSTRAINT IF EXISTS dns_change_owned_records_provider_domain_id_record_id_key;

ALTER TABLE dns_change_owned_records
    RENAME COLUMN domain_id TO zone_id;
ALTER TABLE dns_change_owned_records
    RENAME COLUMN host TO name;

ALTER TABLE dns_change_owned_records
    ALTER COLUMN zone_id TYPE text USING zone_id::text,
    ALTER COLUMN record_id TYPE text USING record_id::text;

ALTER TABLE dns_change_owned_records
    ADD CONSTRAINT dns_change_owned_records_pkey PRIMARY KEY (installation_id, owner_key),
    ADD CONSTRAINT dns_change_owned_records_installation_id_check CHECK (length(trim(installation_id)) > 0 AND length(installation_id) <= 512),
    ADD CONSTRAINT dns_change_owned_records_provider_check CHECK (length(trim(provider)) > 0 AND length(provider) <= 128),
    ADD CONSTRAINT dns_change_owned_records_zone_id_check CHECK (length(trim(zone_id)) > 0 AND length(zone_id) <= 512),
    ADD CONSTRAINT dns_change_owned_records_record_id_check CHECK (length(trim(record_id)) > 0 AND length(record_id) <= 512),
    ADD CONSTRAINT dns_change_owned_records_record_type_check CHECK (record_type IN ('A','CNAME','TXT')),
    ADD CONSTRAINT dns_change_owned_records_provider_record_uidx UNIQUE (installation_id, provider, zone_id, record_id);

CREATE INDEX IF NOT EXISTS dns_change_owned_records_zone_lookup_idx
    ON dns_change_owned_records(installation_id, provider, zone_id, owner_key);
