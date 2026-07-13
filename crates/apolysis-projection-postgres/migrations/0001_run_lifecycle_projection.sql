-- SPDX-License-Identifier: Apache-2.0

-- This schema has its own checksum ledger because sqlx's default global
-- migration table is already owned by the Gateway adapter. The Rust runner
-- executes this file and records its SHA-256 in one advisory-locked transaction.
-- Unexpected pre-existing objects fail rather than being hidden by IF NOT EXISTS.

CREATE SCHEMA apolysis_projection;

CREATE TABLE apolysis_projection.schema_migrations (
    version bigint PRIMARY KEY CHECK (version > 0),
    description text NOT NULL CHECK (octet_length(description) BETWEEN 1 AND 128),
    checksum bytea NOT NULL CHECK (octet_length(checksum) = 32),
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE DOMAIN apolysis_projection.contract_identifier AS text
    CHECK (
        octet_length(VALUE) BETWEEN 1 AND 128
        AND VALUE ~ '^[A-Za-z0-9]([A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$'
    );

CREATE DOMAIN apolysis_projection.bounded_reference AS text
    CHECK (
        octet_length(VALUE) BETWEEN 1 AND 512
        AND VALUE !~ '[[:cntrl:]]'
    );

CREATE DOMAIN apolysis_projection.sha256_digest AS bytea
    CHECK (octet_length(VALUE) = 32);

CREATE DOMAIN apolysis_projection.ijson_nonnegative AS bigint
    CHECK (VALUE BETWEEN 0 AND 9007199254740991);

CREATE DOMAIN apolysis_projection.ijson_positive AS bigint
    CHECK (VALUE BETWEEN 1 AND 9007199254740991);

CREATE TABLE apolysis_projection.generations (
    organization_id apolysis_projection.contract_identifier NOT NULL,
    generation_id bigint GENERATED ALWAYS AS IDENTITY,
    view_version text NOT NULL DEFAULT '0' CHECK (view_version = '0'),
    computation_version apolysis_projection.contract_identifier NOT NULL,
    generation_state text NOT NULL
        CHECK (generation_state IN ('building', 'active', 'retired')),
    rebuild_of_generation_id bigint,
    created_source_watermark apolysis_projection.ijson_nonnegative NOT NULL,
    created_at_unix_ms apolysis_projection.ijson_positive NOT NULL,
    activated_at_unix_ms apolysis_projection.ijson_positive,
    retired_at_unix_ms apolysis_projection.ijson_positive,
    PRIMARY KEY (organization_id, generation_id),
    UNIQUE (organization_id, generation_id, generation_state),
    CONSTRAINT generations_id_ck
        CHECK (generation_id BETWEEN 1 AND 9007199254740991),
    CONSTRAINT generations_organization_fk
        FOREIGN KEY (organization_id)
        REFERENCES apolysis_gateway.organization_sequences (organization_id),
    CONSTRAINT generations_rebuild_of_fk
        FOREIGN KEY (organization_id, rebuild_of_generation_id)
        REFERENCES apolysis_projection.generations (organization_id, generation_id),
    CONSTRAINT generations_state_time_ck
        CHECK (
            (generation_state = 'building'
                AND activated_at_unix_ms IS NULL
                AND retired_at_unix_ms IS NULL)
            OR (generation_state = 'active'
                AND activated_at_unix_ms IS NOT NULL
                AND retired_at_unix_ms IS NULL)
            OR (generation_state = 'retired'
                AND activated_at_unix_ms IS NOT NULL
                AND retired_at_unix_ms IS NOT NULL)
        ),
    CONSTRAINT generations_initial_or_rebuild_ck
        CHECK (
            (rebuild_of_generation_id IS NULL AND generation_state IN ('active', 'retired'))
            OR rebuild_of_generation_id IS NOT NULL
        )
);

CREATE UNIQUE INDEX generations_one_active_per_organization_idx
    ON apolysis_projection.generations (organization_id)
    WHERE generation_state = 'active';

CREATE UNIQUE INDEX generations_one_building_per_organization_idx
    ON apolysis_projection.generations (organization_id)
    WHERE generation_state = 'building';

CREATE TABLE apolysis_projection.commits (
    organization_id apolysis_projection.contract_identifier NOT NULL,
    generation_id bigint NOT NULL,
    commit_revision apolysis_projection.ijson_positive NOT NULL,
    previous_commit_revision apolysis_projection.ijson_positive,
    from_input_watermark apolysis_projection.ijson_nonnegative NOT NULL,
    through_input_watermark apolysis_projection.ijson_positive NOT NULL,
    record_count smallint NOT NULL CHECK (record_count BETWEEN 1 AND 200),
    projected_at_unix_ms apolysis_projection.ijson_positive NOT NULL,
    batch_digest apolysis_projection.sha256_digest NOT NULL,
    PRIMARY KEY (organization_id, generation_id, commit_revision),
    UNIQUE (
        organization_id,
        generation_id,
        commit_revision,
        through_input_watermark
    ),
    UNIQUE (organization_id, generation_id, through_input_watermark),
    CONSTRAINT commits_generation_fk
        FOREIGN KEY (organization_id, generation_id)
        REFERENCES apolysis_projection.generations (organization_id, generation_id),
    CONSTRAINT commits_previous_fk
        FOREIGN KEY (
            organization_id,
            generation_id,
            previous_commit_revision,
            from_input_watermark
        )
        REFERENCES apolysis_projection.commits (
            organization_id,
            generation_id,
            commit_revision,
            through_input_watermark
        )
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT commits_predecessor_ck
        CHECK (
            (commit_revision = 1
                AND previous_commit_revision IS NULL
                AND from_input_watermark = 0)
            OR (commit_revision > 1
                AND previous_commit_revision = commit_revision - 1)
        ),
    CONSTRAINT commits_contiguous_range_ck
        CHECK (through_input_watermark = from_input_watermark + record_count)
);

CREATE TABLE apolysis_projection.checkpoints (
    organization_id apolysis_projection.contract_identifier NOT NULL,
    generation_id bigint NOT NULL,
    input_watermark apolysis_projection.ijson_nonnegative NOT NULL DEFAULT 0,
    last_commit_revision apolysis_projection.ijson_positive,
    updated_at_unix_ms apolysis_projection.ijson_positive NOT NULL,
    checkpoint_health text NOT NULL DEFAULT 'ready'
        CHECK (checkpoint_health IN ('ready', 'blocked')),
    last_error_code text
        CHECK (last_error_code IN (
            'missing_input',
            'oversized_input',
            'digest_mismatch',
            'invalid_contract',
            'metadata_mismatch',
            'lifecycle_conflict',
            'outbox_state'
        )),
    failed_ingest_sequence apolysis_projection.ijson_positive,
    PRIMARY KEY (organization_id, generation_id),
    UNIQUE (organization_id, generation_id, input_watermark),
    CONSTRAINT checkpoints_generation_fk
        FOREIGN KEY (organization_id, generation_id)
        REFERENCES apolysis_projection.generations (organization_id, generation_id),
    CONSTRAINT checkpoints_commit_fk
        FOREIGN KEY (
            organization_id,
            generation_id,
            last_commit_revision,
            input_watermark
        )
        REFERENCES apolysis_projection.commits (
            organization_id,
            generation_id,
            commit_revision,
            through_input_watermark
        )
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT checkpoints_progress_ck
        CHECK (
            (input_watermark = 0 AND last_commit_revision IS NULL)
            OR (input_watermark > 0 AND last_commit_revision IS NOT NULL)
        ),
    CONSTRAINT checkpoints_health_ck
        CHECK (
            (checkpoint_health = 'ready'
                AND last_error_code IS NULL
                AND failed_ingest_sequence IS NULL)
            OR (checkpoint_health = 'blocked'
                AND last_error_code IS NOT NULL
                AND failed_ingest_sequence IS NOT NULL)
        )
);

CREATE TABLE apolysis_projection.run_lifecycle (
    organization_id apolysis_projection.contract_identifier NOT NULL,
    generation_id bigint NOT NULL,
    run_id apolysis_projection.contract_identifier NOT NULL,
    authority_kind text NOT NULL CHECK (authority_kind IN ('human', 'service', 'policy')),
    authority_id apolysis_projection.contract_identifier NOT NULL,
    principal_kind text NOT NULL CHECK (principal_kind IN ('human', 'workload')),
    principal_id apolysis_projection.contract_identifier NOT NULL,
    objective_ref apolysis_projection.bounded_reference NOT NULL,
    environment text NOT NULL CHECK (environment IN (
        'local_cli_or_ide',
        'ci_runner_or_remote_workspace',
        'vendor_hosted_coding_sandbox',
        'customer_built_agent_service',
        'fully_managed_agent_runtime'
    )),
    privacy_profile_ref apolysis_projection.contract_identifier NOT NULL,
    retention_profile_ref apolysis_projection.contract_identifier NOT NULL,
    run_state text NOT NULL
        CHECK (run_state IN ('opening', 'active', 'finishing', 'finished', 'incomplete')),
    opened_at_unix_ms apolysis_projection.ijson_positive NOT NULL,
    state_changed_at_unix_ms apolysis_projection.ijson_positive NOT NULL,
    terminal_at_unix_ms apolysis_projection.ijson_positive,
    lifecycle_revision apolysis_projection.ijson_positive NOT NULL,
    opened_ingest_sequence apolysis_projection.ijson_positive NOT NULL,
    last_lifecycle_ingest_sequence apolysis_projection.ijson_positive NOT NULL,
    last_modified_commit_revision apolysis_projection.ijson_positive NOT NULL,
    last_modified_commit_watermark apolysis_projection.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, generation_id, run_id),
    CONSTRAINT run_lifecycle_generation_fk
        FOREIGN KEY (organization_id, generation_id)
        REFERENCES apolysis_projection.generations (organization_id, generation_id),
    CONSTRAINT run_lifecycle_opened_record_fk
        FOREIGN KEY (organization_id, run_id, opened_ingest_sequence)
        REFERENCES apolysis_gateway.record_items (organization_id, run_id, ingest_sequence),
    CONSTRAINT run_lifecycle_last_record_fk
        FOREIGN KEY (organization_id, run_id, last_lifecycle_ingest_sequence)
        REFERENCES apolysis_gateway.record_items (organization_id, run_id, ingest_sequence),
    CONSTRAINT run_lifecycle_commit_fk
        FOREIGN KEY (
            organization_id,
            generation_id,
            last_modified_commit_revision,
            last_modified_commit_watermark
        )
        REFERENCES apolysis_projection.commits (
            organization_id,
            generation_id,
            commit_revision,
            through_input_watermark
        )
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT run_lifecycle_sequence_ck
        CHECK (
            last_lifecycle_ingest_sequence >= opened_ingest_sequence
            AND opened_ingest_sequence <= last_modified_commit_watermark
            AND last_lifecycle_ingest_sequence <= last_modified_commit_watermark
        ),
    CONSTRAINT run_lifecycle_terminal_ck
        CHECK (
            (run_state IN ('finished', 'incomplete'))
                = (terminal_at_unix_ms IS NOT NULL)
        )
);

CREATE INDEX run_lifecycle_inventory_idx
    ON apolysis_projection.run_lifecycle (
        organization_id,
        generation_id,
        opened_at_unix_ms DESC,
        run_id ASC,
        opened_ingest_sequence
    );

CREATE TABLE apolysis_projection.organization_heads (
    organization_id apolysis_projection.contract_identifier PRIMARY KEY,
    active_generation_id bigint NOT NULL,
    active_generation_state text NOT NULL DEFAULT 'active'
        CHECK (active_generation_state = 'active'),
    cutover_revision apolysis_projection.ijson_positive NOT NULL,
    query_visible_watermark apolysis_projection.ijson_nonnegative NOT NULL,
    cutover_at_unix_ms apolysis_projection.ijson_positive NOT NULL,
    CONSTRAINT organization_heads_active_generation_fk
        FOREIGN KEY (
            organization_id,
            active_generation_id,
            active_generation_state
        )
        REFERENCES apolysis_projection.generations (
            organization_id,
            generation_id,
            generation_state
        )
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT organization_heads_checkpoint_fk
        FOREIGN KEY (
            organization_id,
            active_generation_id,
            query_visible_watermark
        )
        REFERENCES apolysis_projection.checkpoints (
            organization_id,
            generation_id,
            input_watermark
        )
        DEFERRABLE INITIALLY DEFERRED
);

-- Runtime roles must set this transaction-local setting before every read or
-- write. Deployment owns role creation; the migration grants no role access.
ALTER TABLE apolysis_projection.generations ENABLE ROW LEVEL SECURITY;
ALTER TABLE apolysis_projection.generations FORCE ROW LEVEL SECURITY;
CREATE POLICY generations_organization_scope ON apolysis_projection.generations
    USING (organization_id = current_setting('apolysis.organization_id', true))
    WITH CHECK (organization_id = current_setting('apolysis.organization_id', true));

ALTER TABLE apolysis_projection.commits ENABLE ROW LEVEL SECURITY;
ALTER TABLE apolysis_projection.commits FORCE ROW LEVEL SECURITY;
CREATE POLICY commits_organization_scope ON apolysis_projection.commits
    USING (organization_id = current_setting('apolysis.organization_id', true))
    WITH CHECK (organization_id = current_setting('apolysis.organization_id', true));

ALTER TABLE apolysis_projection.checkpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE apolysis_projection.checkpoints FORCE ROW LEVEL SECURITY;
CREATE POLICY checkpoints_organization_scope ON apolysis_projection.checkpoints
    USING (organization_id = current_setting('apolysis.organization_id', true))
    WITH CHECK (organization_id = current_setting('apolysis.organization_id', true));

ALTER TABLE apolysis_projection.run_lifecycle ENABLE ROW LEVEL SECURITY;
ALTER TABLE apolysis_projection.run_lifecycle FORCE ROW LEVEL SECURITY;
CREATE POLICY run_lifecycle_organization_scope ON apolysis_projection.run_lifecycle
    USING (organization_id = current_setting('apolysis.organization_id', true))
    WITH CHECK (organization_id = current_setting('apolysis.organization_id', true));

ALTER TABLE apolysis_projection.organization_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE apolysis_projection.organization_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY organization_heads_organization_scope
    ON apolysis_projection.organization_heads
    USING (organization_id = current_setting('apolysis.organization_id', true))
    WITH CHECK (organization_id = current_setting('apolysis.organization_id', true));

COMMENT ON SCHEMA apolysis_projection IS
    'Generation-scoped, rebuildable internal read foundation; not a Console or authorization boundary.';

COMMENT ON COLUMN apolysis_projection.commits.batch_digest IS
    'Unkeyed deterministic input-batch digest for reconstruction checks; not a signature or tamper-proof anchor.';
