-- SPDX-License-Identifier: Apache-2.0

-- This migration is intentionally not written with IF NOT EXISTS. The migration
-- runner owns exactly-once execution and checksum verification; an unexpected
-- pre-existing object must fail loudly instead of concealing schema drift.

CREATE SCHEMA apolysis_gateway;

CREATE DOMAIN apolysis_gateway.contract_identifier AS text
    CHECK (
        octet_length(VALUE) BETWEEN 1 AND 128
        AND VALUE ~ '^[A-Za-z0-9]([A-Za-z0-9._:-]{0,126}[A-Za-z0-9])?$'
    );

CREATE DOMAIN apolysis_gateway.bounded_reference AS text
    CHECK (
        octet_length(VALUE) BETWEEN 1 AND 512
        AND VALUE !~ '[[:cntrl:]]'
    );

CREATE DOMAIN apolysis_gateway.sha256_digest AS bytea
    CHECK (octet_length(VALUE) = 32);

-- Contract integers pass through JSON/JCS. Keep them within the exact I-JSON
-- range as well as PostgreSQL's signed BIGINT range.
CREATE DOMAIN apolysis_gateway.ijson_nonnegative AS bigint
    CHECK (VALUE BETWEEN 0 AND 9007199254740991);

CREATE DOMAIN apolysis_gateway.ijson_positive AS bigint
    CHECK (VALUE BETWEEN 1 AND 9007199254740991);

-- Shared wire vocabularies are domains rather than repeated text checks so a
-- future contract revision cannot update one persistence path but miss another.
CREATE DOMAIN apolysis_gateway.contract_schema_version AS text
    CHECK (VALUE = '0.1');

CREATE DOMAIN apolysis_gateway.run_state AS text
    CHECK (VALUE IN ('opening', 'active', 'finishing', 'finished', 'incomplete'));

CREATE DOMAIN apolysis_gateway.environment_kind AS text
    CHECK (VALUE IN (
        'local_cli_or_ide',
        'ci_runner_or_remote_workspace',
        'vendor_hosted_coding_sandbox',
        'customer_built_agent_service',
        'fully_managed_agent_runtime'
    ));

CREATE DOMAIN apolysis_gateway.principal_kind AS text
    CHECK (VALUE IN ('human', 'workload'));

CREATE DOMAIN apolysis_gateway.source_kind AS text
    CHECK (VALUE IN (
        'semantic_hook',
        'sdk_processor',
        'protocol_tap',
        'provider_adapter',
        'runtime_witness',
        'outcome_verifier'
    ));

CREATE DOMAIN apolysis_gateway.trust_profile AS text
    CHECK (VALUE IN (
        'declared',
        'harness_observed',
        'host_verified',
        'provider_attested',
        'opaque',
        'incomplete'
    ));

CREATE DOMAIN apolysis_gateway.gateway_operation_kind AS text
    CHECK (VALUE IN ('open_run', 'bind_runtime', 'ingest', 'finish_run'));

CREATE DOMAIN apolysis_gateway.runtime_identity_kind AS text
    CHECK (VALUE IN (
        'process',
        'cgroup',
        'container',
        'pod',
        'vm',
        'runner',
        'provider_workload'
    ));

CREATE DOMAIN apolysis_gateway.runtime_attribution AS text
    CHECK (VALUE IN ('exact', 'inferred', 'ambiguous', 'unattributed'));

CREATE TABLE apolysis_gateway.organization_sequences (
    organization_id apolysis_gateway.contract_identifier PRIMARY KEY,
    next_ingest_sequence apolysis_gateway.ijson_positive NOT NULL DEFAULT 1,
    updated_at_unix_ms apolysis_gateway.ijson_positive NOT NULL
);

CREATE TABLE apolysis_gateway.runs (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    schema_version apolysis_gateway.contract_schema_version NOT NULL DEFAULT '0.1',
    state apolysis_gateway.run_state NOT NULL,
    environment apolysis_gateway.environment_kind NOT NULL,
    authority_kind text NOT NULL
        CHECK (authority_kind IN ('human', 'service', 'policy')),
    authority_id apolysis_gateway.contract_identifier NOT NULL,
    principal_kind apolysis_gateway.principal_kind NOT NULL,
    principal_id apolysis_gateway.contract_identifier NOT NULL,
    objective_ref apolysis_gateway.bounded_reference NOT NULL,
    privacy_profile_ref apolysis_gateway.contract_identifier NOT NULL,
    retention_profile_ref apolysis_gateway.contract_identifier NOT NULL,
    initiating_source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    initiating_principal_kind apolysis_gateway.principal_kind NOT NULL,
    initiating_principal_id apolysis_gateway.contract_identifier NOT NULL,
    opened_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    state_changed_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    finalization_deadline_unix_ms apolysis_gateway.ijson_positive,
    lock_version apolysis_gateway.ijson_nonnegative NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, run_id),
    CONSTRAINT runs_organization_fk
        FOREIGN KEY (organization_id)
        REFERENCES apolysis_gateway.organization_sequences (organization_id),
    CONSTRAINT runs_state_deadline_ck
        CHECK ((state = 'finishing') = (finalization_deadline_unix_ms IS NOT NULL)),
    CONSTRAINT runs_state_time_ck
        CHECK (state_changed_at_unix_ms >= opened_at_unix_ms)
);

CREATE INDEX runs_lifecycle_deadline_idx
    ON apolysis_gateway.runs (organization_id, state, finalization_deadline_unix_ms)
    WHERE state IN ('active', 'finishing');

CREATE TABLE apolysis_gateway.run_expected_source_kinds (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    source_kind apolysis_gateway.source_kind NOT NULL,
    PRIMARY KEY (organization_id, run_id, source_kind),
    CONSTRAINT run_expected_source_kinds_run_fk
        FOREIGN KEY (organization_id, run_id)
        REFERENCES apolysis_gateway.runs (organization_id, run_id)
        ON DELETE CASCADE
);

CREATE TABLE apolysis_gateway.client_runs (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    principal_kind apolysis_gateway.principal_kind NOT NULL,
    principal_id apolysis_gateway.contract_identifier NOT NULL,
    client_run_key apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    created_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, principal_kind, principal_id, client_run_key),
    UNIQUE (organization_id, run_id),
    CONSTRAINT client_runs_run_fk
        FOREIGN KEY (organization_id, run_id)
        REFERENCES apolysis_gateway.runs (organization_id, run_id)
        ON DELETE CASCADE
);

CREATE TABLE apolysis_gateway.record_items (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    ingest_sequence apolysis_gateway.ijson_positive NOT NULL,
    schema_version apolysis_gateway.contract_schema_version NOT NULL DEFAULT '0.1',
    ingested_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    fact_kind text NOT NULL
        CHECK (fact_kind IN (
            'run_opened',
            'run_state_changed',
            'run_finalization_declared',
            'source_registered',
            'runtime_bound',
            'evidence_accepted',
            'coverage_computed'
        )),
    fact_json jsonb NOT NULL
        CHECK (jsonb_typeof(fact_json) = 'object'),
    fact_digest apolysis_gateway.sha256_digest NOT NULL,
    outbox_ingest_sequence apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, ingest_sequence),
    UNIQUE (organization_id, run_id, ingest_sequence),
    CONSTRAINT record_items_run_fk
        FOREIGN KEY (organization_id, run_id)
        REFERENCES apolysis_gateway.runs (organization_id, run_id),
    CONSTRAINT record_items_outbox_identity_ck
        CHECK (outbox_ingest_sequence = ingest_sequence)
);

CREATE TABLE apolysis_gateway.projection_outbox (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    ingest_sequence apolysis_gateway.ijson_positive NOT NULL,
    topic text NOT NULL DEFAULT 'agent_execution_record'
        CHECK (topic = 'agent_execution_record'),
    delivery_state text NOT NULL DEFAULT 'pending'
        CHECK (delivery_state IN ('pending', 'processing', 'published', 'dead_letter')),
    attempt_count integer NOT NULL DEFAULT 0
        CHECK (attempt_count >= 0),
    available_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    claimed_by apolysis_gateway.contract_identifier,
    claimed_at_unix_ms apolysis_gateway.ijson_positive,
    published_at_unix_ms apolysis_gateway.ijson_positive,
    last_error_code apolysis_gateway.contract_identifier,
    PRIMARY KEY (organization_id, ingest_sequence),
    CONSTRAINT projection_outbox_record_fk
        FOREIGN KEY (organization_id, ingest_sequence)
        REFERENCES apolysis_gateway.record_items (organization_id, ingest_sequence)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT projection_outbox_claim_ck
        CHECK ((claimed_by IS NULL) = (claimed_at_unix_ms IS NULL)),
    CONSTRAINT projection_outbox_publish_ck
        CHECK ((delivery_state = 'published') = (published_at_unix_ms IS NOT NULL))
);

-- The deferred reverse FK makes the record/outbox relation exactly 1:1 at
-- transaction commit while still allowing either insert order.
ALTER TABLE apolysis_gateway.record_items
    ADD CONSTRAINT record_items_outbox_fk
    FOREIGN KEY (organization_id, outbox_ingest_sequence)
    REFERENCES apolysis_gateway.projection_outbox (organization_id, ingest_sequence)
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX projection_outbox_dispatch_idx
    ON apolysis_gateway.projection_outbox (
        delivery_state,
        available_at_unix_ms,
        organization_id,
        ingest_sequence
    )
    WHERE delivery_state IN ('pending', 'processing');

CREATE TABLE apolysis_gateway.source_streams (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    source_stream_id apolysis_gateway.contract_identifier NOT NULL,
    source_id apolysis_gateway.contract_identifier NOT NULL,
    source_kind apolysis_gateway.source_kind NOT NULL,
    environment apolysis_gateway.environment_kind NOT NULL,
    registration_principal_kind apolysis_gateway.principal_kind NOT NULL,
    registration_principal_id apolysis_gateway.contract_identifier NOT NULL,
    registration_policy_revision apolysis_gateway.ijson_positive NOT NULL,
    effective_trust_profile apolysis_gateway.trust_profile NOT NULL,
    manifest_version apolysis_gateway.contract_schema_version NOT NULL DEFAULT '0.1',
    manifest_digest apolysis_gateway.sha256_digest NOT NULL,
    manifest_json jsonb NOT NULL
        CHECK (jsonb_typeof(manifest_json) = 'object'),
    registered_ingest_sequence apolysis_gateway.ijson_positive NOT NULL,
    registered_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id
    ),
    UNIQUE (organization_id, run_id, source_stream_id),
    UNIQUE (organization_id, run_id, source_stream_id, source_id),
    UNIQUE (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_id
    ),
    UNIQUE (organization_id, registered_ingest_sequence),
    CONSTRAINT source_streams_run_fk
        FOREIGN KEY (organization_id, run_id)
        REFERENCES apolysis_gateway.runs (organization_id, run_id),
    CONSTRAINT source_streams_record_fk
        FOREIGN KEY (organization_id, run_id, registered_ingest_sequence)
        REFERENCES apolysis_gateway.record_items (
            organization_id,
            run_id,
            ingest_sequence
        )
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX source_streams_source_idx
    ON apolysis_gateway.source_streams (
        organization_id,
        run_id,
        source_id,
        source_stream_id
    );

CREATE TABLE apolysis_gateway.source_stream_capabilities (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    source_stream_id apolysis_gateway.contract_identifier NOT NULL,
    capability text NOT NULL
        CHECK (capability IN (
            'semantic_lifecycle',
            'delegation',
            'tool_calls',
            'mcp',
            'a2a',
            'policy_decisions',
            'policy_actuation',
            'process',
            'file',
            'network',
            'identity',
            'workload',
            'claimed_outcome',
            'verified_outcome',
            'source_health'
        )),
    PRIMARY KEY (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        capability
    ),
    CONSTRAINT source_stream_capabilities_stream_fk
        FOREIGN KEY (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id
        )
        REFERENCES apolysis_gateway.source_streams (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id
        )
        ON DELETE CASCADE
);

CREATE TABLE apolysis_gateway.leases (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    lease_digest apolysis_gateway.sha256_digest NOT NULL,
    lease_hash_version text NOT NULL DEFAULT 'apolysis.gateway.lease-id/v1'
        CHECK (lease_hash_version = 'apolysis.gateway.lease-id/v1'),
    hash_algorithm text NOT NULL DEFAULT 'sha256'
        CHECK (hash_algorithm = 'sha256'),
    run_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    source_stream_id apolysis_gateway.contract_identifier NOT NULL,
    source_id apolysis_gateway.contract_identifier NOT NULL,
    principal_kind apolysis_gateway.principal_kind NOT NULL,
    principal_id apolysis_gateway.contract_identifier NOT NULL,
    registration_policy_revision apolysis_gateway.ijson_positive NOT NULL,
    issued_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    expires_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    revoked_at_unix_ms apolysis_gateway.ijson_positive,
    PRIMARY KEY (organization_id, lease_digest),
    CONSTRAINT leases_stream_fk
        FOREIGN KEY (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id
        )
        REFERENCES apolysis_gateway.source_streams (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id
        ),
    CONSTRAINT leases_expiry_ck
        CHECK (expires_at_unix_ms > issued_at_unix_ms),
    CONSTRAINT leases_revocation_ck
        CHECK (revoked_at_unix_ms IS NULL OR revoked_at_unix_ms >= issued_at_unix_ms)
);

COMMENT ON COLUMN apolysis_gateway.leases.lease_digest IS
    'SHA-256 domain-separated lease lookup; the bearer lease ID is never stored.';

CREATE INDEX leases_run_expiry_idx
    ON apolysis_gateway.leases (organization_id, run_id, expires_at_unix_ms)
    WHERE revoked_at_unix_ms IS NULL;

CREATE INDEX leases_registration_revision_idx
    ON apolysis_gateway.leases (
        organization_id,
        source_registration_id,
        registration_policy_revision
    );

CREATE TABLE apolysis_gateway.lease_operations (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    lease_digest apolysis_gateway.sha256_digest NOT NULL,
    operation_kind apolysis_gateway.gateway_operation_kind NOT NULL
        CHECK (operation_kind <> 'open_run'),
    PRIMARY KEY (organization_id, lease_digest, operation_kind),
    CONSTRAINT lease_operations_lease_fk
        FOREIGN KEY (organization_id, lease_digest)
        REFERENCES apolysis_gateway.leases (organization_id, lease_digest)
        ON DELETE CASCADE
);

CREATE TABLE apolysis_gateway.join_authorizations (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    proof_digest apolysis_gateway.sha256_digest NOT NULL,
    proof_hash_version text NOT NULL DEFAULT 'apolysis.gateway.join-proof-ref/v1'
        CHECK (proof_hash_version = 'apolysis.gateway.join-proof-ref/v1'),
    hash_algorithm text NOT NULL DEFAULT 'sha256'
        CHECK (hash_algorithm = 'sha256'),
    authorization_kind text NOT NULL
        CHECK (authorization_kind IN ('grant', 'registration_policy')),
    authorization_state text NOT NULL DEFAULT 'pending'
        CHECK (authorization_state IN ('pending', 'consumed', 'revoked')),
    run_id apolysis_gateway.contract_identifier NOT NULL,
    source_id apolysis_gateway.contract_identifier NOT NULL,
    source_kind apolysis_gateway.source_kind NOT NULL,
    environment apolysis_gateway.environment_kind NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    principal_kind apolysis_gateway.principal_kind NOT NULL,
    principal_id apolysis_gateway.contract_identifier NOT NULL,
    registration_policy_revision apolysis_gateway.ijson_positive NOT NULL,
    issued_by_source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    issued_by_principal_kind apolysis_gateway.principal_kind NOT NULL,
    issued_by_principal_id apolysis_gateway.contract_identifier NOT NULL,
    issued_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    expires_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    consumed_at_unix_ms apolysis_gateway.ijson_positive,
    revoked_at_unix_ms apolysis_gateway.ijson_positive,
    PRIMARY KEY (organization_id, proof_digest),
    CONSTRAINT join_authorizations_run_fk
        FOREIGN KEY (organization_id, run_id)
        REFERENCES apolysis_gateway.runs (organization_id, run_id),
    CONSTRAINT join_authorizations_expiry_ck
        CHECK (expires_at_unix_ms > issued_at_unix_ms),
    CONSTRAINT join_authorizations_state_ck
        CHECK (
            (authorization_state = 'pending'
                AND consumed_at_unix_ms IS NULL
                AND revoked_at_unix_ms IS NULL)
            OR (authorization_state = 'consumed'
                AND consumed_at_unix_ms IS NOT NULL
                AND revoked_at_unix_ms IS NULL)
            OR (authorization_state = 'revoked'
                AND consumed_at_unix_ms IS NULL
                AND revoked_at_unix_ms IS NOT NULL)
        ),
    CONSTRAINT join_authorizations_grant_consumption_ck
        CHECK (authorization_kind = 'grant' OR consumed_at_unix_ms IS NULL)
);

COMMENT ON COLUMN apolysis_gateway.join_authorizations.proof_digest IS
    'SHA-256 domain-separated join proof lookup; proof_ref is never stored.';

CREATE INDEX join_authorizations_target_idx
    ON apolysis_gateway.join_authorizations (
        organization_id,
        run_id,
        source_registration_id,
        authorization_state,
        expires_at_unix_ms
    );

CREATE TABLE apolysis_gateway.gateway_operations (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    operation_id bigint GENERATED ALWAYS AS IDENTITY,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    principal_kind apolysis_gateway.principal_kind NOT NULL,
    principal_id apolysis_gateway.contract_identifier NOT NULL,
    operation_kind apolysis_gateway.gateway_operation_kind NOT NULL,
    client_operation_id apolysis_gateway.contract_identifier NOT NULL,
    request_digest apolysis_gateway.sha256_digest NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    outcome_kind apolysis_gateway.gateway_operation_kind NOT NULL,
    committed_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, operation_id),
    UNIQUE (
        organization_id,
        source_registration_id,
        principal_kind,
        principal_id,
        operation_kind,
        client_operation_id
    ),
    CONSTRAINT gateway_operations_run_fk
        FOREIGN KEY (organization_id, run_id)
        REFERENCES apolysis_gateway.runs (organization_id, run_id)
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT gateway_operations_outcome_ck
        CHECK (outcome_kind = operation_kind),
    CONSTRAINT gateway_operations_id_ck
        CHECK (operation_id > 0)
);

CREATE INDEX gateway_operations_run_idx
    ON apolysis_gateway.gateway_operations (
        organization_id,
        run_id,
        committed_at_unix_ms
    );

-- The durable idempotency row above outlives this TTL-bound secret-bearing
-- replay row. Deleting expired ciphertext must not make a reused operation ID
-- appear novel.
CREATE TABLE apolysis_gateway.operation_replays (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    operation_id bigint NOT NULL,
    outcome_schema_version apolysis_gateway.contract_schema_version NOT NULL DEFAULT '0.1',
    encryption_algorithm text NOT NULL
        CHECK (encryption_algorithm = 'aes-256-gcm'),
    cipher_version integer NOT NULL
        CHECK (cipher_version BETWEEN 1 AND 65535),
    encryption_key_ref apolysis_gateway.bounded_reference NOT NULL,
    wrapped_data_key bytea
        CHECK (wrapped_data_key IS NULL OR octet_length(wrapped_data_key) > 0),
    nonce bytea NOT NULL
        CHECK (octet_length(nonce) = 12),
    authentication_tag bytea NOT NULL
        CHECK (octet_length(authentication_tag) = 16),
    aad_digest apolysis_gateway.sha256_digest NOT NULL,
    outcome_ciphertext bytea NOT NULL
        CHECK (octet_length(outcome_ciphertext) > 0),
    created_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    expires_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, operation_id),
    CONSTRAINT operation_replays_operation_fk
        FOREIGN KEY (organization_id, operation_id)
        REFERENCES apolysis_gateway.gateway_operations (organization_id, operation_id)
        ON DELETE CASCADE,
    CONSTRAINT operation_replays_expiry_ck
        CHECK (expires_at_unix_ms > created_at_unix_ms)
);

COMMENT ON TABLE apolysis_gateway.operation_replays IS
    'Encrypted exact response replay; never store plaintext lease or proof bearer material.';

CREATE INDEX operation_replays_expiry_idx
    ON apolysis_gateway.operation_replays (expires_at_unix_ms);

CREATE TABLE apolysis_gateway.evidence_events (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    source_stream_id apolysis_gateway.contract_identifier NOT NULL,
    source_id apolysis_gateway.contract_identifier NOT NULL,
    source_event_id apolysis_gateway.contract_identifier NOT NULL,
    source_sequence apolysis_gateway.ijson_positive NOT NULL,
    envelope_digest apolysis_gateway.sha256_digest NOT NULL,
    ledger_ingest_sequence apolysis_gateway.ijson_positive NOT NULL,
    accepted_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    payload_type apolysis_gateway.contract_identifier NOT NULL,
    accepted_envelope_json jsonb NOT NULL
        CHECK (jsonb_typeof(accepted_envelope_json) = 'object'),
    PRIMARY KEY (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_event_id
    ),
    UNIQUE (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_sequence
    ),
    UNIQUE (organization_id, ledger_ingest_sequence),
    CONSTRAINT evidence_events_stream_fk
        FOREIGN KEY (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id
        )
        REFERENCES apolysis_gateway.source_streams (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id
        ),
    CONSTRAINT evidence_events_record_fk
        FOREIGN KEY (organization_id, run_id, ledger_ingest_sequence)
        REFERENCES apolysis_gateway.record_items (
            organization_id,
            run_id,
            ingest_sequence
        )
        DEFERRABLE INITIALLY DEFERRED
);

CREATE INDEX evidence_events_run_ingest_idx
    ON apolysis_gateway.evidence_events (
        organization_id,
        run_id,
        ledger_ingest_sequence
    );

CREATE TABLE apolysis_gateway.runtime_bindings (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    binding_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    source_stream_id apolysis_gateway.contract_identifier NOT NULL,
    asserting_source_id apolysis_gateway.contract_identifier NOT NULL,
    registration_policy_revision apolysis_gateway.ijson_positive NOT NULL,
    effective_trust_profile apolysis_gateway.trust_profile NOT NULL,
    manifest_version apolysis_gateway.contract_schema_version NOT NULL DEFAULT '0.1',
    manifest_digest apolysis_gateway.sha256_digest NOT NULL,
    binding_digest apolysis_gateway.sha256_digest NOT NULL,
    identity_kind apolysis_gateway.runtime_identity_kind NOT NULL,
    identity_ref apolysis_gateway.bounded_reference NOT NULL,
    identity_digest apolysis_gateway.sha256_digest NOT NULL,
    identity_hash_version text NOT NULL DEFAULT 'apolysis.gateway.runtime-identity-ref/v1'
        CHECK (identity_hash_version = 'apolysis.gateway.runtime-identity-ref/v1'),
    attribution apolysis_gateway.runtime_attribution NOT NULL,
    valid_from_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    valid_until_unix_ms apolysis_gateway.ijson_positive,
    ledger_ingest_sequence apolysis_gateway.ijson_positive NOT NULL,
    accepted_binding_json jsonb NOT NULL
        CHECK (jsonb_typeof(accepted_binding_json) = 'object'),
    PRIMARY KEY (organization_id, run_id, binding_id),
    UNIQUE (organization_id, ledger_ingest_sequence),
    UNIQUE (
        organization_id,
        run_id,
        binding_id,
        identity_kind,
        identity_digest,
        identity_hash_version,
        attribution
    ),
    CONSTRAINT runtime_bindings_stream_fk
        FOREIGN KEY (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id,
            asserting_source_id
        )
        REFERENCES apolysis_gateway.source_streams (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id
        ),
    CONSTRAINT runtime_bindings_record_fk
        FOREIGN KEY (organization_id, run_id, ledger_ingest_sequence)
        REFERENCES apolysis_gateway.record_items (
            organization_id,
            run_id,
            ingest_sequence
        )
        DEFERRABLE INITIALLY DEFERRED,
    CONSTRAINT runtime_bindings_validity_ck
        CHECK (valid_until_unix_ms IS NULL OR valid_until_unix_ms > valid_from_unix_ms)
);

CREATE INDEX runtime_bindings_run_identity_idx
    ON apolysis_gateway.runtime_bindings (
        organization_id,
        run_id,
        identity_kind,
        identity_digest
    );

CREATE TABLE apolysis_gateway.active_runtime_identities (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    identity_kind apolysis_gateway.runtime_identity_kind NOT NULL,
    identity_digest apolysis_gateway.sha256_digest NOT NULL,
    identity_hash_version text NOT NULL DEFAULT 'apolysis.gateway.runtime-identity-ref/v1'
        CHECK (identity_hash_version = 'apolysis.gateway.runtime-identity-ref/v1'),
    binding_attribution apolysis_gateway.runtime_attribution NOT NULL DEFAULT 'exact'
        CHECK (binding_attribution = 'exact'),
    run_id apolysis_gateway.contract_identifier NOT NULL,
    binding_id apolysis_gateway.contract_identifier NOT NULL,
    activated_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, identity_kind, identity_digest),
    UNIQUE (organization_id, run_id, binding_id),
    CONSTRAINT active_runtime_identities_binding_fk
        FOREIGN KEY (
            organization_id,
            run_id,
            binding_id,
            identity_kind,
            identity_digest,
            identity_hash_version,
            binding_attribution
        )
        REFERENCES apolysis_gateway.runtime_bindings (
            organization_id,
            run_id,
            binding_id,
            identity_kind,
            identity_digest,
            identity_hash_version,
            attribution
        )
        ON DELETE CASCADE
);

CREATE TABLE apolysis_gateway.finalization_declarations (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    declaration_revision apolysis_gateway.ijson_positive NOT NULL,
    declared_by_source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    declared_by_source_stream_id apolysis_gateway.contract_identifier NOT NULL,
    declared_by_source_id apolysis_gateway.contract_identifier NOT NULL,
    declared_by_principal_kind apolysis_gateway.principal_kind NOT NULL,
    declared_by_principal_id apolysis_gateway.contract_identifier NOT NULL,
    registration_policy_revision apolysis_gateway.ijson_positive NOT NULL,
    accepted_deadline_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    resulting_run_state apolysis_gateway.run_state NOT NULL
        CHECK (resulting_run_state IN ('finishing', 'finished')),
    declared_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    ledger_ingest_sequence apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, run_id, declaration_revision),
    UNIQUE (organization_id, ledger_ingest_sequence),
    CONSTRAINT finalization_declarations_stream_fk
        FOREIGN KEY (
            organization_id,
            run_id,
            declared_by_source_registration_id,
            declared_by_source_stream_id,
            declared_by_source_id
        )
        REFERENCES apolysis_gateway.source_streams (
            organization_id,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id
        ),
    CONSTRAINT finalization_declarations_record_fk
        FOREIGN KEY (organization_id, run_id, ledger_ingest_sequence)
        REFERENCES apolysis_gateway.record_items (
            organization_id,
            run_id,
            ingest_sequence
        )
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE apolysis_gateway.finalization_terminal_positions (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    declaration_revision apolysis_gateway.ijson_positive NOT NULL,
    source_stream_id apolysis_gateway.contract_identifier NOT NULL,
    source_id apolysis_gateway.contract_identifier NOT NULL,
    final_source_sequence apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (
        organization_id,
        run_id,
        declaration_revision,
        source_stream_id
    ),
    CONSTRAINT finalization_terminal_positions_declaration_fk
        FOREIGN KEY (organization_id, run_id, declaration_revision)
        REFERENCES apolysis_gateway.finalization_declarations (
            organization_id,
            run_id,
            declaration_revision
        )
        ON DELETE CASCADE,
    CONSTRAINT finalization_terminal_positions_stream_fk
        FOREIGN KEY (organization_id, run_id, source_stream_id, source_id)
        REFERENCES apolysis_gateway.source_streams (
            organization_id,
            run_id,
            source_stream_id,
            source_id
        )
);

CREATE TABLE apolysis_gateway.finalization_outcome_claims (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    declaration_revision apolysis_gateway.ijson_positive NOT NULL,
    outcome_claim_ref apolysis_gateway.bounded_reference NOT NULL,
    PRIMARY KEY (
        organization_id,
        run_id,
        declaration_revision,
        outcome_claim_ref
    ),
    CONSTRAINT finalization_outcome_claims_declaration_fk
        FOREIGN KEY (organization_id, run_id, declaration_revision)
        REFERENCES apolysis_gateway.finalization_declarations (
            organization_id,
            run_id,
            declaration_revision
        )
        ON DELETE CASCADE
);

COMMENT ON COLUMN apolysis_gateway.record_items.fact_json IS
    'JSONB is a query/storage representation, not RFC 8785 canonical bytes; verify JCS digest before insert.';

COMMENT ON COLUMN apolysis_gateway.evidence_events.accepted_envelope_json IS
    'JSONB numeric values must be rejected by the adapter when outside the exact I-JSON integer range.';
