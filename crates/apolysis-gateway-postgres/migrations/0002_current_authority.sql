-- SPDX-License-Identifier: Apache-2.0

-- Current transport authority for the production Gateway. The ledger schema
-- and current authority deliberately share one ordered sqlx migration stream.

CREATE TABLE apolysis_gateway.organizations (
    organization_id apolysis_gateway.contract_identifier PRIMARY KEY,
    organization_state text NOT NULL
        CHECK (organization_state IN ('active', 'suspended')),
    created_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    updated_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    CHECK (updated_at_unix_ms >= created_at_unix_ms)
);

CREATE TABLE apolysis_gateway.source_registrations (
    source_registration_id apolysis_gateway.contract_identifier PRIMARY KEY,
    organization_id apolysis_gateway.contract_identifier NOT NULL
        REFERENCES apolysis_gateway.organizations (organization_id)
        ON DELETE RESTRICT,
    source_id apolysis_gateway.contract_identifier NOT NULL,
    principal_kind apolysis_gateway.principal_kind NOT NULL,
    principal_id apolysis_gateway.contract_identifier NOT NULL,
    registration_state text NOT NULL
        CHECK (registration_state IN ('active', 'suspended', 'revoked')),
    policy_revision apolysis_gateway.ijson_positive NOT NULL,
    credential_epoch apolysis_gateway.ijson_positive NOT NULL,
    effective_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    expires_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    policy_document jsonb NOT NULL
        CHECK (jsonb_typeof(policy_document) = 'object'),
    created_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    updated_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    UNIQUE (organization_id, source_registration_id),
    CHECK (expires_at_unix_ms > effective_at_unix_ms),
    CHECK (updated_at_unix_ms >= created_at_unix_ms)
);

CREATE INDEX source_registrations_current_authority_idx
    ON apolysis_gateway.source_registrations (
        organization_id,
        registration_state,
        source_registration_id
    );

CREATE TABLE apolysis_gateway.transport_credentials (
    credential_id apolysis_gateway.contract_identifier PRIMARY KEY,
    certificate_fingerprint apolysis_gateway.sha256_digest NOT NULL UNIQUE,
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    credential_epoch apolysis_gateway.ijson_positive NOT NULL,
    effective_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    expires_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    revoked_at_unix_ms apolysis_gateway.ijson_positive,
    revocation_reason apolysis_gateway.contract_identifier,
    created_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    updated_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    FOREIGN KEY (organization_id, source_registration_id)
        REFERENCES apolysis_gateway.source_registrations (
            organization_id,
            source_registration_id
        )
        ON DELETE RESTRICT,
    CHECK (expires_at_unix_ms > effective_at_unix_ms),
    CHECK (
        (revoked_at_unix_ms IS NULL AND revocation_reason IS NULL)
        OR
        (revoked_at_unix_ms IS NOT NULL AND revocation_reason IS NOT NULL)
    ),
    CHECK (updated_at_unix_ms >= created_at_unix_ms)
);

CREATE INDEX transport_credentials_registration_idx
    ON apolysis_gateway.transport_credentials (
        organization_id,
        source_registration_id,
        credential_epoch
    );

CREATE UNIQUE INDEX transport_credentials_one_current_registration_idx
    ON apolysis_gateway.transport_credentials (source_registration_id)
    WHERE revoked_at_unix_ms IS NULL;

CREATE TABLE apolysis_gateway.authority_change_audit (
    authority_change_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    action text NOT NULL
        CHECK (action IN ('register_source', 'revoke_credential')),
    reason_code apolysis_gateway.contract_identifier NOT NULL,
    organization_id apolysis_gateway.contract_identifier,
    source_registration_id apolysis_gateway.contract_identifier,
    credential_id apolysis_gateway.contract_identifier,
    policy_revision apolysis_gateway.ijson_positive,
    credential_epoch apolysis_gateway.ijson_positive
);

CREATE INDEX authority_change_audit_registration_idx
    ON apolysis_gateway.authority_change_audit (
        organization_id,
        source_registration_id,
        occurred_at_unix_ms
    );

CREATE TABLE apolysis_gateway.gateway_authority_audit (
    gateway_authority_audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    requested_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    operation text NOT NULL
        CHECK (operation IN ('open_run', 'bind_runtime', 'ingest', 'finish_run')),
    decision text NOT NULL
        CHECK (decision IN ('authorized', 'unauthenticated', 'forbidden')),
    reason_code apolysis_gateway.contract_identifier NOT NULL,
    certificate_fingerprint apolysis_gateway.sha256_digest NOT NULL,
    organization_id apolysis_gateway.contract_identifier,
    source_registration_id apolysis_gateway.contract_identifier,
    credential_id apolysis_gateway.contract_identifier,
    policy_revision apolysis_gateway.ijson_positive,
    credential_epoch apolysis_gateway.ijson_positive
);

CREATE INDEX gateway_authority_audit_registration_idx
    ON apolysis_gateway.gateway_authority_audit (
        organization_id,
        source_registration_id,
        requested_at_unix_ms
    );

CREATE INDEX gateway_authority_audit_decision_idx
    ON apolysis_gateway.gateway_authority_audit (
        decision,
        requested_at_unix_ms
    );
