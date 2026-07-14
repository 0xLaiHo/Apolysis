-- SPDX-License-Identifier: Apache-2.0

-- Durable write-side lifecycle for explicitly authorized evidence objects.
-- Object bytes never enter PostgreSQL; this schema stores encrypted-key
-- material, immutable integrity metadata, lifecycle state, and audit facts.

CREATE DOMAIN apolysis_gateway.evidence_object_state AS text
    CHECK (VALUE IN ('uploading', 'available', 'delete_pending', 'deleted'));

-- Object lifecycle authority, deadlines, claims, and audit facts use one
-- PostgreSQL clock. Callers may propose durations, but never authoritative
-- wall-clock facts.
CREATE FUNCTION apolysis_gateway.evidence_object_db_now_unix_ms()
RETURNS bigint
LANGUAGE sql
VOLATILE
AS $$
    SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
$$;

-- Control-plane policy and deletion-target changes need the same organization
-- row mutex used by lifecycle transitions, but the control role must not gain
-- UPDATE authority over organizations merely to acquire that lock.
CREATE FUNCTION apolysis_gateway.lock_evidence_object_organization(
    checked_organization_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.organizations AS organization
    WHERE organization.organization_id = checked_organization_id
    FOR UPDATE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_evidence_object_organization(text)
FROM PUBLIC;

-- Runtime authority checks need row stability without UPDATE privilege on the
-- authority tables. These bounded helpers expose only lock acquisition and a
-- presence bit; callers still read and validate the rows through their normal
-- least-privilege SELECT grants.
CREATE FUNCTION apolysis_gateway.lock_evidence_object_organization_shared(
    checked_organization_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.organizations AS organization
    WHERE organization.organization_id = checked_organization_id
    FOR SHARE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_evidence_object_organization_shared(text)
FROM PUBLIC;

-- Reapers discover candidates without taking object locks, then acquire every
-- ancestor organization lock in database order before claiming any object.
-- Busy organizations are skipped so one control-plane transaction cannot
-- block unrelated tenants or invert organization -> object lock order.
CREATE FUNCTION apolysis_gateway.lock_evidence_object_reaper_organizations(
    checked_now_unix_ms bigint,
    checked_limit integer
)
RETURNS SETOF text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    IF checked_now_unix_ms IS NULL
        OR checked_limit IS NULL
        OR checked_now_unix_ms NOT BETWEEN 1 AND 9007199254740991
        OR checked_limit NOT BETWEEN 1 AND 256
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'evidence object organization lock batch is invalid';
    END IF;
    RETURN QUERY
    SELECT organization.organization_id::text
    FROM apolysis_gateway.organizations AS organization
    JOIN LATERAL (
        SELECT coalesce(
                   object.reap_claimed_at_unix_ms,
                   object.delete_requested_at_unix_ms,
                   object.created_at_unix_ms
               ) AS priority_unix_ms
        FROM apolysis_gateway.evidence_objects AS object
        WHERE object.organization_id = organization.organization_id
          AND (
                object.object_state = 'uploading' AND (
                    least(
                        object.upload_deadline_unix_ms,
                        object.created_at_unix_ms + coalesce((
                            SELECT policy.upload_timeout_ms
                            FROM apolysis_gateway.evidence_object_policy_revisions AS policy
                            WHERE policy.organization_id = object.organization_id
                              AND policy.privacy_profile_ref = object.privacy_profile_ref
                              AND policy.retention_profile_ref = object.retention_profile_ref
                              AND policy.policy_state = 'active'
                              AND policy.effective_at_unix_ms <= checked_now_unix_ms
                        ), object.upload_deadline_unix_ms - object.created_at_unix_ms)
                    ) <= checked_now_unix_ms
                    OR NOT EXISTS (
                        SELECT 1
                        FROM apolysis_gateway.evidence_object_policy_revisions AS policy
                        WHERE policy.organization_id = object.organization_id
                          AND policy.privacy_profile_ref = object.privacy_profile_ref
                          AND policy.retention_profile_ref = object.retention_profile_ref
                          AND policy.policy_state = 'active'
                          AND policy.effective_at_unix_ms <= checked_now_unix_ms
                          AND object.content_size_bytes <= policy.max_object_size_bytes
                          AND object.requested_retention_ms <= policy.retention_ms
                    )
                    OR NOT EXISTS (
                        SELECT 1
                        FROM apolysis_gateway.organizations AS current_organization
                        JOIN apolysis_gateway.runs AS run
                          ON run.organization_id = current_organization.organization_id
                        JOIN apolysis_gateway.source_registrations AS registration
                          ON registration.organization_id = current_organization.organization_id
                        JOIN apolysis_gateway.leases AS lease
                          ON lease.organization_id = current_organization.organization_id
                         AND lease.run_id = run.run_id
                         AND lease.source_registration_id = registration.source_registration_id
                        JOIN apolysis_gateway.lease_operations AS lease_operation
                          ON lease_operation.organization_id = lease.organization_id
                         AND lease_operation.lease_digest = lease.lease_digest
                         AND lease_operation.operation_kind = 'ingest'
                        WHERE current_organization.organization_id = object.organization_id
                          AND current_organization.organization_state = 'active'
                          AND run.run_id = object.run_id
                          AND run.state IN ('active', 'finishing')
                          AND registration.source_registration_id = object.source_registration_id
                          AND registration.source_id = object.source_id
                          AND registration.registration_state = 'active'
                          AND registration.policy_revision = object.lease_policy_revision
                          AND registration.effective_at_unix_ms <= checked_now_unix_ms
                          AND registration.expires_at_unix_ms > checked_now_unix_ms
                          AND lease.lease_digest = object.lease_digest
                          AND lease.source_stream_id = object.source_stream_id
                          AND lease.source_id = object.source_id
                          AND lease.registration_policy_revision = object.lease_policy_revision
                          AND lease.issued_at_unix_ms <= checked_now_unix_ms
                          AND lease.expires_at_unix_ms > checked_now_unix_ms
                          AND lease.revoked_at_unix_ms IS NULL
                    )
                )
                OR object.object_state = 'available' AND (
                    least(
                        object.expires_at_unix_ms,
                        object.created_at_unix_ms + coalesce((
                            SELECT policy.retention_ms
                            FROM apolysis_gateway.evidence_object_policy_revisions AS policy
                            WHERE policy.organization_id = object.organization_id
                              AND policy.privacy_profile_ref = object.privacy_profile_ref
                              AND policy.retention_profile_ref = object.retention_profile_ref
                              AND policy.policy_state = 'active'
                              AND policy.effective_at_unix_ms <= checked_now_unix_ms
                        ), object.requested_retention_ms)
                    ) <= checked_now_unix_ms
                    OR NOT EXISTS (
                        SELECT 1
                        FROM apolysis_gateway.evidence_object_policy_revisions AS policy
                        WHERE policy.organization_id = object.organization_id
                          AND policy.privacy_profile_ref = object.privacy_profile_ref
                          AND policy.retention_profile_ref = object.retention_profile_ref
                          AND policy.policy_state = 'active'
                          AND policy.effective_at_unix_ms <= checked_now_unix_ms
                          AND object.content_size_bytes <= policy.max_object_size_bytes
                          AND object.requested_retention_ms <= policy.retention_ms
                    )
                )
                OR object.object_state = 'delete_pending' AND (
                    object.storage_purged_at_unix_ms IS NULL
                    OR NOT EXISTS (
                        SELECT 1
                        FROM apolysis_gateway.evidence_object_deletion_requirements AS requirement
                        WHERE requirement.organization_id = object.organization_id
                          AND requirement.object_id = object.object_id
                          AND requirement.lifecycle_revision = object.delete_request_revision
                          AND NOT EXISTS (
                              SELECT 1
                              FROM apolysis_gateway.evidence_object_deletion_acknowledgements AS ack
                              WHERE ack.organization_id = requirement.organization_id
                                AND ack.object_id = requirement.object_id
                                AND ack.lifecycle_revision = requirement.lifecycle_revision
                                AND ack.component_id = requirement.component_id
                          )
                    )
                )
          )
          AND (
                object.reap_claim_until_unix_ms IS NULL
                OR object.reap_claim_until_unix_ms <= checked_now_unix_ms
          )
          AND (
                object.upload_fence_until_unix_ms IS NULL
                OR object.upload_fence_until_unix_ms <= checked_now_unix_ms
          )
        ORDER BY
            coalesce(
                object.reap_claimed_at_unix_ms,
                object.delete_requested_at_unix_ms,
                object.created_at_unix_ms
            ),
            object.object_id
        LIMIT 1
    ) AS candidate ON true
    ORDER BY candidate.priority_unix_ms, organization.organization_id
    LIMIT checked_limit
    FOR SHARE OF organization SKIP LOCKED;
    RETURN;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_evidence_object_reaper_organizations(bigint, integer)
FROM PUBLIC;

CREATE FUNCTION apolysis_gateway.lock_evidence_object_run_shared(
    checked_organization_id text,
    checked_run_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.runs AS run
    WHERE run.organization_id = checked_organization_id
      AND run.run_id = checked_run_id
    FOR SHARE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_evidence_object_run_shared(text, text)
FROM PUBLIC;

CREATE FUNCTION apolysis_gateway.lock_evidence_object_lease_shared(
    checked_organization_id text,
    checked_lease_digest bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.leases AS lease
    WHERE lease.organization_id = checked_organization_id
      AND lease.lease_digest = checked_lease_digest
    FOR SHARE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_evidence_object_lease_shared(text, bytea)
FROM PUBLIC;

CREATE FUNCTION apolysis_gateway.lock_evidence_source_authority_shared(
    checked_organization_id text,
    checked_source_registration_id text,
    checked_credential_id text,
    checked_run_id text,
    checked_source_stream_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.source_registrations AS registration
    WHERE registration.organization_id = checked_organization_id
      AND registration.source_registration_id = checked_source_registration_id
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM apolysis_gateway.transport_credentials AS credential
    WHERE credential.organization_id = checked_organization_id
      AND credential.source_registration_id = checked_source_registration_id
      AND credential.credential_id = checked_credential_id
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM apolysis_gateway.source_streams AS stream
    WHERE stream.organization_id = checked_organization_id
      AND stream.source_registration_id = checked_source_registration_id
      AND stream.run_id = checked_run_id
      AND stream.source_stream_id = checked_source_stream_id
    FOR SHARE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_evidence_source_authority_shared(
    text, text, text, text, text
) FROM PUBLIC;

CREATE FUNCTION apolysis_gateway.lock_gateway_authority_by_fingerprint(
    checked_certificate_fingerprint bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
DECLARE
    checked_organization_id text;
    checked_source_registration_id text;
BEGIN
    SELECT credential.organization_id, credential.source_registration_id
    INTO checked_organization_id, checked_source_registration_id
    FROM apolysis_gateway.transport_credentials AS credential
    WHERE credential.certificate_fingerprint = checked_certificate_fingerprint;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM apolysis_gateway.organizations AS organization
    WHERE organization.organization_id = checked_organization_id
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM apolysis_gateway.source_registrations AS registration
    WHERE registration.organization_id = checked_organization_id
      AND registration.source_registration_id = checked_source_registration_id
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM apolysis_gateway.transport_credentials AS credential
    WHERE credential.certificate_fingerprint = checked_certificate_fingerprint
      AND credential.organization_id = checked_organization_id
      AND credential.source_registration_id = checked_source_registration_id
    FOR SHARE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_gateway_authority_by_fingerprint(bytea)
FROM PUBLIC;

-- Gateway idempotency and lease coordination use exclusive row locks, but the
-- runtime never mutates these immutable records. Keep that lock authority
-- behind exact-key helpers instead of granting arbitrary UPDATE.
CREATE FUNCTION apolysis_gateway.lock_gateway_operation(
    checked_organization_id text,
    checked_source_registration_id text,
    checked_principal_kind text,
    checked_principal_id text,
    checked_operation_kind text,
    checked_client_operation_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.gateway_operations AS operation
    WHERE operation.organization_id = checked_organization_id
      AND operation.source_registration_id = checked_source_registration_id
      AND operation.principal_kind = checked_principal_kind
      AND operation.principal_id = checked_principal_id
      AND operation.operation_kind = checked_operation_kind
      AND operation.client_operation_id = checked_client_operation_id
    FOR UPDATE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_gateway_operation(
    text, text, text, text, text, text
) FROM PUBLIC;

CREATE FUNCTION apolysis_gateway.lock_gateway_client_run(
    checked_organization_id text,
    checked_principal_kind text,
    checked_principal_id text,
    checked_client_run_key text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.client_runs AS client_run
    WHERE client_run.organization_id = checked_organization_id
      AND client_run.principal_kind = checked_principal_kind
      AND client_run.principal_id = checked_principal_id
      AND client_run.client_run_key = checked_client_run_key
    FOR UPDATE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_gateway_client_run(text, text, text, text)
FROM PUBLIC;

CREATE FUNCTION apolysis_gateway.lock_gateway_runtime_binding(
    checked_organization_id text,
    checked_run_id text,
    checked_binding_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.runtime_bindings AS binding
    WHERE binding.organization_id = checked_organization_id
      AND binding.run_id = checked_run_id
      AND binding.binding_id = checked_binding_id
    FOR UPDATE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_gateway_runtime_binding(text, text, text)
FROM PUBLIC;

CREATE FUNCTION apolysis_gateway.lock_gateway_lease(
    checked_organization_id text,
    checked_lease_digest bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.leases AS lease
    WHERE lease.organization_id = checked_organization_id
      AND lease.lease_digest = checked_lease_digest
    FOR UPDATE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_gateway_lease(text, bytea)
FROM PUBLIC;

ALTER TABLE apolysis_gateway.runs
    ADD CONSTRAINT runs_object_policy_scope_key
    UNIQUE (
        organization_id,
        run_id,
        privacy_profile_ref,
        retention_profile_ref
    );

ALTER TABLE apolysis_gateway.leases
    ADD CONSTRAINT leases_evidence_object_scope_key
    UNIQUE (
        organization_id,
        lease_digest,
        run_id,
        source_registration_id,
        source_stream_id,
        source_id,
        registration_policy_revision
    );

CREATE TABLE apolysis_gateway.evidence_object_policy_revisions (
    organization_id apolysis_gateway.contract_identifier NOT NULL
        REFERENCES apolysis_gateway.organizations (organization_id)
        ON DELETE RESTRICT,
    privacy_profile_ref apolysis_gateway.contract_identifier NOT NULL,
    retention_profile_ref apolysis_gateway.contract_identifier NOT NULL,
    policy_revision apolysis_gateway.ijson_positive NOT NULL,
    policy_state text NOT NULL CHECK (policy_state IN ('active', 'retired')),
    max_object_size_bytes apolysis_gateway.ijson_positive NOT NULL,
    organization_quota_bytes apolysis_gateway.ijson_positive NOT NULL,
    organization_quota_objects apolysis_gateway.ijson_positive NOT NULL,
    uploads_per_minute apolysis_gateway.ijson_positive NOT NULL,
    upload_timeout_ms apolysis_gateway.ijson_positive NOT NULL,
    retention_ms apolysis_gateway.ijson_positive NOT NULL,
    effective_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    retired_at_unix_ms apolysis_gateway.ijson_positive,
    created_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (
        organization_id,
        privacy_profile_ref,
        retention_profile_ref,
        policy_revision
    ),
    CHECK (max_object_size_bytes <= organization_quota_bytes),
    CHECK (max_object_size_bytes <= 9007199254740975),
    CHECK (upload_timeout_ms < retention_ms),
    CHECK ((policy_state = 'active') = (retired_at_unix_ms IS NULL)),
    CHECK (effective_at_unix_ms <= created_at_unix_ms),
    CHECK (retired_at_unix_ms IS NULL OR retired_at_unix_ms >= effective_at_unix_ms)
);

CREATE UNIQUE INDEX evidence_object_policy_one_active_idx
    ON apolysis_gateway.evidence_object_policy_revisions (
        organization_id,
        privacy_profile_ref,
        retention_profile_ref
    )
    WHERE policy_state = 'active';

CREATE TABLE apolysis_gateway.organization_object_usage (
    organization_id apolysis_gateway.contract_identifier PRIMARY KEY
        REFERENCES apolysis_gateway.organizations (organization_id)
        ON DELETE RESTRICT,
    reserved_bytes apolysis_gateway.ijson_nonnegative NOT NULL DEFAULT 0,
    reserved_objects apolysis_gateway.ijson_nonnegative NOT NULL DEFAULT 0,
    updated_at_unix_ms apolysis_gateway.ijson_positive NOT NULL
);

CREATE TABLE apolysis_gateway.evidence_object_rate_windows (
    organization_id apolysis_gateway.contract_identifier NOT NULL
        REFERENCES apolysis_gateway.organizations (organization_id)
        ON DELETE CASCADE,
    window_start_unix_ms apolysis_gateway.ijson_nonnegative NOT NULL,
    accepted_uploads apolysis_gateway.ijson_positive NOT NULL,
    updated_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, window_start_unix_ms),
    CHECK (window_start_unix_ms % 60000 = 0)
);

CREATE INDEX evidence_object_rate_windows_expiry_idx
    ON apolysis_gateway.evidence_object_rate_windows (window_start_unix_ms);

CREATE TABLE apolysis_gateway.evidence_objects (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    object_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    source_stream_id apolysis_gateway.contract_identifier NOT NULL,
    source_id apolysis_gateway.contract_identifier NOT NULL,
    lease_digest apolysis_gateway.sha256_digest NOT NULL,
    lease_policy_revision apolysis_gateway.ijson_positive NOT NULL,
    lease_operation_kind apolysis_gateway.gateway_operation_kind
        GENERATED ALWAYS AS (
            'ingest'::apolysis_gateway.gateway_operation_kind
        ) STORED,
    client_upload_id apolysis_gateway.contract_identifier NOT NULL,
    capture_request_digest apolysis_gateway.sha256_digest NOT NULL,
    required_source_capability text NOT NULL
        CHECK (required_source_capability IN (
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
    payload_type apolysis_gateway.contract_identifier NOT NULL,
    payload_version apolysis_gateway.bounded_reference NOT NULL,
    content_digest apolysis_gateway.sha256_digest NOT NULL,
    content_size_bytes apolysis_gateway.ijson_positive NOT NULL,
    ciphertext_size_bytes apolysis_gateway.ijson_positive NOT NULL,
    object_state apolysis_gateway.evidence_object_state NOT NULL,
    privacy_profile_ref apolysis_gateway.contract_identifier NOT NULL,
    retention_profile_ref apolysis_gateway.contract_identifier NOT NULL,
    object_policy_revision apolysis_gateway.ijson_positive NOT NULL,
    requested_retention_ms apolysis_gateway.ijson_positive NOT NULL,
    lifecycle_revision apolysis_gateway.ijson_positive NOT NULL DEFAULT 1,
    delete_request_revision apolysis_gateway.ijson_positive,
    created_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    lifecycle_changed_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    upload_deadline_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    available_at_unix_ms apolysis_gateway.ijson_positive,
    expires_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    access_denied_at_unix_ms apolysis_gateway.ijson_positive,
    delete_requested_at_unix_ms apolysis_gateway.ijson_positive,
    storage_purged_at_unix_ms apolysis_gateway.ijson_positive,
    purged_at_unix_ms apolysis_gateway.ijson_positive,
    delete_reason apolysis_gateway.contract_identifier,
    upload_fence_token apolysis_gateway.contract_identifier,
    upload_fence_started_at_unix_ms apolysis_gateway.ijson_positive,
    upload_fence_until_unix_ms apolysis_gateway.ijson_positive,
    reap_claimed_by apolysis_gateway.contract_identifier,
    reap_claimed_at_unix_ms apolysis_gateway.ijson_positive,
    reap_claim_until_unix_ms apolysis_gateway.ijson_positive,
    PRIMARY KEY (organization_id, object_id),
    CONSTRAINT evidence_object_upload_identity_uq
        UNIQUE (organization_id, source_registration_id, client_upload_id),
    UNIQUE (
        organization_id,
        object_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_id,
        lease_digest,
        required_source_capability,
        payload_type,
        payload_version,
        content_digest,
        content_size_bytes
    ),
    FOREIGN KEY (organization_id, run_id)
        REFERENCES apolysis_gateway.runs (organization_id, run_id)
        ON DELETE RESTRICT,
    CONSTRAINT evidence_objects_lease_scope_fk
        FOREIGN KEY (
            organization_id,
            lease_digest,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id,
            lease_policy_revision
        ) REFERENCES apolysis_gateway.leases (
            organization_id,
            lease_digest,
            run_id,
            source_registration_id,
            source_stream_id,
            source_id,
            registration_policy_revision
        ) ON DELETE RESTRICT,
    CONSTRAINT evidence_objects_lease_ingest_fk
        FOREIGN KEY (
            organization_id,
            lease_digest,
            lease_operation_kind
        ) REFERENCES apolysis_gateway.lease_operations (
            organization_id,
            lease_digest,
            operation_kind
        ) ON DELETE RESTRICT,
    FOREIGN KEY (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_id
    ) REFERENCES apolysis_gateway.source_streams (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_id
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        required_source_capability
    ) REFERENCES apolysis_gateway.source_stream_capabilities (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        capability
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        organization_id,
        run_id,
        privacy_profile_ref,
        retention_profile_ref
    ) REFERENCES apolysis_gateway.runs (
        organization_id,
        run_id,
        privacy_profile_ref,
        retention_profile_ref
    ) ON DELETE RESTRICT,
    FOREIGN KEY (
        organization_id,
        privacy_profile_ref,
        retention_profile_ref,
        object_policy_revision
    ) REFERENCES apolysis_gateway.evidence_object_policy_revisions (
        organization_id,
        privacy_profile_ref,
        retention_profile_ref,
        policy_revision
    ) ON DELETE RESTRICT,
    CHECK (ciphertext_size_bytes = content_size_bytes + 16),
    CHECK (lifecycle_changed_at_unix_ms >= created_at_unix_ms),
    CHECK (upload_deadline_unix_ms > created_at_unix_ms),
    CHECK (expires_at_unix_ms > upload_deadline_unix_ms),
    CHECK (available_at_unix_ms IS NULL OR available_at_unix_ms >= created_at_unix_ms),
    CHECK (access_denied_at_unix_ms IS NULL OR access_denied_at_unix_ms >= created_at_unix_ms),
    CHECK (
        delete_requested_at_unix_ms IS NULL
        OR delete_requested_at_unix_ms >= created_at_unix_ms
    ),
    CHECK (
        storage_purged_at_unix_ms IS NULL
        OR storage_purged_at_unix_ms >= delete_requested_at_unix_ms
    ),
    CHECK (purged_at_unix_ms IS NULL OR purged_at_unix_ms >= storage_purged_at_unix_ms),
    CHECK (
        (upload_fence_token IS NULL)
        = (upload_fence_started_at_unix_ms IS NULL)
        AND (upload_fence_token IS NULL) = (upload_fence_until_unix_ms IS NULL)
    ),
    CHECK (
        upload_fence_until_unix_ms IS NULL
        OR upload_fence_until_unix_ms > upload_fence_started_at_unix_ms
    ),
    CHECK (
        (reap_claimed_by IS NULL) = (reap_claimed_at_unix_ms IS NULL)
        AND (reap_claimed_by IS NULL) = (reap_claim_until_unix_ms IS NULL)
    ),
    CHECK (reap_claim_until_unix_ms IS NULL OR reap_claim_until_unix_ms > created_at_unix_ms),
    CHECK (
        (object_state = 'uploading'
            AND available_at_unix_ms IS NULL
            AND delete_request_revision IS NULL
            AND access_denied_at_unix_ms IS NULL
            AND delete_requested_at_unix_ms IS NULL
            AND storage_purged_at_unix_ms IS NULL
            AND purged_at_unix_ms IS NULL
            AND delete_reason IS NULL)
        OR
        (object_state = 'available'
            AND available_at_unix_ms IS NOT NULL
            AND delete_request_revision IS NULL
            AND access_denied_at_unix_ms IS NULL
            AND delete_requested_at_unix_ms IS NULL
            AND storage_purged_at_unix_ms IS NULL
            AND purged_at_unix_ms IS NULL
            AND delete_reason IS NULL
            AND upload_fence_token IS NULL
            AND upload_fence_started_at_unix_ms IS NULL
            AND upload_fence_until_unix_ms IS NULL)
        OR
        (object_state = 'delete_pending'
            AND delete_request_revision IS NOT NULL
            AND access_denied_at_unix_ms IS NOT NULL
            AND delete_requested_at_unix_ms IS NOT NULL
            AND purged_at_unix_ms IS NULL
            AND delete_reason IS NOT NULL)
        OR
        (object_state = 'deleted'
            AND delete_request_revision IS NOT NULL
            AND access_denied_at_unix_ms IS NOT NULL
            AND delete_requested_at_unix_ms IS NOT NULL
            AND storage_purged_at_unix_ms IS NOT NULL
            AND purged_at_unix_ms IS NOT NULL
            AND delete_reason IS NOT NULL
            AND upload_fence_token IS NULL
            AND upload_fence_started_at_unix_ms IS NULL
            AND upload_fence_until_unix_ms IS NULL
            AND reap_claimed_by IS NULL
            AND reap_claimed_at_unix_ms IS NULL
            AND reap_claim_until_unix_ms IS NULL)
    )
);

-- Gateway ingest serializes competing references by exact object identity.
-- The helper keeps ordered row locking without granting the Gateway role any
-- UPDATE privilege over immutable lifecycle records.
CREATE FUNCTION apolysis_gateway.lock_evidence_objects_for_ingest(
    checked_organization_id text,
    checked_object_ids text[]
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
DECLARE
    locked_object_id text;
    locked_count bigint := 0;
BEGIN
    IF checked_object_ids IS NULL
        OR cardinality(checked_object_ids) NOT BETWEEN 1 AND 256
        OR array_position(checked_object_ids, NULL) IS NOT NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'evidence object lock set is invalid';
    END IF;
    FOR locked_object_id IN
        SELECT object.object_id
        FROM apolysis_gateway.evidence_objects AS object
        WHERE object.organization_id = checked_organization_id
          AND object.object_id = ANY(checked_object_ids)
        ORDER BY object.object_id
        FOR UPDATE OF object
    LOOP
        locked_count := locked_count + 1;
    END LOOP;
    RETURN locked_count;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_evidence_objects_for_ingest(text, text[])
FROM PUBLIC;

CREATE TABLE apolysis_gateway.evidence_object_storage_material (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    object_id apolysis_gateway.contract_identifier NOT NULL,
    storage_backend_ref apolysis_gateway.contract_identifier NOT NULL,
    storage_backend_binding_digest apolysis_gateway.sha256_digest NOT NULL,
    storage_operation_timeout_ms apolysis_gateway.ijson_positive NOT NULL,
    storage_key apolysis_gateway.contract_identifier NOT NULL,
    storage_etag apolysis_gateway.bounded_reference,
    storage_version_id apolysis_gateway.bounded_reference,
    encryption_algorithm text NOT NULL CHECK (encryption_algorithm = 'aes-256-gcm'),
    cipher_version integer NOT NULL CHECK (cipher_version = 1),
    encryption_key_ref apolysis_gateway.bounded_reference NOT NULL,
    encrypted_data_key bytea NOT NULL CHECK (octet_length(encrypted_data_key) = 48),
    key_wrap_nonce bytea NOT NULL CHECK (octet_length(key_wrap_nonce) = 12),
    content_nonce bytea NOT NULL CHECK (octet_length(content_nonce) = 12),
    aad_digest apolysis_gateway.sha256_digest NOT NULL,
    PRIMARY KEY (organization_id, object_id),
    UNIQUE (storage_backend_ref, storage_key),
    UNIQUE (encryption_key_ref, key_wrap_nonce),
    CONSTRAINT evidence_object_storage_timeout_ck
        CHECK (storage_operation_timeout_ms BETWEEN 100 AND 300000),
    FOREIGN KEY (organization_id, object_id)
        REFERENCES apolysis_gateway.evidence_objects (organization_id, object_id)
        ON DELETE RESTRICT
);

CREATE INDEX evidence_objects_reaper_idx
    ON apolysis_gateway.evidence_objects (
        object_state,
        upload_deadline_unix_ms,
        expires_at_unix_ms,
        upload_fence_until_unix_ms,
        reap_claim_until_unix_ms
    )
    WHERE object_state IN ('uploading', 'available', 'delete_pending');

CREATE INDEX evidence_objects_scope_idx
    ON apolysis_gateway.evidence_objects (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        object_state
    );

CREATE TABLE apolysis_gateway.evidence_event_objects (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    run_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    source_stream_id apolysis_gateway.contract_identifier NOT NULL,
    source_id apolysis_gateway.contract_identifier NOT NULL,
    source_event_id apolysis_gateway.contract_identifier NOT NULL,
    object_id apolysis_gateway.contract_identifier NOT NULL,
    lease_digest apolysis_gateway.sha256_digest NOT NULL,
    required_source_capability text NOT NULL,
    payload_type apolysis_gateway.contract_identifier NOT NULL,
    payload_version apolysis_gateway.bounded_reference NOT NULL,
    content_digest apolysis_gateway.sha256_digest NOT NULL,
    content_size_bytes apolysis_gateway.ijson_positive NOT NULL,
    bound_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_event_id
    ),
    UNIQUE (organization_id, object_id),
    FOREIGN KEY (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_event_id
    ) REFERENCES apolysis_gateway.evidence_events (
        organization_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_event_id
    ) DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (
        organization_id,
        object_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_id,
        lease_digest,
        required_source_capability,
        payload_type,
        payload_version,
        content_digest,
        content_size_bytes
    ) REFERENCES apolysis_gateway.evidence_objects (
        organization_id,
        object_id,
        run_id,
        source_registration_id,
        source_stream_id,
        source_id,
        lease_digest,
        required_source_capability,
        payload_type,
        payload_version,
        content_digest,
        content_size_bytes
    ) ON DELETE RESTRICT
);

CREATE TABLE apolysis_gateway.evidence_object_outbox (
    object_outbox_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    object_id apolysis_gateway.contract_identifier NOT NULL,
    lifecycle_revision apolysis_gateway.ijson_positive NOT NULL,
    event_kind text NOT NULL CHECK (event_kind IN (
        'upload_reserved',
        'object_available',
        'deletion_requested',
        'object_deleted',
        'retention_extended'
    )),
    event_json jsonb NOT NULL CHECK (jsonb_typeof(event_json) = 'object'),
    delivery_state text NOT NULL DEFAULT 'pending'
        CHECK (delivery_state IN ('pending', 'processing', 'published', 'dead_letter')),
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    claimed_by apolysis_gateway.contract_identifier,
    claimed_at_unix_ms apolysis_gateway.ijson_positive,
    claim_until_unix_ms apolysis_gateway.ijson_positive,
    published_at_unix_ms apolysis_gateway.ijson_positive,
    last_error_code apolysis_gateway.contract_identifier,
    created_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    UNIQUE (organization_id, object_id, lifecycle_revision),
    FOREIGN KEY (organization_id, object_id)
        REFERENCES apolysis_gateway.evidence_objects (organization_id, object_id)
        ON DELETE RESTRICT,
    CHECK (
        (delivery_state IN ('pending', 'dead_letter')
            AND claimed_by IS NULL
            AND claimed_at_unix_ms IS NULL
            AND claim_until_unix_ms IS NULL
            AND published_at_unix_ms IS NULL)
        OR
        (delivery_state = 'processing'
            AND claimed_by IS NOT NULL
            AND claimed_at_unix_ms IS NOT NULL
            AND claim_until_unix_ms > claimed_at_unix_ms
            AND published_at_unix_ms IS NULL)
        OR
        (delivery_state = 'published'
            AND claimed_by IS NULL
            AND claimed_at_unix_ms IS NULL
            AND claim_until_unix_ms IS NULL
            AND published_at_unix_ms IS NOT NULL)
    ),
    CHECK (available_at_unix_ms >= created_at_unix_ms),
    CHECK (claimed_at_unix_ms IS NULL OR claimed_at_unix_ms >= created_at_unix_ms),
    CHECK (published_at_unix_ms IS NULL OR published_at_unix_ms >= created_at_unix_ms),
    CHECK (octet_length(event_json::text) <= 4096)
);

CREATE INDEX evidence_object_outbox_dispatch_idx
    ON apolysis_gateway.evidence_object_outbox (
        delivery_state,
        available_at_unix_ms,
        object_outbox_id
    )
    WHERE delivery_state IN ('pending', 'processing');

CREATE TABLE apolysis_gateway.evidence_object_audit (
    object_audit_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    object_id apolysis_gateway.contract_identifier,
    lifecycle_revision apolysis_gateway.ijson_positive,
    occurred_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    actor_kind text NOT NULL CHECK (actor_kind IN ('source', 'system', 'operator')),
    actor_id apolysis_gateway.contract_identifier NOT NULL,
    action text NOT NULL CHECK (action IN (
        'reserve_upload',
        'finalize_upload',
        'reject_upload',
        'request_delete',
        'purge_object',
        'extend_retention',
        'register_deletion_target'
    )),
    decision text NOT NULL CHECK (decision IN ('allowed', 'denied', 'completed', 'failed')),
    reason_code apolysis_gateway.contract_identifier NOT NULL,
    metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata_json) = 'object'),
    UNIQUE (organization_id, object_id, lifecycle_revision),
    FOREIGN KEY (organization_id)
        REFERENCES apolysis_gateway.organizations (organization_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, object_id)
        REFERENCES apolysis_gateway.evidence_objects (organization_id, object_id)
        ON DELETE RESTRICT
        DEFERRABLE INITIALLY DEFERRED,
    CHECK (lifecycle_revision IS NULL OR object_id IS NOT NULL),
    CHECK (octet_length(metadata_json::text) <= 2048)
);

CREATE INDEX evidence_object_audit_scope_idx
    ON apolysis_gateway.evidence_object_audit (
        organization_id,
        object_id,
        occurred_at_unix_ms
    );

-- Future projectors, caches, grants, exports, and streams register here when
-- they begin retaining object reachability. Deletion remains pending until all
-- currently required targets acknowledge the object's lifecycle revision.
CREATE TABLE apolysis_gateway.evidence_object_deletion_targets (
    organization_id apolysis_gateway.contract_identifier NOT NULL
        REFERENCES apolysis_gateway.organizations (organization_id)
        ON DELETE CASCADE,
    component_id apolysis_gateway.contract_identifier NOT NULL,
    principal_kind apolysis_gateway.principal_kind NOT NULL,
    principal_id apolysis_gateway.contract_identifier NOT NULL,
    required boolean NOT NULL DEFAULT true,
    registered_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, component_id),
    CONSTRAINT evidence_object_delete_target_principal_key
        UNIQUE (
            organization_id,
            component_id,
            principal_kind,
            principal_id
        )
);

-- Component bearer credentials are represented only by a keyed digest. The
-- plaintext bearer is authenticated above this seam and is never persisted.
CREATE TABLE apolysis_gateway.evidence_object_deletion_credentials (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    component_id apolysis_gateway.contract_identifier NOT NULL,
    principal_kind apolysis_gateway.principal_kind NOT NULL,
    principal_id apolysis_gateway.contract_identifier NOT NULL,
    credential_id apolysis_gateway.contract_identifier NOT NULL,
    credential_epoch apolysis_gateway.ijson_positive NOT NULL,
    credential_digest apolysis_gateway.sha256_digest NOT NULL,
    credential_hash_version text NOT NULL DEFAULT
        'apolysis.evidence-deletion-component/v1'
        CHECK (
            credential_hash_version =
                'apolysis.evidence-deletion-component/v1'
        ),
    effective_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    expires_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    revoked_at_unix_ms apolysis_gateway.ijson_positive,
    created_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, component_id, credential_id),
    CONSTRAINT evidence_object_delete_credential_scope_key
        UNIQUE (
            organization_id,
            component_id,
            principal_kind,
            principal_id,
            credential_id,
            credential_epoch
        ),
    CONSTRAINT evidence_object_delete_credential_digest_key
        UNIQUE (credential_digest),
    CONSTRAINT evidence_object_delete_credential_target_fk
        FOREIGN KEY (
            organization_id,
            component_id,
            principal_kind,
            principal_id
        )
        REFERENCES apolysis_gateway.evidence_object_deletion_targets (
            organization_id,
            component_id,
            principal_kind,
            principal_id
        ) ON DELETE RESTRICT,
    CONSTRAINT evidence_object_delete_credential_time_ck
        CHECK (
            expires_at_unix_ms > effective_at_unix_ms
            AND (
                revoked_at_unix_ms IS NULL
                OR revoked_at_unix_ms >= effective_at_unix_ms
            )
        )
);

CREATE UNIQUE INDEX evidence_object_delete_one_current_credential_idx
    ON apolysis_gateway.evidence_object_deletion_credentials (
        organization_id,
        component_id
    )
    WHERE revoked_at_unix_ms IS NULL;

CREATE TABLE apolysis_gateway.evidence_object_deletion_acknowledgements (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    object_id apolysis_gateway.contract_identifier NOT NULL,
    component_id apolysis_gateway.contract_identifier NOT NULL,
    lifecycle_revision apolysis_gateway.ijson_positive NOT NULL,
    principal_kind apolysis_gateway.principal_kind NOT NULL,
    principal_id apolysis_gateway.contract_identifier NOT NULL,
    credential_id apolysis_gateway.contract_identifier NOT NULL,
    credential_epoch apolysis_gateway.ijson_positive NOT NULL,
    -- Input-only proof. The BEFORE INSERT guard authenticates it and clears it
    -- so the durable acknowledgement never stores reusable credential data.
    presented_credential_digest apolysis_gateway.sha256_digest,
    acknowledged_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, object_id, lifecycle_revision, component_id),
    FOREIGN KEY (organization_id, object_id)
        REFERENCES apolysis_gateway.evidence_objects (organization_id, object_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, component_id)
        REFERENCES apolysis_gateway.evidence_object_deletion_targets (
            organization_id,
            component_id
        ) ON DELETE RESTRICT,
    CONSTRAINT evidence_object_delete_ack_credential_fk
        FOREIGN KEY (
            organization_id,
            component_id,
            principal_kind,
            principal_id,
            credential_id,
            credential_epoch
        ) REFERENCES apolysis_gateway.evidence_object_deletion_credentials (
            organization_id,
            component_id,
            principal_kind,
            principal_id,
            credential_id,
            credential_epoch
        ) ON DELETE RESTRICT,
    CHECK (presented_credential_digest IS NULL)
);

CREATE TABLE apolysis_gateway.evidence_object_deletion_requirements (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    object_id apolysis_gateway.contract_identifier NOT NULL,
    component_id apolysis_gateway.contract_identifier NOT NULL,
    lifecycle_revision apolysis_gateway.ijson_positive NOT NULL,
    required_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (organization_id, object_id, lifecycle_revision, component_id),
    FOREIGN KEY (organization_id, object_id)
        REFERENCES apolysis_gateway.evidence_objects (organization_id, object_id)
        ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, component_id)
        REFERENCES apolysis_gateway.evidence_object_deletion_targets (
            organization_id,
            component_id
        ) ON DELETE RESTRICT
);

ALTER TABLE apolysis_gateway.evidence_object_deletion_acknowledgements
    ADD CONSTRAINT evidence_object_deletion_ack_requirement_fk
    FOREIGN KEY (
        organization_id,
        object_id,
        lifecycle_revision,
        component_id
    ) REFERENCES apolysis_gateway.evidence_object_deletion_requirements (
        organization_id,
        object_id,
        lifecycle_revision,
        component_id
    ) ON DELETE RESTRICT;

ALTER TABLE apolysis_gateway.evidence_objects
    ADD CONSTRAINT evidence_objects_current_outbox_fk
    FOREIGN KEY (organization_id, object_id, lifecycle_revision)
    REFERENCES apolysis_gateway.evidence_object_outbox (
        organization_id,
        object_id,
        lifecycle_revision
    ) DEFERRABLE INITIALLY DEFERRED,
    ADD CONSTRAINT evidence_objects_current_audit_fk
    FOREIGN KEY (organization_id, object_id, lifecycle_revision)
    REFERENCES apolysis_gateway.evidence_object_audit (
        organization_id,
        object_id,
        lifecycle_revision
    ) DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION apolysis_gateway.enforce_evidence_object_policy_revision()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    database_now_unix_ms bigint;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    IF NOT apolysis_gateway.lock_evidence_object_organization(NEW.organization_id) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            CONSTRAINT = 'evidence_object_policy_organization_fk',
            MESSAGE = 'evidence object policy organization is unavailable';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF NEW.effective_at_unix_ms > database_now_unix_ms THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_policy_time_ck',
                MESSAGE = 'evidence object policy effective time is in the future';
        END IF;
        NEW.created_at_unix_ms := database_now_unix_ms;
    ELSIF OLD.policy_state = 'active' AND NEW.policy_state = 'retired' THEN
        NEW.retired_at_unix_ms := database_now_unix_ms;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        IF OLD.policy_state = 'retired'
            OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
            OR NEW.privacy_profile_ref IS DISTINCT FROM OLD.privacy_profile_ref
            OR NEW.retention_profile_ref IS DISTINCT FROM OLD.retention_profile_ref
            OR NEW.policy_revision IS DISTINCT FROM OLD.policy_revision
            OR NEW.max_object_size_bytes IS DISTINCT FROM OLD.max_object_size_bytes
            OR NEW.organization_quota_bytes IS DISTINCT FROM OLD.organization_quota_bytes
            OR NEW.organization_quota_objects IS DISTINCT FROM OLD.organization_quota_objects
            OR NEW.uploads_per_minute IS DISTINCT FROM OLD.uploads_per_minute
            OR NEW.upload_timeout_ms IS DISTINCT FROM OLD.upload_timeout_ms
            OR NEW.retention_ms IS DISTINCT FROM OLD.retention_ms
            OR NEW.effective_at_unix_ms IS DISTINCT FROM OLD.effective_at_unix_ms
            OR NEW.created_at_unix_ms IS DISTINCT FROM OLD.created_at_unix_ms
            OR (OLD.policy_state = 'active' AND NEW.policy_state <> 'retired')
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_policy_immutable_ck',
                MESSAGE = 'evidence object policy revision is immutable';
        END IF;
    END IF;

    IF NEW.policy_state = 'active' AND EXISTS (
        SELECT 1
        FROM apolysis_gateway.evidence_object_policy_revisions AS active_policy
        WHERE active_policy.organization_id = NEW.organization_id
          AND active_policy.policy_state = 'active'
          AND (
              active_policy.privacy_profile_ref,
              active_policy.retention_profile_ref,
              active_policy.policy_revision
          ) <> (
              NEW.privacy_profile_ref,
              NEW.retention_profile_ref,
              NEW.policy_revision
          )
          AND (
              active_policy.organization_quota_bytes,
              active_policy.organization_quota_objects,
              active_policy.uploads_per_minute
          ) <> (
              NEW.organization_quota_bytes,
              NEW.organization_quota_objects,
              NEW.uploads_per_minute
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_organization_limits_ck',
            MESSAGE = 'active evidence object organization limits disagree';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_object_policy_revision_guard
BEFORE INSERT OR UPDATE ON apolysis_gateway.evidence_object_policy_revisions
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.enforce_evidence_object_policy_revision();

CREATE FUNCTION apolysis_gateway.assert_evidence_object_current_lease(
    checked_organization_id text,
    checked_run_id text,
    checked_source_registration_id text,
    checked_source_stream_id text,
    checked_source_id text,
    checked_lease_digest bytea,
    checked_lease_policy_revision bigint,
    allowed_run_states text[]
)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    database_now_unix_ms bigint;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    PERFORM 1
    FROM apolysis_gateway.organizations AS organization
    JOIN apolysis_gateway.source_registrations AS registration
      ON registration.organization_id = organization.organization_id
    JOIN apolysis_gateway.runs AS run
      ON run.organization_id = organization.organization_id
    JOIN apolysis_gateway.source_streams AS stream
      ON stream.organization_id = run.organization_id
     AND stream.run_id = run.run_id
     AND stream.source_registration_id = registration.source_registration_id
    JOIN apolysis_gateway.leases AS lease
      ON lease.organization_id = stream.organization_id
     AND lease.run_id = stream.run_id
     AND lease.source_registration_id = stream.source_registration_id
     AND lease.source_stream_id = stream.source_stream_id
     AND lease.source_id = stream.source_id
    JOIN apolysis_gateway.lease_operations AS operation
      ON operation.organization_id = lease.organization_id
     AND operation.lease_digest = lease.lease_digest
     AND operation.operation_kind = 'ingest'
    WHERE organization.organization_id = checked_organization_id
      AND organization.organization_state = 'active'
      AND registration.source_registration_id = checked_source_registration_id
      AND registration.source_id = checked_source_id
      AND registration.registration_state = 'active'
      AND registration.policy_revision = checked_lease_policy_revision
      AND registration.effective_at_unix_ms <= database_now_unix_ms
      AND registration.expires_at_unix_ms > database_now_unix_ms
      AND run.run_id = checked_run_id
      AND run.state = ANY(allowed_run_states)
      AND stream.source_stream_id = checked_source_stream_id
      AND stream.source_id = checked_source_id
      AND stream.registration_policy_revision = checked_lease_policy_revision
      AND lease.lease_digest = checked_lease_digest
      AND lease.registration_policy_revision = checked_lease_policy_revision
      AND lease.principal_kind = registration.principal_kind
      AND lease.principal_id = registration.principal_id
      AND lease.issued_at_unix_ms <= database_now_unix_ms
      AND lease.expires_at_unix_ms > database_now_unix_ms
      AND lease.revoked_at_unix_ms IS NULL
    FOR SHARE OF organization, registration, run, stream, lease, operation;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_current_lease_ck',
            MESSAGE = 'evidence object lease authority is unavailable';
    END IF;
END;
$$;

CREATE FUNCTION apolysis_gateway.reserve_evidence_object_capacity()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
DECLARE
    selected_policy apolysis_gateway.evidence_object_policy_revisions%ROWTYPE;
    database_now_unix_ms bigint;
    lease_expires_at_unix_ms bigint;
    rate_window_unix_ms bigint;
    capacity_reserved boolean;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    IF NEW.object_state <> 'uploading'
        OR NEW.lifecycle_revision <> 1
        OR NEW.delete_request_revision IS NOT NULL
        OR NEW.upload_fence_token IS NOT NULL
        OR NEW.upload_fence_started_at_unix_ms IS NOT NULL
        OR NEW.upload_fence_until_unix_ms IS NOT NULL
        OR NEW.reap_claimed_by IS NOT NULL
        OR NEW.reap_claimed_at_unix_ms IS NOT NULL
        OR NEW.reap_claim_until_unix_ms IS NOT NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_trusted_creation_ck',
            MESSAGE = 'evidence object creation facts are invalid';
    END IF;

    PERFORM apolysis_gateway.assert_evidence_object_current_lease(
        NEW.organization_id,
        NEW.run_id,
        NEW.source_registration_id,
        NEW.source_stream_id,
        NEW.source_id,
        NEW.lease_digest,
        NEW.lease_policy_revision,
        ARRAY['active']::text[]
    );
    SELECT lease.expires_at_unix_ms
    INTO STRICT lease_expires_at_unix_ms
    FROM apolysis_gateway.leases AS lease
    WHERE lease.organization_id = NEW.organization_id
      AND lease.lease_digest = NEW.lease_digest;

    SELECT policy.* INTO selected_policy
    FROM apolysis_gateway.evidence_object_policy_revisions AS policy
    WHERE policy.organization_id = NEW.organization_id
      AND policy.privacy_profile_ref = NEW.privacy_profile_ref
      AND policy.retention_profile_ref = NEW.retention_profile_ref
      AND policy.policy_revision = NEW.object_policy_revision
    FOR SHARE;
    IF NOT FOUND
        OR selected_policy.policy_state <> 'active'
        OR selected_policy.effective_at_unix_ms > database_now_unix_ms
        OR NEW.content_size_bytes > selected_policy.max_object_size_bytes
        OR NEW.requested_retention_ms <= selected_policy.upload_timeout_ms
        OR NEW.requested_retention_ms > selected_policy.retention_ms
        OR database_now_unix_ms
            > 9007199254740991 - NEW.requested_retention_ms
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_policy_bounds_ck',
            MESSAGE = 'evidence object exceeds active policy bounds';
    END IF;

    NEW.created_at_unix_ms := database_now_unix_ms;
    NEW.lifecycle_changed_at_unix_ms := database_now_unix_ms;
    NEW.upload_deadline_unix_ms :=
        least(
            database_now_unix_ms + selected_policy.upload_timeout_ms,
            lease_expires_at_unix_ms
        );
    NEW.expires_at_unix_ms :=
        database_now_unix_ms + NEW.requested_retention_ms;

    rate_window_unix_ms := (database_now_unix_ms / 60000) * 60000;
    capacity_reserved := NULL;
    INSERT INTO apolysis_gateway.evidence_object_rate_windows (
        organization_id,
        window_start_unix_ms,
        accepted_uploads,
        updated_at_unix_ms
    ) VALUES (
        NEW.organization_id,
        rate_window_unix_ms,
        1,
        database_now_unix_ms
    )
    ON CONFLICT (organization_id, window_start_unix_ms) DO UPDATE
        SET accepted_uploads =
                apolysis_gateway.evidence_object_rate_windows.accepted_uploads + 1,
            updated_at_unix_ms = EXCLUDED.updated_at_unix_ms
        WHERE apolysis_gateway.evidence_object_rate_windows.accepted_uploads
            < selected_policy.uploads_per_minute
    RETURNING true INTO capacity_reserved;
    IF capacity_reserved IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_rate_limit_ck',
            MESSAGE = 'evidence object upload rate exceeded';
    END IF;

    INSERT INTO apolysis_gateway.organization_object_usage (
        organization_id,
        reserved_bytes,
        reserved_objects,
        updated_at_unix_ms
    ) VALUES (NEW.organization_id, 0, 0, database_now_unix_ms)
    ON CONFLICT (organization_id) DO NOTHING;
    capacity_reserved := NULL;
    UPDATE apolysis_gateway.organization_object_usage AS usage
       SET reserved_bytes = usage.reserved_bytes + NEW.content_size_bytes,
           reserved_objects = usage.reserved_objects + 1,
           updated_at_unix_ms = database_now_unix_ms
     WHERE usage.organization_id = NEW.organization_id
       AND usage.reserved_bytes
            <= selected_policy.organization_quota_bytes - NEW.content_size_bytes
       AND usage.reserved_objects < selected_policy.organization_quota_objects
    RETURNING true INTO capacity_reserved;
    IF capacity_reserved IS DISTINCT FROM true THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_quota_ck',
            MESSAGE = 'evidence object organization quota exceeded';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_object_reservation_guard
BEFORE INSERT ON apolysis_gateway.evidence_objects
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.reserve_evidence_object_capacity();

CREATE FUNCTION apolysis_gateway.enforce_evidence_object_rate_window()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    database_now_unix_ms bigint;
    current_window_unix_ms bigint;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    current_window_unix_ms := (database_now_unix_ms / 60000) * 60000;
    IF TG_OP = 'INSERT' THEN
        NEW.window_start_unix_ms := current_window_unix_ms;
        NEW.accepted_uploads := 1;
        NEW.updated_at_unix_ms := database_now_unix_ms;
        RETURN NEW;
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
            OR NEW.window_start_unix_ms IS DISTINCT FROM OLD.window_start_unix_ms
            OR OLD.window_start_unix_ms <> current_window_unix_ms
            OR NEW.accepted_uploads <> OLD.accepted_uploads + 1
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_rate_window_history_ck',
                MESSAGE = 'evidence object rate history cannot be rewritten';
        END IF;
        NEW.updated_at_unix_ms := database_now_unix_ms;
        RETURN NEW;
    END IF;
    IF OLD.window_start_unix_ms >= database_now_unix_ms - 86400000 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_rate_window_history_ck',
            MESSAGE = 'current evidence object rate history cannot be deleted';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER evidence_object_rate_window_history_guard
BEFORE INSERT OR UPDATE OR DELETE
ON apolysis_gateway.evidence_object_rate_windows
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.enforce_evidence_object_rate_window();

CREATE FUNCTION apolysis_gateway.validate_evidence_object_rate_aggregate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    checked_organization_id text;
    checked_window_start_unix_ms bigint;
    expected_uploads bigint;
    stored_uploads bigint;
BEGIN
    checked_organization_id := NEW.organization_id;
    IF TG_TABLE_NAME = 'evidence_objects' THEN
        checked_window_start_unix_ms :=
            (NEW.created_at_unix_ms / 60000) * 60000;
    ELSE
        checked_window_start_unix_ms := NEW.window_start_unix_ms;
    END IF;
    SELECT count(*)
    INTO expected_uploads
    FROM apolysis_gateway.evidence_objects AS object
    WHERE object.organization_id = checked_organization_id
      AND object.created_at_unix_ms >= checked_window_start_unix_ms
      AND object.created_at_unix_ms < checked_window_start_unix_ms + 60000;
    SELECT rate.accepted_uploads
    INTO stored_uploads
    FROM apolysis_gateway.evidence_object_rate_windows AS rate
    WHERE rate.organization_id = checked_organization_id
      AND rate.window_start_unix_ms = checked_window_start_unix_ms;
    IF stored_uploads IS DISTINCT FROM expected_uploads THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_rate_aggregate_ck',
            MESSAGE = 'evidence object rate history disagrees with durable objects';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER evidence_object_rate_counter_guard
AFTER INSERT OR UPDATE ON apolysis_gateway.evidence_object_rate_windows
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.validate_evidence_object_rate_aggregate();

CREATE CONSTRAINT TRIGGER evidence_object_rate_object_guard
AFTER INSERT ON apolysis_gateway.evidence_objects
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.validate_evidence_object_rate_aggregate();

CREATE FUNCTION apolysis_gateway.prevent_evidence_object_counter_truncate()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = 'evidence_object_counter_truncate_ck',
        MESSAGE = 'evidence object counter history cannot be truncated';
END;
$$;

CREATE TRIGGER evidence_object_rate_window_no_truncate
BEFORE TRUNCATE ON apolysis_gateway.evidence_object_rate_windows
FOR EACH STATEMENT
EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_counter_truncate();

CREATE FUNCTION apolysis_gateway.enforce_evidence_object_usage_counter()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.reserved_bytes <> 0 OR NEW.reserved_objects <> 0 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_usage_history_ck',
                MESSAGE = 'evidence object usage must begin empty';
        END IF;
        NEW.updated_at_unix_ms :=
            apolysis_gateway.evidence_object_db_now_unix_ms();
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_usage_history_ck',
            MESSAGE = 'evidence object usage history cannot be deleted';
    END IF;
    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR NOT (
            (
                NEW.reserved_objects = OLD.reserved_objects + 1
                AND NEW.reserved_bytes > OLD.reserved_bytes
            )
            OR (
                OLD.reserved_objects > 0
                AND NEW.reserved_objects = OLD.reserved_objects - 1
                AND NEW.reserved_bytes < OLD.reserved_bytes
            )
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_usage_history_ck',
            MESSAGE = 'evidence object usage history cannot be rewritten';
    END IF;
    NEW.updated_at_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_object_usage_history_guard
BEFORE INSERT OR UPDATE OR DELETE
ON apolysis_gateway.organization_object_usage
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.enforce_evidence_object_usage_counter();

CREATE TRIGGER evidence_object_usage_no_truncate
BEFORE TRUNCATE ON apolysis_gateway.organization_object_usage
FOR EACH STATEMENT
EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_counter_truncate();

CREATE FUNCTION apolysis_gateway.validate_evidence_object_usage_aggregate()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
DECLARE
    checked_organization_id text;
    expected_bytes bigint;
    expected_objects bigint;
    stored_bytes bigint;
    stored_objects bigint;
BEGIN
    checked_organization_id := NEW.organization_id;
    SELECT
        coalesce(sum(object.content_size_bytes), 0),
        count(*)
    INTO expected_bytes, expected_objects
    FROM apolysis_gateway.evidence_objects AS object
    WHERE object.organization_id = checked_organization_id
      AND object.object_state <> 'deleted';
    SELECT usage.reserved_bytes, usage.reserved_objects
    INTO stored_bytes, stored_objects
    FROM apolysis_gateway.organization_object_usage AS usage
    WHERE usage.organization_id = checked_organization_id;
    IF stored_bytes IS DISTINCT FROM expected_bytes
        OR stored_objects IS DISTINCT FROM expected_objects
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_usage_aggregate_ck',
            MESSAGE = 'evidence object usage disagrees with durable objects';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER evidence_object_usage_counter_guard
AFTER INSERT OR UPDATE ON apolysis_gateway.organization_object_usage
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.validate_evidence_object_usage_aggregate();

CREATE CONSTRAINT TRIGGER evidence_object_usage_object_guard
AFTER INSERT OR UPDATE ON apolysis_gateway.evidence_objects
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.validate_evidence_object_usage_aggregate();

CREATE FUNCTION apolysis_gateway.enforce_evidence_object_transition()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
DECLARE
    policy_retention_ms bigint;
    current_policy_max_object_size_bytes bigint;
    current_policy_upload_timeout_ms bigint;
    current_policy_retention_ms bigint;
    lifecycle_changed boolean;
    database_now_unix_ms bigint;
    latest_target_registration_ms bigint;
    storage_operation_timeout_ms bigint;
    upload_fence_changed boolean;
    reap_claim_changed boolean;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    IF NEW.object_state = 'delete_pending' AND OLD.object_state <> 'delete_pending' THEN
        -- Serialize the deletion target snapshot with target registration.
        -- Registrations that win this lock are included; registrations that
        -- wait receive a later trusted timestamp and apply only to later
        -- deletion requests.
        PERFORM 1
        FROM apolysis_gateway.organizations AS organization
        WHERE organization.organization_id = NEW.organization_id
        FOR SHARE;
        SELECT max(target.registered_at_unix_ms)
          INTO latest_target_registration_ms
          FROM apolysis_gateway.evidence_object_deletion_targets AS target
         WHERE target.organization_id = NEW.organization_id
           AND target.required;
        -- The caller's timestamp is not an authority. Accepting a future
        -- value here could strand the object forever because no later purge
        -- timestamp could satisfy the lifecycle ordering checks.
        NEW.delete_requested_at_unix_ms := greatest(
            database_now_unix_ms,
            coalesce(latest_target_registration_ms, 0)
        );
        NEW.access_denied_at_unix_ms := NEW.delete_requested_at_unix_ms;
    END IF;

    IF OLD.object_state = 'uploading' AND NEW.object_state = 'available' THEN
        PERFORM apolysis_gateway.assert_evidence_object_current_lease(
            NEW.organization_id,
            NEW.run_id,
            NEW.source_registration_id,
            NEW.source_stream_id,
            NEW.source_id,
            NEW.lease_digest,
            NEW.lease_policy_revision,
            ARRAY['active', 'finishing']::text[]
        );
        IF database_now_unix_ms >= OLD.upload_deadline_unix_ms
            OR database_now_unix_ms >= OLD.expires_at_unix_ms
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_upload_window_ck',
                MESSAGE = 'evidence object upload window has closed';
        END IF;
        NEW.available_at_unix_ms := database_now_unix_ms;
    END IF;

    IF OLD.object_state = 'delete_pending' AND NEW.object_state = 'deleted' THEN
        NEW.purged_at_unix_ms := database_now_unix_ms;
    END IF;

    IF NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR NEW.object_id IS DISTINCT FROM OLD.object_id
        OR NEW.run_id IS DISTINCT FROM OLD.run_id
        OR NEW.source_registration_id IS DISTINCT FROM OLD.source_registration_id
        OR NEW.source_stream_id IS DISTINCT FROM OLD.source_stream_id
        OR NEW.source_id IS DISTINCT FROM OLD.source_id
        OR NEW.lease_digest IS DISTINCT FROM OLD.lease_digest
        OR NEW.lease_policy_revision IS DISTINCT FROM OLD.lease_policy_revision
        OR NEW.client_upload_id IS DISTINCT FROM OLD.client_upload_id
        OR NEW.capture_request_digest IS DISTINCT FROM OLD.capture_request_digest
        OR NEW.required_source_capability IS DISTINCT FROM OLD.required_source_capability
        OR NEW.payload_type IS DISTINCT FROM OLD.payload_type
        OR NEW.payload_version IS DISTINCT FROM OLD.payload_version
        OR NEW.content_digest IS DISTINCT FROM OLD.content_digest
        OR NEW.content_size_bytes IS DISTINCT FROM OLD.content_size_bytes
        OR NEW.ciphertext_size_bytes IS DISTINCT FROM OLD.ciphertext_size_bytes
        OR NEW.privacy_profile_ref IS DISTINCT FROM OLD.privacy_profile_ref
        OR NEW.retention_profile_ref IS DISTINCT FROM OLD.retention_profile_ref
        OR NEW.object_policy_revision IS DISTINCT FROM OLD.object_policy_revision
        OR NEW.requested_retention_ms IS DISTINCT FROM OLD.requested_retention_ms
        OR NEW.created_at_unix_ms IS DISTINCT FROM OLD.created_at_unix_ms
        OR NEW.upload_deadline_unix_ms IS DISTINCT FROM OLD.upload_deadline_unix_ms
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_immutable_ck',
            MESSAGE = 'immutable evidence object metadata changed';
    END IF;

    upload_fence_changed :=
        NEW.upload_fence_token IS DISTINCT FROM OLD.upload_fence_token
        OR NEW.upload_fence_started_at_unix_ms
            IS DISTINCT FROM OLD.upload_fence_started_at_unix_ms
        OR NEW.upload_fence_until_unix_ms
            IS DISTINCT FROM OLD.upload_fence_until_unix_ms;
    IF upload_fence_changed THEN
        IF NEW.upload_fence_token IS NOT NULL
            AND (
                OLD.upload_fence_token IS NULL
                OR OLD.upload_fence_until_unix_ms <= database_now_unix_ms
            )
        THEN
            IF OLD.object_state <> 'uploading' OR NEW.object_state <> 'uploading' THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    CONSTRAINT = 'evidence_object_upload_fence_ck',
                    MESSAGE = 'evidence object upload fence requires uploading state';
            END IF;
            PERFORM apolysis_gateway.assert_evidence_object_current_lease(
                NEW.organization_id,
                NEW.run_id,
                NEW.source_registration_id,
                NEW.source_stream_id,
                NEW.source_id,
                NEW.lease_digest,
                NEW.lease_policy_revision,
                ARRAY['active', 'finishing']::text[]
            );
            SELECT material.storage_operation_timeout_ms
              INTO STRICT storage_operation_timeout_ms
              FROM apolysis_gateway.evidence_object_storage_material AS material
             WHERE material.organization_id = NEW.organization_id
               AND material.object_id = NEW.object_id;
            NEW.upload_fence_started_at_unix_ms := database_now_unix_ms;
            IF NEW.upload_fence_until_unix_ms <= database_now_unix_ms
                OR NEW.upload_fence_until_unix_ms
                    > database_now_unix_ms
                        + (3 * storage_operation_timeout_ms)
                        + 5000
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    CONSTRAINT = 'evidence_object_upload_fence_window_ck',
                    MESSAGE = 'evidence object upload fence window is invalid';
            END IF;
        ELSIF OLD.upload_fence_token IS NOT NULL
            AND NEW.upload_fence_token IS NULL
        THEN
            IF OLD.upload_fence_until_unix_ms > database_now_unix_ms
                AND NEW.object_state = 'deleted'
            THEN
                RAISE EXCEPTION USING
                    ERRCODE = '23514',
                    CONSTRAINT = 'evidence_object_upload_fence_active_ck',
                    MESSAGE = 'active evidence object upload fence cannot be cleared';
            END IF;
            NEW.upload_fence_started_at_unix_ms := NULL;
            NEW.upload_fence_until_unix_ms := NULL;
        ELSE
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_upload_fence_ck',
                MESSAGE = 'evidence object upload fence cannot be rewritten';
        END IF;
    END IF;

    IF NEW.object_state = 'deleted'
        AND NEW.upload_fence_until_unix_ms > database_now_unix_ms
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_upload_fence_active_ck',
            MESSAGE = 'active evidence object upload fence prevents deletion';
    END IF;

    reap_claim_changed :=
        NEW.reap_claimed_by IS DISTINCT FROM OLD.reap_claimed_by
        OR NEW.reap_claimed_at_unix_ms IS DISTINCT FROM OLD.reap_claimed_at_unix_ms
        OR NEW.reap_claim_until_unix_ms IS DISTINCT FROM OLD.reap_claim_until_unix_ms;
    IF reap_claim_changed THEN
        IF NEW.reap_claimed_by IS NULL THEN
            NEW.reap_claimed_at_unix_ms := NULL;
            NEW.reap_claim_until_unix_ms := NULL;
        ELSIF NEW.object_state = 'delete_pending'
            AND (
                OLD.reap_claimed_by IS NULL
                OR OLD.reap_claim_until_unix_ms <= database_now_unix_ms
            )
            AND NEW.reap_claim_until_unix_ms > database_now_unix_ms
            AND NEW.reap_claim_until_unix_ms <= database_now_unix_ms + 3600000
        THEN
            NEW.reap_claimed_at_unix_ms := database_now_unix_ms;
        ELSE
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_reap_claim_ck',
                MESSAGE = 'evidence object reaper claim is invalid';
        END IF;
    END IF;

    lifecycle_changed :=
        NEW.object_state IS DISTINCT FROM OLD.object_state
        OR NEW.expires_at_unix_ms IS DISTINCT FROM OLD.expires_at_unix_ms
        OR NEW.available_at_unix_ms IS DISTINCT FROM OLD.available_at_unix_ms
        OR NEW.access_denied_at_unix_ms IS DISTINCT FROM OLD.access_denied_at_unix_ms
        OR NEW.delete_requested_at_unix_ms IS DISTINCT FROM OLD.delete_requested_at_unix_ms
        OR NEW.purged_at_unix_ms IS DISTINCT FROM OLD.purged_at_unix_ms
        OR NEW.delete_reason IS DISTINCT FROM OLD.delete_reason
        OR NEW.delete_request_revision IS DISTINCT FROM OLD.delete_request_revision;

    IF lifecycle_changed THEN
        IF NEW.lifecycle_revision <> OLD.lifecycle_revision + 1 THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_revision_ck',
                MESSAGE = 'evidence object lifecycle revision must advance once';
        END IF;
        IF NOT (
            (OLD.object_state = 'uploading'
                AND NEW.object_state IN ('available', 'delete_pending'))
            OR (OLD.object_state = 'available' AND NEW.object_state = 'delete_pending')
            OR (OLD.object_state = 'delete_pending' AND NEW.object_state = 'deleted')
            OR (
                OLD.object_state = NEW.object_state
                AND OLD.object_state IN ('uploading', 'available')
                AND NEW.expires_at_unix_ms > OLD.expires_at_unix_ms
                AND NEW.available_at_unix_ms IS NOT DISTINCT FROM OLD.available_at_unix_ms
                AND NEW.access_denied_at_unix_ms IS NOT DISTINCT FROM OLD.access_denied_at_unix_ms
                AND NEW.delete_requested_at_unix_ms IS NOT DISTINCT FROM OLD.delete_requested_at_unix_ms
                AND NEW.purged_at_unix_ms IS NOT DISTINCT FROM OLD.purged_at_unix_ms
                AND NEW.delete_reason IS NOT DISTINCT FROM OLD.delete_reason
                AND NEW.delete_request_revision IS NOT DISTINCT FROM OLD.delete_request_revision
            )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_transition_ck',
                MESSAGE = 'invalid evidence object lifecycle transition';
        END IF;
        NEW.lifecycle_changed_at_unix_ms := database_now_unix_ms;
    ELSIF NEW.lifecycle_revision <> OLD.lifecycle_revision
        OR NEW.lifecycle_changed_at_unix_ms
            IS DISTINCT FROM OLD.lifecycle_changed_at_unix_ms
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_revision_ck',
            MESSAGE = 'operational claim cannot change lifecycle history';
    END IF;

    IF OLD.storage_purged_at_unix_ms IS NULL
        AND NEW.storage_purged_at_unix_ms IS NOT NULL
    THEN
        IF NEW.upload_fence_until_unix_ms > database_now_unix_ms THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_upload_fence_active_ck',
                MESSAGE = 'active evidence object upload fence prevents storage purge';
        END IF;
        NEW.storage_purged_at_unix_ms := database_now_unix_ms;
    END IF;

    IF NEW.storage_purged_at_unix_ms IS DISTINCT FROM OLD.storage_purged_at_unix_ms
        AND NOT (
            OLD.object_state = 'delete_pending'
            AND OLD.storage_purged_at_unix_ms IS NULL
            AND NEW.storage_purged_at_unix_ms IS NOT NULL
            AND (
                (NEW.object_state = 'delete_pending'
                    AND NEW.lifecycle_revision = OLD.lifecycle_revision)
                OR (NEW.object_state = 'deleted'
                    AND NEW.lifecycle_revision = OLD.lifecycle_revision + 1)
            )
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_storage_purge_fact_ck',
            MESSAGE = 'evidence object storage purge fact is immutable';
    END IF;

    IF NEW.object_state = 'delete_pending'
        AND OLD.object_state <> 'delete_pending'
        AND NEW.delete_request_revision <> NEW.lifecycle_revision
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_delete_revision_ck',
            MESSAGE = 'deletion request revision is invalid';
    END IF;
    IF OLD.object_state = 'delete_pending'
        AND NEW.object_state = 'deleted'
        AND NEW.delete_request_revision <> OLD.delete_request_revision
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_delete_revision_ck',
            MESSAGE = 'deletion request revision changed';
    END IF;
    IF NEW.object_state = 'available' AND NEW.available_at_unix_ms >= NEW.expires_at_unix_ms THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_availability_window_ck',
            MESSAGE = 'evidence object availability is outside retention';
    END IF;

    SELECT policy.retention_ms INTO STRICT policy_retention_ms
    FROM apolysis_gateway.evidence_object_policy_revisions AS policy
    WHERE policy.organization_id = NEW.organization_id
      AND policy.privacy_profile_ref = NEW.privacy_profile_ref
      AND policy.retention_profile_ref = NEW.retention_profile_ref
      AND policy.policy_revision = NEW.object_policy_revision;
    IF NEW.expires_at_unix_ms > NEW.created_at_unix_ms + policy_retention_ms THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_retention_ceiling_ck',
            MESSAGE = 'evidence object retention exceeds policy';
    END IF;

    IF (OLD.object_state = 'uploading' AND NEW.object_state = 'available')
        OR (
            OLD.object_state = NEW.object_state
            AND NEW.expires_at_unix_ms > OLD.expires_at_unix_ms
        )
    THEN
        SELECT
            policy.max_object_size_bytes,
            policy.upload_timeout_ms,
            policy.retention_ms
        INTO
            current_policy_max_object_size_bytes,
            current_policy_upload_timeout_ms,
            current_policy_retention_ms
        FROM apolysis_gateway.evidence_object_policy_revisions AS policy
        WHERE policy.organization_id = NEW.organization_id
          AND policy.privacy_profile_ref = NEW.privacy_profile_ref
          AND policy.retention_profile_ref = NEW.retention_profile_ref
          AND policy.policy_state = 'active'
          AND policy.effective_at_unix_ms <= database_now_unix_ms;
        IF NOT FOUND
            OR NEW.content_size_bytes > current_policy_max_object_size_bytes
            OR NEW.expires_at_unix_ms
                > NEW.created_at_unix_ms + current_policy_retention_ms
            OR (
                OLD.object_state = 'uploading'
                AND NEW.object_state = 'available'
                AND database_now_unix_ms
                    >= NEW.created_at_unix_ms + current_policy_upload_timeout_ms
            )
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_current_policy_ck',
                MESSAGE = 'current evidence object policy denies the transition';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_object_transition_guard
BEFORE UPDATE ON apolysis_gateway.evidence_objects
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.enforce_evidence_object_transition();

CREATE FUNCTION apolysis_gateway.snapshot_evidence_object_deletion_targets()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    IF NEW.object_state = 'delete_pending' AND OLD.object_state <> 'delete_pending' THEN
        INSERT INTO apolysis_gateway.evidence_object_deletion_requirements (
            organization_id,
            object_id,
            component_id,
            lifecycle_revision,
            required_at_unix_ms
        )
        SELECT
            NEW.organization_id,
            NEW.object_id,
            target.component_id,
            NEW.delete_request_revision,
            NEW.delete_requested_at_unix_ms
        FROM apolysis_gateway.evidence_object_deletion_targets AS target
        WHERE target.organization_id = NEW.organization_id
          AND target.required
          AND target.registered_at_unix_ms <= NEW.delete_requested_at_unix_ms;
    END IF;
    IF NEW.object_state = 'deleted' AND OLD.object_state <> 'deleted' THEN
        UPDATE apolysis_gateway.organization_object_usage AS usage
           SET reserved_bytes = usage.reserved_bytes - NEW.content_size_bytes,
               reserved_objects = usage.reserved_objects - 1,
               updated_at_unix_ms = NEW.purged_at_unix_ms
         WHERE usage.organization_id = NEW.organization_id
           AND usage.reserved_bytes >= NEW.content_size_bytes
           AND usage.reserved_objects >= 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_usage_release_ck',
                MESSAGE = 'evidence object quota reservation is inconsistent';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE TRIGGER evidence_object_transition_effects
AFTER UPDATE ON apolysis_gateway.evidence_objects
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.snapshot_evidence_object_deletion_targets();

CREATE FUNCTION apolysis_gateway.enforce_evidence_object_storage_material()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    current_state text;
    current_upload_fence_until_unix_ms bigint;
    database_now_unix_ms bigint;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    SELECT object_state, upload_fence_until_unix_ms
    INTO STRICT current_state, current_upload_fence_until_unix_ms
    FROM apolysis_gateway.evidence_objects
    WHERE organization_id = COALESCE(NEW.organization_id, OLD.organization_id)
      AND object_id = COALESCE(NEW.object_id, OLD.object_id)
    FOR UPDATE;
    IF TG_OP = 'INSERT' AND current_state <> 'uploading' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_storage_material_insert_state_ck',
            MESSAGE = 'evidence object storage material cannot be introduced';
    END IF;
    IF TG_OP = 'UPDATE'
        AND NEW.storage_backend_binding_digest
            IS DISTINCT FROM OLD.storage_backend_binding_digest
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_storage_backend_binding_ck',
            MESSAGE = 'evidence object storage backend binding is immutable';
    END IF;
    IF TG_OP = 'UPDATE' AND (
        NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR NEW.object_id IS DISTINCT FROM OLD.object_id
        OR NEW.storage_backend_ref IS DISTINCT FROM OLD.storage_backend_ref
        OR NEW.storage_operation_timeout_ms
            IS DISTINCT FROM OLD.storage_operation_timeout_ms
        OR NEW.storage_key IS DISTINCT FROM OLD.storage_key
        OR NEW.encryption_algorithm IS DISTINCT FROM OLD.encryption_algorithm
        OR NEW.cipher_version IS DISTINCT FROM OLD.cipher_version
        OR NEW.encryption_key_ref IS DISTINCT FROM OLD.encryption_key_ref
        OR NEW.encrypted_data_key IS DISTINCT FROM OLD.encrypted_data_key
        OR NEW.key_wrap_nonce IS DISTINCT FROM OLD.key_wrap_nonce
        OR NEW.content_nonce IS DISTINCT FROM OLD.content_nonce
        OR NEW.aad_digest IS DISTINCT FROM OLD.aad_digest
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_storage_material_immutable_ck',
            MESSAGE = 'evidence object storage material is immutable';
    END IF;
    IF TG_OP = 'UPDATE' AND current_state <> 'uploading' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_storage_metadata_state_ck',
            MESSAGE = 'evidence object storage metadata is frozen';
    END IF;
    IF TG_OP = 'DELETE' AND (
        current_state <> 'delete_pending'
        OR current_upload_fence_until_unix_ms > database_now_unix_ms
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_storage_purge_state_ck',
            MESSAGE = 'evidence object storage material cannot be purged';
    END IF;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$$;

CREATE TRIGGER evidence_object_storage_material_guard
BEFORE INSERT OR UPDATE OR DELETE ON apolysis_gateway.evidence_object_storage_material
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.enforce_evidence_object_storage_material();

CREATE FUNCTION apolysis_gateway.serialize_evidence_object_deletion_target()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT apolysis_gateway.lock_evidence_object_organization(NEW.organization_id) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            CONSTRAINT = 'evidence_object_deletion_target_organization_fk',
            MESSAGE = 'evidence object deletion target organization is unavailable';
    END IF;
    SELECT greatest(
        apolysis_gateway.evidence_object_db_now_unix_ms(),
        coalesce(max(object.delete_requested_at_unix_ms) + 1, 1)
    )
    INTO NEW.registered_at_unix_ms
    FROM apolysis_gateway.evidence_objects AS object
    WHERE object.organization_id = NEW.organization_id;
    RETURN NEW;
END;
$$;

-- The target row is the per-component credential-rotation mutex. Keeping this
-- operation behind a definer helper avoids a write-capable lock-only grant on
-- the append-only target registry.
CREATE FUNCTION apolysis_gateway.lock_evidence_object_deletion_target(
    checked_organization_id text,
    checked_component_id text
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    PERFORM 1
    FROM apolysis_gateway.evidence_object_deletion_targets AS target
    WHERE target.organization_id = checked_organization_id
      AND target.component_id = checked_component_id
    FOR UPDATE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_evidence_object_deletion_target(text, text)
FROM PUBLIC;

CREATE TRIGGER evidence_object_deletion_target_registration_guard
BEFORE INSERT ON apolysis_gateway.evidence_object_deletion_targets
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.serialize_evidence_object_deletion_target();

CREATE FUNCTION apolysis_gateway.enforce_evidence_object_deletion_credential()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    database_now_unix_ms bigint;
    latest_credential_epoch bigint;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_delete_credential_history_ck',
            MESSAGE = 'evidence object deletion credential cannot be deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NOT apolysis_gateway.lock_evidence_object_deletion_target(
            NEW.organization_id,
            NEW.component_id
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23503',
                CONSTRAINT = 'evidence_object_delete_credential_target_fk',
                MESSAGE = 'evidence object deletion credential target is unavailable';
        END IF;
        PERFORM 1
        FROM apolysis_gateway.evidence_object_deletion_targets AS target
        WHERE target.organization_id = NEW.organization_id
          AND target.component_id = NEW.component_id
          AND target.principal_kind = NEW.principal_kind
          AND target.principal_id = NEW.principal_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING
                ERRCODE = '23503',
                CONSTRAINT = 'evidence_object_delete_credential_target_fk',
                MESSAGE = 'evidence object deletion credential target is unavailable';
        END IF;
        SELECT coalesce(max(credential.credential_epoch), 0)
        INTO latest_credential_epoch
        FROM apolysis_gateway.evidence_object_deletion_credentials AS credential
        WHERE credential.organization_id = NEW.organization_id
          AND credential.component_id = NEW.component_id;
        IF NEW.credential_epoch <> latest_credential_epoch + 1
            OR NEW.effective_at_unix_ms > database_now_unix_ms
            OR NEW.expires_at_unix_ms <= database_now_unix_ms
            OR NEW.revoked_at_unix_ms IS NOT NULL
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_delete_credential_authority_ck',
                MESSAGE = 'evidence object deletion credential is invalid';
        END IF;
        NEW.created_at_unix_ms := database_now_unix_ms;
        RETURN NEW;
    END IF;
    IF OLD.revoked_at_unix_ms IS NOT NULL
        OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR NEW.component_id IS DISTINCT FROM OLD.component_id
        OR NEW.principal_kind IS DISTINCT FROM OLD.principal_kind
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.credential_id IS DISTINCT FROM OLD.credential_id
        OR NEW.credential_epoch IS DISTINCT FROM OLD.credential_epoch
        OR NEW.credential_digest IS DISTINCT FROM OLD.credential_digest
        OR NEW.credential_hash_version IS DISTINCT FROM OLD.credential_hash_version
        OR NEW.effective_at_unix_ms IS DISTINCT FROM OLD.effective_at_unix_ms
        OR NEW.expires_at_unix_ms IS DISTINCT FROM OLD.expires_at_unix_ms
        OR NEW.created_at_unix_ms IS DISTINCT FROM OLD.created_at_unix_ms
        OR NEW.revoked_at_unix_ms IS NULL
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_delete_credential_history_ck',
            MESSAGE = 'evidence object deletion credential history is immutable';
    END IF;
    NEW.revoked_at_unix_ms := database_now_unix_ms;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_object_deletion_credential_guard
BEFORE INSERT OR UPDATE OR DELETE
ON apolysis_gateway.evidence_object_deletion_credentials
FOR EACH ROW
EXECUTE FUNCTION apolysis_gateway.enforce_evidence_object_deletion_credential();

CREATE FUNCTION apolysis_gateway.validate_evidence_object_deletion_ack()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    database_now_unix_ms bigint;
    required_at_unix_ms bigint;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    PERFORM 1
    FROM apolysis_gateway.evidence_object_deletion_credentials AS credential
    WHERE credential.organization_id = NEW.organization_id
      AND credential.component_id = NEW.component_id
      AND credential.principal_kind = NEW.principal_kind
      AND credential.principal_id = NEW.principal_id
      AND credential.credential_id = NEW.credential_id
      AND credential.credential_epoch = NEW.credential_epoch
      AND credential.credential_digest = NEW.presented_credential_digest
      AND credential.effective_at_unix_ms <= database_now_unix_ms
      AND credential.expires_at_unix_ms > database_now_unix_ms
      AND credential.revoked_at_unix_ms IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_deletion_ack_authority_ck',
            MESSAGE = 'evidence object deletion acknowledgement authority is unavailable';
    END IF;
    NEW.presented_credential_digest := NULL;
    SELECT requirement.required_at_unix_ms
    INTO required_at_unix_ms
    FROM apolysis_gateway.evidence_object_deletion_requirements AS requirement
    WHERE requirement.organization_id = NEW.organization_id
      AND requirement.object_id = NEW.object_id
      AND requirement.component_id = NEW.component_id
      AND requirement.lifecycle_revision = NEW.lifecycle_revision
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            CONSTRAINT = 'evidence_object_deletion_ack_requirement_fk',
            MESSAGE = 'evidence object deletion requirement is unavailable';
    END IF;
    NEW.acknowledged_at_unix_ms :=
        greatest(database_now_unix_ms, required_at_unix_ms);
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_object_deletion_ack_authority_guard
BEFORE INSERT
ON apolysis_gateway.evidence_object_deletion_acknowledgements
FOR EACH ROW
EXECUTE FUNCTION apolysis_gateway.validate_evidence_object_deletion_ack();

CREATE FUNCTION apolysis_gateway.acknowledge_evidence_object_deletion(
    p_organization_id text,
    p_object_id text,
    p_component_id text,
    p_lifecycle_revision bigint,
    p_principal_kind text,
    p_principal_id text,
    p_credential_id text,
    p_credential_epoch bigint,
    p_presented_credential_digest bytea
)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
DECLARE
    database_now_unix_ms bigint;
    inserted_rows bigint;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    PERFORM 1
    FROM apolysis_gateway.evidence_object_deletion_credentials AS credential
    WHERE credential.organization_id = p_organization_id
      AND credential.component_id = p_component_id
      AND credential.principal_kind::text = p_principal_kind
      AND credential.principal_id = p_principal_id
      AND credential.credential_id = p_credential_id
      AND credential.credential_epoch = p_credential_epoch
      AND credential.credential_digest = p_presented_credential_digest
      AND credential.effective_at_unix_ms <= database_now_unix_ms
      AND credential.expires_at_unix_ms > database_now_unix_ms
      AND credential.revoked_at_unix_ms IS NULL
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_deletion_ack_authority_ck',
            MESSAGE = 'evidence object deletion acknowledgement authority is unavailable';
    END IF;
    INSERT INTO apolysis_gateway.evidence_object_deletion_acknowledgements (
        organization_id,
        object_id,
        component_id,
        lifecycle_revision,
        principal_kind,
        principal_id,
        credential_id,
        credential_epoch,
        presented_credential_digest,
        acknowledged_at_unix_ms
    ) VALUES (
        p_organization_id,
        p_object_id,
        p_component_id,
        p_lifecycle_revision,
        p_principal_kind::apolysis_gateway.principal_kind,
        p_principal_id,
        p_credential_id,
        p_credential_epoch,
        p_presented_credential_digest,
        database_now_unix_ms
    )
    ON CONFLICT (
        organization_id,
        object_id,
        lifecycle_revision,
        component_id
    ) DO NOTHING;
    GET DIAGNOSTICS inserted_rows = ROW_COUNT;
    IF inserted_rows = 0 AND NOT EXISTS (
        SELECT 1
        FROM apolysis_gateway.evidence_object_deletion_acknowledgements AS acknowledgement
        WHERE acknowledgement.organization_id = p_organization_id
          AND acknowledgement.object_id = p_object_id
          AND acknowledgement.component_id = p_component_id
          AND acknowledgement.lifecycle_revision = p_lifecycle_revision
          AND acknowledgement.principal_kind::text = p_principal_kind
          AND acknowledgement.principal_id = p_principal_id
          AND acknowledgement.credential_id = p_credential_id
          AND acknowledgement.credential_epoch = p_credential_epoch
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_deletion_ack_provenance_ck',
            MESSAGE = 'evidence object deletion acknowledgement provenance conflicts';
    END IF;
    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.acknowledge_evidence_object_deletion(
    text, text, text, bigint, text, text, text, bigint, bytea
) FROM PUBLIC;

CREATE FUNCTION apolysis_gateway.validate_evidence_event_object_link()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
DECLARE
    event_source_id text;
    event_payload_type text;
    event_envelope jsonb;
    database_now_unix_ms bigint;
    stored_object_state apolysis_gateway.evidence_object_state;
    stored_object_created_at_unix_ms bigint;
    stored_object_expires_at_unix_ms bigint;
    stored_requested_retention_ms bigint;
    stored_lease_policy_revision bigint;
    stored_privacy_profile_ref text;
    stored_retention_profile_ref text;
    current_max_object_size_bytes bigint;
    current_retention_ms bigint;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    NEW.bound_at_unix_ms := database_now_unix_ms;
    SELECT
        event.source_id,
        event.payload_type,
        event.accepted_envelope_json
    INTO
        event_source_id,
        event_payload_type,
        event_envelope
    FROM apolysis_gateway.evidence_events AS event
    WHERE event.organization_id = NEW.organization_id
      AND event.run_id = NEW.run_id
      AND event.source_registration_id = NEW.source_registration_id
      AND event.source_stream_id = NEW.source_stream_id
      AND event.source_event_id = NEW.source_event_id
    FOR SHARE;
    IF NOT FOUND
        OR event_source_id IS DISTINCT FROM NEW.source_id
        OR event_payload_type IS DISTINCT FROM NEW.payload_type
        OR event_envelope ->> 'source_registration_id'
            IS DISTINCT FROM NEW.source_registration_id
        OR event_envelope ->> 'source_stream_id' IS DISTINCT FROM NEW.source_stream_id
        OR event_envelope #>> '{envelope,run_id}' IS DISTINCT FROM NEW.run_id
        OR event_envelope #>> '{envelope,source_id}' IS DISTINCT FROM NEW.source_id
        OR event_envelope #>> '{envelope,source_stream_id}'
            IS DISTINCT FROM NEW.source_stream_id
        OR event_envelope #>> '{envelope,source_event_id}'
            IS DISTINCT FROM NEW.source_event_id
        OR event_envelope #>> '{envelope,payload_type}' IS DISTINCT FROM NEW.payload_type
        OR event_envelope #>> '{envelope,payload_version}' IS DISTINCT FROM NEW.payload_version
        OR event_envelope #>> '{envelope,payload_digest}'
            IS DISTINCT FROM encode(NEW.content_digest, 'hex')
        OR event_envelope #>> '{envelope,object_ref,object_id}' IS DISTINCT FROM NEW.object_id
        OR event_envelope #>> '{envelope,object_ref,sha256}'
            IS DISTINCT FROM encode(NEW.content_digest, 'hex')
        OR event_envelope #>> '{envelope,object_ref,size_bytes}'
            IS DISTINCT FROM NEW.content_size_bytes::text
        OR event_envelope #>> '{envelope,flags,contains_content}' IS DISTINCT FROM 'true'
        OR event_envelope #> '{envelope,inline_payload}' IS DISTINCT FROM 'null'::jsonb
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_event_object_exact_binding_ck',
            MESSAGE = 'evidence event object binding does not match the accepted envelope';
    END IF;

    SELECT
        object.lease_policy_revision,
        object.privacy_profile_ref,
        object.retention_profile_ref
    INTO
        stored_lease_policy_revision,
        stored_privacy_profile_ref,
        stored_retention_profile_ref
    FROM apolysis_gateway.evidence_objects AS object
    WHERE object.organization_id = NEW.organization_id
      AND object.object_id = NEW.object_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_event_object_current_authority_ck',
            MESSAGE = 'evidence event object is not currently authorized';
    END IF;
    PERFORM apolysis_gateway.assert_evidence_object_current_lease(
        NEW.organization_id,
        NEW.run_id,
        NEW.source_registration_id,
        NEW.source_stream_id,
        NEW.source_id,
        NEW.lease_digest,
        stored_lease_policy_revision,
        ARRAY['active', 'finishing']::text[]
    );
    SELECT
        policy.max_object_size_bytes,
        policy.retention_ms
    INTO
        current_max_object_size_bytes,
        current_retention_ms
    FROM apolysis_gateway.evidence_object_policy_revisions AS policy
    WHERE policy.organization_id = NEW.organization_id
      AND policy.privacy_profile_ref = stored_privacy_profile_ref
      AND policy.retention_profile_ref = stored_retention_profile_ref
      AND policy.policy_state = 'active'
      AND policy.effective_at_unix_ms <= database_now_unix_ms
    FOR SHARE OF policy;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_event_object_current_authority_ck',
            MESSAGE = 'evidence event object is not currently authorized';
    END IF;
    SELECT
        object.object_state,
        object.created_at_unix_ms,
        object.expires_at_unix_ms,
        object.requested_retention_ms
    INTO
        stored_object_state,
        stored_object_created_at_unix_ms,
        stored_object_expires_at_unix_ms,
        stored_requested_retention_ms
    FROM apolysis_gateway.evidence_objects AS object
    WHERE object.organization_id = NEW.organization_id
      AND object.object_id = NEW.object_id
      AND object.lease_policy_revision = stored_lease_policy_revision
      AND object.privacy_profile_ref = stored_privacy_profile_ref
      AND object.retention_profile_ref = stored_retention_profile_ref
    FOR SHARE OF object;
    IF NOT FOUND
        OR stored_object_state <> 'available'
        OR stored_object_expires_at_unix_ms <= database_now_unix_ms
        OR NEW.content_size_bytes > current_max_object_size_bytes
        OR stored_requested_retention_ms > current_retention_ms
        OR stored_object_created_at_unix_ms + current_retention_ms
            <= database_now_unix_ms
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_event_object_current_authority_ck',
            MESSAGE = 'evidence event object is not currently authorized';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_event_object_exact_binding_guard
BEFORE INSERT ON apolysis_gateway.evidence_event_objects
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.validate_evidence_event_object_link();

CREATE FUNCTION apolysis_gateway.enforce_evidence_object_outbox_history()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    database_now_unix_ms bigint;
BEGIN
    database_now_unix_ms :=
        apolysis_gateway.evidence_object_db_now_unix_ms();
    IF TG_OP = 'INSERT' THEN
        SELECT object.lifecycle_changed_at_unix_ms
        INTO STRICT database_now_unix_ms
        FROM apolysis_gateway.evidence_objects AS object
        WHERE object.organization_id = NEW.organization_id
          AND object.object_id = NEW.object_id
          AND object.lifecycle_revision = NEW.lifecycle_revision;
        NEW.created_at_unix_ms := database_now_unix_ms;
        NEW.available_at_unix_ms := database_now_unix_ms;
        IF NEW.delivery_state <> 'pending'
            OR NEW.attempt_count <> 0
            OR NEW.claimed_by IS NOT NULL
            OR NEW.claimed_at_unix_ms IS NOT NULL
            OR NEW.claim_until_unix_ms IS NOT NULL
            OR NEW.published_at_unix_ms IS NOT NULL
            OR NEW.last_error_code IS NOT NULL
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_outbox_initial_ck',
                MESSAGE = 'evidence object outbox history must begin pending and immediately available';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_outbox_history_ck',
            MESSAGE = 'evidence object outbox history is immutable';
    END IF;
    IF NEW.object_outbox_id IS DISTINCT FROM OLD.object_outbox_id
        OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
        OR NEW.object_id IS DISTINCT FROM OLD.object_id
        OR NEW.lifecycle_revision IS DISTINCT FROM OLD.lifecycle_revision
        OR NEW.event_kind IS DISTINCT FROM OLD.event_kind
        OR NEW.event_json IS DISTINCT FROM OLD.event_json
        OR NEW.created_at_unix_ms IS DISTINCT FROM OLD.created_at_unix_ms
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_outbox_history_ck',
            MESSAGE = 'evidence object outbox history is immutable';
    END IF;
    IF OLD.delivery_state IN ('published', 'dead_letter') AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_outbox_terminal_ck',
            MESSAGE = 'terminal evidence object outbox state cannot be reopened';
    END IF;
    IF NOT (
        (OLD.delivery_state = 'pending' AND NEW.delivery_state = 'processing')
        OR (OLD.delivery_state = 'processing'
            AND NEW.delivery_state IN ('processing', 'pending', 'published', 'dead_letter'))
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_outbox_transition_ck',
            MESSAGE = 'evidence object outbox transition is invalid';
    END IF;
    IF NEW.delivery_state = 'processing' THEN
        IF NEW.claim_until_unix_ms <= database_now_unix_ms
            OR NEW.claim_until_unix_ms > database_now_unix_ms + 3600000
        THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                CONSTRAINT = 'evidence_object_outbox_claim_time_ck',
                MESSAGE = 'evidence object outbox claim time is invalid';
        END IF;
        NEW.claimed_at_unix_ms := database_now_unix_ms;
    ELSIF NEW.delivery_state = 'published' THEN
        NEW.published_at_unix_ms := database_now_unix_ms;
    END IF;
    IF (
        NEW.delivery_state = 'processing'
        AND NEW.attempt_count <> OLD.attempt_count + 1
    ) OR (
        NEW.delivery_state <> 'processing'
        AND NEW.attempt_count <> OLD.attempt_count
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_outbox_attempt_ck',
            MESSAGE = 'evidence object outbox attempt progression is invalid';
    END IF;
    IF NEW.available_at_unix_ms < OLD.available_at_unix_ms
        OR (
            NEW.available_at_unix_ms IS DISTINCT FROM OLD.available_at_unix_ms
            AND NOT (
                OLD.delivery_state = 'processing'
                AND NEW.delivery_state = 'pending'
                AND NEW.available_at_unix_ms > OLD.available_at_unix_ms
            )
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_outbox_schedule_ck',
            MESSAGE = 'evidence object outbox retry schedule is invalid';
    END IF;
    IF NEW.delivery_state = 'published'
        AND NEW.published_at_unix_ms < OLD.claimed_at_unix_ms
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_outbox_publish_time_ck',
            MESSAGE = 'evidence object outbox publish time is invalid';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_object_outbox_history_guard
BEFORE INSERT OR UPDATE OR DELETE ON apolysis_gateway.evidence_object_outbox
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.enforce_evidence_object_outbox_history();

CREATE FUNCTION apolysis_gateway.stamp_evidence_object_audit_time()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.object_id IS NOT NULL AND NEW.lifecycle_revision IS NOT NULL THEN
        SELECT object.lifecycle_changed_at_unix_ms
        INTO STRICT NEW.occurred_at_unix_ms
        FROM apolysis_gateway.evidence_objects AS object
        WHERE object.organization_id = NEW.organization_id
          AND object.object_id = NEW.object_id
          AND object.lifecycle_revision = NEW.lifecycle_revision;
    ELSE
        NEW.occurred_at_unix_ms :=
            apolysis_gateway.evidence_object_db_now_unix_ms();
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER evidence_object_audit_time_guard
BEFORE INSERT ON apolysis_gateway.evidence_object_audit
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.stamp_evidence_object_audit_time();

CREATE FUNCTION apolysis_gateway.prevent_evidence_object_append_only_rewrite()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '23514',
        CONSTRAINT = 'evidence_object_append_only_ck',
        MESSAGE = 'append-only evidence object history cannot be rewritten';
END;
$$;

CREATE TRIGGER evidence_objects_no_delete
BEFORE DELETE ON apolysis_gateway.evidence_objects
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_append_only_rewrite();

CREATE TRIGGER evidence_object_policy_no_delete
BEFORE DELETE ON apolysis_gateway.evidence_object_policy_revisions
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_append_only_rewrite();

CREATE TRIGGER evidence_events_append_only
BEFORE UPDATE OR DELETE ON apolysis_gateway.evidence_events
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_append_only_rewrite();

CREATE TRIGGER evidence_event_objects_append_only
BEFORE UPDATE OR DELETE ON apolysis_gateway.evidence_event_objects
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_append_only_rewrite();

CREATE TRIGGER evidence_object_audit_append_only
BEFORE UPDATE OR DELETE ON apolysis_gateway.evidence_object_audit
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_append_only_rewrite();

CREATE TRIGGER evidence_object_deletion_targets_append_only
BEFORE UPDATE OR DELETE ON apolysis_gateway.evidence_object_deletion_targets
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_append_only_rewrite();

CREATE TRIGGER evidence_object_deletion_requirements_append_only
BEFORE UPDATE OR DELETE ON apolysis_gateway.evidence_object_deletion_requirements
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_append_only_rewrite();

CREATE TRIGGER evidence_object_deletion_acknowledgements_append_only
BEFORE UPDATE OR DELETE ON apolysis_gateway.evidence_object_deletion_acknowledgements
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.prevent_evidence_object_append_only_rewrite();

CREATE FUNCTION apolysis_gateway.validate_evidence_object_deletion()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
BEGIN
    IF (
        NEW.object_state IN ('uploading', 'available')
        OR (NEW.object_state = 'delete_pending' AND NEW.storage_purged_at_unix_ms IS NULL)
    ) AND NOT EXISTS (
        SELECT 1
        FROM apolysis_gateway.evidence_object_storage_material AS material
        WHERE material.organization_id = NEW.organization_id
          AND material.object_id = NEW.object_id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_storage_material_required_ck',
            MESSAGE = 'evidence object storage material is missing';
    END IF;
    IF NEW.object_state IN ('delete_pending', 'deleted')
        AND NEW.storage_purged_at_unix_ms IS NOT NULL
        AND EXISTS (
            SELECT 1
            FROM apolysis_gateway.evidence_object_storage_material AS material
            WHERE material.organization_id = NEW.organization_id
              AND material.object_id = NEW.object_id
        )
    THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_storage_material_purged_ck',
            MESSAGE = 'purged evidence object retains storage material';
    END IF;
    IF NEW.object_state IN ('delete_pending', 'deleted') AND EXISTS (
        SELECT 1
        FROM apolysis_gateway.evidence_object_deletion_targets AS target
        WHERE target.organization_id = NEW.organization_id
          AND target.required
          AND target.registered_at_unix_ms <= NEW.delete_requested_at_unix_ms
          AND NOT EXISTS (
              SELECT 1
              FROM apolysis_gateway.evidence_object_deletion_requirements AS requirement
              WHERE requirement.organization_id = NEW.organization_id
                AND requirement.object_id = NEW.object_id
                AND requirement.lifecycle_revision = NEW.delete_request_revision
                AND requirement.component_id = target.component_id
          )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_deletion_snapshot_ck',
            MESSAGE = 'evidence object deletion target snapshot is incomplete';
    END IF;

    IF NEW.object_state = 'deleted' AND (
        EXISTS (
            SELECT 1
            FROM apolysis_gateway.evidence_object_storage_material AS material
            WHERE material.organization_id = NEW.organization_id
              AND material.object_id = NEW.object_id
        )
        OR EXISTS (
            SELECT 1
            FROM apolysis_gateway.evidence_object_deletion_requirements AS requirement
            WHERE requirement.organization_id = NEW.organization_id
              AND requirement.object_id = NEW.object_id
              AND requirement.lifecycle_revision = NEW.delete_request_revision
              AND NOT EXISTS (
                  SELECT 1
                  FROM apolysis_gateway.evidence_object_deletion_acknowledgements AS acknowledgement
                  WHERE acknowledgement.organization_id = requirement.organization_id
                    AND acknowledgement.object_id = requirement.object_id
                    AND acknowledgement.lifecycle_revision = requirement.lifecycle_revision
                    AND acknowledgement.component_id = requirement.component_id
              )
        )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            CONSTRAINT = 'evidence_object_deletion_completion_ck',
            MESSAGE = 'evidence object deletion is not complete';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER evidence_object_deletion_completion_guard
AFTER INSERT OR UPDATE ON apolysis_gateway.evidence_objects
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.validate_evidence_object_deletion();

COMMENT ON TABLE apolysis_gateway.evidence_objects IS
    'Encrypted object registry; object references are integrity metadata and never read authority.';
COMMENT ON COLUMN apolysis_gateway.evidence_object_storage_material.storage_key IS
    'Server-generated opaque S3 key; never returned in browser or source contracts.';
