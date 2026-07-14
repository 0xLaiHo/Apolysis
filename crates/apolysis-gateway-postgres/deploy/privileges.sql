-- SPDX-License-Identifier: Apache-2.0

-- Run bootstrap_roles.sql first, run the ordered sqlx migrations on one
-- connection after SET ROLE apolysis_schema_owner, and then run this artifact
-- from a deployment login that can SET ROLE to the schema owner. This artifact
-- changes only its transaction-local role; the session login remains unchanged.
-- Each application or migration login receives membership in exactly one of
-- these NOLOGIN capability roles through separately managed secret/bootstrap
-- automation. Re-run bootstrap_roles.sql after assigning login membership so
-- its mutual-exclusion audit can fail closed.
--
-- Re-run this artifact after every schema migration. Objects accidentally
-- created as another owner make the ownership pass fail closed and require an
-- explicit privileged repair before this owner-only pass can succeed.

BEGIN;

-- Neutralize deployment-login and database defaults before the first
-- privileged catalog inspection. Every application object below is qualified.
SET LOCAL search_path = pg_catalog;

DO $bootstrap_required$
BEGIN
    IF EXISTS (
        SELECT required.role_name
        FROM unnest(ARRAY[
            'apolysis_schema_owner',
            'apolysis_gateway_runtime',
            'apolysis_gateway_control',
            'apolysis_evidence_runtime',
            'apolysis_evidence_control',
            'apolysis_deletion_ack'
        ]) AS required(role_name)
        LEFT JOIN pg_catalog.pg_roles AS present
          ON present.rolname = required.role_name
        WHERE present.oid IS NULL
           OR pg_catalog.shobj_description(present.oid, 'pg_authid') IS DISTINCT FROM
              format(
                  'apolysis-managed-role:v1:database=%s:role=%s',
                  current_database(),
                  required.role_name
              )
    ) THEN
        RAISE EXCEPTION 'run deploy/bootstrap_roles.sql before deploy/privileges.sql';
    END IF;
END
$bootstrap_required$;

SET LOCAL ROLE apolysis_schema_owner;

REVOKE ALL PRIVILEGES ON SCHEMA apolysis_gateway FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA apolysis_gateway FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA apolysis_gateway FROM PUBLIC;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA apolysis_gateway FROM PUBLIC;

REVOKE ALL PRIVILEGES ON SCHEMA apolysis_gateway FROM
    apolysis_gateway_runtime,
    apolysis_gateway_control,
    apolysis_evidence_runtime,
    apolysis_evidence_control,
    apolysis_deletion_ack;
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA apolysis_gateway FROM
    apolysis_gateway_runtime,
    apolysis_gateway_control,
    apolysis_evidence_runtime,
    apolysis_evidence_control,
    apolysis_deletion_ack;
REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA apolysis_gateway FROM
    apolysis_gateway_runtime,
    apolysis_gateway_control,
    apolysis_evidence_runtime,
    apolysis_evidence_control,
    apolysis_deletion_ack;
REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA apolysis_gateway FROM
    apolysis_gateway_runtime,
    apolysis_gateway_control,
    apolysis_evidence_runtime,
    apolysis_evidence_control,
    apolysis_deletion_ack;

REVOKE ALL PRIVILEGES ON TYPE
    apolysis_gateway.contract_identifier,
    apolysis_gateway.bounded_reference,
    apolysis_gateway.sha256_digest,
    apolysis_gateway.ijson_nonnegative,
    apolysis_gateway.ijson_positive,
    apolysis_gateway.contract_schema_version,
    apolysis_gateway.run_state,
    apolysis_gateway.environment_kind,
    apolysis_gateway.principal_kind,
    apolysis_gateway.source_kind,
    apolysis_gateway.trust_profile,
    apolysis_gateway.gateway_operation_kind,
    apolysis_gateway.runtime_identity_kind,
    apolysis_gateway.runtime_attribution,
    apolysis_gateway.evidence_object_state
FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TYPE
    apolysis_gateway.contract_identifier,
    apolysis_gateway.bounded_reference,
    apolysis_gateway.sha256_digest,
    apolysis_gateway.ijson_nonnegative,
    apolysis_gateway.ijson_positive,
    apolysis_gateway.contract_schema_version,
    apolysis_gateway.run_state,
    apolysis_gateway.environment_kind,
    apolysis_gateway.principal_kind,
    apolysis_gateway.source_kind,
    apolysis_gateway.trust_profile,
    apolysis_gateway.gateway_operation_kind,
    apolysis_gateway.runtime_identity_kind,
    apolysis_gateway.runtime_attribution,
    apolysis_gateway.evidence_object_state
FROM
    apolysis_gateway_runtime,
    apolysis_gateway_control,
    apolysis_evidence_runtime,
    apolysis_evidence_control,
    apolysis_deletion_ack;

-- sqlx keeps migration continuity outside the application schema. Normalize
-- its owner as well so a bootstrap login never remains the effective DDL
-- authority, and keep every served capability role table-blind to it.
ALTER TABLE public._sqlx_migrations OWNER TO apolysis_schema_owner;
REVOKE ALL PRIVILEGES ON TABLE public._sqlx_migrations FROM PUBLIC;
REVOKE ALL PRIVILEGES ON TABLE public._sqlx_migrations FROM
    apolysis_gateway_runtime,
    apolysis_gateway_control,
    apolysis_evidence_runtime,
    apolysis_evidence_control,
    apolysis_deletion_ack;

ALTER SCHEMA apolysis_gateway OWNER TO apolysis_schema_owner;

-- PostgreSQL does not provide ALTER ... ALL ... OWNER. Transfer every current
-- schema object without using REASSIGN OWNED, which could capture unrelated
-- objects belonging to the migration principal.
DO $relations$
DECLARE
    relation record;
BEGIN
    FOR relation IN
        SELECT class.relkind, namespace.nspname, class.relname
        FROM pg_catalog.pg_class AS class
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
        WHERE namespace.nspname = 'apolysis_gateway'
          AND class.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
          AND (
              class.relkind <> 'S'
              OR NOT EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_depend AS dependency
                  WHERE dependency.classid = 'pg_catalog.pg_class'::pg_catalog.regclass
                    AND dependency.objid = class.oid
                    AND dependency.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass
                    AND dependency.deptype IN ('a', 'i')
              )
          )
        ORDER BY class.oid
    LOOP
        EXECUTE CASE relation.relkind
            WHEN 'v' THEN format(
                'ALTER VIEW %I.%I OWNER TO apolysis_schema_owner',
                relation.nspname,
                relation.relname
            )
            WHEN 'm' THEN format(
                'ALTER MATERIALIZED VIEW %I.%I OWNER TO apolysis_schema_owner',
                relation.nspname,
                relation.relname
            )
            WHEN 'S' THEN format(
                'ALTER SEQUENCE %I.%I OWNER TO apolysis_schema_owner',
                relation.nspname,
                relation.relname
            )
            WHEN 'f' THEN format(
                'ALTER FOREIGN TABLE %I.%I OWNER TO apolysis_schema_owner',
                relation.nspname,
                relation.relname
            )
            ELSE format(
                'ALTER TABLE %I.%I OWNER TO apolysis_schema_owner',
                relation.nspname,
                relation.relname
            )
        END;
    END LOOP;
END
$relations$;

DO $types$
DECLARE
    schema_type record;
BEGIN
    FOR schema_type IN
        SELECT type.typtype, namespace.nspname, type.typname
        FROM pg_catalog.pg_type AS type
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = type.typnamespace
        WHERE namespace.nspname = 'apolysis_gateway'
          AND type.typrelid = 0
          AND type.typelem = 0
          AND type.typtype IN ('c', 'd', 'e', 'm', 'r')
        ORDER BY type.oid
    LOOP
        IF schema_type.typtype = 'd' THEN
            EXECUTE format(
                'ALTER DOMAIN %I.%I OWNER TO apolysis_schema_owner',
                schema_type.nspname,
                schema_type.typname
            );
        ELSE
            EXECUTE format(
                'ALTER TYPE %I.%I OWNER TO apolysis_schema_owner',
                schema_type.nspname,
                schema_type.typname
            );
        END IF;
    END LOOP;
END
$types$;

DO $routines$
DECLARE
    routine record;
BEGIN
    FOR routine IN
        SELECT procedure.prokind, procedure.oid::pg_catalog.regprocedure AS identity
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'apolysis_gateway'
        ORDER BY procedure.oid
    LOOP
        EXECUTE CASE routine.prokind
            WHEN 'p' THEN format(
                'ALTER PROCEDURE %s OWNER TO apolysis_schema_owner',
                routine.identity
            )
            WHEN 'a' THEN format(
                'ALTER AGGREGATE %s OWNER TO apolysis_schema_owner',
                routine.identity
            )
            ELSE format(
                'ALTER FUNCTION %s OWNER TO apolysis_schema_owner',
                routine.identity
            )
        END;
    END LOOP;
END
$routines$;

GRANT USAGE ON SCHEMA apolysis_gateway TO
    apolysis_gateway_runtime,
    apolysis_gateway_control,
    apolysis_evidence_runtime,
    apolysis_evidence_control,
    apolysis_deletion_ack;

GRANT USAGE ON TYPE
    apolysis_gateway.contract_identifier,
    apolysis_gateway.bounded_reference,
    apolysis_gateway.sha256_digest,
    apolysis_gateway.ijson_nonnegative,
    apolysis_gateway.ijson_positive,
    apolysis_gateway.contract_schema_version,
    apolysis_gateway.run_state,
    apolysis_gateway.environment_kind,
    apolysis_gateway.principal_kind,
    apolysis_gateway.source_kind,
    apolysis_gateway.trust_profile,
    apolysis_gateway.gateway_operation_kind,
    apolysis_gateway.runtime_identity_kind,
    apolysis_gateway.runtime_attribution,
    apolysis_gateway.evidence_object_state
TO
    apolysis_gateway_runtime,
    apolysis_gateway_control,
    apolysis_evidence_runtime,
    apolysis_evidence_control;

-- Gateway command/runtime plane.
GRANT SELECT, INSERT, UPDATE ON apolysis_gateway.organization_sequences
    TO apolysis_gateway_runtime;
GRANT SELECT, INSERT, UPDATE ON apolysis_gateway.runs
    TO apolysis_gateway_runtime;
GRANT SELECT, INSERT ON
    apolysis_gateway.run_expected_source_kinds,
    apolysis_gateway.client_runs,
    apolysis_gateway.record_items,
    apolysis_gateway.projection_outbox,
    apolysis_gateway.source_streams,
    apolysis_gateway.source_stream_capabilities,
    apolysis_gateway.leases,
    apolysis_gateway.lease_operations,
    apolysis_gateway.gateway_operations,
    apolysis_gateway.operation_replays,
    apolysis_gateway.evidence_events,
    apolysis_gateway.runtime_bindings,
    apolysis_gateway.finalization_declarations,
    apolysis_gateway.finalization_terminal_positions,
    apolysis_gateway.finalization_outcome_claims
TO apolysis_gateway_runtime;
GRANT SELECT, INSERT, UPDATE ON apolysis_gateway.join_authorizations
    TO apolysis_gateway_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON apolysis_gateway.active_runtime_identities
    TO apolysis_gateway_runtime;
GRANT SELECT ON
    apolysis_gateway.organizations,
    apolysis_gateway.source_registrations,
    apolysis_gateway.transport_credentials,
    apolysis_gateway.evidence_object_policy_revisions,
    apolysis_gateway.evidence_objects
TO apolysis_gateway_runtime;
GRANT SELECT, INSERT ON apolysis_gateway.evidence_event_objects
    TO apolysis_gateway_runtime;
GRANT INSERT ON apolysis_gateway.gateway_authority_audit
    TO apolysis_gateway_runtime;
GRANT USAGE, SELECT ON SEQUENCE
    apolysis_gateway.gateway_operations_operation_id_seq,
    apolysis_gateway.gateway_authority_audit_gateway_authority_audit_id_seq
TO apolysis_gateway_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.evidence_object_db_now_unix_ms()
    TO apolysis_gateway_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_evidence_objects_for_ingest(text, text[])
    TO apolysis_gateway_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_gateway_authority_by_fingerprint(bytea)
    TO apolysis_gateway_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_evidence_object_organization_shared(text)
    TO apolysis_gateway_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_gateway_operation(
    text, text, text, text, text, text
) TO apolysis_gateway_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_gateway_client_run(text, text, text, text)
    TO apolysis_gateway_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_gateway_runtime_binding(text, text, text)
    TO apolysis_gateway_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_gateway_lease(text, bytea)
    TO apolysis_gateway_runtime;

-- Gateway authority/control plane.
GRANT SELECT, INSERT, UPDATE ON
    apolysis_gateway.organizations,
    apolysis_gateway.source_registrations,
    apolysis_gateway.transport_credentials
TO apolysis_gateway_control;
GRANT SELECT, INSERT ON
    apolysis_gateway.authority_change_audit,
    apolysis_gateway.gateway_authority_audit
TO apolysis_gateway_control;
GRANT USAGE, SELECT ON SEQUENCE
    apolysis_gateway.authority_change_audit_authority_change_id_seq,
    apolysis_gateway.gateway_authority_audit_gateway_authority_audit_id_seq
TO apolysis_gateway_control;

-- Evidence-object capture, access, recovery, and reaper runtime. Credential
-- registration and acknowledgement submission are deliberately absent.
GRANT SELECT ON
    apolysis_gateway.organizations,
    apolysis_gateway.runs,
    apolysis_gateway.source_registrations,
    apolysis_gateway.transport_credentials,
    apolysis_gateway.source_streams,
    apolysis_gateway.source_stream_capabilities,
    apolysis_gateway.leases,
    apolysis_gateway.lease_operations,
    apolysis_gateway.evidence_object_policy_revisions,
    apolysis_gateway.evidence_object_deletion_targets,
    apolysis_gateway.evidence_object_deletion_acknowledgements
TO apolysis_evidence_runtime;
GRANT SELECT ON apolysis_gateway.organization_object_usage
    TO apolysis_evidence_runtime;
GRANT SELECT, INSERT ON apolysis_gateway.evidence_objects
    TO apolysis_evidence_runtime;
-- Keep this allowlist synchronized with capture/finalize/delete/reaper SQL.
-- Retention expiry, control-only policy facts, immutable metadata, and future
-- columns receive no runtime UPDATE authority by default.
GRANT UPDATE (
    object_state,
    lifecycle_revision,
    delete_request_revision,
    available_at_unix_ms,
    access_denied_at_unix_ms,
    delete_requested_at_unix_ms,
    storage_purged_at_unix_ms,
    purged_at_unix_ms,
    delete_reason,
    upload_fence_token,
    upload_fence_started_at_unix_ms,
    upload_fence_until_unix_ms,
    reap_claimed_by,
    reap_claimed_at_unix_ms,
    reap_claim_until_unix_ms
) ON apolysis_gateway.evidence_objects
    TO apolysis_evidence_runtime;
GRANT SELECT, INSERT, UPDATE ON apolysis_gateway.evidence_object_storage_material
    TO apolysis_evidence_runtime;
GRANT DELETE ON apolysis_gateway.evidence_object_storage_material
    TO apolysis_evidence_runtime;
GRANT SELECT, DELETE ON apolysis_gateway.evidence_object_rate_windows
    TO apolysis_evidence_runtime;
GRANT INSERT ON
    apolysis_gateway.evidence_object_outbox,
    apolysis_gateway.evidence_object_audit
TO apolysis_evidence_runtime;
GRANT SELECT ON apolysis_gateway.evidence_object_deletion_requirements
    TO apolysis_evidence_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.evidence_object_db_now_unix_ms()
    TO apolysis_evidence_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_evidence_object_organization_shared(text)
    TO apolysis_evidence_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_evidence_object_reaper_organizations(bigint, integer)
    TO apolysis_evidence_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_evidence_object_run_shared(text, text)
    TO apolysis_evidence_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_evidence_object_lease_shared(text, bytea)
    TO apolysis_evidence_runtime;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_evidence_source_authority_shared(
    text, text, text, text, text
) TO apolysis_evidence_runtime;
GRANT USAGE, SELECT ON SEQUENCE
    apolysis_gateway.evidence_object_outbox_object_outbox_id_seq,
    apolysis_gateway.evidence_object_audit_object_audit_id_seq
TO apolysis_evidence_runtime;

-- Evidence policy and deletion-component registration control plane. This is
-- the only application capability role allowed to read stored credential
-- verifiers, and it cannot execute or write deletion acknowledgements.
GRANT SELECT ON
    apolysis_gateway.organizations,
    apolysis_gateway.evidence_objects
TO apolysis_evidence_control;
GRANT SELECT, INSERT ON apolysis_gateway.evidence_object_policy_revisions
    TO apolysis_evidence_control;
GRANT UPDATE (policy_state, retired_at_unix_ms)
    ON apolysis_gateway.evidence_object_policy_revisions
    TO apolysis_evidence_control;
GRANT SELECT, INSERT ON apolysis_gateway.evidence_object_deletion_targets
    TO apolysis_evidence_control;
GRANT SELECT, INSERT ON apolysis_gateway.evidence_object_deletion_credentials
    TO apolysis_evidence_control;
GRANT UPDATE (revoked_at_unix_ms)
    ON apolysis_gateway.evidence_object_deletion_credentials
    TO apolysis_evidence_control;
GRANT EXECUTE ON FUNCTION apolysis_gateway.evidence_object_db_now_unix_ms()
    TO apolysis_evidence_control;
GRANT UPDATE (expires_at_unix_ms, lifecycle_revision)
    ON apolysis_gateway.evidence_objects
    TO apolysis_evidence_control;
GRANT INSERT ON
    apolysis_gateway.evidence_object_outbox,
    apolysis_gateway.evidence_object_audit
TO apolysis_evidence_control;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_evidence_object_organization(text)
    TO apolysis_evidence_control;
GRANT EXECUTE ON FUNCTION apolysis_gateway.lock_evidence_object_deletion_target(text, text)
    TO apolysis_evidence_control;
GRANT USAGE, SELECT ON SEQUENCE
    apolysis_gateway.evidence_object_outbox_object_outbox_id_seq,
    apolysis_gateway.evidence_object_audit_object_audit_id_seq
TO apolysis_evidence_control;

-- Deletion components receive no table, sequence, type, owner, or DDL
-- privilege. The security-definer function validates the presented verifier
-- and writes the acknowledgement while keeping stored verifiers unreadable.
GRANT EXECUTE ON FUNCTION apolysis_gateway.acknowledge_evidence_object_deletion(
    text, text, text, bigint, text, text, text, bigint, bytea
) TO apolysis_deletion_ack;

COMMIT;
