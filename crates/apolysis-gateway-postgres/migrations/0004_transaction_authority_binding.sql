-- SPDX-License-Identifier: Apache-2.0

-- Persist every authority tuple that may be referenced by immutable ledger
-- history. The current registration remains mutable; this table is append-only
-- to served roles and therefore keeps the policy document that accompanied a
-- credential/policy cutover.
ALTER TABLE apolysis_gateway.transport_credentials
    ADD CONSTRAINT transport_credentials_authority_revision_key
    UNIQUE (
        organization_id,
        source_registration_id,
        credential_id,
        credential_epoch
    );

CREATE TABLE apolysis_gateway.source_authority_revisions (
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    credential_id apolysis_gateway.contract_identifier NOT NULL,
    credential_epoch apolysis_gateway.ijson_positive NOT NULL,
    registration_policy_revision apolysis_gateway.ijson_positive NOT NULL,
    policy_document jsonb NOT NULL
        CHECK (jsonb_typeof(policy_document) = 'object'),
    effective_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    expires_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    recorded_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    PRIMARY KEY (
        organization_id,
        source_registration_id,
        credential_id,
        credential_epoch,
        registration_policy_revision
    ),
    CONSTRAINT source_authority_revisions_registration_fk
        FOREIGN KEY (organization_id, source_registration_id)
        REFERENCES apolysis_gateway.source_registrations (
            organization_id,
            source_registration_id
        )
        ON DELETE RESTRICT,
    CONSTRAINT source_authority_revisions_credential_fk
        FOREIGN KEY (
            organization_id,
            source_registration_id,
            credential_id,
            credential_epoch
        )
        REFERENCES apolysis_gateway.transport_credentials (
            organization_id,
            source_registration_id,
            credential_id,
            credential_epoch
        )
        ON DELETE RESTRICT,
    CONSTRAINT source_authority_revisions_validity_ck
        CHECK (expires_at_unix_ms > effective_at_unix_ms)
);

COMMENT ON TABLE apolysis_gateway.source_authority_revisions IS
    'Append-only authority tuples referenced by ledger, lease, and replay history.';

-- Before this migration there was no credential identity on ledger rows. Only
-- the registration's current epoch can be recorded honestly during upgrade;
-- old ledger rows are deliberately left unbound and failed closed below.
INSERT INTO apolysis_gateway.source_authority_revisions (
    organization_id,
    source_registration_id,
    credential_id,
    credential_epoch,
    registration_policy_revision,
    policy_document,
    effective_at_unix_ms,
    expires_at_unix_ms,
    recorded_at_unix_ms
)
SELECT
    registration.organization_id,
    registration.source_registration_id,
    credential.credential_id,
    credential.credential_epoch,
    registration.policy_revision,
    registration.policy_document,
    registration.effective_at_unix_ms,
    registration.expires_at_unix_ms,
    greatest(registration.updated_at_unix_ms, credential.updated_at_unix_ms)
FROM apolysis_gateway.source_registrations AS registration
JOIN apolysis_gateway.transport_credentials AS credential
  ON credential.organization_id = registration.organization_id
 AND credential.source_registration_id = registration.source_registration_id
 AND credential.credential_epoch = registration.credential_epoch;

REVOKE ALL PRIVILEGES
    ON TABLE apolysis_gateway.source_authority_revisions
    FROM PUBLIC;

-- Existing rows receive the explicit legacy marker. The default is switched
-- before served writers can observe the schema, so every new row must carry a
-- complete v1 tuple.
ALTER TABLE apolysis_gateway.leases
    ADD COLUMN authority_binding_version text NOT NULL
        DEFAULT 'apolysis.gateway.authority-binding/legacy-unbound-v0',
    ADD COLUMN credential_id apolysis_gateway.contract_identifier,
    ADD COLUMN credential_epoch apolysis_gateway.ijson_positive;

ALTER TABLE apolysis_gateway.leases
    ALTER COLUMN authority_binding_version
        SET DEFAULT 'apolysis.gateway.authority-binding/v1',
    ADD CONSTRAINT leases_authority_binding_shape_ck
        CHECK (
            (
                authority_binding_version =
                    'apolysis.gateway.authority-binding/legacy-unbound-v0'
                AND credential_id IS NULL
                AND credential_epoch IS NULL
            )
            OR
            (
                authority_binding_version =
                    'apolysis.gateway.authority-binding/v1'
                AND credential_id IS NOT NULL
                AND credential_epoch IS NOT NULL
            )
        ),
    ADD CONSTRAINT leases_authority_revision_fk
        FOREIGN KEY (
            organization_id,
            source_registration_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        REFERENCES apolysis_gateway.source_authority_revisions (
            organization_id,
            source_registration_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        ON DELETE RESTRICT;

CREATE INDEX leases_authority_revision_idx
    ON apolysis_gateway.leases (
        organization_id,
        source_registration_id,
        credential_id,
        credential_epoch,
        registration_policy_revision
    );

ALTER TABLE apolysis_gateway.gateway_operations
    ADD COLUMN authority_binding_version text NOT NULL
        DEFAULT 'apolysis.gateway.authority-binding/legacy-unbound-v0',
    ADD COLUMN credential_id apolysis_gateway.contract_identifier,
    ADD COLUMN credential_epoch apolysis_gateway.ijson_positive,
    ADD COLUMN registration_policy_revision apolysis_gateway.ijson_positive;

ALTER TABLE apolysis_gateway.gateway_operations
    ALTER COLUMN authority_binding_version
        SET DEFAULT 'apolysis.gateway.authority-binding/v1',
    ADD CONSTRAINT gateway_operations_authority_binding_shape_ck
        CHECK (
            (
                authority_binding_version =
                    'apolysis.gateway.authority-binding/legacy-unbound-v0'
                AND credential_id IS NULL
                AND credential_epoch IS NULL
                AND registration_policy_revision IS NULL
            )
            OR
            (
                authority_binding_version =
                    'apolysis.gateway.authority-binding/v1'
                AND credential_id IS NOT NULL
                AND credential_epoch IS NOT NULL
                AND registration_policy_revision IS NOT NULL
            )
        ),
    ADD CONSTRAINT gateway_operations_authority_revision_fk
        FOREIGN KEY (
            organization_id,
            source_registration_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        REFERENCES apolysis_gateway.source_authority_revisions (
            organization_id,
            source_registration_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        ON DELETE RESTRICT,
    ADD CONSTRAINT gateway_operations_authority_binding_key
        UNIQUE (
            organization_id,
            operation_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        );

CREATE INDEX gateway_operations_authority_revision_idx
    ON apolysis_gateway.gateway_operations (
        organization_id,
        source_registration_id,
        credential_id,
        credential_epoch,
        registration_policy_revision
    );

ALTER TABLE apolysis_gateway.join_authorizations
    ADD COLUMN authority_binding_version text NOT NULL
        DEFAULT 'apolysis.gateway.authority-binding/legacy-unbound-v0',
    ADD COLUMN credential_id apolysis_gateway.contract_identifier,
    ADD COLUMN credential_epoch apolysis_gateway.ijson_positive,
    ADD COLUMN issued_by_credential_id apolysis_gateway.contract_identifier,
    ADD COLUMN issued_by_credential_epoch apolysis_gateway.ijson_positive,
    ADD COLUMN issued_by_registration_policy_revision
        apolysis_gateway.ijson_positive;

ALTER TABLE apolysis_gateway.join_authorizations
    ALTER COLUMN authority_binding_version
        SET DEFAULT 'apolysis.gateway.authority-binding/v1',
    ADD CONSTRAINT join_authorizations_authority_binding_shape_ck
        CHECK (
            (
                authority_binding_version =
                    'apolysis.gateway.authority-binding/legacy-unbound-v0'
                AND credential_id IS NULL
                AND credential_epoch IS NULL
                AND issued_by_credential_id IS NULL
                AND issued_by_credential_epoch IS NULL
                AND issued_by_registration_policy_revision IS NULL
            )
            OR
            (
                authority_binding_version =
                    'apolysis.gateway.authority-binding/v1'
                AND credential_id IS NOT NULL
                AND credential_epoch IS NOT NULL
                AND issued_by_credential_id IS NOT NULL
                AND issued_by_credential_epoch IS NOT NULL
                AND issued_by_registration_policy_revision IS NOT NULL
            )
        ),
    ADD CONSTRAINT join_authorizations_target_authority_revision_fk
        FOREIGN KEY (
            organization_id,
            source_registration_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        REFERENCES apolysis_gateway.source_authority_revisions (
            organization_id,
            source_registration_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        ON DELETE RESTRICT,
    ADD CONSTRAINT join_authorizations_issuer_authority_revision_fk
        FOREIGN KEY (
            organization_id,
            issued_by_source_registration_id,
            issued_by_credential_id,
            issued_by_credential_epoch,
            issued_by_registration_policy_revision
        )
        REFERENCES apolysis_gateway.source_authority_revisions (
            organization_id,
            source_registration_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        ON DELETE RESTRICT;

CREATE INDEX join_authorizations_target_authority_revision_idx
    ON apolysis_gateway.join_authorizations (
        organization_id,
        source_registration_id,
        credential_id,
        credential_epoch,
        registration_policy_revision
    );

CREATE INDEX join_authorizations_issuer_authority_revision_idx
    ON apolysis_gateway.join_authorizations (
        organization_id,
        issued_by_source_registration_id,
        issued_by_credential_id,
        issued_by_credential_epoch,
        issued_by_registration_policy_revision
    );

-- A legacy replay cannot be authenticated to the credential/policy tuple that
-- created it. Erase only the TTL-bound ciphertext; its gateway_operations row
-- deliberately survives as the durable operation-ID tombstone.
DELETE FROM apolysis_gateway.operation_replays;

-- credential_id is globally unique in transport_credentials, so this
-- registration-free key remains unambiguous for replay rows while the fuller
-- key continues to serve leases, operations, and grants.
ALTER TABLE apolysis_gateway.source_authority_revisions
    ADD CONSTRAINT source_authority_revisions_operation_replay_key
    UNIQUE (
        organization_id,
        credential_id,
        credential_epoch,
        registration_policy_revision
    );

ALTER TABLE apolysis_gateway.operation_replays
    ADD COLUMN authority_binding_version text NOT NULL
        DEFAULT 'apolysis.gateway.authority-binding/v1'
        CHECK (
            authority_binding_version =
                'apolysis.gateway.authority-binding/v1'
        ),
    ADD COLUMN credential_id apolysis_gateway.contract_identifier NOT NULL,
    ADD COLUMN credential_epoch apolysis_gateway.ijson_positive NOT NULL,
    ADD COLUMN registration_policy_revision
        apolysis_gateway.ijson_positive NOT NULL,
    ADD CONSTRAINT operation_replays_operation_authority_fk
        FOREIGN KEY (
            organization_id,
            operation_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        REFERENCES apolysis_gateway.gateway_operations (
            organization_id,
            operation_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        ON DELETE CASCADE,
    ADD CONSTRAINT operation_replays_authority_revision_fk
        FOREIGN KEY (
            organization_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        REFERENCES apolysis_gateway.source_authority_revisions (
            organization_id,
            credential_id,
            credential_epoch,
            registration_policy_revision
        )
        ON DELETE RESTRICT;

CREATE INDEX operation_replays_authority_revision_idx
    ON apolysis_gateway.operation_replays (
        organization_id,
        credential_id,
        credential_epoch,
        registration_policy_revision
    );

-- Prevent a served writer from opting into the migration-only marker, freeze
-- every capability scope, and allow only monotonic lease revocation or
-- pending-to-terminal join-authorization transitions.
CREATE FUNCTION apolysis_gateway.enforce_gateway_authority_binding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, apolysis_gateway, pg_temp
AS $$
DECLARE
    binding_column text;
BEGIN
    IF TG_OP = 'INSERT'
       AND NEW.authority_binding_version IS DISTINCT FROM
           'apolysis.gateway.authority-binding/v1'
    THEN
        RAISE EXCEPTION 'new gateway rows require a v1 authority binding'
            USING ERRCODE = '23514';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF TG_TABLE_NAME = 'leases' THEN
            IF NEW.revoked_at_unix_ms IS NOT NULL THEN
                RAISE EXCEPTION 'new gateway leases must be active'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF TG_TABLE_NAME = 'join_authorizations' THEN
            IF NEW.authorization_state IS DISTINCT FROM 'pending'
               OR NEW.consumed_at_unix_ms IS NOT NULL
               OR NEW.revoked_at_unix_ms IS NOT NULL
            THEN
                RAISE EXCEPTION 'new join authorizations must be pending'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        FOREACH binding_column IN ARRAY TG_ARGV
        LOOP
            IF to_jsonb(NEW) -> binding_column
               IS DISTINCT FROM to_jsonb(OLD) -> binding_column
            THEN
                RAISE EXCEPTION 'gateway authority bindings are immutable'
                    USING ERRCODE = '23514';
            END IF;
        END LOOP;

        IF TG_TABLE_NAME = 'leases' THEN
            IF OLD.revoked_at_unix_ms IS NOT NULL
               AND NEW.revoked_at_unix_ms
                       IS DISTINCT FROM OLD.revoked_at_unix_ms
            THEN
                RAISE EXCEPTION 'revoked gateway leases are immutable'
                    USING ERRCODE = '23514';
            END IF;
        ELSIF TG_TABLE_NAME = 'join_authorizations' THEN
            IF OLD.authorization_state = 'pending' THEN
                IF NEW.authorization_state = 'pending' THEN
                    IF NEW.consumed_at_unix_ms
                           IS DISTINCT FROM OLD.consumed_at_unix_ms
                       OR NEW.revoked_at_unix_ms
                           IS DISTINCT FROM OLD.revoked_at_unix_ms
                    THEN
                        RAISE EXCEPTION
                            'pending join authorization state is immutable'
                            USING ERRCODE = '23514';
                    END IF;
                ELSIF NEW.authorization_state = 'consumed' THEN
                    IF NEW.consumed_at_unix_ms IS NULL
                       OR NEW.consumed_at_unix_ms < OLD.issued_at_unix_ms
                       OR NEW.revoked_at_unix_ms IS NOT NULL
                    THEN
                        RAISE EXCEPTION
                            'invalid join authorization consumption'
                            USING ERRCODE = '23514';
                    END IF;
                ELSIF NEW.authorization_state = 'revoked' THEN
                    IF NEW.revoked_at_unix_ms IS NULL
                       OR NEW.revoked_at_unix_ms < OLD.issued_at_unix_ms
                       OR NEW.consumed_at_unix_ms IS NOT NULL
                    THEN
                        RAISE EXCEPTION
                            'invalid join authorization revocation'
                            USING ERRCODE = '23514';
                    END IF;
                ELSE
                    RAISE EXCEPTION
                        'join authorization transitions must be monotonic'
                        USING ERRCODE = '23514';
                END IF;
            ELSIF NEW.authorization_state
                       IS DISTINCT FROM OLD.authorization_state
               OR NEW.consumed_at_unix_ms
                       IS DISTINCT FROM OLD.consumed_at_unix_ms
               OR NEW.revoked_at_unix_ms
                       IS DISTINCT FROM OLD.revoked_at_unix_ms
            THEN
                RAISE EXCEPTION 'terminal join authorizations are immutable'
                    USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.enforce_gateway_authority_binding()
FROM PUBLIC;

CREATE TRIGGER leases_enforce_authority_binding
BEFORE INSERT OR UPDATE ON apolysis_gateway.leases
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.enforce_gateway_authority_binding(
    'authority_binding_version',
    'organization_id',
    'lease_digest',
    'lease_hash_version',
    'hash_algorithm',
    'run_id',
    'source_registration_id',
    'source_stream_id',
    'source_id',
    'principal_kind',
    'principal_id',
    'credential_id',
    'credential_epoch',
    'registration_policy_revision',
    'issued_at_unix_ms',
    'expires_at_unix_ms'
);

CREATE TRIGGER gateway_operations_enforce_authority_binding
BEFORE INSERT OR UPDATE ON apolysis_gateway.gateway_operations
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.enforce_gateway_authority_binding(
    'authority_binding_version',
    'organization_id',
    'source_registration_id',
    'credential_id',
    'credential_epoch',
    'registration_policy_revision'
);

CREATE TRIGGER join_authorizations_enforce_authority_binding
BEFORE INSERT OR UPDATE ON apolysis_gateway.join_authorizations
FOR EACH ROW EXECUTE FUNCTION apolysis_gateway.enforce_gateway_authority_binding(
    'authority_binding_version',
    'organization_id',
    'proof_digest',
    'proof_hash_version',
    'hash_algorithm',
    'authorization_kind',
    'run_id',
    'source_id',
    'source_kind',
    'environment',
    'source_registration_id',
    'principal_kind',
    'principal_id',
    'credential_id',
    'credential_epoch',
    'registration_policy_revision',
    'issued_by_source_registration_id',
    'issued_by_principal_kind',
    'issued_by_principal_id',
    'issued_by_credential_id',
    'issued_by_credential_epoch',
    'issued_by_registration_policy_revision',
    'issued_at_unix_ms',
    'expires_at_unix_ms'
);

-- Fail closed on every pre-binding capability that could still authorize or
-- replay work. Historical operations remain immutable tombstones.
UPDATE apolysis_gateway.leases
SET revoked_at_unix_ms = greatest(
    issued_at_unix_ms,
    floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
)
WHERE revoked_at_unix_ms IS NULL;

UPDATE apolysis_gateway.join_authorizations
SET authorization_state = 'revoked',
    revoked_at_unix_ms = greatest(
        issued_at_unix_ms,
        floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
    )
WHERE authorization_state = 'pending';

-- Lock the mutable current-authority rows in one deterministic order. A
-- runtime transaction calls this only after locking its operation identity,
-- then reads the rows while these FOR SHARE locks remain held through commit.
CREATE FUNCTION apolysis_gateway.lock_gateway_current_authority(
    checked_organization_id text,
    checked_source_registration_id text,
    checked_credential_id text
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
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM apolysis_gateway.source_registrations AS registration
    WHERE registration.organization_id = checked_organization_id
      AND registration.source_registration_id =
          checked_source_registration_id
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    PERFORM 1
    FROM apolysis_gateway.transport_credentials AS credential
    WHERE credential.organization_id = checked_organization_id
      AND credential.source_registration_id =
          checked_source_registration_id
      AND credential.credential_id = checked_credential_id
    FOR SHARE;
    RETURN FOUND;
END;
$$;

REVOKE ALL ON FUNCTION apolysis_gateway.lock_gateway_current_authority(
    text, text, text
) FROM PUBLIC;

CREATE TABLE apolysis_gateway.transaction_authority_audit (
    transaction_authority_audit_id bigint GENERATED ALWAYS AS IDENTITY
        PRIMARY KEY,
    checked_at_unix_ms apolysis_gateway.ijson_positive NOT NULL,
    operation_kind apolysis_gateway.gateway_operation_kind NOT NULL,
    decision text NOT NULL
        CHECK (decision IN ('authorized', 'unauthenticated', 'forbidden')),
    reason_code apolysis_gateway.contract_identifier NOT NULL,
    organization_id apolysis_gateway.contract_identifier NOT NULL,
    source_registration_id apolysis_gateway.contract_identifier NOT NULL,
    credential_id apolysis_gateway.contract_identifier NOT NULL,
    registration_policy_revision apolysis_gateway.ijson_positive NOT NULL,
    credential_epoch apolysis_gateway.ijson_positive NOT NULL
);

COMMENT ON TABLE apolysis_gateway.transaction_authority_audit IS
    'Content-free authority decisions committed atomically with Gateway transaction outcomes.';

CREATE INDEX transaction_authority_audit_registration_idx
    ON apolysis_gateway.transaction_authority_audit (
        organization_id,
        source_registration_id,
        checked_at_unix_ms
    );

CREATE INDEX transaction_authority_audit_decision_idx
    ON apolysis_gateway.transaction_authority_audit (
        decision,
        checked_at_unix_ms
    );

REVOKE ALL PRIVILEGES
    ON TABLE apolysis_gateway.transaction_authority_audit
    FROM PUBLIC;
REVOKE ALL PRIVILEGES
    ON SEQUENCE
        apolysis_gateway.transaction_authority_audit_transaction_authority_audit_id_seq
    FROM PUBLIC;

ALTER TABLE apolysis_gateway.authority_change_audit
    DROP CONSTRAINT authority_change_audit_action_check,
    ADD CONSTRAINT authority_change_audit_action_ck
        CHECK (
            action IN (
                'register_source',
                'revoke_credential',
                'rotate_policy',
                'rotate_credential'
            )
        );
