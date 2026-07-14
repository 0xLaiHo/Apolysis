-- SPDX-License-Identifier: Apache-2.0

-- Run once per PostgreSQL cluster/database, before the ordered sqlx migrations,
-- as a PostgreSQL superuser. Role creation is deliberately separated from the
-- later non-superuser migration and application logins. Then run
-- every migration on one connection after:
--
--     SET ROLE apolysis_schema_owner;
--
-- The public-schema grant is limited to the NOLOGIN migration owner and is
-- required because sqlx stores its private _sqlx_migrations table there.
-- Capability-role names are intentionally fixed for a dedicated Apolysis
-- PostgreSQL cluster. A database marker makes reuse in another database fail
-- closed instead of silently sharing cluster-global roles.

BEGIN;
SET LOCAL search_path = pg_catalog;

DO $superuser_required$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = current_user
          AND role.rolsuper
    ) THEN
        RAISE EXCEPTION 'Apolysis role bootstrap requires a PostgreSQL superuser';
    END IF;
END
$superuser_required$;

DO $roles$
DECLARE
    role_name text;
    role_oid oid;
    role_marker text;
    expected_marker text;
BEGIN
    FOREACH role_name IN ARRAY ARRAY[
        'apolysis_schema_owner',
        'apolysis_gateway_runtime',
        'apolysis_gateway_control',
        'apolysis_evidence_runtime',
        'apolysis_evidence_control',
        'apolysis_deletion_ack'
    ]
    LOOP
        SELECT role.oid, pg_catalog.shobj_description(role.oid, 'pg_authid')
        INTO role_oid, role_marker
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname = role_name;
        expected_marker := format(
            'apolysis-managed-role:v1:database=%s:role=%s',
            current_database(),
            role_name
        );
        IF role_oid IS NULL THEN
            EXECUTE format('CREATE ROLE %I', role_name);
            EXECUTE format('COMMENT ON ROLE %I IS %L', role_name, expected_marker);
        ELSIF role_marker IS DISTINCT FROM expected_marker THEN
            RAISE EXCEPTION
                'role % already exists without the Apolysis marker for database %',
                role_name,
                current_database();
        END IF;
        EXECUTE format(
            'ALTER ROLE %I WITH NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
            role_name
        );
    END LOOP;
END
$roles$;

-- Capability roles never inherit a more powerful role. Membership granted to
-- deployment logins is intentionally left to the deployment secret manager.
DO $memberships$
DECLARE
    membership record;
BEGIN
    FOR membership IN
        SELECT granted.rolname AS granted_role, member.rolname AS member_role
        FROM pg_catalog.pg_auth_members AS relation
        JOIN pg_catalog.pg_roles AS granted ON granted.oid = relation.roleid
        JOIN pg_catalog.pg_roles AS member ON member.oid = relation.member
        WHERE member.rolname IN (
            'apolysis_schema_owner',
            'apolysis_gateway_runtime',
            'apolysis_gateway_control',
            'apolysis_evidence_runtime',
            'apolysis_evidence_control',
            'apolysis_deletion_ack'
        )
    LOOP
        EXECUTE format(
            'REVOKE %I FROM %I',
            membership.granted_role,
            membership.member_role
        );
    END LOOP;
END
$memberships$;

-- One login must never combine control-plane verifier access, acknowledgement
-- execution, served runtime authority, or schema ownership. Re-running the
-- bootstrap is the deployment audit for that mutually exclusive membership
-- rule. Indirect NOLOGIN distribution groups are rejected as well, and no
-- login may redistribute any fixed capability through ADMIN OPTION.
DO $exclusive_login_membership$
DECLARE
    unsafe_member record;
BEGIN
    FOR unsafe_member IN
        SELECT
            member.rolname AS member_role,
            ARRAY[granted.rolname] AS granted_roles
        FROM pg_catalog.pg_auth_members AS relation
        JOIN pg_catalog.pg_roles AS granted ON granted.oid = relation.roleid
        JOIN pg_catalog.pg_roles AS member ON member.oid = relation.member
        WHERE granted.rolname IN (
            'apolysis_schema_owner',
            'apolysis_gateway_runtime',
            'apolysis_gateway_control',
            'apolysis_evidence_runtime',
            'apolysis_evidence_control',
            'apolysis_deletion_ack'
        )
          AND (NOT member.rolcanlogin OR member.rolsuper)
    LOOP
        RAISE EXCEPTION
            'role % has unsafe Apolysis capability memberships: %',
            unsafe_member.member_role,
            unsafe_member.granted_roles;
    END LOOP;

    FOR unsafe_member IN
        SELECT
            member.rolname AS member_role,
            array_agg(granted.rolname ORDER BY granted.rolname) AS granted_roles
        FROM pg_catalog.pg_auth_members AS relation
        JOIN pg_catalog.pg_roles AS granted ON granted.oid = relation.roleid
        JOIN pg_catalog.pg_roles AS member ON member.oid = relation.member
        WHERE granted.rolname IN (
            'apolysis_schema_owner',
            'apolysis_gateway_runtime',
            'apolysis_gateway_control',
            'apolysis_evidence_runtime',
            'apolysis_evidence_control',
            'apolysis_deletion_ack'
        )
          AND member.rolcanlogin
          AND relation.admin_option
        GROUP BY member.rolname
    LOOP
        RAISE EXCEPTION
            'role % can delegate Apolysis capability memberships: %',
            unsafe_member.member_role,
            unsafe_member.granted_roles;
    END LOOP;

    FOR unsafe_member IN
        SELECT login.rolname AS member_role, ARRAY['unsafe-role-attribute'] AS granted_roles
        FROM pg_catalog.pg_roles AS login
        WHERE login.rolcanlogin
          AND NOT login.rolsuper
          AND EXISTS (
              SELECT 1
              FROM pg_catalog.pg_roles AS capability
              WHERE capability.rolname IN (
                  'apolysis_gateway_runtime',
                  'apolysis_gateway_control',
                  'apolysis_evidence_runtime',
                  'apolysis_evidence_control',
                  'apolysis_deletion_ack'
              )
                AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
          )
          AND (
              login.rolcreatedb
              OR login.rolcreaterole
              OR login.rolreplication
              OR login.rolbypassrls
              OR login.oid = (
                  SELECT database.datdba
                  FROM pg_catalog.pg_database AS database
                  WHERE database.datname = current_database()
              )
              OR login.oid = (
                  SELECT namespace.nspowner
                  FROM pg_catalog.pg_namespace AS namespace
                  WHERE namespace.nspname = 'public'
              )
          )
    LOOP
        RAISE EXCEPTION
            'served role % has unsafe database authority',
            unsafe_member.member_role;
    END LOOP;

    FOR unsafe_member IN
        SELECT
            login.rolname AS member_role,
            array_agg(capability.rolname ORDER BY capability.rolname) AS granted_roles
        FROM pg_catalog.pg_roles AS login
        CROSS JOIN pg_catalog.pg_roles AS capability
        WHERE login.rolcanlogin
          AND NOT login.rolsuper
          AND capability.rolname IN (
              'apolysis_schema_owner',
              'apolysis_gateway_runtime',
              'apolysis_gateway_control',
              'apolysis_evidence_runtime',
              'apolysis_evidence_control',
              'apolysis_deletion_ack'
          )
          AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
        GROUP BY login.rolname
        HAVING count(*) > 1
    LOOP
        RAISE EXCEPTION
            'role % has unsafe effective Apolysis capability memberships: %',
            unsafe_member.member_role,
            unsafe_member.granted_roles;
    END LOOP;

    FOR unsafe_member IN
        SELECT
            login.rolname AS member_role,
            array_agg(granted.rolname ORDER BY granted.rolname) AS granted_roles
        FROM pg_catalog.pg_roles AS login
        JOIN pg_catalog.pg_auth_members AS membership ON membership.member = login.oid
        JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
        WHERE login.rolcanlogin
          AND NOT login.rolsuper
          AND EXISTS (
              SELECT 1
              FROM pg_catalog.pg_roles AS capability
              WHERE capability.rolname IN (
                  'apolysis_gateway_runtime',
                  'apolysis_gateway_control',
                  'apolysis_evidence_runtime',
                  'apolysis_evidence_control',
                  'apolysis_deletion_ack'
              )
                AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
          )
          AND granted.rolname NOT IN (
              'apolysis_schema_owner',
              'apolysis_gateway_runtime',
              'apolysis_gateway_control',
              'apolysis_evidence_runtime',
              'apolysis_evidence_control',
              'apolysis_deletion_ack'
          )
        GROUP BY login.rolname
    LOOP
        RAISE EXCEPTION
            'served role % has external role memberships: %',
            unsafe_member.member_role,
            unsafe_member.granted_roles;
    END LOOP;
END
$exclusive_login_membership$;

-- A served writer must never be able to disable origin-only triggers. PostgreSQL
-- parameter ACLs are effective through PUBLIC and inherited role membership, so
-- use the privilege inquiry function instead of auditing only direct ACL rows.
DO $served_login_parameter_authority$
DECLARE
    unsafe_authority record;
BEGIN
    FOR unsafe_authority IN
        WITH served_login AS (
            SELECT login.oid, login.rolname
            FROM pg_catalog.pg_roles AS login
            WHERE login.rolcanlogin
              AND NOT login.rolsuper
              AND EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_roles AS capability
                  WHERE capability.rolname IN (
                      'apolysis_gateway_runtime',
                      'apolysis_gateway_control',
                      'apolysis_evidence_runtime',
                      'apolysis_evidence_control',
                      'apolysis_deletion_ack'
                  )
                    AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
              )
        )
        SELECT login.rolname AS member_role
        FROM served_login AS login
        WHERE pg_catalog.has_parameter_privilege(
            login.oid,
            'session_replication_role',
            'SET'
        )
           OR pg_catalog.has_parameter_privilege(
               login.oid,
               'session_replication_role',
               'ALTER SYSTEM'
           )
           OR EXISTS (
               SELECT 1
               FROM pg_catalog.pg_roles AS capability
               WHERE capability.rolname IN (
                   'apolysis_gateway_runtime',
                   'apolysis_gateway_control',
                   'apolysis_evidence_runtime',
                   'apolysis_evidence_control',
                   'apolysis_deletion_ack'
               )
                 AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
                 AND (
                     pg_catalog.has_parameter_privilege(
                         capability.oid,
                         'session_replication_role',
                         'SET'
                     )
                     OR pg_catalog.has_parameter_privilege(
                         capability.oid,
                         'session_replication_role',
                         'ALTER SYSTEM'
                     )
                 )
           )
    LOOP
        RAISE EXCEPTION
            'served role % has unsafe session_replication_role parameter authority',
            unsafe_authority.member_role;
    END LOOP;
END
$served_login_parameter_authority$;

-- ALTER ROLE/ALTER DATABASE settings are applied while a connection is being
-- established. They remain unsafe even when the login has no parameter ACL.
DO $served_login_persistent_setting$
DECLARE
    unsafe_setting record;
BEGIN
    FOR unsafe_setting IN
        WITH served_login AS (
            SELECT login.oid, login.rolname
            FROM pg_catalog.pg_roles AS login
            WHERE login.rolcanlogin
              AND NOT login.rolsuper
              AND EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_roles AS capability
                  WHERE capability.rolname IN (
                      'apolysis_gateway_runtime',
                      'apolysis_gateway_control',
                      'apolysis_evidence_runtime',
                      'apolysis_evidence_control',
                      'apolysis_deletion_ack'
                  )
                    AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
              )
        ),
        current_database_oid AS (
            SELECT database.oid
            FROM pg_catalog.pg_database AS database
            WHERE database.datname = current_database()
        )
        SELECT
            login.rolname AS member_role,
            array_agg(DISTINCT configuration.value ORDER BY configuration.value) AS settings
        FROM served_login AS login
        CROSS JOIN current_database_oid AS database
        JOIN pg_catalog.pg_db_role_setting AS setting
          ON setting.setrole IN (0, login.oid)
         AND setting.setdatabase IN (0, database.oid)
        CROSS JOIN LATERAL pg_catalog.unnest(setting.setconfig) AS configuration(value)
        WHERE pg_catalog.split_part(configuration.value, '=', 1)
              = 'session_replication_role'
          AND pg_catalog.split_part(configuration.value, '=', 2) <> 'origin'
        GROUP BY login.rolname
    LOOP
        RAISE EXCEPTION
            'served role % has unsafe persistent session_replication_role setting: %',
            unsafe_setting.member_role,
            unsafe_setting.settings;
    END LOOP;
END
$served_login_persistent_setting$;

-- A served login receives authority only through its one capability role.
-- Direct ACLs would survive capability-role convergence, while object
-- ownership would bypass ACLs entirely, so both conditions fail closed across
-- every non-temporary schema.
DO $served_login_direct_authority$
DECLARE
    unsafe_authority record;
BEGIN
    FOR unsafe_authority IN
        WITH served_login AS (
            SELECT login.oid, login.rolname
            FROM pg_catalog.pg_roles AS login
            WHERE login.rolcanlogin
              AND NOT login.rolsuper
              AND EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_roles AS capability
                  WHERE capability.rolname IN (
                      'apolysis_gateway_runtime',
                      'apolysis_gateway_control',
                      'apolysis_evidence_runtime',
                      'apolysis_evidence_control',
                      'apolysis_deletion_ack'
                  )
                    AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
              )
        ),
        authority AS (
            SELECT
                login.rolname AS member_role,
                format('database:%I:%s', database.datname, acl.privilege_type) AS authority
            FROM served_login AS login
            JOIN pg_catalog.pg_database AS database
              ON database.datname = current_database()
            CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS acl
            WHERE acl.grantee = login.oid

            UNION ALL

            SELECT
                login.rolname,
                format('schema:%I:%s', namespace.nspname, acl.privilege_type)
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_namespace AS namespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND acl.grantee = login.oid

            UNION ALL

            SELECT
                login.rolname,
                format(
                    'relation:%I.%I:%s',
                    namespace.nspname,
                    class.relname,
                    acl.privilege_type
                )
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_class AS class
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(class.relacl) AS acl
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND acl.grantee = login.oid

            UNION ALL

            SELECT
                login.rolname,
                format(
                    'column:%I.%I.%I:%s',
                    namespace.nspname,
                    class.relname,
                    attribute.attname,
                    acl.privilege_type
                )
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_attribute AS attribute
            JOIN pg_catalog.pg_class AS class ON class.oid = attribute.attrelid
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
              AND acl.grantee = login.oid

            UNION ALL

            SELECT
                login.rolname,
                format(
                    'routine:%I.%I:%s',
                    namespace.nspname,
                    procedure.proname,
                    acl.privilege_type
                )
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(procedure.proacl) AS acl
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND acl.grantee = login.oid

            UNION ALL

            SELECT
                login.rolname,
                format(
                    'type:%I.%I:%s',
                    namespace.nspname,
                    type.typname,
                    acl.privilege_type
                )
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_type AS type
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = type.typnamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(type.typacl) AS acl
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND acl.grantee = login.oid

            UNION ALL

            SELECT
                login.rolname,
                format(
                    'default:%s:%s',
                    default_acl.defaclobjtype,
                    acl.privilege_type
                )
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_default_acl AS default_acl
            LEFT JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = default_acl.defaclnamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(default_acl.defaclacl) AS acl
            WHERE (
                    default_acl.defaclnamespace = 0
                    OR (
                        namespace.nspname !~ '^pg_temp_[0-9]+$'
                        AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
                    )
                  )
              AND acl.grantee = login.oid

            UNION ALL

            SELECT login.rolname, format('owner:schema:%I', namespace.nspname)
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND namespace.nspowner = login.oid

            UNION ALL

            SELECT
                login.rolname,
                format('owner:relation:%I.%I', namespace.nspname, class.relname)
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_class AS class
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND class.relowner = login.oid

            UNION ALL

            SELECT
                login.rolname,
                format('owner:routine:%I.%I', namespace.nspname, procedure.proname)
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND procedure.proowner = login.oid

            UNION ALL

            SELECT
                login.rolname,
                format('owner:type:%I.%I', namespace.nspname, type.typname)
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_type AS type
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = type.typnamespace
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND type.typowner = login.oid
        )
        SELECT
            member_role,
            array_agg(DISTINCT authority ORDER BY authority) AS authorities
        FROM authority
        GROUP BY member_role
    LOOP
        RAISE EXCEPTION
            'served role % has direct database/object authority: %',
            unsafe_authority.member_role,
            unsafe_authority.authorities;
    END LOOP;
END
$served_login_direct_authority$;

-- Explicit capability-role object ACLs are reviewed only in the application
-- schema. Any ACL outside that surface, any capability-targeted default ACL,
-- and any object ownership at all would be inherited by a served login without
-- appearing as direct login authority.
DO $served_capability_unexpected_authority$
DECLARE
    unsafe_authority record;
BEGIN
    FOR unsafe_authority IN
        WITH served_capability AS (
            SELECT capability.oid, capability.rolname
            FROM pg_catalog.pg_roles AS capability
            WHERE capability.rolname IN (
                'apolysis_gateway_runtime',
                'apolysis_gateway_control',
                'apolysis_evidence_runtime',
                'apolysis_evidence_control',
                'apolysis_deletion_ack'
            )
        ),
        authority AS (
            SELECT
                capability.rolname AS capability_role,
                format('database:%I:%s', database.datname, acl.privilege_type) AS authority
            FROM served_capability AS capability
            JOIN pg_catalog.pg_database AS database
              ON database.datname = current_database()
            CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS acl
            WHERE acl.grantee = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format('owner:database:%I', database.datname)
            FROM served_capability AS capability
            JOIN pg_catalog.pg_database AS database ON database.datdba = capability.oid
            WHERE database.datname = current_database()

            UNION ALL

            SELECT
                capability.rolname,
                format('schema:%I:%s', namespace.nspname, acl.privilege_type)
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_namespace AS namespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl
            WHERE namespace.nspname <> 'apolysis_gateway'
              AND namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND acl.grantee = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format(
                    'relation:%I.%I:%s',
                    namespace.nspname,
                    class.relname,
                    acl.privilege_type
                )
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_class AS class
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(class.relacl) AS acl
            WHERE namespace.nspname <> 'apolysis_gateway'
              AND namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND acl.grantee = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format(
                    'column:%I.%I.%I:%s',
                    namespace.nspname,
                    class.relname,
                    attribute.attname,
                    acl.privilege_type
                )
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_attribute AS attribute
            JOIN pg_catalog.pg_class AS class ON class.oid = attribute.attrelid
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
            WHERE namespace.nspname <> 'apolysis_gateway'
              AND namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND attribute.attnum > 0
              AND NOT attribute.attisdropped
              AND acl.grantee = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format(
                    'routine:%I.%I:%s',
                    namespace.nspname,
                    procedure.proname,
                    acl.privilege_type
                )
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(procedure.proacl) AS acl
            WHERE namespace.nspname <> 'apolysis_gateway'
              AND namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND acl.grantee = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format(
                    'type:%I.%I:%s',
                    namespace.nspname,
                    type.typname,
                    acl.privilege_type
                )
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_type AS type
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = type.typnamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(type.typacl) AS acl
            WHERE namespace.nspname <> 'apolysis_gateway'
              AND namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND acl.grantee = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format(
                    'default:%s:%s',
                    default_acl.defaclobjtype,
                    acl.privilege_type
                )
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_default_acl AS default_acl
            LEFT JOIN pg_catalog.pg_namespace AS namespace
              ON namespace.oid = default_acl.defaclnamespace
            CROSS JOIN LATERAL pg_catalog.aclexplode(default_acl.defaclacl) AS acl
            WHERE (
                    default_acl.defaclnamespace = 0
                    OR (
                        namespace.nspname !~ '^pg_temp_[0-9]+$'
                        AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
                    )
                  )
              AND acl.grantee = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format('owner:schema:%I', namespace.nspname)
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND namespace.nspowner = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format('owner:relation:%I.%I', namespace.nspname, class.relname)
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_class AS class
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND class.relowner = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format('owner:routine:%I.%I', namespace.nspname, procedure.proname)
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_proc AS procedure
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND procedure.proowner = capability.oid

            UNION ALL

            SELECT
                capability.rolname,
                format('owner:type:%I.%I', namespace.nspname, type.typname)
            FROM served_capability AS capability
            CROSS JOIN pg_catalog.pg_type AS type
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = type.typnamespace
            WHERE namespace.nspname !~ '^pg_temp_[0-9]+$'
              AND namespace.nspname !~ '^pg_toast_temp_[0-9]+$'
              AND type.typowner = capability.oid
        )
        SELECT
            capability_role,
            array_agg(DISTINCT authority ORDER BY authority) AS authorities
        FROM authority
        GROUP BY capability_role
    LOOP
        RAISE EXCEPTION
            'capability role % has unexpected database/object authority: %',
            unsafe_authority.capability_role,
            unsafe_authority.authorities;
    END LOOP;
END
$served_capability_unexpected_authority$;

-- Reject effective DDL authority before convergence so a poisoned PUBLIC grant
-- cannot be silently normalized. A first bootstrap has no served login yet;
-- subsequent runs audit every deployed login before applying the defensive
-- revokes below.
DO $served_login_effective_create$
DECLARE
    unsafe_authority record;
BEGIN
    FOR unsafe_authority IN
        WITH served_login AS (
            SELECT login.oid, login.rolname
            FROM pg_catalog.pg_roles AS login
            WHERE login.rolcanlogin
              AND NOT login.rolsuper
              AND EXISTS (
                  SELECT 1
                  FROM pg_catalog.pg_roles AS capability
                  WHERE capability.rolname IN (
                      'apolysis_gateway_runtime',
                      'apolysis_gateway_control',
                      'apolysis_evidence_runtime',
                      'apolysis_evidence_control',
                      'apolysis_deletion_ack'
                  )
                    AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
              )
        ),
        authority AS (
            SELECT
                login.rolname AS member_role,
                format('database:%I:CREATE', database.datname) AS authority
            FROM served_login AS login
            JOIN pg_catalog.pg_database AS database
              ON database.datname = current_database()
            WHERE (
                pg_catalog.has_database_privilege(
                    login.oid,
                    database.oid,
                    'CREATE'
                )
                OR EXISTS (
                   SELECT 1
                   FROM pg_catalog.pg_roles AS capability
                   WHERE capability.rolname IN (
                       'apolysis_gateway_runtime',
                       'apolysis_gateway_control',
                       'apolysis_evidence_runtime',
                       'apolysis_evidence_control',
                       'apolysis_deletion_ack'
                   )
                     AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
                     AND pg_catalog.has_database_privilege(
                         capability.oid,
                         database.oid,
                         'CREATE'
                     )
               )
            )

            UNION ALL

            SELECT
                login.rolname,
                format('schema:%I:CREATE', namespace.nspname)
            FROM served_login AS login
            CROSS JOIN pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspname IN ('public', 'apolysis_gateway')
              AND (
                  pg_catalog.has_schema_privilege(
                      login.oid,
                      namespace.oid,
                      'CREATE'
                  )
                  OR EXISTS (
                       SELECT 1
                       FROM pg_catalog.pg_roles AS capability
                       WHERE capability.rolname IN (
                           'apolysis_gateway_runtime',
                           'apolysis_gateway_control',
                           'apolysis_evidence_runtime',
                           'apolysis_evidence_control',
                           'apolysis_deletion_ack'
                       )
                         AND pg_catalog.pg_has_role(login.oid, capability.oid, 'MEMBER')
                         AND pg_catalog.has_schema_privilege(
                             capability.oid,
                             namespace.oid,
                             'CREATE'
                         )
                   )
              )
        )
        SELECT
            member_role,
            array_agg(DISTINCT authority ORDER BY authority) AS authorities
        FROM authority
        GROUP BY member_role
    LOOP
        RAISE EXCEPTION
            'served role % has unsafe effective database/schema CREATE authority: %',
            unsafe_authority.member_role,
            unsafe_authority.authorities;
    END LOOP;
END
$served_login_effective_create$;

REVOKE ALL PRIVILEGES ON SCHEMA public FROM PUBLIC;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM
    apolysis_gateway_runtime,
    apolysis_gateway_control,
    apolysis_evidence_runtime,
    apolysis_evidence_control,
    apolysis_deletion_ack;
GRANT USAGE, CREATE ON SCHEMA public TO apolysis_schema_owner;
DO $database_create$
BEGIN
    EXECUTE format(
        'REVOKE CREATE ON DATABASE %I FROM PUBLIC',
        current_database()
    );
    EXECUTE format(
        'REVOKE CREATE ON DATABASE %I FROM apolysis_gateway_runtime, apolysis_gateway_control, apolysis_evidence_runtime, apolysis_evidence_control, apolysis_deletion_ack',
        current_database()
    );
    EXECUTE format(
        'GRANT CREATE ON DATABASE %I TO apolysis_schema_owner',
        current_database()
    );
END
$database_create$;

-- Seal the migration window itself. Objects created while the migration
-- connection is SET ROLE to the owner never receive PostgreSQL's default
-- PUBLIC function/type privileges before the post-migration grant pass.
ALTER DEFAULT PRIVILEGES FOR ROLE apolysis_schema_owner
    REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE apolysis_schema_owner
    REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE apolysis_schema_owner
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE apolysis_schema_owner
    REVOKE USAGE ON TYPES FROM PUBLIC;

COMMIT;
