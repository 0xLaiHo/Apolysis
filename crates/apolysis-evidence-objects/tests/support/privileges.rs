// SPDX-License-Identifier: Apache-2.0

use std::{error::Error, str::FromStr};

use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use zeroize::Zeroizing;

pub const BOOTSTRAP_ROLES_SQL: &str =
    include_str!("../../../apolysis-gateway-postgres/deploy/bootstrap_roles.sql");
pub const PRIVILEGES_SQL: &str =
    include_str!("../../../apolysis-gateway-postgres/deploy/privileges.sql");

type SupportResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

pub struct ApplicationRolePools {
    pub gateway_runtime: PgPool,
    pub gateway_control: PgPool,
    pub evidence_runtime: PgPool,
    pub evidence_control: PgPool,
    pub deletion_ack: PgPool,
    #[allow(dead_code)]
    gateway_runtime_database_url: Zeroizing<String>,
    login_roles: Vec<String>,
}

impl ApplicationRolePools {
    pub async fn provision(owner_pool: &PgPool, database_url: &str) -> SupportResult<Self> {
        let mut suffix_bytes = [0_u8; 8];
        getrandom::fill(&mut suffix_bytes)?;
        let suffix = suffix_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let role_specs = [
            ("gateway_runtime", "apolysis_gateway_runtime", 4_u32),
            ("gateway_control", "apolysis_gateway_control", 2_u32),
            ("evidence_runtime", "apolysis_evidence_runtime", 8_u32),
            ("evidence_control", "apolysis_evidence_control", 4_u32),
            ("deletion_ack", "apolysis_deletion_ack", 2_u32),
        ];
        let mut pools = Vec::with_capacity(role_specs.len());
        let mut login_roles = Vec::with_capacity(role_specs.len());
        let mut gateway_runtime_database_url = None;
        let mut owner_connection = owner_pool.acquire().await?;
        sqlx::raw_sql(
            r#"
            CREATE OR REPLACE FUNCTION pg_temp.apolysis_create_test_login(
                p_login_role text,
                p_password text,
                p_capability_role text
            ) RETURNS void
            LANGUAGE plpgsql
            AS $function$
            BEGIN
                IF p_login_role !~ '^apolysis_test_[a-z_]+_[0-9a-f]{16}$'
                   OR p_capability_role NOT IN (
                       'apolysis_gateway_runtime',
                       'apolysis_gateway_control',
                       'apolysis_evidence_runtime',
                       'apolysis_evidence_control',
                       'apolysis_deletion_ack'
                   )
                THEN
                    RAISE EXCEPTION 'invalid test role request';
                END IF;
                EXECUTE format(
                    'CREATE ROLE %I WITH LOGIN NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD %L',
                    p_login_role,
                    p_password
                );
                EXECUTE format('GRANT %I TO %I', p_capability_role, p_login_role);
            END
            $function$;
            "#,
        )
        .execute(&mut *owner_connection)
        .await?;

        for (label, capability_role, max_connections) in role_specs {
            let login_role = format!("apolysis_test_{label}_{suffix}");
            let mut password_bytes = [0_u8; 24];
            getrandom::fill(&mut password_bytes)?;
            let password = format!(
                "ApolysisRole_{}",
                password_bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            sqlx::query("SELECT pg_temp.apolysis_create_test_login($1,$2,$3)")
                .bind(&login_role)
                .bind(&password)
                .bind(capability_role)
                .execute(&mut *owner_connection)
                .await?;

            let options = PgConnectOptions::from_str(database_url)?
                .username(&login_role)
                .password(&password);
            let pool = PgPoolOptions::new()
                .max_connections(max_connections)
                .connect_with(options)
                .await?;
            if label == "gateway_runtime" {
                gateway_runtime_database_url = Some(Zeroizing::new(login_database_url(
                    database_url,
                    &login_role,
                    &password,
                )?));
            }
            login_roles.push(login_role);
            pools.push(pool);
        }
        sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
            .execute(&mut *owner_connection)
            .await?;

        let mut pools = pools.into_iter();
        Ok(Self {
            gateway_runtime: pools.next().expect("gateway runtime pool"),
            gateway_control: pools.next().expect("gateway control pool"),
            evidence_runtime: pools.next().expect("evidence runtime pool"),
            evidence_control: pools.next().expect("evidence control pool"),
            deletion_ack: pools.next().expect("deletion acknowledgement pool"),
            gateway_runtime_database_url: gateway_runtime_database_url
                .expect("gateway runtime database URL"),
            login_roles,
        })
    }

    #[allow(dead_code)]
    pub fn gateway_runtime_database_url(&self) -> &str {
        self.gateway_runtime_database_url.as_str()
    }

    #[allow(dead_code)]
    pub fn login_roles(&self) -> &[String] {
        &self.login_roles
    }

    pub async fn close_and_drop(self, owner_pool: &PgPool) -> SupportResult<()> {
        self.gateway_runtime.close().await;
        self.gateway_control.close().await;
        self.evidence_runtime.close().await;
        self.evidence_control.close().await;
        self.deletion_ack.close().await;
        for login_role in self.login_roles {
            sqlx::query(
                "SELECT pg_catalog.pg_terminate_backend(pid) \
                 FROM pg_catalog.pg_stat_activity \
                 WHERE usename=$1 AND pid<>pg_catalog.pg_backend_pid()",
            )
            .bind(&login_role)
            .execute(owner_pool)
            .await?;
            sqlx::query(&format!("DROP ROLE {login_role}"))
                .execute(owner_pool)
                .await?;
        }
        Ok(())
    }
}

fn login_database_url(
    database_url: &str,
    login_role: &str,
    password: &str,
) -> SupportResult<String> {
    let authority_start = database_url
        .find("://")
        .map(|index| index + 3)
        .ok_or("test database URL is missing a scheme")?;
    let host_start = database_url[authority_start..]
        .find('@')
        .map(|index| authority_start + index)
        .ok_or("test database URL must contain an explicit owner user")?;
    Ok(format!(
        "{}{}:{}{}",
        &database_url[..authority_start],
        login_role,
        password,
        &database_url[host_start..]
    ))
}

#[allow(dead_code)]
pub async fn apply_post_migration_privileges(owner_pool: &PgPool) -> SupportResult<()> {
    sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
        .execute(owner_pool)
        .await?;
    sqlx::raw_sql(PRIVILEGES_SQL).execute(owner_pool).await?;
    Ok(())
}
