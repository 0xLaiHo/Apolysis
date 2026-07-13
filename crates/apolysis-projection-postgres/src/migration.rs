// SPDX-License-Identifier: Apache-2.0

use sha2::{Digest, Sha256};
use sqlx::{PgPool, Row};

use crate::{
    error::{database_failure, invariant_failure},
    ProjectionResult,
};

const MIGRATION_VERSION: i64 = 1;
const MIGRATION_DESCRIPTION: &str = "run lifecycle projection";
const MIGRATION_LOCK: &str = "apolysis_projection.migration/v1";
const MIGRATION_SQL: &str = include_str!("../migrations/0001_run_lifecycle_projection.sql");

/// Install or checksum-verify the independently owned projection schema.
///
/// The Gateway adapter and this crate cannot safely share sqlx's default global
/// migration table. This runner therefore serializes on a transaction advisory
/// lock and keeps a checksum ledger inside `apolysis_projection`.
pub async fn migrate_projection_schema(pool: &PgPool) -> ProjectionResult<()> {
    let checksum = Sha256::digest(MIGRATION_SQL.as_bytes()).to_vec();
    let mut transaction = pool
        .begin()
        .await
        .map_err(|error| database_failure("migration_begin", &error))?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(MIGRATION_LOCK)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("migration_lock", &error))?;

    let schema_exists: bool =
        sqlx::query_scalar("SELECT to_regnamespace('apolysis_projection') IS NOT NULL")
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| database_failure("migration_schema_probe", &error))?;

    if schema_exists {
        let rows = sqlx::query(
            "SELECT version, description, checksum \
             FROM apolysis_projection.schema_migrations ORDER BY version",
        )
        .fetch_all(&mut *transaction)
        .await
        .map_err(|error| database_failure("migration_history_read", &error))?;
        if rows.len() != 1 {
            return Err(invariant_failure("migration_history_cardinality"));
        }
        let row = &rows[0];
        let version: i64 = row
            .try_get("version")
            .map_err(|error| database_failure("migration_history_decode", &error))?;
        let description: String = row
            .try_get("description")
            .map_err(|error| database_failure("migration_history_decode", &error))?;
        let installed_checksum: Vec<u8> = row
            .try_get("checksum")
            .map_err(|error| database_failure("migration_history_decode", &error))?;
        if version != MIGRATION_VERSION
            || description != MIGRATION_DESCRIPTION
            || installed_checksum != checksum
        {
            return Err(invariant_failure("migration_checksum_mismatch"));
        }
    } else {
        sqlx::raw_sql(MIGRATION_SQL)
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_failure("migration_execute", &error))?;
        sqlx::query(
            "INSERT INTO apolysis_projection.schema_migrations \
             (version, description, checksum) VALUES ($1,$2,$3)",
        )
        .bind(MIGRATION_VERSION)
        .bind(MIGRATION_DESCRIPTION)
        .bind(checksum)
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_failure("migration_history_insert", &error))?;
    }

    transaction
        .commit()
        .await
        .map_err(|error| database_failure("migration_commit", &error))
}
