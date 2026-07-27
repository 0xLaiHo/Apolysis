// SPDX-License-Identifier: Apache-2.0

use std::{
    error::Error,
    ffi::OsStr,
    fs,
    io::Cursor,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use apolysis_gateway_server::AuthorityStore;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{postgres::PgPoolOptions, Connection, PgConnection, PgPool};
use tokio::time::timeout;

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

const BOOTSTRAP_ROLES_SQL: &str =
    include_str!("../../apolysis-gateway-postgres/deploy/bootstrap_roles.sql");
const PRIVILEGES_SQL: &str = include_str!("../../apolysis-gateway-postgres/deploy/privileges.sql");
const AUTHORITY_BIN: &str = env!("CARGO_BIN_EXE_apolysis-gateway-authority");
const ORGANIZATION_ID: &str = "org_gateway_authority_rotation";
const REGISTRATION_ID: &str = "registration_gateway_authority_rotation";
const SOURCE_ID: &str = "source_gateway_authority_rotation";
const PRINCIPAL_ID: &str = "principal_gateway_authority_rotation";
const APPLICATION_NAME: &str = "apolysis_gateway_authority_rotation_lock";
const TEST_DATABASE_LOCK: i64 = 4_715_382_012_602_313_076;
const MTLS_FINGERPRINT_DOMAIN: &[u8] = b"apolysis.gateway.mtls-leaf/v1\0";

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create(label: &str) -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::env::temp_dir().join(format!("apolysis-{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self { path })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn write_private(&self, name: &str, bytes: impl AsRef<[u8]>) -> TestResult<PathBuf> {
        let path = self.path(name);
        fs::write(&path, bytes)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct TestCertificate {
    certificate_path: PathBuf,
    leaf_der: Vec<u8>,
    credential_id: String,
}

struct RealFixture {
    directory: TestDirectory,
    admin_pool: PgPool,
    runtime_store: AuthorityStore,
    control_database_url_file: PathBuf,
    _database_guard: PgConnection,
}

impl RealFixture {
    async fn create(application_name: Option<&str>) -> TestResult<Self> {
        if std::env::var("APOLYSIS_TEST_ALLOW_DATABASE_RESET").as_deref() != Ok("1") {
            return Err(
                "real authority-rotation gate requires explicit ephemeral database reset opt-in"
                    .into(),
            );
        }
        let database_url = std::env::var("APOLYSIS_TEST_DATABASE_URL")?;
        let mut database_guard = PgConnection::connect(&database_url).await?;
        sqlx::query("SELECT pg_advisory_lock($1)")
            .bind(TEST_DATABASE_LOCK)
            .execute(&mut database_guard)
            .await?;
        sqlx::query("DROP SCHEMA IF EXISTS apolysis_gateway CASCADE")
            .execute(&mut database_guard)
            .await?;
        sqlx::query("DROP TABLE IF EXISTS public._sqlx_migrations")
            .execute(&mut database_guard)
            .await?;
        sqlx::raw_sql(BOOTSTRAP_ROLES_SQL)
            .execute(&mut database_guard)
            .await?;
        AuthorityStore::migrate(&database_url).await?;
        let admin_pool = PgPoolOptions::new()
            .max_connections(6)
            .connect(&database_url)
            .await?;
        sqlx::raw_sql(PRIVILEGES_SQL).execute(&admin_pool).await?;

        let directory = TestDirectory::create("gateway-authority-rotation")?;
        let control_database_url =
            served_database_url(&database_url, "apolysis_gateway_control", application_name);
        let control_database_url_file =
            directory.write_private("control.database-url", control_database_url)?;
        let runtime_database_url =
            served_database_url(&database_url, "apolysis_gateway_runtime", None);
        let runtime_store = AuthorityStore::connect(&runtime_database_url).await?;
        Ok(Self {
            directory,
            admin_pool,
            runtime_store,
            control_database_url_file,
            _database_guard: database_guard,
        })
    }

    fn certificate(&self, name: &str) -> TestResult<TestCertificate> {
        let certificate_path = self.directory.path(&format!("{name}.pem"));
        let private_key_path = self.directory.path(&format!("{name}.key"));
        let output = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "2",
                "-subj",
                &format!("/CN={name}"),
                "-addext",
                "basicConstraints=critical,CA:FALSE",
                "-addext",
                "keyUsage=critical,digitalSignature",
                "-addext",
                "extendedKeyUsage=clientAuth",
                "-keyout",
            ])
            .arg(&private_key_path)
            .arg("-out")
            .arg(&certificate_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output()?;
        if !output.status.success() {
            return Err("OpenSSL failed to create a test client certificate".into());
        }
        fs::set_permissions(&private_key_path, fs::Permissions::from_mode(0o600))?;
        let pem = fs::read(&certificate_path)?;
        let mut cursor = Cursor::new(pem);
        let leaf_der = rustls_pemfile::certs(&mut cursor)
            .next()
            .transpose()?
            .ok_or("generated certificate PEM contained no certificate")?
            .as_ref()
            .to_vec();
        let credential_id = credential_id(&mtls_leaf_fingerprint(&leaf_der));
        Ok(TestCertificate {
            certificate_path,
            leaf_der,
            credential_id,
        })
    }

    fn registration(
        &self,
        name: &str,
        now_unix_ms: u64,
        policy_revision: u64,
        credential_epoch: u64,
        allowed_operations: &[&str],
    ) -> TestResult<PathBuf> {
        self.directory.write_private(
            name,
            serde_json::to_vec(&json!({
                "organization_id": ORGANIZATION_ID,
                "organization_state": "active",
                "source_registration_id": REGISTRATION_ID,
                "source_id": SOURCE_ID,
                "principal": {"kind": "workload", "id": PRINCIPAL_ID},
                "policy_revision": policy_revision,
                "credential_epoch": credential_epoch,
                "effective_at_unix_ms": now_unix_ms,
                "expires_at_unix_ms": now_unix_ms + 86_400_000,
                "allowed_source_kinds": ["semantic_hook"],
                "allowed_environments": ["ci_runner_or_remote_workspace"],
                "allowed_operations": allowed_operations,
                "effective_trust_profile": "harness_observed",
                "allowed_capabilities": ["tool_calls", "source_health"],
                "allowed_privacy_capabilities": ["structure_only"],
                "allowed_redaction_profile_refs": ["redaction_gateway_authority_rotation"],
                "allowed_run_authorities": [
                    {"kind": "service", "id": "authority_gateway_authority_rotation"}
                ],
                "allowed_run_privacy_profile_refs": ["privacy_gateway_authority_rotation"],
                "allowed_run_retention_profile_refs": ["retention_gateway_authority_rotation"],
                "required_run_source_kinds": ["semantic_hook"],
                "may_create_runs": true,
                "may_join_runs": false,
                "may_finalize_runs": true
            }))?,
        )
    }
}

fn served_database_url(database_url: &str, role: &str, application_name: Option<&str>) -> String {
    let query_separator = if database_url.contains('?') { '&' } else { '?' };
    let application_option = application_name
        .map(|name| format!("application_name={name}&"))
        .unwrap_or_default();
    format!(
        "{database_url}{query_separator}{application_option}\
         options=-c%20role%3D{role}"
    )
}

fn now_unix_ms() -> TestResult<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn mtls_leaf_fingerprint(leaf_der: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(MTLS_FINGERPRINT_DOMAIN);
    digest.update(leaf_der);
    digest.finalize().into()
}

fn credential_id(fingerprint: &[u8; 32]) -> String {
    let mut value = String::with_capacity(5 + fingerprint.len() * 2);
    value.push_str("mtls_");
    for byte in fingerprint {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

fn authority_command<I, S>(arguments: I) -> TestResult<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Ok(Command::new(AUTHORITY_BIN).args(arguments).output()?)
}

fn register_source(
    database_url_file: &Path,
    registration: &Path,
    certificate: &Path,
) -> TestResult<Output> {
    authority_command([
        OsStr::new("register-source"),
        OsStr::new("--database-url-file"),
        database_url_file.as_os_str(),
        OsStr::new("--registration"),
        registration.as_os_str(),
        OsStr::new("--client-certificate"),
        certificate.as_os_str(),
    ])
}

fn rotate_policy(
    database_url_file: &Path,
    registration: &Path,
    current_certificate: &Path,
    reason: &str,
) -> TestResult<Output> {
    authority_command([
        OsStr::new("rotate-policy"),
        OsStr::new("--database-url-file"),
        database_url_file.as_os_str(),
        OsStr::new("--registration"),
        registration.as_os_str(),
        OsStr::new("--current-client-certificate"),
        current_certificate.as_os_str(),
        OsStr::new("--reason"),
        OsStr::new(reason),
    ])
}

fn rotate_credential(
    database_url_file: &Path,
    registration: &Path,
    current_certificate: &Path,
    replacement_certificate: &Path,
    reason: &str,
) -> TestResult<Output> {
    authority_command([
        OsStr::new("rotate-credential"),
        OsStr::new("--database-url-file"),
        database_url_file.as_os_str(),
        OsStr::new("--registration"),
        registration.as_os_str(),
        OsStr::new("--current-client-certificate"),
        current_certificate.as_os_str(),
        OsStr::new("--new-client-certificate"),
        replacement_certificate.as_os_str(),
        OsStr::new("--reason"),
        OsStr::new(reason),
    ])
}

fn revoke_credential(
    database_url_file: &Path,
    certificate: &Path,
    reason: &str,
) -> TestResult<Output> {
    authority_command([
        OsStr::new("revoke-credential"),
        OsStr::new("--database-url-file"),
        database_url_file.as_os_str(),
        OsStr::new("--client-certificate"),
        certificate.as_os_str(),
        OsStr::new("--reason"),
        OsStr::new(reason),
    ])
}

fn require_cli_success(output: Output, operation: &str) -> TestResult {
    assert_cli_output_is_content_free(&output);
    if !output.status.success() {
        return Err(format!(
            "{operation} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    if !output.stdout.is_empty() || !output.stderr.is_empty() {
        return Err(format!("{operation} produced unexpected process output").into());
    }
    Ok(())
}

fn require_cli_failure(output: Output, operation: &str) -> TestResult {
    assert_cli_output_is_content_free(&output);
    if output.status.success() {
        return Err(format!("{operation} unexpectedly succeeded").into());
    }
    Ok(())
}

fn assert_cli_output_is_content_free(output: &Output) {
    for bytes in [&output.stdout, &output.stderr] {
        let text = String::from_utf8_lossy(bytes);
        assert!(!text.contains("BEGIN CERTIFICATE"));
        assert!(!text.contains("BEGIN PRIVATE KEY"));
        assert!(!text.contains("PRIVATE KEY"));
    }
}

#[allow(clippy::too_many_arguments)]
async fn seed_rotation_effects(
    pool: &PgPool,
    now_unix_ms: i64,
    credential_id: &str,
    policy_revision: i64,
    credential_epoch: i64,
    run_id: &str,
    stream_id: &str,
    sequence: i64,
    digest_seed: u8,
) -> TestResult {
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.organization_sequences ( \
             organization_id, next_ingest_sequence, updated_at_unix_ms \
         ) VALUES ($1,$2,$3) \
         ON CONFLICT (organization_id) DO UPDATE SET \
             next_ingest_sequence=greatest( \
                 apolysis_gateway.organization_sequences.next_ingest_sequence, \
                 EXCLUDED.next_ingest_sequence \
             ), \
             updated_at_unix_ms=greatest( \
                 apolysis_gateway.organization_sequences.updated_at_unix_ms, \
                 EXCLUDED.updated_at_unix_ms \
             )",
    )
    .bind(ORGANIZATION_ID)
    .bind(sequence + 1)
    .bind(now_unix_ms)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.runs ( \
             organization_id, run_id, state, environment, authority_kind, authority_id, \
             principal_kind, principal_id, objective_ref, privacy_profile_ref, \
             retention_profile_ref, initiating_source_registration_id, \
             initiating_principal_kind, initiating_principal_id, opened_at_unix_ms, \
             state_changed_at_unix_ms \
         ) VALUES ( \
             $1,$2,'active','ci_runner_or_remote_workspace','service', \
             'authority_gateway_rotation','workload',$3,'objective_gateway_rotation', \
             'privacy_gateway_authority_rotation','retention_gateway_authority_rotation', \
             $4,'workload',$3,$5,$5 \
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(run_id)
    .bind(PRINCIPAL_ID)
    .bind(REGISTRATION_ID)
    .bind(now_unix_ms)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.record_items ( \
             organization_id, run_id, ingest_sequence, ingested_at_unix_ms, fact_kind, \
             fact_json, fact_digest, outbox_ingest_sequence \
         ) VALUES ($1,$2,$3,$4,'source_registered','{}'::jsonb,$5,$3)",
    )
    .bind(ORGANIZATION_ID)
    .bind(run_id)
    .bind(sequence)
    .bind(now_unix_ms)
    .bind(vec![digest_seed; 32])
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.projection_outbox ( \
             organization_id, ingest_sequence, available_at_unix_ms \
         ) VALUES ($1,$2,$3)",
    )
    .bind(ORGANIZATION_ID)
    .bind(sequence)
    .bind(now_unix_ms)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.source_streams ( \
             organization_id, run_id, source_registration_id, source_stream_id, source_id, \
             source_kind, environment, registration_principal_kind, \
             registration_principal_id, registration_policy_revision, \
             effective_trust_profile, manifest_digest, manifest_json, \
             registered_ingest_sequence, registered_at_unix_ms \
         ) VALUES ( \
             $1,$2,$3,$4,$5,'semantic_hook','ci_runner_or_remote_workspace', \
             'workload',$6,$7,'harness_observed',$8,'{}'::jsonb,$9,$10 \
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(run_id)
    .bind(REGISTRATION_ID)
    .bind(stream_id)
    .bind(SOURCE_ID)
    .bind(PRINCIPAL_ID)
    .bind(policy_revision)
    .bind(vec![digest_seed.wrapping_add(1); 32])
    .bind(sequence)
    .bind(now_unix_ms)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.leases ( \
             organization_id, lease_digest, run_id, source_registration_id, \
             source_stream_id, source_id, principal_kind, principal_id, \
             credential_id, credential_epoch, registration_policy_revision, \
             issued_at_unix_ms, expires_at_unix_ms \
         ) VALUES ($1,$2,$3,$4,$5,$6,'workload',$7,$8,$9,$10,$11,$12)",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![digest_seed.wrapping_add(2); 32])
    .bind(run_id)
    .bind(REGISTRATION_ID)
    .bind(stream_id)
    .bind(SOURCE_ID)
    .bind(PRINCIPAL_ID)
    .bind(credential_id)
    .bind(credential_epoch)
    .bind(policy_revision)
    .bind(now_unix_ms)
    .bind(now_unix_ms + 600_000)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "INSERT INTO apolysis_gateway.join_authorizations ( \
             organization_id, proof_digest, authorization_kind, run_id, source_id, \
             source_kind, environment, source_registration_id, principal_kind, \
             principal_id, credential_id, credential_epoch, registration_policy_revision, \
             issued_by_source_registration_id, issued_by_principal_kind, \
             issued_by_principal_id, issued_by_credential_id, \
             issued_by_credential_epoch, issued_by_registration_policy_revision, \
             issued_at_unix_ms, expires_at_unix_ms \
         ) VALUES ( \
             $1,$2,'grant',$3,$4,'semantic_hook','ci_runner_or_remote_workspace', \
             $5,'workload',$6,$7,$8,$9,$5,'workload',$6,$7,$8,$9,$10,$11 \
         )",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![digest_seed.wrapping_add(3); 32])
    .bind(run_id)
    .bind(SOURCE_ID)
    .bind(REGISTRATION_ID)
    .bind(PRINCIPAL_ID)
    .bind(credential_id)
    .bind(credential_epoch)
    .bind(policy_revision)
    .bind(now_unix_ms)
    .bind(now_unix_ms + 600_000)
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn current_effect_count(pool: &PgPool, digest_seed: u8) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT \
             (SELECT count(*) FROM apolysis_gateway.leases \
              WHERE organization_id=$1 AND lease_digest=$2 \
                AND revoked_at_unix_ms IS NULL) \
           + (SELECT count(*) FROM apolysis_gateway.join_authorizations \
              WHERE organization_id=$1 AND proof_digest=$3 \
                AND authorization_state='pending')",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![digest_seed.wrapping_add(2); 32])
    .bind(vec![digest_seed.wrapping_add(3); 32])
    .fetch_one(pool)
    .await?)
}

async fn revoked_effect_count(pool: &PgPool, digest_seed: u8) -> TestResult<i64> {
    Ok(sqlx::query_scalar(
        "SELECT \
             (SELECT count(*) FROM apolysis_gateway.leases \
              WHERE organization_id=$1 AND lease_digest=$2 \
                AND revoked_at_unix_ms IS NOT NULL) \
           + (SELECT count(*) FROM apolysis_gateway.join_authorizations \
              WHERE organization_id=$1 AND proof_digest=$3 \
                AND authorization_state='revoked' \
                AND consumed_at_unix_ms IS NULL \
                AND revoked_at_unix_ms IS NOT NULL)",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![digest_seed.wrapping_add(2); 32])
    .bind(vec![digest_seed.wrapping_add(3); 32])
    .fetch_one(pool)
    .await?)
}

async fn install_audit_failure(pool: &PgPool, action: &str, reason: &str) -> TestResult {
    let function_sql = format!(
        "CREATE OR REPLACE FUNCTION apolysis_gateway.fail_test_authority_rotation_audit() \
         RETURNS trigger LANGUAGE plpgsql AS $function$ \
         BEGIN \
             IF NEW.action='{action}' AND NEW.reason_code='{reason}' THEN \
                 RAISE EXCEPTION 'forced test rollback' USING ERRCODE='23514'; \
             END IF; \
             RETURN NEW; \
         END; \
         $function$; \
         DROP TRIGGER IF EXISTS fail_test_authority_rotation_audit \
             ON apolysis_gateway.authority_change_audit; \
         CREATE TRIGGER fail_test_authority_rotation_audit \
         BEFORE INSERT ON apolysis_gateway.authority_change_audit \
         FOR EACH ROW EXECUTE FUNCTION \
             apolysis_gateway.fail_test_authority_rotation_audit();"
    );
    sqlx::raw_sql(&function_sql).execute(pool).await?;
    Ok(())
}

async fn remove_audit_failure(pool: &PgPool) -> TestResult {
    sqlx::raw_sql(
        "DROP TRIGGER fail_test_authority_rotation_audit \
             ON apolysis_gateway.authority_change_audit; \
         DROP FUNCTION apolysis_gateway.fail_test_authority_rotation_audit();",
    )
    .execute(pool)
    .await?;
    Ok(())
}

async fn wait_until_control_write_is_blocked_by(
    pool: &PgPool,
    blocking_pid: i32,
) -> TestResult<i32> {
    timeout(Duration::from_secs(10), async {
        loop {
            let blocked_pid = sqlx::query_scalar::<_, i32>(
                "SELECT activity.pid \
                 FROM pg_catalog.pg_stat_activity AS activity \
                 WHERE activity.datname=current_database() \
                   AND activity.application_name=$1 \
                   AND activity.state='active' \
                   AND activity.wait_event_type='Lock' \
                   AND $2=ANY(pg_catalog.pg_blocking_pids(activity.pid)) \
                   AND activity.query LIKE '%apolysis_gateway.organizations%'",
            )
            .bind(APPLICATION_NAME)
            .bind(blocking_pid)
            .fetch_optional(pool)
            .await?;
            if let Some(pid) = blocked_pid {
                return Ok::<i32, sqlx::Error>(pid);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "authority write did not block on the organization row within the bound")?
    .map_err(Into::into)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL, OpenSSL, and explicit database reset opt-in"]
async fn rotation_cli_enforces_monotonic_atomic_cutovers() -> TestResult {
    let fixture = RealFixture::create(None).await?;
    let initial = fixture.certificate("initial-client")?;
    let replacement = fixture.certificate("replacement-client")?;
    let combined = fixture.certificate("combined-client")?;
    let now = now_unix_ms()?;
    let default_operations = ["bind_runtime", "ingest", "finish_run"];
    let revision_1 = fixture.registration("revision-1.json", now, 1, 1, &default_operations)?;

    require_cli_success(
        register_source(
            &fixture.control_database_url_file,
            &revision_1,
            &initial.certificate_path,
        )?,
        "initial register-source",
    )?;
    require_cli_success(
        register_source(
            &fixture.control_database_url_file,
            &revision_1,
            &initial.certificate_path,
        )?,
        "idempotent register-source",
    )?;
    let forbidden_policy_register = fixture.registration(
        "forbidden-register-policy.json",
        now,
        2,
        1,
        &default_operations,
    )?;
    require_cli_failure(
        register_source(
            &fixture.control_database_url_file,
            &forbidden_policy_register,
            &initial.certificate_path,
        )?,
        "register-source policy bypass",
    )?;
    let forbidden_credential_register = fixture.registration(
        "forbidden-register-credential.json",
        now,
        2,
        2,
        &default_operations,
    )?;
    require_cli_failure(
        register_source(
            &fixture.control_database_url_file,
            &forbidden_credential_register,
            &replacement.certificate_path,
        )?,
        "register-source credential bypass",
    )?;
    let registered = fixture
        .runtime_store
        .resolve_mtls(&initial.leaf_der, "ingest", now + 1)
        .await?;
    assert_eq!(registered.authentication().policy_revision(), 1);
    assert_eq!(registered.authentication().credential_epoch(), 1);

    seed_rotation_effects(
        &fixture.admin_pool,
        i64::try_from(now)?,
        &initial.credential_id,
        1,
        1,
        "run_policy_rotation",
        "stream_policy_rotation",
        1,
        0x20,
    )
    .await?;
    let revision_2 = fixture.registration("revision-2.json", now, 2, 1, &default_operations)?;
    install_audit_failure(
        &fixture.admin_pool,
        "rotate_policy",
        "force_policy_rollback",
    )
    .await?;
    require_cli_failure(
        rotate_policy(
            &fixture.control_database_url_file,
            &revision_2,
            &initial.certificate_path,
            "force_policy_rollback",
        )?,
        "forced policy rollback",
    )?;
    let policy_rollback = fixture
        .runtime_store
        .resolve_mtls(&initial.leaf_der, "ingest", now + 2)
        .await?;
    assert_eq!(policy_rollback.authentication().policy_revision(), 1);
    assert_eq!(current_effect_count(&fixture.admin_pool, 0x20).await?, 2);
    let rolled_back_policy_history: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.source_authority_revisions \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND registration_policy_revision=2",
    )
    .bind(ORGANIZATION_ID)
    .bind(REGISTRATION_ID)
    .fetch_one(&fixture.admin_pool)
    .await?;
    assert_eq!(rolled_back_policy_history, 0);
    remove_audit_failure(&fixture.admin_pool).await?;

    require_cli_success(
        rotate_policy(
            &fixture.control_database_url_file,
            &revision_2,
            &initial.certificate_path,
            "successful_policy_rotation",
        )?,
        "policy rotation",
    )?;
    let policy_current = fixture
        .runtime_store
        .resolve_mtls(&initial.leaf_der, "ingest", now + 3)
        .await?;
    assert_eq!(policy_current.authentication().policy_revision(), 2);
    assert_eq!(policy_current.authentication().credential_epoch(), 1);
    assert_eq!(revoked_effect_count(&fixture.admin_pool, 0x20).await?, 2);

    seed_rotation_effects(
        &fixture.admin_pool,
        i64::try_from(now + 1)?,
        &initial.credential_id,
        2,
        1,
        "run_credential_rotation",
        "stream_credential_rotation",
        2,
        0x30,
    )
    .await?;
    let credential_revision_2 =
        fixture.registration("credential-revision-2.json", now, 2, 2, &default_operations)?;
    install_audit_failure(
        &fixture.admin_pool,
        "rotate_credential",
        "force_credential_rollback",
    )
    .await?;
    require_cli_failure(
        rotate_credential(
            &fixture.control_database_url_file,
            &credential_revision_2,
            &initial.certificate_path,
            &replacement.certificate_path,
            "force_credential_rollback",
        )?,
        "forced credential rollback",
    )?;
    let credential_rollback = fixture
        .runtime_store
        .resolve_mtls(&initial.leaf_der, "ingest", now + 4)
        .await?;
    assert_eq!(credential_rollback.authentication().policy_revision(), 2);
    assert_eq!(credential_rollback.authentication().credential_epoch(), 1);
    fixture
        .runtime_store
        .resolve_mtls(&replacement.leaf_der, "ingest", now + 4)
        .await
        .expect_err("rolled-back replacement credential must remain unknown");
    assert_eq!(current_effect_count(&fixture.admin_pool, 0x30).await?, 2);
    let rolled_back_credential_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.transport_credentials \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND credential_epoch=2",
    )
    .bind(ORGANIZATION_ID)
    .bind(REGISTRATION_ID)
    .fetch_one(&fixture.admin_pool)
    .await?;
    assert_eq!(rolled_back_credential_count, 0);
    remove_audit_failure(&fixture.admin_pool).await?;

    require_cli_success(
        rotate_credential(
            &fixture.control_database_url_file,
            &credential_revision_2,
            &initial.certificate_path,
            &replacement.certificate_path,
            "successful_credential_rotation",
        )?,
        "credential rotation",
    )?;
    fixture
        .runtime_store
        .resolve_mtls(&initial.leaf_der, "ingest", now + 5)
        .await
        .expect_err("replaced credential must stop authenticating");
    let credential_current = fixture
        .runtime_store
        .resolve_mtls(&replacement.leaf_der, "ingest", now + 5)
        .await?;
    assert_eq!(credential_current.authentication().policy_revision(), 2);
    assert_eq!(credential_current.authentication().credential_epoch(), 2);
    assert_eq!(revoked_effect_count(&fixture.admin_pool, 0x30).await?, 2);

    let skipped_epoch =
        fixture.registration("skipped-epoch.json", now, 2, 4, &default_operations)?;
    require_cli_failure(
        rotate_credential(
            &fixture.control_database_url_file,
            &skipped_epoch,
            &replacement.certificate_path,
            &combined.certificate_path,
            "skipped_credential_epoch",
        )?,
        "skipped credential epoch",
    )?;
    let unversioned_policy =
        fixture.registration("unversioned-policy.json", now, 2, 3, &["ingest"])?;
    require_cli_failure(
        rotate_credential(
            &fixture.control_database_url_file,
            &unversioned_policy,
            &replacement.certificate_path,
            &combined.certificate_path,
            "unversioned_policy_change",
        )?,
        "unversioned policy change",
    )?;
    let combined_revision =
        fixture.registration("combined-revision.json", now, 3, 3, &["ingest"])?;
    require_cli_success(
        rotate_credential(
            &fixture.control_database_url_file,
            &combined_revision,
            &replacement.certificate_path,
            &combined.certificate_path,
            "successful_combined_rotation",
        )?,
        "combined rotation",
    )?;
    fixture
        .runtime_store
        .resolve_mtls(&replacement.leaf_der, "ingest", now + 6)
        .await
        .expect_err("second replaced credential must stop authenticating");
    let combined_current = fixture
        .runtime_store
        .resolve_mtls(&combined.leaf_der, "ingest", now + 6)
        .await?;
    assert_eq!(combined_current.authentication().policy_revision(), 3);
    assert_eq!(combined_current.authentication().credential_epoch(), 3);

    let current_credential_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.transport_credentials \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND revoked_at_unix_ms IS NULL",
    )
    .bind(ORGANIZATION_ID)
    .bind(REGISTRATION_ID)
    .fetch_one(&fixture.admin_pool)
    .await?;
    assert_eq!(current_credential_count, 1);
    let authority_history_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.source_authority_revisions \
         WHERE organization_id=$1 AND source_registration_id=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(REGISTRATION_ID)
    .fetch_one(&fixture.admin_pool)
    .await?;
    assert_eq!(authority_history_count, 4);
    let forced_audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.authority_change_audit \
         WHERE reason_code IN ('force_policy_rollback','force_credential_rollback')",
    )
    .fetch_one(&fixture.admin_pool)
    .await?;
    assert_eq!(forced_audit_count, 0);
    let successful_rotation_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM apolysis_gateway.authority_change_audit \
         WHERE action IN ('rotate_policy','rotate_credential')",
    )
    .fetch_one(&fixture.admin_pool)
    .await?;
    assert_eq!(successful_rotation_count, 3);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL, OpenSSL, and explicit database reset opt-in"]
async fn direct_revoke_invalidates_only_the_revoked_current_epoch() -> TestResult {
    let fixture = RealFixture::create(None).await?;
    let initial = fixture.certificate("revoke-initial-client")?;
    let replacement = fixture.certificate("revoke-replacement-client")?;
    let now = now_unix_ms()?;
    let operations = ["bind_runtime", "ingest", "finish_run"];
    let revision_1 = fixture.registration("revoke-revision-1.json", now, 1, 1, &operations)?;
    require_cli_success(
        register_source(
            &fixture.control_database_url_file,
            &revision_1,
            &initial.certificate_path,
        )?,
        "revoke register-source",
    )?;
    let revision_2 = fixture.registration("revoke-revision-2.json", now, 1, 2, &operations)?;
    require_cli_success(
        rotate_credential(
            &fixture.control_database_url_file,
            &revision_2,
            &initial.certificate_path,
            &replacement.certificate_path,
            "prepare_direct_revoke",
        )?,
        "prepare direct revoke rotation",
    )?;
    seed_rotation_effects(
        &fixture.admin_pool,
        i64::try_from(now + 1)?,
        &replacement.credential_id,
        1,
        2,
        "run_direct_revoke",
        "stream_direct_revoke",
        1,
        0x40,
    )
    .await?;

    require_cli_success(
        revoke_credential(
            &fixture.control_database_url_file,
            &initial.certificate_path,
            "repeat_old_credential_revoke",
        )?,
        "repeat old credential revoke",
    )?;
    assert_eq!(
        current_effect_count(&fixture.admin_pool, 0x40).await?,
        2,
        "re-revoking an old epoch must not invalidate current capabilities"
    );
    fixture
        .runtime_store
        .resolve_mtls(&replacement.leaf_der, "ingest", now + 2)
        .await
        .expect("the replacement credential remains current");

    require_cli_success(
        revoke_credential(
            &fixture.control_database_url_file,
            &replacement.certificate_path,
            "revoke_current_credential",
        )?,
        "direct current credential revoke",
    )?;
    assert_eq!(
        revoked_effect_count(&fixture.admin_pool, 0x40).await?,
        2,
        "direct current revocation must invalidate its lease and pending join authorization"
    );
    fixture
        .runtime_store
        .resolve_mtls(&replacement.leaf_der, "ingest", now + 3)
        .await
        .expect_err("directly revoked current credential must stop authenticating");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL, OpenSSL, and explicit database reset opt-in"]
async fn served_roles_cannot_rewrite_or_resurrect_authority_capabilities() -> TestResult {
    let fixture = RealFixture::create(None).await?;
    let certificate = fixture.certificate("capability-transition-client")?;
    let now = now_unix_ms()?;
    let registration = fixture.registration(
        "capability-transition-registration.json",
        now,
        1,
        1,
        &["bind_runtime", "ingest", "finish_run"],
    )?;
    require_cli_success(
        register_source(
            &fixture.control_database_url_file,
            &registration,
            &certificate.certificate_path,
        )?,
        "capability-transition register-source",
    )?;
    seed_rotation_effects(
        &fixture.admin_pool,
        i64::try_from(now)?,
        &certificate.credential_id,
        1,
        1,
        "run_capability_transition",
        "stream_capability_transition",
        1,
        0x50,
    )
    .await?;

    let mut scope_rewrite = fixture.admin_pool.begin().await?;
    sqlx::query("SET LOCAL ROLE apolysis_gateway_runtime")
        .execute(&mut *scope_rewrite)
        .await?;
    let scope_error = sqlx::query(
        "UPDATE apolysis_gateway.join_authorizations \
         SET expires_at_unix_ms=$3 \
         WHERE organization_id=$1 AND proof_digest=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![0x53_u8; 32])
    .bind(i64::try_from(now)? + 600_001)
    .execute(&mut *scope_rewrite)
    .await
    .expect_err("the runtime role must not rewrite join-authorization scope");
    assert_eq!(
        scope_error
            .as_database_error()
            .and_then(|error| error.code()),
        Some(std::borrow::Cow::Borrowed("42501")),
        "unexpected scope-rewrite error: {scope_error}"
    );
    scope_rewrite.rollback().await?;

    let mut consume = fixture.admin_pool.begin().await?;
    sqlx::query("SET LOCAL ROLE apolysis_gateway_runtime")
        .execute(&mut *consume)
        .await?;
    let consumed = sqlx::query(
        "UPDATE apolysis_gateway.join_authorizations \
         SET authorization_state='consumed', consumed_at_unix_ms=issued_at_unix_ms \
         WHERE organization_id=$1 AND proof_digest=$2 \
           AND authorization_state='pending'",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![0x53_u8; 32])
    .execute(&mut *consume)
    .await?;
    assert_eq!(consumed.rows_affected(), 1);
    consume.commit().await?;

    let mut resurrect_grant = fixture.admin_pool.begin().await?;
    sqlx::query("SET LOCAL ROLE apolysis_gateway_runtime")
        .execute(&mut *resurrect_grant)
        .await?;
    let resurrection_error = sqlx::query(
        "UPDATE apolysis_gateway.join_authorizations \
         SET authorization_state='pending', consumed_at_unix_ms=NULL \
         WHERE organization_id=$1 AND proof_digest=$2",
    )
    .bind(ORGANIZATION_ID)
    .bind(vec![0x53_u8; 32])
    .execute(&mut *resurrect_grant)
    .await
    .expect_err("a consumed join grant must remain terminal");
    assert_eq!(
        resurrection_error
            .as_database_error()
            .and_then(|error| error.code()),
        Some(std::borrow::Cow::Borrowed("23514"))
    );
    resurrect_grant.rollback().await?;

    let mut revoke_lease = fixture.admin_pool.begin().await?;
    sqlx::query("SET LOCAL ROLE apolysis_gateway_control")
        .execute(&mut *revoke_lease)
        .await?;
    let revoked = sqlx::query(
        "UPDATE apolysis_gateway.leases \
         SET revoked_at_unix_ms=issued_at_unix_ms \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND credential_id=$3 AND credential_epoch=1 \
           AND revoked_at_unix_ms IS NULL",
    )
    .bind(ORGANIZATION_ID)
    .bind(REGISTRATION_ID)
    .bind(&certificate.credential_id)
    .execute(&mut *revoke_lease)
    .await?;
    assert_eq!(revoked.rows_affected(), 1);
    revoke_lease.commit().await?;

    let mut resurrect_lease = fixture.admin_pool.begin().await?;
    sqlx::query("SET LOCAL ROLE apolysis_gateway_control")
        .execute(&mut *resurrect_lease)
        .await?;
    let lease_error = sqlx::query(
        "UPDATE apolysis_gateway.leases \
         SET revoked_at_unix_ms=NULL \
         WHERE organization_id=$1 AND source_registration_id=$2 \
           AND credential_id=$3 AND credential_epoch=1",
    )
    .bind(ORGANIZATION_ID)
    .bind(REGISTRATION_ID)
    .bind(&certificate.credential_id)
    .execute(&mut *resurrect_lease)
    .await
    .expect_err("a revoked lease must remain revoked");
    assert_eq!(
        lease_error
            .as_database_error()
            .and_then(|error| error.code()),
        Some(std::borrow::Cow::Borrowed("23514"))
    );
    resurrect_lease.rollback().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires APOLYSIS_TEST_DATABASE_URL, OpenSSL, and explicit database reset opt-in"]
async fn rotation_cli_obeys_organization_registration_credential_lock_order() -> TestResult {
    let fixture = RealFixture::create(Some(APPLICATION_NAME)).await?;
    let initial = fixture.certificate("lock-order-client")?;
    let now = now_unix_ms()?;
    let revision_1 = fixture.registration(
        "lock-order-revision-1.json",
        now,
        1,
        1,
        &["bind_runtime", "ingest", "finish_run"],
    )?;
    require_cli_success(
        register_source(
            &fixture.control_database_url_file,
            &revision_1,
            &initial.certificate_path,
        )?,
        "lock-order register-source",
    )?;

    let mut evidence_transaction = fixture.admin_pool.begin().await?;
    sqlx::query("SET LOCAL deadlock_timeout='100ms'")
        .execute(&mut *evidence_transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout='5s'")
        .execute(&mut *evidence_transaction)
        .await?;
    let evidence_pid: i32 = sqlx::query_scalar("SELECT pg_catalog.pg_backend_pid()")
        .fetch_one(&mut *evidence_transaction)
        .await?;
    sqlx::query(
        "SELECT organization_id \
         FROM apolysis_gateway.organizations \
         WHERE organization_id=$1 \
         FOR SHARE",
    )
    .bind(ORGANIZATION_ID)
    .fetch_one(&mut *evidence_transaction)
    .await?;

    let revision_2 = fixture.registration(
        "lock-order-revision-2.json",
        now,
        2,
        1,
        &["bind_runtime", "ingest", "finish_run"],
    )?;
    let control_url_file = fixture.control_database_url_file.clone();
    let current_certificate = initial.certificate_path.clone();
    let rotating = std::thread::spawn(move || {
        rotate_policy(
            &control_url_file,
            &revision_2,
            &current_certificate,
            "lock_order_rotation",
        )
    });
    let rotation_pid =
        wait_until_control_write_is_blocked_by(&fixture.admin_pool, evidence_pid).await?;
    if rotation_pid == evidence_pid {
        return Err("rotate-policy lock observation returned the blocking backend".into());
    }
    sqlx::query(
        "SELECT source_registration_id \
         FROM apolysis_gateway.source_registrations \
         WHERE source_registration_id=$1 \
         FOR SHARE",
    )
    .bind(REGISTRATION_ID)
    .fetch_one(&mut *evidence_transaction)
    .await?;
    sqlx::query(
        "SELECT credential_id \
         FROM apolysis_gateway.transport_credentials \
         WHERE source_registration_id=$1 \
         ORDER BY credential_id \
         FOR SHARE",
    )
    .bind(REGISTRATION_ID)
    .fetch_all(&mut *evidence_transaction)
    .await?;
    evidence_transaction.commit().await?;

    let rotation_output = rotating
        .join()
        .map_err(|_| "rotate-policy CLI thread did not complete")??;
    require_cli_success(rotation_output, "lock-order policy rotation")?;
    let current = fixture
        .runtime_store
        .resolve_mtls(&initial.leaf_der, "ingest", now + 1)
        .await?;
    assert_eq!(current.authentication().policy_revision(), 2);
    assert_eq!(current.authentication().credential_epoch(), 1);
    Ok(())
}
