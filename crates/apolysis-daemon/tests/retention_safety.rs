// SPDX-License-Identifier: Apache-2.0

use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apolysis_accountability::{
    ActionClass, RetentionTier, SessionIntent, SessionStatus, DEFAULT_TENANT_ID,
};
use apolysis_core::CollectorLifecycleRecord;
use apolysis_daemon::{DaemonConfig, DaemonState};
use serde_json::json;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

const REGISTERED_AT_UNIX_MS: u64 = 1_700_000_000_000;
const EXPIRES_AT_UNIX_MS: u64 = REGISTERED_AT_UNIX_MS + 1_000;
const AGENT_RUN_ID: &str = "retention-safety-agent-run";
const LEGACY_AGENT_RUN_STORAGE_DIR: &str = "sessions";

#[tokio::test]
async fn active_agent_run_is_never_retention_eligible_after_its_lease_expires() {
    let config = config("active-agent-run");
    let state = DaemonState::new(&config).expect("create daemon state");
    let agent_run_id = AGENT_RUN_ID;
    state
        .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
        .await
        .expect("register active Agent Run");
    let timeline = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(agent_run_id)
        .join("timeline.jsonl");

    let report = state
        .apply_retention()
        .await
        .expect("retention must leave an active Agent Run untouched");

    assert!(report.eligible_session_ids.is_empty());
    assert!(report.purged_session_ids.is_empty());
    assert!(state.query(agent_run_id).await.is_some());
    assert!(timeline.is_file());

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn durable_closed_agent_run_remains_retention_eligible_after_restart() {
    let config = config("closed-agent-run-restart");
    let agent_run_id = AGENT_RUN_ID;
    {
        let state = DaemonState::new(&config).expect("create daemon state");
        state
            .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
            .await
            .expect("register Agent Run");
        state
            .close(agent_run_id)
            .await
            .expect("durably close Agent Run");
    }

    let restarted = DaemonState::new(&config).expect("restart daemon state");
    let recovered = restarted
        .query(agent_run_id)
        .await
        .expect("durably closed Agent Run must remain in the retention catalog");
    assert_eq!(recovered.status, SessionStatus::Closed);
    assert!(restarted.tracked_cgroups().await.is_empty());

    let report = restarted
        .apply_retention()
        .await
        .expect("purge recovered closed Agent Run");

    assert_eq!(report.eligible_session_ids, vec![agent_run_id]);
    assert_eq!(report.purged_session_ids, vec![agent_run_id]);
    assert!(!config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(agent_run_id)
        .exists());

    drop(restarted);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn startup_refuses_a_closed_agent_run_stored_under_a_different_identity() {
    let config = config("closed-agent-run-identity-mismatch");
    create_closed_agent_run(&config);
    let legacy_agent_runs_dir = config.state_dir.join(LEGACY_AGENT_RUN_STORAGE_DIR);
    let mismatched_agent_run = legacy_agent_runs_dir.join("different-agent-run");
    std::fs::rename(
        legacy_agent_runs_dir.join(AGENT_RUN_ID),
        &mismatched_agent_run,
    )
    .expect("rename durable Agent Run to a mismatched storage identity");

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("startup must reject a durable Agent Run stored under another identity"),
        Err(error) => error,
    };

    assert!(
        error.contains("durable Agent Run identity mismatch"),
        "{error}"
    );
    assert!(
        mismatched_agent_run.join("timeline.jsonl").is_file(),
        "identity rejection must preserve the durable Agent Run"
    );

    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn closed_retention_catalog_does_not_consume_active_capacity_after_restart() {
    let config = config("closed-catalog-capacity");
    let closed_agent_run_ids = [
        "closed-agent-run-a",
        "closed-agent-run-b",
        "closed-agent-run-c",
    ];
    {
        let state = DaemonState::new(&config).expect("create daemon state");
        for agent_run_id in closed_agent_run_ids {
            state
                .register(
                    agent_run_intent_for(agent_run_id, EXPIRES_AT_UNIX_MS),
                    REGISTERED_AT_UNIX_MS,
                )
                .await
                .expect("register Agent Run for retention catalog");
            state
                .close(agent_run_id)
                .await
                .expect("durably close Agent Run for retention catalog");
        }
    }

    let mut limited_config = config.clone();
    limited_config.max_sessions = 1;
    let restarted = DaemonState::new(&limited_config)
        .expect("closed retention catalog must not block restart at lower active capacity");
    for agent_run_id in closed_agent_run_ids {
        assert_eq!(
            restarted
                .query(agent_run_id)
                .await
                .expect("closed Agent Run remains queryable")
                .status,
            SessionStatus::Closed
        );
    }
    restarted
        .register(
            agent_run_intent_for("active-agent-run-a", 4_102_444_800_000),
            REGISTERED_AT_UNIX_MS,
        )
        .await
        .expect("closed retention catalog must not consume active capacity");
    let error = restarted
        .register(
            agent_run_intent_for("active-agent-run-b", 4_102_444_800_000),
            REGISTERED_AT_UNIX_MS,
        )
        .await
        .expect_err("active capacity must remain bounded");
    assert_eq!(error, "session capacity reached: 1");

    let report = restarted
        .apply_retention()
        .await
        .expect("purge durable closed retention catalog");
    assert_eq!(
        report.purged_session_ids,
        closed_agent_run_ids.map(str::to_string).to_vec()
    );
    assert!(restarted.query("active-agent-run-a").await.is_some());

    drop(restarted);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn retention_refuses_linked_timeline_without_touching_external_data() {
    let config = config("linked-timeline");
    let state = DaemonState::new(&config).expect("create daemon state");
    state
        .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
        .await
        .expect("register test Agent Run");
    state
        .close(AGENT_RUN_ID)
        .await
        .expect("close test Agent Run");

    let timeline = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(AGENT_RUN_ID)
        .join("timeline.jsonl");
    let external = config.state_dir.join("external-sentinel.jsonl");
    std::fs::write(&external, b"must remain unchanged\n").expect("write external sentinel");
    std::fs::remove_file(&timeline).expect("remove managed timeline");
    symlink(&external, &timeline).expect("replace timeline with symlink");

    let error = state
        .apply_retention()
        .await
        .expect_err("unsafe linked timeline must block retention");

    assert_eq!(error.code(), "retention_target_unsafe");
    assert_eq!(
        std::fs::read(&external).expect("read external sentinel"),
        b"must remain unchanged\n"
    );
    assert!(
        state.query(AGENT_RUN_ID).await.is_some(),
        "failed retention must leave the registry unchanged"
    );
    assert!(
        std::fs::symlink_metadata(&timeline)
            .expect("linked timeline remains")
            .file_type()
            .is_symlink(),
        "failed retention must not remove the unsafe target"
    );

    drop(state);
    std::fs::remove_file(&timeline).expect("remove test symlink");
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn retention_staging_failure_keeps_registry_and_agent_run_state() {
    let config = config("blocked-trash");
    let state = DaemonState::new(&config).expect("create daemon state");
    state
        .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
        .await
        .expect("register test Agent Run");
    state
        .close(AGENT_RUN_ID)
        .await
        .expect("close test Agent Run");

    let timeline = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(AGENT_RUN_ID)
        .join("timeline.jsonl");
    std::fs::remove_dir(config.state_dir.join(".retention-trash"))
        .expect("remove empty retention staging root");
    std::fs::write(
        config.state_dir.join(".retention-trash"),
        b"not a directory\n",
    )
    .expect("block retention staging root");

    let error = state
        .apply_retention()
        .await
        .expect_err("unsafe staging root must block retention");

    assert_eq!(error.code(), "retention_trash_unsafe");
    assert!(timeline.is_file(), "failed staging must preserve timeline");
    assert!(
        state.query(AGENT_RUN_ID).await.is_some(),
        "failed staging must leave the registry unchanged"
    );

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn retention_refuses_unknown_and_non_directory_agent_run_targets_before_mutation() {
    let config = config("unknown-content");
    let state = DaemonState::new(&config).expect("create daemon state");
    state
        .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
        .await
        .expect("register test Agent Run");
    state
        .close(AGENT_RUN_ID)
        .await
        .expect("close test Agent Run");

    let agent_run_dir = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(AGENT_RUN_ID);
    let unknown = agent_run_dir.join("operator-owned.txt");
    std::fs::write(&unknown, b"must not be removed\n").expect("write unknown Agent Run content");

    let error = state
        .apply_retention()
        .await
        .expect_err("unknown content must block retention");

    assert_eq!(error.code(), "retention_target_unsafe");
    assert_eq!(
        std::fs::read(&unknown).expect("read unknown content"),
        b"must not be removed\n"
    );
    assert!(state.query(AGENT_RUN_ID).await.is_some());

    std::fs::remove_file(&unknown).expect("remove unknown test content");
    let original_agent_run_dir = config.state_dir.join("original-agent-run-state");
    std::fs::rename(&agent_run_dir, &original_agent_run_dir).expect("move managed Agent Run aside");
    std::fs::write(&agent_run_dir, b"not a directory\n")
        .expect("replace Agent Run with regular file");

    let error = state
        .apply_retention()
        .await
        .expect_err("non-directory Agent Run target must block retention");
    assert_eq!(error.code(), "retention_target_unsafe");
    assert_eq!(
        std::fs::read(&agent_run_dir).expect("read non-directory Agent Run target"),
        b"not a directory\n"
    );
    assert!(state.query(AGENT_RUN_ID).await.is_some());

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn retention_refuses_a_valid_looking_replacement_agent_run_directory() {
    let config = config("replacement-directory");
    let state = DaemonState::new(&config).expect("create daemon state");
    state
        .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
        .await
        .expect("register test Agent Run");
    state
        .close(AGENT_RUN_ID)
        .await
        .expect("close test Agent Run");

    let agent_run_dir = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(AGENT_RUN_ID);
    let original_agent_run_dir = config.state_dir.join("original-agent-run-state");
    std::fs::rename(&agent_run_dir, &original_agent_run_dir).expect("move managed Agent Run aside");
    std::fs::create_dir(&agent_run_dir).expect("create replacement Agent Run directory");
    let replacement = agent_run_dir.join("timeline.jsonl");
    std::fs::write(&replacement, b"operator-owned replacement\n")
        .expect("write replacement timeline");

    let error = state
        .apply_retention()
        .await
        .expect_err("replacement directory must not inherit managed ownership");

    assert_eq!(error.code(), "retention_target_unsafe");
    assert_eq!(
        std::fs::read(&replacement).expect("read replacement timeline"),
        b"operator-owned replacement\n"
    );
    assert!(original_agent_run_dir.join("timeline.jsonl").is_file());
    assert!(state.query(AGENT_RUN_ID).await.is_some());

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn retention_purges_only_the_default_context_qualified_agent_run() {
    let config = config("qualified-purge");
    let state = DaemonState::new(&config).expect("create daemon state");
    state
        .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
        .await
        .expect("register test Agent Run");
    state
        .close(AGENT_RUN_ID)
        .await
        .expect("close test Agent Run");
    let mut unsupported_context = agent_run_intent();
    unsupported_context.tenant_id = "tenant-b".to_string();
    unsupported_context.session_id = "non-default-agent-run".to_string();
    state
        .register(unsupported_context, REGISTERED_AT_UNIX_MS)
        .await
        .expect("register Agent Run in unsupported context");
    state
        .close("non-default-agent-run")
        .await
        .expect("close Agent Run in unsupported context");

    let agent_run_dir = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(AGENT_RUN_ID);
    let unsupported_context_timeline = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join("non-default-agent-run/timeline.jsonl");
    let unrelated = config.state_dir.join("operator-owned.txt");
    std::fs::write(&unrelated, b"must remain unchanged\n").expect("write unrelated sentinel");
    let report = state
        .apply_retention()
        .await
        .expect("purge qualified default-context Agent Run");

    assert_eq!(report.eligible_session_ids, vec![AGENT_RUN_ID]);
    assert_eq!(report.purged_session_ids, vec![AGENT_RUN_ID]);
    assert!(state.query(AGENT_RUN_ID).await.is_none());
    assert!(!agent_run_dir.exists());
    assert!(state.query("non-default-agent-run").await.is_some());
    assert!(
        unsupported_context_timeline.is_file(),
        "default-context retention must preserve unsupported context state"
    );
    assert_eq!(
        std::fs::read(&unrelated).expect("read unrelated sentinel"),
        b"must remain unchanged\n"
    );
    let trash_entries = std::fs::read_dir(config.state_dir.join(".retention-trash"))
        .expect("read retention trash")
        .count();
    assert_eq!(trash_entries, 0, "completed purge must clean staging state");

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn retention_accepts_the_current_private_quarantine_name() {
    let config = config("current-quarantine-name");
    let state = DaemonState::new(&config).expect("create daemon state");
    state
        .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
        .await
        .expect("register test Agent Run");
    state
        .close(AGENT_RUN_ID)
        .await
        .expect("close test Agent Run");

    let agent_run_dir = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(AGENT_RUN_ID);
    let quarantine = agent_run_dir.join("timeline.jsonl.quarantine-1700000000000-4242-1");
    std::fs::write(&quarantine, b"quarantined invalid tail\n")
        .expect("write private quarantine fixture");

    let report = state
        .apply_retention()
        .await
        .expect("purge a recovered Agent Run with its managed quarantine");

    assert_eq!(report.purged_session_ids, vec![AGENT_RUN_ID]);
    assert!(!agent_run_dir.exists());

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[tokio::test]
async fn purged_agent_run_rejects_late_evidence_without_recreating_storage() {
    let config = config("late-evidence");
    let state = DaemonState::new(&config).expect("create daemon state");
    state
        .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
        .await
        .expect("register test Agent Run");
    state
        .close(AGENT_RUN_ID)
        .await
        .expect("close test Agent Run");
    state
        .apply_retention()
        .await
        .expect("purge qualified Agent Run");

    let error = state
        .persist_collector_lifecycle(CollectorLifecycleRecord::started(
            AGENT_RUN_ID,
            "late-collector-instance",
        ))
        .await
        .expect_err("purged Agent Run must reject late evidence");

    assert_eq!(error, "Agent Run storage write is blocked");
    assert!(
        !config
            .state_dir
            .join(LEGACY_AGENT_RUN_STORAGE_DIR)
            .join(AGENT_RUN_ID)
            .exists(),
        "late evidence must not recreate purged Agent Run storage"
    );

    drop(state);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn startup_rolls_back_an_uncommitted_retention_transaction() {
    let config = config("recover-staging");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "staging");

    let recovered = DaemonState::new(&config).expect("recover uncommitted retention transaction");

    assert!(
        config
            .state_dir
            .join(LEGACY_AGENT_RUN_STORAGE_DIR)
            .join(AGENT_RUN_ID)
            .join("timeline.jsonl")
            .is_file(),
        "uncommitted staged state must return to the live Agent Run directory"
    );
    assert!(!transaction_dir.exists());

    drop(recovered);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn startup_finishes_cleanup_for_a_committed_retention_transaction() {
    let config = config("recover-committed");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "committed");

    let recovered = DaemonState::new(&config).expect("recover committed retention transaction");

    assert!(
        !config
            .state_dir
            .join(LEGACY_AGENT_RUN_STORAGE_DIR)
            .join(AGENT_RUN_ID)
            .exists(),
        "committed staged state must remain purged"
    );
    assert!(!transaction_dir.exists());

    drop(recovered);
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn committed_recovery_refuses_unknown_content_before_deleting_agent_run_or_canary() {
    let config = config("recover-unknown-transaction-content");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "committed");
    let canary = transaction_dir.join("operator-canary.txt");
    std::fs::write(&canary, b"must remain unchanged\n").expect("write transaction canary");

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("committed recovery must reject unknown transaction content"),
        Err(error) => error,
    };

    assert!(error.contains("retention_cleanup_incomplete"), "{error}");
    assert!(
        transaction_dir.join(AGENT_RUN_ID).is_dir(),
        "shape validation must precede Agent Run deletion"
    );
    assert_eq!(
        std::fs::read(&canary).expect("read transaction canary"),
        b"must remain unchanged\n"
    );

    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn startup_refuses_a_non_private_retention_journal_without_deleting_state() {
    let config = config("recover-public-journal");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "committed");
    let journal = transaction_dir.join("transaction-v1.json");
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o644))
        .expect("make recovery journal non-private");
    let canary = config.state_dir.join("operator-canary.txt");
    std::fs::write(&canary, b"must remain unchanged\n").expect("write recovery canary");

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("startup must fail closed for a non-private retention journal"),
        Err(error) => error,
    };

    assert!(error.contains("retention_trash_unsafe"), "{error}");
    assert!(journal.is_file(), "unsafe journal must not be removed");
    assert!(
        transaction_dir.join(AGENT_RUN_ID).is_dir(),
        "staged Agent Run must not be removed"
    );
    assert_eq!(
        std::fs::read(&canary).expect("read recovery canary"),
        b"must remain unchanged\n"
    );

    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn startup_refuses_wrong_retention_journal_ownership_without_deleting_state() {
    let config = config("recover-wrong-journal-owner");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "committed");
    let journal = transaction_dir.join("transaction-v1.json");
    if !assign_journal_to_another_group(&journal) {
        eprintln!("skipped: changing journal ownership requires another permitted group or root");
        std::fs::remove_dir_all(config.state_dir).expect("clean skipped test state");
        return;
    }
    let canary = config.state_dir.join("operator-canary.txt");
    std::fs::write(&canary, b"must remain unchanged\n").expect("write recovery canary");

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("startup must fail closed for wrong retention journal ownership"),
        Err(error) => error,
    };

    assert!(error.contains("retention_trash_unsafe"), "{error}");
    assert!(journal.is_file(), "unsafe journal must not be removed");
    assert!(transaction_dir.join(AGENT_RUN_ID).is_dir());
    assert_eq!(
        std::fs::read(&canary).expect("read recovery canary"),
        b"must remain unchanged\n"
    );

    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn startup_refuses_an_unsafe_temporary_retention_journal_without_deleting_state() {
    let config = config("recover-unsafe-temporary-journal");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "committed");
    let temporary_journal = transaction_dir.join("transaction-v1.json.tmp");
    std::fs::write(&temporary_journal, b"incomplete journal\n")
        .expect("write interrupted temporary journal");
    std::fs::set_permissions(&temporary_journal, std::fs::Permissions::from_mode(0o644))
        .expect("make temporary recovery journal non-private");
    let canary = config.state_dir.join("operator-canary.txt");
    std::fs::write(&canary, b"must remain unchanged\n").expect("write recovery canary");

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("startup must fail closed for an unsafe temporary retention journal"),
        Err(error) => error,
    };

    assert!(error.contains("retention_trash_unsafe"), "{error}");
    assert!(temporary_journal.is_file());
    assert!(transaction_dir.join(AGENT_RUN_ID).is_dir());
    assert_eq!(
        std::fs::read(&canary).expect("read recovery canary"),
        b"must remain unchanged\n"
    );

    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn startup_refuses_a_hard_linked_retention_journal_without_deleting_the_canary() {
    let config = config("recover-hard-linked-journal");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "committed");
    let journal = transaction_dir.join("transaction-v1.json");
    let canary = config.state_dir.join("journal-canary.json");
    std::fs::hard_link(&journal, &canary).expect("hard-link recovery journal to canary");
    let expected = std::fs::read(&canary).expect("read journal canary");

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("startup must fail closed for a multiply linked retention journal"),
        Err(error) => error,
    };

    assert!(error.contains("retention_trash_unsafe"), "{error}");
    assert!(journal.is_file(), "linked journal must not be removed");
    assert_eq!(
        std::fs::read(&canary).expect("read preserved journal canary"),
        expected
    );
    assert!(transaction_dir.join(AGENT_RUN_ID).is_dir());

    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn startup_refuses_a_symlinked_retention_journal_without_deleting_the_canary() {
    let config = config("recover-symlinked-journal");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "committed");
    let journal = transaction_dir.join("transaction-v1.json");
    let canary = config.state_dir.join("journal-canary.json");
    let journal_bytes = std::fs::read(&journal).expect("read recovery journal fixture");
    std::fs::write(&canary, &journal_bytes).expect("write journal canary");
    std::fs::remove_file(&journal).expect("remove managed recovery journal");
    symlink(&canary, &journal).expect("replace recovery journal with symlink");

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("startup must fail closed for a symlinked retention journal"),
        Err(error) => error,
    };

    assert!(error.contains("retention_trash_unsafe"), "{error}");
    assert!(std::fs::symlink_metadata(&journal)
        .expect("symlinked journal remains")
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::read(&canary).expect("read preserved journal canary"),
        journal_bytes
    );
    assert!(transaction_dir.join(AGENT_RUN_ID).is_dir());

    std::fs::remove_file(&journal).expect("remove test symlink");
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn committed_recovery_refuses_a_recreated_live_agent_run_path() {
    let config = config("recover-live-conflict");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "committed");
    let recreated = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(AGENT_RUN_ID);
    std::fs::create_dir(&recreated).expect("recreate conflicting live Agent Run directory");
    let sentinel = recreated.join("timeline.jsonl");
    std::fs::write(&sentinel, b"late replacement must remain\n")
        .expect("write late replacement timeline");

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("committed recovery must fail closed on a live-path conflict"),
        Err(error) => error,
    };

    assert!(error.contains("retention_cleanup_incomplete"), "{error}");
    assert_eq!(
        std::fs::read(&sentinel).expect("read late replacement"),
        b"late replacement must remain\n"
    );
    assert!(transaction_dir.join(AGENT_RUN_ID).is_dir());

    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

#[test]
fn committed_recovery_refuses_a_replaced_staged_timeline() {
    let config = config("recover-staged-replacement");
    create_closed_agent_run(&config);
    let transaction_dir = stage_recovery_transaction(&config, "committed");
    let staged_timeline = transaction_dir.join(AGENT_RUN_ID).join("timeline.jsonl");
    let external = config.state_dir.join("external-sentinel.jsonl");
    std::fs::write(&external, b"external evidence must remain\n").expect("write external evidence");
    std::fs::remove_file(&staged_timeline).expect("remove staged managed timeline");
    symlink(&external, &staged_timeline).expect("replace staged timeline with symlink");

    let error = match DaemonState::new(&config) {
        Ok(_) => panic!("committed recovery must reject replaced staged content"),
        Err(error) => error,
    };

    assert!(error.contains("retention_cleanup_incomplete"), "{error}");
    assert_eq!(
        std::fs::read(&external).expect("read external evidence"),
        b"external evidence must remain\n"
    );
    assert!(std::fs::symlink_metadata(&staged_timeline)
        .expect("staged replacement remains")
        .file_type()
        .is_symlink());

    std::fs::remove_file(&staged_timeline).expect("remove test symlink");
    std::fs::remove_dir_all(config.state_dir).expect("clean test state");
}

fn agent_run_intent() -> SessionIntent {
    agent_run_intent_for(AGENT_RUN_ID, EXPIRES_AT_UNIX_MS)
}

fn agent_run_intent_for(agent_run_id: &str, expires_at_unix_ms: u64) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        tenant_id: DEFAULT_TENANT_ID.to_string(),
        retention_tier: RetentionTier::Short,
        session_id: agent_run_id.to_string(),
        expires_at_unix_ms,
        declared_actions: vec![ActionClass::Test],
        allowed_resources: Vec::new(),
        workload_selectors: Vec::new(),
        kubernetes_claims: Vec::new(),
    }
}

fn create_closed_agent_run(config: &DaemonConfig) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build test runtime");
    runtime.block_on(async {
        let state = DaemonState::new(config).expect("create daemon state");
        state
            .register(agent_run_intent(), REGISTERED_AT_UNIX_MS)
            .await
            .expect("register test Agent Run");
        state
            .close(AGENT_RUN_ID)
            .await
            .expect("close test Agent Run");
    });
}

fn stage_recovery_transaction(config: &DaemonConfig, status: &str) -> std::path::PathBuf {
    let agent_run_dir = config
        .state_dir
        .join(LEGACY_AGENT_RUN_STORAGE_DIR)
        .join(AGENT_RUN_ID);
    let metadata = std::fs::symlink_metadata(&agent_run_dir).expect("inspect managed Agent Run");
    let timeline_metadata = std::fs::symlink_metadata(agent_run_dir.join("timeline.jsonl"))
        .expect("inspect managed timeline");
    let transaction_dir = config
        .state_dir
        .join(".retention-trash")
        .join(format!("purge-recovery-{status}"));
    std::fs::create_dir(&transaction_dir).expect("create recovery transaction");
    std::fs::set_permissions(&transaction_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restrict recovery transaction");
    let journal = json!({
        "schema_version": 1,
        "status": status,
        "targets": [{
            "agent_run_id": AGENT_RUN_ID,
            "device": metadata.dev(),
            "inode": metadata.ino(),
            "timeline_device": timeline_metadata.dev(),
            "timeline_inode": timeline_metadata.ino()
        }]
    });
    let journal_path = transaction_dir.join("transaction-v1.json");
    std::fs::write(
        &journal_path,
        serde_json::to_vec(&journal).expect("serialize recovery journal"),
    )
    .expect("write recovery journal");
    std::fs::set_permissions(&journal_path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict recovery journal");
    std::fs::rename(&agent_run_dir, transaction_dir.join(AGENT_RUN_ID))
        .expect("stage managed Agent Run");
    transaction_dir
}

fn assign_journal_to_another_group(journal: &std::path::Path) -> bool {
    // SAFETY: getegid/geteuid only read the calling process credentials.
    let effective_gid = unsafe { libc::getegid() };
    // SAFETY: a zero-size getgroups call accepts a null output pointer.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups = if count > 0 {
        vec![0; count as usize]
    } else {
        Vec::new()
    };
    if count > 0 {
        // SAFETY: groups has capacity for exactly count gid_t values.
        if unsafe { libc::getgroups(count, groups.as_mut_ptr()) } < 0 {
            return false;
        }
    }
    let alternative = groups
        .into_iter()
        .find(|group| *group != effective_gid)
        .or_else(|| {
            // Root may select a synthetic group when it has no supplementary
            // group; an unprivileged process cannot safely do so.
            if unsafe { libc::geteuid() } == 0 {
                Some(effective_gid.wrapping_add(1))
            } else {
                None
            }
        });
    let Some(alternative) = alternative else {
        return false;
    };
    let file = match std::fs::OpenOptions::new().read(true).open(journal) {
        Ok(file) => file,
        Err(_) => return false,
    };
    // SAFETY: file owns a valid descriptor; uid_t::MAX asks fchown to retain
    // the current user owner while changing only the group owner.
    unsafe {
        libc::fchown(
            file.as_raw_fd(),
            libc::uid_t::MAX,
            alternative as libc::gid_t,
        ) == 0
    }
}

fn config(name: &str) -> DaemonConfig {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "apolysis-retention-safety-{name}-{}-{id}-{nonce}",
        std::process::id()
    ));
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        request_timeout: Duration::from_millis(100),
        ..DaemonConfig::default()
    }
}
