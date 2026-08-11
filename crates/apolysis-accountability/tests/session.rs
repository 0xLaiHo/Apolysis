// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    ActionClass, AssociationOutcome, RegisterOutcome, RegistryError, RetentionTier, SessionIntent,
    SessionRegistry, SessionStatus, MAX_RETAINED_AGENT_RUNS,
};

const NOW_MS: u64 = 1_780_000_000_000;

#[test]
fn registers_replaces_renews_and_closes_sessions() {
    let mut registry = SessionRegistry::new(2, 2);

    assert_eq!(
        registry.register(intent("session-a", NOW_MS + 1_000), NOW_MS),
        Ok(RegisterOutcome::Inserted)
    );
    assert_eq!(
        registry.register(intent("session-a", NOW_MS + 2_000), NOW_MS),
        Ok(RegisterOutcome::Replaced)
    );
    assert_eq!(registry.renew("session-a", NOW_MS + 3_000, NOW_MS), Ok(()));
    assert_eq!(
        registry
            .get("session-a")
            .expect("registered")
            .expires_at_unix_ms,
        NOW_MS + 3_000
    );

    let closed = registry.close("session-a").expect("close session");
    assert_eq!(closed.status, SessionStatus::Closed);
    assert!(!registry.is_scope_admitted("session-a"));
}

#[test]
fn expires_sessions_without_discarding_diagnostic_state() {
    let mut registry = SessionRegistry::new(2, 2);
    registry
        .register(intent("session-a", NOW_MS + 10), NOW_MS)
        .expect("register");
    registry
        .associate_cgroup("session-a", 41)
        .expect("associate cgroup");

    assert_eq!(registry.expire(NOW_MS + 10), vec!["session-a".to_string()]);
    let state = registry.get("session-a").expect("expired state retained");
    assert_eq!(state.status, SessionStatus::Expired);
    assert_eq!(state.cgroup_ids, vec![41]);
    assert!(!registry.is_scope_admitted("session-a"));
}

#[test]
fn degrades_sessions_without_discarding_diagnostic_state() {
    let mut registry = SessionRegistry::new(2, 2);
    registry
        .register(intent("session-a", NOW_MS + 10_000), NOW_MS)
        .expect("register");
    registry
        .associate_cgroup("session-a", 41)
        .expect("associate cgroup");

    let degraded = registry.degrade("session-a").expect("degrade session");

    assert_eq!(degraded.status, SessionStatus::Degraded);
    assert_eq!(degraded.cgroup_ids, vec![41]);
    assert_eq!(
        registry
            .get("session-a")
            .expect("degraded state retained")
            .status,
        SessionStatus::Degraded
    );
    assert!(!registry.is_scope_admitted("session-a"));
    assert_eq!(registry.session_for_cgroup(41), None);
    assert_eq!(
        registry.associate_cgroup("session-a", 42),
        Err(RegistryError::SessionNotActive("session-a".to_string()))
    );
}

#[test]
fn enforces_session_capacity_without_rejecting_replacement() {
    let mut registry = SessionRegistry::new(1, 1);
    registry
        .register(intent("session-a", NOW_MS + 1_000), NOW_MS)
        .expect("first session");
    assert_eq!(
        registry.register(intent("session-b", NOW_MS + 1_000), NOW_MS),
        Err(RegistryError::SessionCapacityReached { capacity: 1 })
    );
    assert_eq!(
        registry.register(intent("session-a", NOW_MS + 2_000), NOW_MS),
        Ok(RegisterOutcome::Replaced)
    );
}

#[test]
fn closed_agent_run_retention_catalog_is_independently_bounded_and_fails_closed() {
    let mut registry = SessionRegistry::new(1, 1);
    for index in 0..MAX_RETAINED_AGENT_RUNS {
        registry
            .restore_closed_agent_run(intent(&format!("closed-agent-run-{index}"), NOW_MS + 1_000))
            .expect("restore closed Agent Run within the retention catalog bound");
    }

    let error = registry
        .restore_closed_agent_run(intent("closed-agent-run-overflow", NOW_MS + 1_000))
        .expect_err("closed retention catalog must fail closed at its independent bound");

    assert_eq!(
        error,
        RegistryError::ClosedAgentRunCapacityReached {
            capacity: MAX_RETAINED_AGENT_RUNS,
        }
    );
    assert!(registry.get("closed-agent-run-0").is_some());
    assert!(registry.get("closed-agent-run-overflow").is_none());
    registry
        .register(intent("active-agent-run", NOW_MS + 1_000), NOW_MS)
        .expect("closed retention catalog must not consume active capacity");
    assert_eq!(
        registry.close("active-agent-run"),
        Err(RegistryError::ClosedAgentRunCapacityReached {
            capacity: MAX_RETAINED_AGENT_RUNS,
        }),
        "a full retention catalog must reject close without dropping the active Agent Run"
    );
    assert_eq!(
        registry
            .get("active-agent-run")
            .expect("failed close preserves the active Agent Run")
            .status,
        SessionStatus::Active
    );
}

#[test]
fn rejects_cgroup_ownership_conflicts() {
    let mut registry = SessionRegistry::new(2, 2);
    registry
        .register(intent("session-a", NOW_MS + 1_000), NOW_MS)
        .expect("session a");
    registry
        .register(intent("session-b", NOW_MS + 1_000), NOW_MS)
        .expect("session b");
    registry
        .associate_cgroup("session-a", 99)
        .expect("associate cgroup");

    assert_eq!(
        registry.associate_cgroup("session-b", 99),
        Err(RegistryError::CgroupAlreadyAssigned {
            cgroup_id: 99,
            session_id: "session-a".to_string(),
        })
    );
}

#[test]
fn tracks_marked_workloads_without_intent_in_a_bounded_pending_set() {
    let mut registry = SessionRegistry::new(2, 1);

    assert_eq!(
        registry.discover_cgroup("missing-session", 51),
        Ok(AssociationOutcome::MissingIntent)
    );
    assert_eq!(
        registry.discover_cgroup("another-session", 52),
        Err(RegistryError::PendingCapacityReached { capacity: 1 })
    );

    assert_eq!(
        registry.register(intent("missing-session", NOW_MS + 1_000), NOW_MS),
        Ok(RegisterOutcome::Inserted)
    );
    assert_eq!(
        registry.get("missing-session").expect("session").cgroup_ids,
        vec![51]
    );
    assert_eq!(registry.pending_count(), 0);
}

#[test]
fn resolves_cgroup_ownership_for_active_and_pending_workloads() {
    let mut registry = SessionRegistry::new(4, 4);
    registry
        .discover_cgroup("pending-session", 41)
        .expect("pending cgroup");
    assert_eq!(
        registry.session_for_cgroup(41),
        Some("pending-session"),
        "pending workloads need attribution for missing_intent findings"
    );

    registry
        .register(intent("active-session", NOW_MS + 10_000), NOW_MS)
        .expect("register active session");
    registry
        .associate_cgroup("active-session", 42)
        .expect("associate active cgroup");
    assert_eq!(registry.session_for_cgroup(42), Some("active-session"));

    registry.close("active-session").expect("close session");
    assert_eq!(registry.session_for_cgroup(42), None);
    assert_eq!(registry.session_for_cgroup(41), Some("pending-session"));
}

#[test]
fn retires_exact_cgroup_ownership_before_numeric_identity_reuse() {
    let mut registry = SessionRegistry::new(4, 4);
    registry
        .register(intent("session-a", NOW_MS + 10_000), NOW_MS)
        .expect("register first Agent Run");
    registry
        .register(intent("session-b", NOW_MS + 10_000), NOW_MS)
        .expect("register replacement Agent Run");
    registry
        .associate_cgroup("session-a", 42)
        .expect("associate original cgroup identity");

    assert_eq!(
        registry.retire_cgroup("session-b", 42),
        Err(RegistryError::CgroupAlreadyAssigned {
            cgroup_id: 42,
            session_id: "session-a".to_string(),
        })
    );
    assert_eq!(registry.session_for_cgroup(42), Some("session-a"));

    assert_eq!(registry.retire_cgroup("session-a", 42), Ok(true));
    assert_eq!(registry.retire_cgroup("session-a", 42), Ok(false));
    assert!(registry
        .get("session-a")
        .expect("first Agent Run remains queryable")
        .cgroup_ids
        .is_empty());
    registry
        .associate_cgroup("session-b", 42)
        .expect("retired numeric cgroup identity may be rebound");
    assert_eq!(registry.session_for_cgroup(42), Some("session-b"));

    registry
        .discover_cgroup("pending-agent-run", 77)
        .expect("record pending runtime workload");
    assert_eq!(registry.retire_cgroup("pending-agent-run", 77), Ok(true));
    assert_eq!(registry.pending_count(), 0);
    assert_eq!(registry.session_for_cgroup(77), None);
}

#[test]
fn rejects_association_for_expired_or_unknown_sessions() {
    let mut registry = SessionRegistry::new(2, 2);
    registry
        .register(intent("session-a", NOW_MS + 1), NOW_MS)
        .expect("register");
    registry.expire(NOW_MS + 1);

    assert_eq!(
        registry.associate_cgroup("session-a", 7),
        Err(RegistryError::SessionNotActive("session-a".to_string()))
    );
    assert_eq!(
        registry.associate_cgroup("unknown", 8),
        Err(RegistryError::SessionNotFound("unknown".to_string()))
    );
}

#[test]
fn lists_sessions_by_tenant_and_retention_tier() {
    let mut registry = SessionRegistry::new(4, 2);
    registry
        .register(
            intent_for_tenant(
                "tenant-a-short",
                NOW_MS + 1_000,
                "tenant-a",
                RetentionTier::Short,
            ),
            NOW_MS,
        )
        .expect("tenant-a short session");
    registry
        .register(
            intent_for_tenant(
                "tenant-a-extended",
                NOW_MS + 1_000,
                "tenant-a",
                RetentionTier::Extended,
            ),
            NOW_MS,
        )
        .expect("tenant-a extended session");
    registry
        .register(
            intent_for_tenant(
                "tenant-b-extended",
                NOW_MS + 1_000,
                "tenant-b",
                RetentionTier::Extended,
            ),
            NOW_MS,
        )
        .expect("tenant-b extended session");

    let tenant_a = registry.list_for_tenant("tenant-a", None);
    let tenant_a_ids: Vec<_> = tenant_a
        .iter()
        .map(|state| state.intent.session_id.as_str())
        .collect();
    assert_eq!(tenant_a_ids, vec!["tenant-a-extended", "tenant-a-short"]);

    let tenant_a_extended = registry.list_for_tenant("tenant-a", Some(RetentionTier::Extended));
    assert_eq!(tenant_a_extended.len(), 1);
    assert_eq!(tenant_a_extended[0].intent.session_id, "tenant-a-extended");
    assert_eq!(
        registry
            .get_for_tenant("tenant-a-short", "tenant-b")
            .map(|state| &state.intent.session_id),
        None
    );
}

#[test]
fn retention_purge_only_removes_closed_agent_runs_from_the_default_context() {
    let mut registry = SessionRegistry::new(8, 2);
    let short_window = RetentionTier::Short.retention_window_ms();
    let purge_now = NOW_MS + short_window + 2_000;
    registry
        .register(
            intent_for_tenant(
                "default-purge",
                NOW_MS + 1_000,
                apolysis_accountability::DEFAULT_TENANT_ID,
                RetentionTier::Short,
            ),
            NOW_MS,
        )
        .expect("default-context purge Agent Run");
    registry
        .register(
            intent_for_tenant(
                "default-keep-active",
                purge_now + 60_000,
                apolysis_accountability::DEFAULT_TENANT_ID,
                RetentionTier::Short,
            ),
            NOW_MS,
        )
        .expect("default-context active Agent Run");
    registry
        .register(
            intent_for_tenant(
                "non-default-keep",
                NOW_MS + 1_000,
                "tenant-b",
                RetentionTier::Short,
            ),
            NOW_MS,
        )
        .expect("non-default Agent Run");
    registry
        .associate_cgroup("default-purge", 41)
        .expect("associate purged cgroup");
    registry
        .close("default-purge")
        .expect("close default-context Agent Run");
    registry
        .close("non-default-keep")
        .expect("close non-default Agent Run");

    let dry_run = registry.retention_purge_report_for_tenant(
        apolysis_accountability::DEFAULT_TENANT_ID,
        purge_now,
        true,
    );
    assert_eq!(dry_run.eligible_session_ids, vec!["default-purge"]);
    assert!(dry_run.purged_session_ids.is_empty());
    assert!(registry.get("default-purge").is_some());

    let applied = registry.apply_retention(purge_now);
    assert_eq!(applied.eligible_session_ids, vec!["default-purge"]);
    assert_eq!(applied.purged_session_ids, vec!["default-purge"]);
    assert_eq!(registry.get("default-purge"), None);
    assert_eq!(registry.session_for_cgroup(41), None);
    assert!(registry.get("default-keep-active").is_some());
    assert!(registry.get("non-default-keep").is_some());
}

#[test]
fn expired_agent_run_without_a_durable_close_is_not_retention_eligible() {
    let mut registry = SessionRegistry::new(2, 2);
    let agent_run_id = "expired-without-durable-close";
    let expires_at_unix_ms = NOW_MS + 1;
    let purge_now = expires_at_unix_ms + RetentionTier::Short.retention_window_ms() + 1;
    registry
        .register(
            intent_for_tenant(
                agent_run_id,
                expires_at_unix_ms,
                apolysis_accountability::DEFAULT_TENANT_ID,
                RetentionTier::Short,
            ),
            NOW_MS,
        )
        .expect("register Agent Run");
    assert_eq!(
        registry.expire(expires_at_unix_ms),
        vec![agent_run_id.to_string()]
    );

    let report = registry.apply_retention(purge_now);

    assert!(report.eligible_session_ids.is_empty());
    assert!(report.purged_session_ids.is_empty());
    assert_eq!(report.retained_session_ids, vec![agent_run_id]);
    assert_eq!(
        registry
            .get(agent_run_id)
            .expect("non-durable terminal Agent Run remains")
            .status,
        SessionStatus::Expired
    );
}

fn intent(session_id: &str, expires_at_unix_ms: u64) -> SessionIntent {
    intent_for_tenant(
        session_id,
        expires_at_unix_ms,
        apolysis_accountability::DEFAULT_TENANT_ID,
        RetentionTier::Standard,
    )
}

fn intent_for_tenant(
    session_id: &str,
    expires_at_unix_ms: u64,
    tenant_id: &str,
    retention_tier: RetentionTier,
) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        tenant_id: tenant_id.to_string(),
        retention_tier,
        session_id: session_id.to_string(),
        expires_at_unix_ms,
        declared_actions: vec![ActionClass::Test],
        allowed_resources: Vec::new(),
        workload_selectors: Vec::new(),
    }
}
