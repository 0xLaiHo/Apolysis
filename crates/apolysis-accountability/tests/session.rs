// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    ActionClass, AssociationOutcome, RegisterOutcome, RegistryError, RetentionTier, SessionIntent,
    SessionRegistry, SessionStatus,
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
        policy_ref: "policy.yaml".to_string(),
        workload_selectors: Vec::new(),
    }
}
