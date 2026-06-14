// SPDX-License-Identifier: Apache-2.0

use apolysis_accountability::{
    ActionClass, AssociationOutcome, RegisterOutcome, RegistryError, SessionIntent,
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
    assert_eq!(
        registry.renew("session-a", NOW_MS + 3_000, NOW_MS),
        Ok(())
    );
    assert_eq!(
        registry.get("session-a").expect("registered").expires_at_unix_ms,
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

fn intent(session_id: &str, expires_at_unix_ms: u64) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        session_id: session_id.to_string(),
        expires_at_unix_ms,
        declared_actions: vec![ActionClass::Test],
        allowed_resources: Vec::new(),
        policy_ref: "policy.yaml".to_string(),
        workload_selectors: Vec::new(),
    }
}
