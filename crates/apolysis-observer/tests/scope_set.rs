// SPDX-License-Identifier: Apache-2.0

use apolysis_observer::{ScopeSet, ScopeSetError, MAX_TRACKED_CGROUPS};

#[test]
fn adds_removes_and_deduplicates_cgroups() {
    let mut scopes = ScopeSet::with_capacity(2);
    assert_eq!(scopes.insert(41), Ok(true));
    assert_eq!(scopes.insert(41), Ok(false));
    assert_eq!(scopes.insert(42), Ok(true));
    assert_eq!(scopes.len(), 2);
    assert!(scopes.contains(41));
    assert!(scopes.remove(41));
    assert!(!scopes.remove(41));
    assert_eq!(scopes.iter().copied().collect::<Vec<_>>(), vec![42]);
}

#[test]
fn rejects_entries_beyond_capacity_without_mutating_the_set() {
    let mut scopes = ScopeSet::with_capacity(1);
    scopes.insert(41).expect("first scope");
    assert_eq!(
        scopes.insert(42),
        Err(ScopeSetError::CapacityReached { capacity: 1 })
    );
    assert_eq!(scopes.iter().copied().collect::<Vec<_>>(), vec![41]);
}

#[test]
fn rejects_the_reserved_zero_cgroup_id() {
    let mut scopes = ScopeSet::new();
    assert_eq!(scopes.insert(0), Err(ScopeSetError::InvalidCgroupId));
    assert!(scopes.is_empty());
}

#[test]
fn default_capacity_matches_the_kernel_map_limit() {
    let scopes = ScopeSet::new();
    assert_eq!(scopes.capacity(), MAX_TRACKED_CGROUPS);
}
