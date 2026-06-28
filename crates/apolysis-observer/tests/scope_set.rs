// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use apolysis_observer::{
    discover_process_tree_scope_pids, ScopeSet, ScopeSetError, MAX_TRACKED_CGROUPS,
};

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

#[test]
fn discovers_process_tree_threads_and_children_from_proc_task_children() {
    let proc_root = temp_proc_root("apolysis-proc-children");
    let _ = std::fs::remove_dir_all(&proc_root);

    write_task_children(&proc_root, 100, 100, "200 201\n");
    write_task_children(&proc_root, 100, 101, "202\n");
    write_task_children(&proc_root, 200, 200, "300\n");
    write_task_children(&proc_root, 201, 201, "");
    write_task_children(&proc_root, 202, 202, "");
    write_task_children(&proc_root, 300, 300, "");

    assert_eq!(
        discover_process_tree_scope_pids(100, &proc_root).expect("discover process tree scope"),
        vec![100, 101, 200, 201, 202, 300]
    );

    let _ = std::fs::remove_dir_all(&proc_root);
}

#[test]
fn discovers_process_tree_descendants_from_proc_parent_scan_fallback() {
    let proc_root = temp_proc_root("apolysis-proc-parent-scan");
    let _ = std::fs::remove_dir_all(&proc_root);

    write_task_children(&proc_root, 500, 500, "");
    write_proc_stat(&proc_root, 610, 500);
    write_proc_stat(&proc_root, 620, 610);
    write_proc_stat(&proc_root, 700, 1);

    assert_eq!(
        discover_process_tree_scope_pids(500, &proc_root).expect("discover process tree scope"),
        vec![500, 610, 620]
    );

    let _ = std::fs::remove_dir_all(&proc_root);
}

fn write_task_children(proc_root: &Path, pid: u32, tid: u32, children: &str) {
    let task_dir = proc_root
        .join(pid.to_string())
        .join("task")
        .join(tid.to_string());
    std::fs::create_dir_all(&task_dir).expect("create fake task dir");
    std::fs::write(task_dir.join("children"), children).expect("write fake children");
    write_proc_stat(proc_root, pid, 1);
}

fn write_proc_stat(proc_root: &Path, pid: u32, ppid: u32) {
    let pid_dir = proc_root.join(pid.to_string());
    std::fs::create_dir_all(&pid_dir).expect("create fake proc pid dir");
    std::fs::write(
        pid_dir.join("stat"),
        format!("{pid} (fake-proc-{pid}) S {ppid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1\n"),
    )
    .expect("write fake proc stat");
}

fn temp_proc_root(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()))
}
