// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use apolysis_observer::{
    discover_process_tree_scope_identities, AgentRegistration, ProcStartClock,
    ProcessRuntimeIdentity, StartBoottimeWindow,
};
use sha2::{Digest, Sha256};

const HOST_BOOT_ID: &str = "11111111-2222-3333-4444-555555555555";

#[test]
fn existing_process_snapshot_rejects_a_missing_root_identity() {
    let proc_root = temp_proc_root("missing-root");
    let _ = std::fs::remove_dir_all(&proc_root);
    std::fs::create_dir_all(&proc_root).expect("create fake proc root");

    let error = discover_process_tree_scope_identities(404, &proc_root)
        .expect_err("a protected attach must not seed a missing root PID");

    assert!(error.contains("root runtime identity is unavailable"));
    assert!(error.contains("pid=404"));
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn existing_process_snapshot_qualifies_every_seeded_pid_with_start_time() {
    let proc_root = temp_proc_root("identity-qualified-tree");
    let _ = std::fs::remove_dir_all(&proc_root);

    write_task_children(&proc_root, 100, 100, 1, "200\n", 1_001);
    write_task_children(&proc_root, 200, 200, 100, "300\n", 2_002);
    write_task_children(&proc_root, 300, 300, 200, "", 3_003);

    let identities = discover_process_tree_scope_identities(100, &proc_root)
        .expect("discover an identity-qualified process tree");

    assert_eq!(
        identities,
        vec![
            ProcessRuntimeIdentity::new(100, 1_001).expect("root identity"),
            ProcessRuntimeIdentity::new(200, 2_002).expect("child identity"),
            ProcessRuntimeIdentity::new(300, 3_003).expect("grandchild identity"),
        ]
    );
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn existing_process_snapshot_normalizes_threads_to_one_tgid_membership() {
    let proc_root = temp_proc_root("tgid-normalization");
    let _ = std::fs::remove_dir_all(&proc_root);

    write_task_children(&proc_root, 100, 100, 1, "", 1_001);
    let thread_dir = proc_root.join("100/task/101");
    std::fs::create_dir_all(&thread_dir).expect("create fake thread task dir");
    write_proc_stat(&proc_root, 101, 1, 1_002);
    std::fs::write(proc_root.join("100/status"), "Name:\troot\nTgid:\t100\n")
        .expect("write root status");
    std::fs::write(proc_root.join("101/status"), "Name:\tworker\nTgid:\t100\n")
        .expect("write thread status");

    let identities = discover_process_tree_scope_identities(100, &proc_root)
        .expect("discover TGID-normalized process tree");

    assert_eq!(
        identities,
        vec![ProcessRuntimeIdentity::new(100, 1_001).expect("root identity")]
    );
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn existing_process_snapshot_never_promotes_an_unresolved_tid_to_tgid_membership() {
    let proc_root = temp_proc_root("unresolved-tgid");
    let _ = std::fs::remove_dir_all(&proc_root);

    write_task_children(&proc_root, 100, 100, 1, "", 1_001);
    let thread_dir = proc_root.join("100/task/101");
    std::fs::create_dir_all(&thread_dir).expect("create fake thread task dir");
    write_proc_stat(&proc_root, 101, 1, 1_002);
    let _ = std::fs::remove_file(proc_root.join("101/status"));

    let identities = discover_process_tree_scope_identities(100, &proc_root)
        .expect("skip a task whose TGID cannot be established");

    assert_eq!(
        identities,
        vec![ProcessRuntimeIdentity::new(100, 1_001).expect("root identity")]
    );
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn existing_process_snapshot_revalidates_each_lineage_edge_before_seeding() {
    let proc_root = temp_proc_root("stale-lineage-edge");
    let _ = std::fs::remove_dir_all(&proc_root);

    write_task_children(&proc_root, 100, 100, 1, "200\n", 1_001);
    write_task_children(&proc_root, 200, 200, 100, "", 2_002);
    write_proc_stat(&proc_root, 200, 999, 2_002);

    let identities = discover_process_tree_scope_identities(100, &proc_root)
        .expect("discard a PID that no longer belongs to the captured lineage edge");

    assert_eq!(
        identities,
        vec![ProcessRuntimeIdentity::new(100, 1_001).expect("root identity")]
    );
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn existing_process_snapshot_excludes_a_zombie_descendant() {
    let proc_root = temp_proc_root("zombie-descendant");
    let _ = std::fs::remove_dir_all(&proc_root);

    write_task_children(&proc_root, 100, 100, 1, "200\n", 1_001);
    write_task_children(&proc_root, 200, 200, 100, "", 2_002);
    write_proc_stat_with_state(&proc_root, 200, 100, 'Z', 2_002);

    let identities = discover_process_tree_scope_identities(100, &proc_root)
        .expect("exclude a descendant whose process exit already occurred");

    assert_eq!(
        identities,
        vec![ProcessRuntimeIdentity::new(100, 1_001).expect("root identity")]
    );
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn registration_runtime_identity_rejects_a_different_host_boot() {
    let proc_root = temp_proc_root("registration-boot-mismatch");
    let _ = std::fs::remove_dir_all(&proc_root);
    write_proc_identity(
        &proc_root,
        410,
        4_100,
        "/usr/bin/test-agent",
        &["test-agent", "serve"],
    );
    let registration = registration(410, 4_100, "/usr/bin/test-agent", &["test-agent", "serve"]);

    let error = registration
        .validate_runtime_identity(&proc_root, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        .expect_err("a registration from another boot must fail closed");

    assert!(error.contains("host boot identity mismatch"));
    assert!(!error.contains("/usr/bin/test-agent"));
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn registration_runtime_identity_rejects_exec_churn_without_leaking_command() {
    let proc_root = temp_proc_root("registration-exec-churn");
    let _ = std::fs::remove_dir_all(&proc_root);
    write_proc_identity(
        &proc_root,
        420,
        4_200,
        "/usr/bin/replacement",
        &["replacement", "--private-token", "do-not-persist"],
    );
    let registration = registration(420, 4_200, "/usr/bin/test-agent", &["test-agent", "serve"]);

    let error = registration
        .validate_runtime_identity(&proc_root, HOST_BOOT_ID)
        .expect_err("an exec transition after registration must fail closed");

    assert!(error.contains("executable identity mismatch"));
    assert!(!error.contains("/usr/bin/replacement"));
    assert!(!error.contains("do-not-persist"));
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn registration_runtime_identity_returns_the_validated_process_generation() {
    let proc_root = temp_proc_root("registration-valid");
    let _ = std::fs::remove_dir_all(&proc_root);
    write_proc_identity(
        &proc_root,
        430,
        4_300,
        "/usr/bin/test-agent",
        &["test-agent", "serve"],
    );
    let registration = registration(430, 4_300, "/usr/bin/test-agent", &["test-agent", "serve"]);

    let identity = registration
        .validate_runtime_identity(&proc_root, HOST_BOOT_ID)
        .expect("validate the complete registration identity");

    assert_eq!(
        identity,
        ProcessRuntimeIdentity::new(430, 4_300).expect("expected identity")
    );
    let _ = std::fs::remove_dir_all(proc_root);
}

#[test]
fn proc_start_ticks_become_a_bounded_kernel_start_window() {
    let clock = ProcStartClock::new(100).expect("Linux USER_HZ clock");
    let identity = ProcessRuntimeIdentity::new(501, 123).expect("process identity");

    assert_eq!(
        clock
            .start_boottime_window(identity)
            .expect("bounded start window"),
        StartBoottimeWindow::new(1_230_000_000, 1_240_000_000).expect("expected start window")
    );
}

#[test]
fn one_proc_tick_models_the_pre_anchor_same_pid_ambiguity() {
    let clock = ProcStartClock::new(100).expect("Linux USER_HZ clock");
    let identity = ProcessRuntimeIdentity::new(501, 123).expect("registered process identity");
    let window = clock
        .start_boottime_window(identity)
        .expect("bounded start window");
    let registered_start_ns = 1_230_000_001;
    let indistinguishable_replacement_start_ns = 1_239_999_999;

    assert_ne!(registered_start_ns, indistinguishable_replacement_start_ns);
    assert!(window.lower_ns <= registered_start_ns && registered_start_ns < window.upper_ns);
    assert!(
        window.lower_ns <= indistinguishable_replacement_start_ns
            && indistinguishable_replacement_start_ns < window.upper_ns
    );
}

#[test]
fn proc_start_zero_ticks_keeps_the_first_clock_tick_representable() {
    let clock = ProcStartClock::new(100).expect("Linux USER_HZ clock");
    let identity = ProcessRuntimeIdentity::new(1, 0).expect("first-tick process identity");

    assert_eq!(
        clock
            .start_boottime_window(identity)
            .expect("first-tick start window"),
        StartBoottimeWindow::new(0, 10_000_000).expect("expected first-tick window")
    );
}

#[test]
fn proc_start_clock_rejects_a_non_integral_nanosecond_tick() {
    let error = ProcStartClock::new(1_024)
        .expect_err("protected attach must not approximate proc start ticks");

    assert!(error.contains("does not divide one second"));
}

fn write_task_children(
    proc_root: &Path,
    pid: u32,
    tid: u32,
    ppid: u32,
    children: &str,
    start_time_ticks: u64,
) {
    let task_dir = proc_root
        .join(pid.to_string())
        .join("task")
        .join(tid.to_string());
    std::fs::create_dir_all(&task_dir).expect("create fake task dir");
    std::fs::write(task_dir.join("children"), children).expect("write fake children");
    write_proc_stat(proc_root, pid, ppid, start_time_ticks);
    std::fs::write(
        proc_root.join(pid.to_string()).join("status"),
        format!("Name:\tfake-proc-{pid}\nTgid:\t{pid}\n"),
    )
    .expect("write fake process status");
}

fn write_proc_stat(proc_root: &Path, pid: u32, ppid: u32, start_time_ticks: u64) {
    write_proc_stat_with_state(proc_root, pid, ppid, 'S', start_time_ticks);
}

fn write_proc_stat_with_state(
    proc_root: &Path,
    pid: u32,
    ppid: u32,
    state: char,
    start_time_ticks: u64,
) {
    let pid_dir = proc_root.join(pid.to_string());
    std::fs::create_dir_all(&pid_dir).expect("create fake proc pid dir");
    std::fs::write(
        pid_dir.join("stat"),
        format!(
            "{pid} (fake-proc-{pid}) {state} {ppid} 1 1 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 {start_time_ticks} 0 0\n"
        ),
    )
    .expect("write fake proc stat");
}

fn write_proc_identity(
    proc_root: &Path,
    pid: u32,
    start_time_ticks: u64,
    executable: &str,
    argv: &[&str],
) {
    write_proc_stat(proc_root, pid, 1, start_time_ticks);
    let pid_root = proc_root.join(pid.to_string());
    std::fs::write(pid_root.join("cmdline"), argv.join("\0")).expect("write fake cmdline");
    symlink(executable, pid_root.join("exe")).expect("create fake executable link");
}

fn registration(
    pid: u32,
    start_time_ticks: u64,
    executable: &str,
    argv: &[&str],
) -> AgentRegistration {
    AgentRegistration {
        kind: "test-agent".to_string(),
        pid,
        start_time_ticks,
        host_boot_id: HOST_BOOT_ID.to_string(),
        workspace_root: PathBuf::from("/workspace/apolysis"),
        executable: executable.to_string(),
        command_fingerprint: command_fingerprint(argv),
        command: None,
    }
}

fn command_fingerprint(argv: &[&str]) -> String {
    let digest = Sha256::digest(argv.join("\0").as_bytes());
    let mut output = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("write digest");
    }
    output
}

fn temp_proc_root(prefix: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("apolysis-{prefix}-{}", std::process::id()))
}
