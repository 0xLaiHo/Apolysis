// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::{symlink, MetadataExt};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apolysis_accountability::{ActionClass, SessionIntent};
use apolysis_daemon::{run_observer_runtime, scope_channel, DaemonConfig, DaemonState};
use apolysis_observer::{DaemonObserver, DaemonObserverConfig};
use tokio::sync::oneshot;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires Linux BTF, tracefs, cgroup v2, CAP_BPF, CAP_PERFMON, and writable cgroups"]
async fn live_daemon_observer_tracks_two_cgroups_and_excludes_untracked_work() {
    let root = workspace_root();
    let object = root.join("target/ebpf/apolysis_observer.bpf.o");
    let observer =
        DaemonObserver::load(DaemonObserverConfig::new(&object)).expect("load daemon observer");
    let temporary = std::env::temp_dir().join(format!("apolysis-f2-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&temporary);
    std::fs::create_dir_all(&temporary).expect("create temporary directory");
    let executable_a = temporary.join("apolf2a");
    let executable_b = temporary.join("apolf2b");
    let executable_untracked = temporary.join("apolf2x");
    symlink("/bin/true", &executable_a).expect("create executable A");
    symlink("/bin/true", &executable_b).expect("create executable B");
    symlink("/bin/true", &executable_untracked).expect("create untracked executable");

    let cgroup_parent = current_cgroup_path();
    let suffix = format!("{}-{}", std::process::id(), now_ms());
    let cgroup_a = cgroup_parent.join(format!("apolysis-f2-a-{suffix}"));
    let cgroup_b = cgroup_parent.join(format!("apolysis-f2-b-{suffix}"));
    std::fs::create_dir(&cgroup_a).expect("create cgroup A");
    std::fs::create_dir(&cgroup_b).expect("create cgroup B");
    let cleanup = LiveCleanup {
        temporary: temporary.clone(),
        cgroups: vec![cgroup_a.clone(), cgroup_b.clone()],
    };
    let cgroup_id_a = std::fs::metadata(&cgroup_a).expect("stat cgroup A").ino();
    let cgroup_id_b = std::fs::metadata(&cgroup_b).expect("stat cgroup B").ino();

    let config = DaemonConfig {
        socket_path: temporary.join("run/apolysisd.sock"),
        state_dir: temporary.join("state"),
        queue_capacity: 1024,
        ..DaemonConfig::default()
    };
    let (scope, scope_receiver) = scope_channel(config.scope_command_capacity);
    let state = Arc::new(DaemonState::new_with_scope(&config, Some(scope)).expect("daemon state"));
    let (writer_shutdown, writer_receiver) = oneshot::channel();
    let writer = {
        let state = Arc::clone(&state);
        tokio::spawn(async move { state.run_writer(writer_receiver).await })
    };
    let (observer_shutdown, observer_receiver) = oneshot::channel();
    let runtime = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            run_observer_runtime(
                observer,
                Vec::new(),
                scope_receiver,
                state,
                observer_receiver,
            )
            .await
        })
    };

    state
        .register(intent("live-a"), now_ms())
        .await
        .expect("register session A");
    state
        .register(intent("live-b"), now_ms())
        .await
        .expect("register session B");
    state
        .discover_cgroup("live-a", cgroup_id_a)
        .await
        .expect("track cgroup A");
    state
        .discover_cgroup("live-b", cgroup_id_b)
        .await
        .expect("track cgroup B");

    run_in_cgroup(&cgroup_a, &executable_a);
    run_in_cgroup(&cgroup_b, &executable_b);
    assert!(Command::new(&executable_untracked)
        .status()
        .expect("run untracked executable")
        .success());
    tokio::time::sleep(Duration::from_millis(500)).await;

    observer_shutdown.send(()).unwrap();
    let observer_summary = runtime.await.unwrap().expect("clean observer shutdown");
    writer_shutdown.send(()).unwrap();
    writer.await.unwrap().expect("clean writer shutdown");

    assert!(observer_summary.ingest.submitted > 0);
    let timeline_a = timeline(&config, "live-a");
    let timeline_b = timeline(&config, "live-b");
    assert!(timeline_a.contains(executable_a.to_str().expect("UTF-8 path")));
    assert!(timeline_b.contains(executable_b.to_str().expect("UTF-8 path")));
    assert!(!timeline_a.contains(executable_untracked.to_str().expect("UTF-8 path")));
    assert!(!timeline_b.contains(executable_untracked.to_str().expect("UTF-8 path")));

    drop(cleanup);
}

fn run_in_cgroup(cgroup: &std::path::Path, executable: &std::path::Path) {
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "sleep 0.2; exec \"$1\"",
            "apolysis-stage",
            executable.to_str().expect("UTF-8 executable path"),
        ])
        .spawn()
        .expect("spawn staged executable");
    std::fs::write(cgroup.join("cgroup.procs"), child.id().to_string())
        .expect("move process into cgroup");
    assert!(child.wait().expect("wait for staged executable").success());
}

fn timeline(config: &DaemonConfig, session_id: &str) -> String {
    std::fs::read_to_string(
        config
            .state_dir
            .join("sessions")
            .join(session_id)
            .join("timeline.jsonl"),
    )
    .expect("read session timeline")
}

fn intent(session_id: &str) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        tenant_id: apolysis_accountability::DEFAULT_TENANT_ID.to_string(),
        retention_tier: apolysis_accountability::RetentionTier::Standard,
        session_id: session_id.to_string(),
        expires_at_unix_ms: 4_102_444_800_000,
        declared_actions: vec![ActionClass::Execute],
        allowed_resources: Vec::new(),
        policy_ref: "policies/local-dev.yaml".to_string(),
        workload_selectors: Vec::new(),
    }
}

fn current_cgroup_path() -> std::path::PathBuf {
    let cgroup = std::fs::read_to_string("/proc/self/cgroup").expect("read process cgroup");
    let relative = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("cgroup v2 entry");
    std::path::Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/'))
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn now_ms() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after Unix epoch")
        .as_millis();
    u64::try_from(millis).expect("timestamp fits u64")
}

struct LiveCleanup {
    temporary: std::path::PathBuf,
    cgroups: Vec<std::path::PathBuf>,
}

impl Drop for LiveCleanup {
    fn drop(&mut self) {
        for cgroup in self.cgroups.iter().rev() {
            let _ = std::fs::remove_dir(cgroup);
        }
        let _ = std::fs::remove_dir_all(&self.temporary);
    }
}
