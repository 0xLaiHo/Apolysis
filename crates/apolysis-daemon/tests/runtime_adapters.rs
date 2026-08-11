// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::future::Future;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::pin::Pin;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use apolysis_accountability::{
    ActionClass, AdapterKind, AssociationOutcome, ComponentState, ResourceKind, ResourceSelector,
    SessionIntent, SessionStatus,
};
use apolysis_daemon::{
    adapter_backoff_delay, cgroup_id_from_cri_inspect_cgroups_path, cgroup_id_from_proc_cgroup,
    containerd_task_snapshot_from_cri_inspect, containerd_task_snapshot_from_metadata,
    containerd_workload_from_snapshot, crictl_marked_container_candidates_from_ps_and_pods,
    crictl_marked_container_ids_from_ps, docker_container_pid_from_engine_inspect,
    docker_snapshot_from_engine_inspect, docker_workload_from_snapshot,
    kubernetes_marked_pod_snapshots_from_api_list, kubernetes_pod_snapshot_from_api_object,
    kubernetes_workload_from_pod_snapshot, run_runtime_adapter_with_policy,
    run_runtime_inventory_adapter_with_policy, serve, AdapterBackoffPolicy, CgroupIdentity,
    ContainerdCriRuntimeAdapter, ContainerdTaskSnapshot, CriRuntimeClient, DaemonConfig,
    DaemonResponse, DaemonState, DockerContainerSnapshot, DockerEngineClient,
    DockerEnginePollingRuntimeAdapter, DockerEngineRuntimeAdapter, KubernetesCliClient,
    KubernetesCliRuntimeAdapter, KubernetesPodSnapshot, RuntimeAdapterBackend, RuntimeBinding,
    RuntimeInventory, RuntimeInventoryAdapter, RuntimeInventoryInvalidCategory,
    RuntimeInventoryScanError, RuntimeSourceGapReason, RuntimeWorkload, RuntimeWorkloadIdentity,
    APOLYSIS_SESSION_ANNOTATION,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
// The fake crictl scripts use distinct paths and inodes, but concurrent write-to-exec lifecycles
// on the test host's tmpfs repeatedly produced execve ETXTBSY. Each script-backed test holds this
// lease from before publication through every exec and final cleanup; production adapters remain
// fully concurrent.
static EXECUTABLE_FIXTURE_TEST_LEASE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const LIVE_CRICTL_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_LIVE_CRICTL_OUTPUT_BYTES: usize = 1024 * 1024;

#[tokio::test]
async fn docker_complete_inventory_contains_every_marked_stable_runtime_identity() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-complete-inventory-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let first_cgroup = cgroup_root.join("docker/first");
    let second_cgroup = cgroup_root.join("docker/second");
    let _ = std::fs::remove_dir_all(&root);
    write_runtime_identity_fixture(&proc_root, 1111, 41, "/docker/first");
    write_runtime_identity_fixture(&proc_root, 2222, 84, "/docker/second");
    std::fs::create_dir_all(&first_cgroup).expect("create first fake cgroup");
    std::fs::create_dir_all(&second_cgroup).expect("create second fake cgroup");

    let listener = UnixListener::bind(&socket).expect("bind fake docker socket");
    let first = json!({
        "Id": "1111111111111111111111111111111111111111111111111111111111111111",
        "State": {
            "Pid": 1111,
            "Running": true,
            "StartedAt": "2026-08-11T01:02:03.000000000Z"
        },
        "Config": {
            "Labels": {"apolysis.session_id": "agent-run-first"}
        },
        "HostConfig": {"Runtime": "runc"}
    });
    let second = json!({
        "Id": "2222222222222222222222222222222222222222222222222222222222222222",
        "State": {
            "Pid": 2222,
            "Running": true,
            "StartedAt": "2026-08-11T01:02:04.000000000Z"
        },
        "Config": {
            "Labels": {"apolysis.session_id": "agent-run-second"}
        },
        "HostConfig": {"Runtime": "runsc"}
    });
    let listed = json!([
        {"Id":"1111111111111111111111111111111111111111111111111111111111111111","Labels":{"apolysis.session_id":"agent-run-first"}},
        {"Id":"2222222222222222222222222222222222222222222222222222222222222222","Labels":{"apolysis.session_id":"agent-run-second"}}
    ]);
    let server = tokio::spawn(serve_fake_docker_responses(
        listener,
        vec![
            ("/containers/json".to_string(), listed.clone()),
            (
                "/containers/1111111111111111111111111111111111111111111111111111111111111111/json"
                    .to_string(),
                first.clone(),
            ),
            (
                "/containers/1111111111111111111111111111111111111111111111111111111111111111/json"
                    .to_string(),
                first,
            ),
            (
                "/containers/2222222222222222222222222222222222222222222222222222222222222222/json"
                    .to_string(),
                second.clone(),
            ),
            (
                "/containers/2222222222222222222222222222222222222222222222222222222222222222/json"
                    .to_string(),
                second,
            ),
            ("/containers/json".to_string(), listed),
        ],
    ));
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    );

    let inventory = adapter
        .scan_inventory()
        .await
        .expect("one complete Docker inventory");

    assert_eq!(inventory.adapter, AdapterKind::Docker);
    assert_eq!(inventory.bindings.len(), 2);
    assert_eq!(inventory.bindings[0].agent_run_id, "agent-run-first");
    assert_eq!(
        inventory.bindings[0].identity.workload_id,
        "1111111111111111111111111111111111111111111111111111111111111111"
    );
    assert_eq!(
        inventory.bindings[0].identity.start_marker,
        "2026-08-11T01:02:03.000000000Z"
    );
    assert_eq!(
        inventory.bindings[0].identity.host_boot_id,
        "82b46386-b87a-4d86-93f6-232bb04c37fb"
    );
    assert_eq!(
        inventory.bindings[0].identity.init_process_start_time_ticks,
        41
    );
    assert_eq!(
        inventory.bindings[0].identity.cgroup.device,
        std::fs::metadata(&first_cgroup).unwrap().dev()
    );
    assert_eq!(
        inventory.bindings[0].identity.cgroup.inode,
        std::fs::metadata(&first_cgroup).unwrap().ino()
    );
    assert_eq!(inventory.bindings[1].agent_run_id, "agent-run-second");
    assert_eq!(
        inventory.bindings[1].identity.init_process_start_time_ticks,
        84
    );
    assert_eq!(
        inventory.bindings[1].identity.cgroup.inode,
        std::fs::metadata(&second_cgroup).unwrap().ino()
    );
    server.await.expect("fake Docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_inventory_fails_closed_when_a_candidate_appears_after_qualification() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-candidate-appeared-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let container_id = "1111111111111111111111111111111111111111111111111111111111111111";
    let appeared_id = "2222222222222222222222222222222222222222222222222222222222222222";
    write_runtime_identity_fixture(&proc_root, 1111, 41, "/docker/stable");
    std::fs::create_dir_all(cgroup_root.join("docker/stable")).expect("create stable fake cgroup");
    let listed = json!([{
        "Id": container_id,
        "Labels": {"apolysis.session_id": "agent-run-stable"}
    }]);
    let inspect = json!({
        "Id": container_id,
        "State": {
            "Pid": 1111,
            "Running": true,
            "StartedAt": "2026-08-11T01:02:03.000000000Z"
        },
        "Config": {"Labels": {"apolysis.session_id": "agent-run-stable"}},
        "HostConfig": {"Runtime": "runc"}
    });
    let listener = UnixListener::bind(&socket).expect("bind fake Docker socket");
    let server = tokio::spawn(serve_fake_docker_responses(
        listener,
        vec![
            ("/containers/json".to_string(), listed.clone()),
            (format!("/containers/{container_id}/json"), inspect.clone()),
            (format!("/containers/{container_id}/json"), inspect),
            (
                "/containers/json".to_string(),
                json!([
                    {"Id":container_id,"Labels":{"apolysis.session_id":"agent-run-stable"}},
                    {"Id":appeared_id,"Labels":{"apolysis.session_id":"agent-run-appeared"}}
                ]),
            ),
        ],
    ));
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    );

    let result = RuntimeInventoryAdapter::scan_inventory(&adapter).await;
    if result.is_ok() {
        server.abort();
    }
    let _ = server.await;
    let _ = std::fs::remove_dir_all(&root);
    let error = result.expect_err("candidate-set churn must invalidate the complete inventory");

    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    assert_eq!(
        error.inventory_invalid_category(),
        Some(RuntimeInventoryInvalidCategory::DoubleInspect)
    );
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    assert!(!format!("{error:?}").contains(appeared_id));
}

#[tokio::test]
async fn docker_inventory_rejects_more_than_the_bounded_candidate_set_before_inspect() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-candidate-bound-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    std::fs::create_dir_all(proc_root.join("sys/kernel/random")).expect("create fake proc sys");
    std::fs::write(
        proc_root.join("sys/kernel/random/boot_id"),
        "82b46386-b87a-4d86-93f6-232bb04c37fb\n",
    )
    .expect("write fake host boot id");
    let candidates = (0..4097)
        .map(|index| {
            json!({
                "Id": format!("{index:064x}"),
                "Labels": {"apolysis.session_id": "agent-run-bounded"}
            })
        })
        .collect::<Vec<_>>();
    let listener = UnixListener::bind(&socket).expect("bind fake Docker socket");
    let server = tokio::spawn(serve_fake_docker_responses(
        listener,
        vec![("/containers/json".to_string(), json!(candidates))],
    ));
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        root.join("sys/fs/cgroup"),
        Duration::from_millis(1),
        32,
    );

    let error = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .expect_err("oversized candidate set must fail before any inspect request");

    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    server.await.expect("bounded fake Docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_inventory_rejects_a_noncanonical_runtime_id_before_it_can_be_persisted() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-runtime-id-boundary-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    std::fs::create_dir_all(proc_root.join("sys/kernel/random")).expect("create fake proc sys");
    std::fs::write(
        proc_root.join("sys/kernel/random/boot_id"),
        "82b46386-b87a-4d86-93f6-232bb04c37fb\n",
    )
    .expect("write fake host boot id");
    let listener = UnixListener::bind(&socket).expect("bind fake Docker socket");
    let server = tokio::spawn(serve_fake_docker_responses(
        listener,
        vec![(
            "/containers/json".to_string(),
            json!([{
                "Id": "private-team-sensitive-agent",
                "Labels": {"apolysis.session_id": "agent-run-private"}
            }]),
        )],
    ));
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        root.join("sys/fs/cgroup"),
        Duration::from_millis(1),
        32,
    );

    let error = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .expect_err("noncanonical runtime IDs must fail at the adapter boundary");

    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    server
        .await
        .expect("runtime ID boundary fake Docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_inventory_fails_closed_when_inspect_generation_changes_at_the_same_pid() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-inspect-churn-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    write_runtime_identity_fixture(&proc_root, 3333, 77, "/docker/reused");
    std::fs::create_dir_all(cgroup_root.join("docker/reused")).expect("create fake cgroup");
    let listener = UnixListener::bind(&socket).expect("bind fake docker socket");
    let inspect = |started_at: &str| {
        json!({
            "Id": "3333333333333333333333333333333333333333333333333333333333333333",
            "State": {"Pid": 3333, "Running": true, "StartedAt": started_at},
            "Config": {"Labels": {"apolysis.session_id": "agent-run-reused"}},
            "HostConfig": {"Runtime": "runc"}
        })
    };
    let server = tokio::spawn(serve_fake_docker_responses(
        listener,
        vec![
            (
                "/containers/json".to_string(),
                json!([{"Id":"3333333333333333333333333333333333333333333333333333333333333333","Labels":{"apolysis.session_id":"agent-run-reused"}}]),
            ),
            (
                "/containers/3333333333333333333333333333333333333333333333333333333333333333/json"
                    .to_string(),
                inspect("2026-08-11T01:02:03.000000000Z"),
            ),
            (
                "/containers/3333333333333333333333333333333333333333333333333333333333333333/json"
                    .to_string(),
                inspect("2026-08-11T01:02:09.000000000Z"),
            ),
        ],
    ));
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    );

    let error = adapter
        .scan_inventory()
        .await
        .expect_err("inspect churn must invalidate the inventory");

    assert_eq!(error, "runtime inventory scan failed: inventory_invalid");
    server.await.expect("fake Docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_inventory_fails_closed_when_the_pid_start_generation_changes_mid_scan() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-pid-reuse-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    write_runtime_identity_fixture(&proc_root, 3888, 700, "/docker/pid-reuse");
    std::fs::create_dir_all(cgroup_root.join("docker/pid-reuse")).expect("create fake cgroup");
    let listener = UnixListener::bind(&socket).expect("bind fake docker socket");
    let inspect = json!({
        "Id":"4444444444444444444444444444444444444444444444444444444444444444",
        "State":{"Pid":3888,"Running":true,"StartedAt":"2026-08-11T01:02:03.000000000Z"},
        "Config":{"Labels":{"apolysis.session_id":"agent-run-pid-reuse"}}
    });
    let replacement_stat = format!(
        "3888 (replacement init) S {} 701\n",
        vec!["0"; 18].join(" ")
    );
    let server = tokio::spawn(serve_fake_docker_responses_with_file_replacement(
        listener,
        vec![
            (
                "/containers/json".to_string(),
                json!([{"Id":"4444444444444444444444444444444444444444444444444444444444444444","Labels":{"apolysis.session_id":"agent-run-pid-reuse"}}]),
            ),
            (
                "/containers/4444444444444444444444444444444444444444444444444444444444444444/json"
                    .to_string(),
                inspect.clone(),
            ),
            (
                "/containers/4444444444444444444444444444444444444444444444444444444444444444/json"
                    .to_string(),
                inspect,
            ),
        ],
        2,
        proc_root.join("3888/stat"),
        replacement_stat,
    ));
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    );

    let error = adapter
        .scan_inventory()
        .await
        .expect_err("PID reuse during proof must invalidate the inventory");

    assert_eq!(error, "runtime inventory scan failed: inventory_invalid");
    server.await.expect("fake Docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_inventory_exposes_new_process_and_cgroup_generations_for_the_same_workload_id() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-runtime-generation-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let cgroup = cgroup_root.join("docker/generation");
    write_runtime_identity_fixture(&proc_root, 6666, 101, "/docker/generation");
    std::fs::create_dir_all(&cgroup).expect("create first cgroup generation");
    let listener = UnixListener::bind(&socket).expect("bind fake docker socket");
    let listed = json!([
        {"Id":"5555555555555555555555555555555555555555555555555555555555555555","Labels":{"apolysis.session_id":"agent-run-generation"}}
    ]);
    let inspect = |start_marker: &str| {
        json!({
            "Id": "5555555555555555555555555555555555555555555555555555555555555555",
            "State": {"Pid": 6666, "Running": true, "StartedAt": start_marker},
            "Config": {"Labels": {"apolysis.session_id": "agent-run-generation"}},
            "HostConfig": {"Runtime": "runc"}
        })
    };
    let server = tokio::spawn(serve_fake_docker_responses(
        listener,
        vec![
            ("/containers/json".to_string(), listed.clone()),
            (
                "/containers/5555555555555555555555555555555555555555555555555555555555555555/json"
                    .to_string(),
                inspect("2026-08-11T01:02:03.000000000Z"),
            ),
            (
                "/containers/5555555555555555555555555555555555555555555555555555555555555555/json"
                    .to_string(),
                inspect("2026-08-11T01:02:03.000000000Z"),
            ),
            ("/containers/json".to_string(), listed.clone()),
            ("/containers/json".to_string(), listed.clone()),
            (
                "/containers/5555555555555555555555555555555555555555555555555555555555555555/json"
                    .to_string(),
                inspect("2026-08-11T01:03:03.000000000Z"),
            ),
            (
                "/containers/5555555555555555555555555555555555555555555555555555555555555555/json"
                    .to_string(),
                inspect("2026-08-11T01:03:03.000000000Z"),
            ),
            ("/containers/json".to_string(), listed),
        ],
    ));
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    );

    let first = adapter.scan_inventory().await.expect("first inventory");
    let old_cgroup = cgroup_root.join("docker/generation-retired");
    std::fs::rename(&cgroup, &old_cgroup).expect("retain old cgroup inode");
    std::fs::create_dir(&cgroup).expect("create replacement cgroup generation");
    write_runtime_identity_fixture(&proc_root, 6666, 202, "/docker/generation");
    let second = adapter.scan_inventory().await.expect("second inventory");

    let first_identity = &first.bindings[0].identity;
    let second_identity = &second.bindings[0].identity;
    assert_eq!(first_identity.workload_id, second_identity.workload_id);
    assert_ne!(first_identity.start_marker, second_identity.start_marker);
    assert_ne!(
        first_identity.init_process_start_time_ticks,
        second_identity.init_process_start_time_ticks
    );
    assert_eq!(first_identity.cgroup.device, second_identity.cgroup.device);
    assert_ne!(first_identity.cgroup.inode, second_identity.cgroup.inode);
    server.await.expect("fake Docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_inventory_does_not_return_a_partial_snapshot_when_one_candidate_is_invalid() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-invalid-inventory-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    write_runtime_identity_fixture(&proc_root, 7001, 10, "/docker/valid");
    write_runtime_identity_fixture(&proc_root, 7002, 20, "/docker/invalid");
    std::fs::create_dir_all(cgroup_root.join("docker/valid")).expect("create valid cgroup");
    std::fs::create_dir_all(cgroup_root.join("docker/invalid")).expect("create invalid cgroup");
    let listener = UnixListener::bind(&socket).expect("bind fake docker socket");
    let valid = json!({
        "Id":"6666666666666666666666666666666666666666666666666666666666666666",
        "State":{"Pid":7001,"Running":true,"StartedAt":"2026-08-11T01:02:03.000000000Z"},
        "Config":{"Labels":{"apolysis.session_id":"agent-run-valid"}}
    });
    let invalid = json!({
        "Id":"7777777777777777777777777777777777777777777777777777777777777777",
        "State":{"Pid":7002,"Running":true},
        "Config":{"Labels":{"apolysis.session_id":"agent-run-invalid"}}
    });
    let server = tokio::spawn(serve_fake_docker_responses(
        listener,
        vec![
            (
                "/containers/json".to_string(),
                json!([
                    {"Id":"6666666666666666666666666666666666666666666666666666666666666666","Labels":{"apolysis.session_id":"agent-run-valid"}},
                    {"Id":"7777777777777777777777777777777777777777777777777777777777777777","Labels":{"apolysis.session_id":"agent-run-invalid"}}
                ]),
            ),
            (
                "/containers/6666666666666666666666666666666666666666666666666666666666666666/json"
                    .to_string(),
                valid.clone(),
            ),
            (
                "/containers/6666666666666666666666666666666666666666666666666666666666666666/json"
                    .to_string(),
                valid,
            ),
            (
                "/containers/7777777777777777777777777777777777777777777777777777777777777777/json"
                    .to_string(),
                invalid,
            ),
        ],
    ));
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    );

    let error = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .expect_err("one invalid candidate invalidates the complete inventory");

    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    server.await.expect("fake Docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_inventory_rejects_empty_zero_time_and_oversized_start_markers() {
    let oversized = format!("2026-{}Z", "1".repeat(160));
    for (case, start_marker) in [
        ("empty", "".to_string()),
        ("zero-time", "0001-01-01T00:00:00Z".to_string()),
        (
            "zero-time-nanos",
            "0001-01-01T00:00:00.000000000Z".to_string(),
        ),
        ("oversized", oversized),
    ] {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "apolysis-docker-start-marker-{case}-{}-{id}",
            std::process::id()
        ));
        let socket = root.join("docker.sock");
        let proc_root = root.join("proc");
        std::fs::create_dir_all(proc_root.join("sys/kernel/random")).expect("create fake proc sys");
        std::fs::write(
            proc_root.join("sys/kernel/random/boot_id"),
            "82b46386-b87a-4d86-93f6-232bb04c37fb\n",
        )
        .expect("write fake host boot id");
        let listener = UnixListener::bind(&socket).expect("bind fake Docker socket");
        let server = tokio::spawn(serve_fake_docker_responses(
            listener,
            vec![
                (
                    "/containers/json".to_string(),
                    json!([{"Id":"8888888888888888888888888888888888888888888888888888888888888888","Labels":{"apolysis.session_id":"agent-run-invalid-start"}}]),
                ),
                (
                    "/containers/8888888888888888888888888888888888888888888888888888888888888888/json".to_string(),
                    json!({
                        "Id":"8888888888888888888888888888888888888888888888888888888888888888",
                        "State":{"Pid":1234,"Running":true,"StartedAt":start_marker},
                        "Config":{"Labels":{"apolysis.session_id":"agent-run-invalid-start"}}
                    }),
                ),
            ],
        ));
        let adapter = DockerEnginePollingRuntimeAdapter::new(
            DockerEngineClient::new(&socket),
            &proc_root,
            root.join("sys/fs/cgroup"),
            Duration::from_millis(1),
            32,
        );

        let error = RuntimeInventoryAdapter::scan_inventory(&adapter)
            .await
            .expect_err("invalid Docker start marker must invalidate inventory");

        assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
        assert_eq!(
            error.to_string(),
            "runtime inventory scan failed: inventory_invalid"
        );
        server.await.expect("fake Docker server");
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn docker_inventory_rejects_a_free_text_started_at_marker() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-start-marker-vocabulary-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let container_id = "8989898989898989898989898989898989898989898989898989898989898989";
    write_runtime_identity_fixture(&proc_root, 4321, 55, "/docker/marker");
    std::fs::create_dir_all(cgroup_root.join("docker/marker")).expect("create fake cgroup");
    let inspect = json!({
        "Id": container_id,
        "State": {
            "Pid": 4321,
            "Running": true,
            "StartedAt": "private/team/start-marker"
        },
        "Config": {"Labels": {"apolysis.session_id": "agent-run-marker"}}
    });
    let listener = UnixListener::bind(&socket).expect("bind fake Docker socket");
    let server = tokio::spawn(serve_fake_docker_responses(
        listener,
        vec![
            (
                "/containers/json".to_string(),
                json!([{"Id":container_id,"Labels":{"apolysis.session_id":"agent-run-marker"}}]),
            ),
            (format!("/containers/{container_id}/json"), inspect.clone()),
            (format!("/containers/{container_id}/json"), inspect),
        ],
    ));
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    );

    let error = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .expect_err("Docker StartedAt must not persist free text");

    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn containerd_complete_inventory_contains_every_marked_stable_runtime_identity() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-complete-inventory-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let first_cgroup = cgroup_root.join("containerd/first");
    let second_cgroup = cgroup_root.join("containerd/second");
    let crictl = root.join("crictl-fixture");
    let _ = std::fs::remove_dir_all(&root);
    write_runtime_identity_fixture(&proc_root, 4444, 91, "/containerd/first");
    write_runtime_identity_fixture(&proc_root, 5555, 123, "/containerd/second");
    std::fs::create_dir_all(&first_cgroup).expect("create first fake cgroup");
    std::fs::create_dir_all(&second_cgroup).expect("create second fake cgroup");
    write_executable_fixture(
        &crictl,
        r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    printf '%s\n' '{"containers":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-first"}},{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-second"}}]}'
    ;;
  *" pods -o json "*)
    printf '%s\n' '{"items":[]}'
    ;;
  *" inspect -o json aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "*)
    printf '%s\n' '{"status":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"CONTAINER_RUNNING","startedAt":"1754874123000000000","labels":{"apolysis.session_id":"agent-run-first","io.kubernetes.pod.namespace":"private-team-namespace"},"image":{"runtimeHandler":"runc"}},"info":{"pid":4444,"runtimeType":"io.containerd.runc.v2","runtimeSpec":{"linux":{"cgroupsPath":"/containerd/first"}}}}'
    ;;
  *" inspect -o json bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "*)
    printf '%s\n' '{"status":{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"CONTAINER_RUNNING","startedAt":1754874124000000000,"labels":{"apolysis.session_id":"agent-run-second","io.kubernetes.pod.namespace":"private-team-namespace"},"image":{"runtimeHandler":"runsc"}},"info":{"pid":5555,"runtimeType":"io.containerd.runsc.v1","runtimeSpec":{"linux":{"cgroupsPath":"/containerd/second"}}}}'
    ;;
  *)
    printf '%s\n' "unexpected crictl invocation: $*" >&2
    exit 64
    ;;
esac
"#,
    );
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("unused-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("containerd inventory adapter");

    let inventory = adapter
        .scan_inventory()
        .await
        .expect("one complete containerd inventory");

    assert_eq!(inventory.adapter, AdapterKind::Containerd);
    assert_eq!(inventory.bindings.len(), 2);
    assert_eq!(inventory.bindings[0].agent_run_id, "agent-run-first");
    assert_eq!(
        inventory.bindings[0].identity.workload_id,
        "containerd/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(
        inventory.bindings[0].identity.start_marker,
        "1754874123000000000"
    );
    assert_eq!(
        inventory.bindings[0].identity.init_process_start_time_ticks,
        91
    );
    assert_eq!(
        inventory.bindings[0].identity.cgroup.device,
        std::fs::metadata(&first_cgroup).unwrap().dev()
    );
    assert_eq!(
        inventory.bindings[0].identity.cgroup.inode,
        std::fs::metadata(&first_cgroup).unwrap().ino()
    );
    assert_eq!(
        inventory.bindings[1].identity.start_marker,
        "1754874124000000000"
    );
    assert_eq!(
        inventory.bindings[1].identity.cgroup.inode,
        std::fs::metadata(&second_cgroup).unwrap().ino()
    );
    let persisted = serde_json::to_string(&inventory.bindings).expect("serialize bindings");
    assert!(!persisted.contains("private-team-namespace"));

    let k3s = ContainerdCriRuntimeAdapter::new(
        AdapterKind::K3sContainerd,
        CriRuntimeClient::new(root.join("unused-k3s-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("k3s containerd inventory adapter");
    let k3s_inventory = k3s
        .scan_inventory()
        .await
        .expect("one complete k3s containerd inventory");
    assert_eq!(k3s_inventory.adapter, AdapterKind::K3sContainerd);
    assert_eq!(
        k3s_inventory.bindings[0].identity.workload_id,
        "k3s_containerd/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    let k3s_persisted =
        serde_json::to_string(&k3s_inventory.bindings).expect("serialize k3s bindings");
    assert!(!k3s_persisted.contains("private-team-namespace"));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn containerd_inventory_normalizes_rfc3339_nano_started_at_to_decimal_nanoseconds() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-rfc3339nano-started-at-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let crictl = root.join("crictl-fixture");
    let _ = std::fs::remove_dir_all(&root);
    write_runtime_identity_fixture(&proc_root, 4444, 91, "/containerd/rfc3339nano");
    write_runtime_identity_fixture(&proc_root, 5555, 92, "/containerd/rfc3339nano-offset");
    write_runtime_identity_fixture(
        &proc_root,
        6666,
        93,
        "/containerd/rfc3339nano-half-hour-offset",
    );
    write_runtime_identity_fixture(
        &proc_root,
        7777,
        94,
        "/containerd/rfc3339nano-negative-offset",
    );
    std::fs::create_dir_all(cgroup_root.join("containerd/rfc3339nano"))
        .expect("create RFC3339Nano fixture cgroup");
    std::fs::create_dir_all(cgroup_root.join("containerd/rfc3339nano-offset"))
        .expect("create offset RFC3339Nano fixture cgroup");
    std::fs::create_dir_all(cgroup_root.join("containerd/rfc3339nano-half-hour-offset"))
        .expect("create half-hour offset RFC3339Nano fixture cgroup");
    std::fs::create_dir_all(cgroup_root.join("containerd/rfc3339nano-negative-offset"))
        .expect("create negative offset RFC3339Nano fixture cgroup");
    write_executable_fixture(
        &crictl,
        r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    printf '%s\n' '{"containers":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-rfc3339nano"}},{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-rfc3339nano-offset"}},{"id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-rfc3339nano-half-hour-offset"}},{"id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-rfc3339nano-negative-offset"}}]}'
    ;;
  *" inspect -o json aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "*)
    printf '%s\n' '{"status":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"CONTAINER_RUNNING","startedAt":"2026-08-11T01:02:03.123456789Z","labels":{"apolysis.session_id":"agent-run-rfc3339nano"}},"info":{"pid":4444,"runtimeType":"io.containerd.runc.v2","runtimeSpec":{"linux":{"cgroupsPath":"/containerd/rfc3339nano"}}}}'
    ;;
  *" inspect -o json bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "*)
    printf '%s\n' '{"status":{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"CONTAINER_RUNNING","startedAt":"2026-08-11T09:02:03.123456789+08:00","labels":{"apolysis.session_id":"agent-run-rfc3339nano-offset"}},"info":{"pid":5555,"runtimeType":"io.containerd.runc.v2","runtimeSpec":{"linux":{"cgroupsPath":"/containerd/rfc3339nano-offset"}}}}'
    ;;
  *" inspect -o json cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc "*)
    printf '%s\n' '{"status":{"id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","state":"CONTAINER_RUNNING","startedAt":"2026-08-11T07:30:00.000000001+05:30","labels":{"apolysis.session_id":"agent-run-rfc3339nano-half-hour-offset"}},"info":{"pid":6666,"runtimeType":"io.containerd.runc.v2","runtimeSpec":{"linux":{"cgroupsPath":"/containerd/rfc3339nano-half-hour-offset"}}}}'
    ;;
  *" inspect -o json dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd "*)
    printf '%s\n' '{"status":{"id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","state":"CONTAINER_RUNNING","startedAt":"2026-08-10T21:00:00.987654321-04:00","labels":{"apolysis.session_id":"agent-run-rfc3339nano-negative-offset"}},"info":{"pid":7777,"runtimeType":"io.containerd.runc.v2","runtimeSpec":{"linux":{"cgroupsPath":"/containerd/rfc3339nano-negative-offset"}}}}'
    ;;
  *) exit 64 ;;
esac
"#,
    );
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("unused-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("containerd RFC3339Nano inventory adapter");

    let inventory = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .expect("RFC3339Nano startedAt must qualify");

    assert_eq!(inventory.bindings.len(), 4);
    assert_eq!(
        inventory.bindings[0].identity.start_marker,
        "1786410123123456789"
    );
    assert_eq!(
        inventory.bindings[1].identity.start_marker,
        "1786410123123456789"
    );
    assert_eq!(
        inventory.bindings[2].identity.start_marker,
        "1786413600000000001"
    );
    assert_eq!(
        inventory.bindings[3].identity.start_marker,
        "1786410000987654321"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn containerd_inventory_failure_categories_are_fixed_and_private() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-private-diagnostic-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("hostile-private-crictl");
    write_executable_fixture(
        &crictl,
        "#!/bin/sh\nprintf '%s\\n' 'hostile-private-stderr-path-id-label' >&2\nexit 97\n",
    );
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("hostile-private-runtime.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        root.join("hostile-private-proc"),
        root.join("hostile-private-cgroup"),
        Duration::from_millis(1),
        32,
    )
    .expect("containerd diagnostic adapter");

    let error = match RuntimeInventoryAdapter::scan_inventory(&adapter).await {
        Err(error) => error,
        Ok(_) => panic!("missing boot identity unexpectedly passed inventory validation"),
    };

    assert_eq!(
        error.inventory_invalid_category(),
        Some(RuntimeInventoryInvalidCategory::HostBoot)
    );
    assert_eq!(
        error
            .inventory_invalid_category()
            .expect("fixed invalid category")
            .code(),
        "host_boot"
    );
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    let debug = format!("{error:?}");
    for hostile in [
        "hostile-private",
        root.to_str().expect("diagnostic root UTF-8"),
    ] {
        assert!(!error.to_string().contains(hostile));
        assert!(!debug.contains(hostile));
    }
    let _ = std::fs::remove_dir_all(&root);

    let list_root = std::env::temp_dir().join(format!(
        "apolysis-containerd-private-list-diagnostic-{}-{id}",
        std::process::id()
    ));
    let proc_root = list_root.join("proc");
    let crictl = list_root.join("crictl");
    write_runtime_identity_fixture(&proc_root, 4242, 77, "/containerd/private");
    write_executable_fixture(
        &crictl,
        "#!/bin/sh\nprintf '%s\\n' '{\"hostile-private-list-shape\":true}'\n",
    );
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(list_root.join("hostile-private-runtime.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        list_root.join("sys/fs/cgroup"),
        Duration::from_millis(1),
        32,
    )
    .expect("containerd list diagnostic adapter");
    let error = match RuntimeInventoryAdapter::scan_inventory(&adapter).await {
        Err(error) => error,
        Ok(_) => panic!("invalid list shape unexpectedly passed inventory validation"),
    };
    assert_eq!(
        error.inventory_invalid_category(),
        Some(RuntimeInventoryInvalidCategory::List)
    );
    assert_eq!(
        error
            .inventory_invalid_category()
            .expect("list category")
            .code(),
        "list"
    );
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    assert!(!format!("{error:?}").contains("hostile-private"));
    let _ = std::fs::remove_dir_all(&list_root);

    let id_root = std::env::temp_dir().join(format!(
        "apolysis-containerd-private-id-diagnostic-{}-{id}",
        std::process::id()
    ));
    let proc_root = id_root.join("proc");
    let crictl = id_root.join("crictl");
    write_runtime_identity_fixture(&proc_root, 4242, 77, "/containerd/private");
    write_executable_fixture(
        &crictl,
        r#"#!/bin/sh
printf '%s\n' '{"containers":[{"id":"hostile/private-id","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"hostile-private-label"}}]}'
"#,
    );
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(id_root.join("hostile-private-runtime.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        id_root.join("sys/fs/cgroup"),
        Duration::from_millis(1),
        32,
    )
    .expect("containerd id diagnostic adapter");
    let error = match RuntimeInventoryAdapter::scan_inventory(&adapter).await {
        Err(error) => error,
        Ok(_) => panic!("invalid candidate id unexpectedly passed inventory validation"),
    };
    assert_eq!(
        error.inventory_invalid_category(),
        Some(RuntimeInventoryInvalidCategory::Id)
    );
    assert_eq!(
        error
            .inventory_invalid_category()
            .expect("id category")
            .code(),
        "id"
    );
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    assert!(!format!("{error:?}").contains("hostile-private"));
    let _ = std::fs::remove_dir_all(&id_root);

    let inspect_shape_root = std::env::temp_dir().join(format!(
        "apolysis-containerd-private-inspect-shape-{}-{id}",
        std::process::id()
    ));
    write_runtime_identity_fixture(
        &inspect_shape_root.join("proc"),
        4242,
        77,
        "/containerd/private",
    );
    std::fs::create_dir_all(inspect_shape_root.join("sys/fs/cgroup/containerd/private"))
        .expect("create diagnostic cgroup");
    let error = scan_containerd_diagnostic_fixture(
        &inspect_shape_root,
        json!({"containers":[{
            "id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "state":"CONTAINER_RUNNING",
            "labels":{"apolysis.session_id":"hostile-private-label"}
        }]}),
        json!({"hostile-private-inspect-shape": true}),
        None,
    )
    .await;
    assert_eq!(
        error.inventory_invalid_category(),
        Some(RuntimeInventoryInvalidCategory::InspectShape)
    );
    assert_eq!(
        error
            .inventory_invalid_category()
            .expect("inspect shape category")
            .code(),
        "inspect_shape"
    );
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    assert!(!format!("{error:?}").contains("hostile-private"));

    for (case, expected, expected_code) in [
        (
            "inspect-state",
            RuntimeInventoryInvalidCategory::InspectState,
            "inspect_state",
        ),
        (
            "inspect-label",
            RuntimeInventoryInvalidCategory::InspectLabel,
            "inspect_label",
        ),
        (
            "inspect-pid",
            RuntimeInventoryInvalidCategory::InspectPid,
            "inspect_pid",
        ),
        (
            "inspect-start-marker",
            RuntimeInventoryInvalidCategory::InspectStartMarker,
            "inspect_start_marker",
        ),
        (
            "proc-start",
            RuntimeInventoryInvalidCategory::ProcStart,
            "proc_start",
        ),
        (
            "cgroup-path",
            RuntimeInventoryInvalidCategory::CgroupPath,
            "cgroup_path",
        ),
        (
            "cgroup-identity",
            RuntimeInventoryInvalidCategory::CgroupIdentity,
            "cgroup_identity",
        ),
        (
            "double-inspect",
            RuntimeInventoryInvalidCategory::DoubleInspect,
            "double_inspect",
        ),
        (
            "binding-validation",
            RuntimeInventoryInvalidCategory::BindingValidation,
            "binding_validation",
        ),
    ] {
        let case_root = std::env::temp_dir().join(format!(
            "apolysis-containerd-private-{case}-{}-{id}",
            std::process::id()
        ));
        prepare_containerd_diagnostic_identity(&case_root);
        let mut first_inspect = containerd_diagnostic_inspect();
        let mut second_inspect = None;
        match case {
            "inspect-state" => {
                *first_inspect
                    .pointer_mut("/status/state")
                    .expect("diagnostic state") = json!("hostile-private-state");
            }
            "inspect-label" => {
                *first_inspect
                    .pointer_mut("/status/labels")
                    .expect("diagnostic labels") =
                    json!({"apolysis.session_id":" ","hostile-private-label":"secret"});
            }
            "inspect-pid" => {
                *first_inspect
                    .pointer_mut("/info/pid")
                    .expect("diagnostic pid") = json!(0);
            }
            "inspect-start-marker" => {
                *first_inspect
                    .pointer_mut("/status/startedAt")
                    .expect("diagnostic start marker") = json!("hostile/private/start-marker");
            }
            "proc-start" => {
                std::fs::remove_file(case_root.join("proc/4242/stat"))
                    .expect("remove diagnostic process stat");
            }
            "cgroup-path" => {
                *first_inspect
                    .pointer_mut("/info/runtimeSpec/linux/cgroupsPath")
                    .expect("diagnostic cgroup path") = json!("../hostile-private-cgroup");
            }
            "cgroup-identity" => {
                *first_inspect
                    .pointer_mut("/info/runtimeSpec/linux/cgroupsPath")
                    .expect("diagnostic cgroup identity") =
                    json!("/containerd/hostile-private-missing");
            }
            "double-inspect" => {
                let mut changed = first_inspect.clone();
                *changed
                    .pointer_mut("/status/startedAt")
                    .expect("diagnostic second start marker") = json!(202);
                second_inspect = Some(changed);
            }
            "binding-validation" => {
                *first_inspect
                    .pointer_mut("/status/labels/apolysis.session_id")
                    .expect("diagnostic binding label") = json!("hostile/private-label");
            }
            _ => unreachable!("fixed diagnostic case"),
        }
        let error = scan_containerd_diagnostic_fixture(
            &case_root,
            containerd_diagnostic_ps(),
            first_inspect,
            second_inspect,
        )
        .await;
        assert_fixed_containerd_inventory_error(&error, expected, expected_code);
    }
}

#[tokio::test]
async fn containerd_inventory_rejects_more_than_the_bounded_candidate_set_before_inspect() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-candidate-bound-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let crictl = root.join("crictl-fixture");
    let ps_fixture = root.join("ps.json");
    let inspect_canary = root.join("inspect-ran");
    std::fs::create_dir_all(proc_root.join("sys/kernel/random")).expect("create fake proc sys");
    std::fs::write(
        proc_root.join("sys/kernel/random/boot_id"),
        "82b46386-b87a-4d86-93f6-232bb04c37fb\n",
    )
    .expect("write fake host boot id");
    let candidates = (0..4097)
        .map(|index| {
            json!({
                "id": format!("{index:064x}"),
                "state": "CONTAINER_RUNNING",
                "labels": {"apolysis.session_id": "agent-run-bounded"}
            })
        })
        .collect::<Vec<_>>();
    std::fs::write(&ps_fixture, json!({"containers": candidates}).to_string())
        .expect("write bounded CRI candidate fixture");
    let script = r#"#!/bin/sh
case " $* " in
  *" ps -o json "*) cat "@PS_FIXTURE@" ;;
  *" inspect -o json "*) touch "@INSPECT_CANARY@"; exit 64 ;;
  *) exit 64 ;;
esac
"#
    .replace("@PS_FIXTURE@", &ps_fixture.to_string_lossy())
    .replace("@INSPECT_CANARY@", &inspect_canary.to_string_lossy());
    write_executable_fixture(&crictl, &script);
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("unused-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        root.join("sys/fs/cgroup"),
        Duration::from_millis(1),
        32,
    )
    .expect("containerd inventory adapter");

    let error = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .expect_err("oversized CRI candidate set must fail before inspect");

    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    assert_eq!(
        error.inventory_invalid_category(),
        Some(RuntimeInventoryInvalidCategory::Count)
    );
    assert_eq!(
        error
            .inventory_invalid_category()
            .expect("count category")
            .code(),
        "count"
    );
    assert!(
        !inspect_canary.exists(),
        "inspect must not run past the bound"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn containerd_inventory_fails_closed_when_a_candidate_is_replaced_after_qualification() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-candidate-replaced-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let crictl = root.join("crictl-fixture");
    write_runtime_identity_fixture(&proc_root, 6060, 181, "/containerd/first");
    write_runtime_identity_fixture(&proc_root, 7070, 282, "/containerd/second");
    std::fs::create_dir_all(cgroup_root.join("containerd/first"))
        .expect("create first fake cgroup");
    std::fs::create_dir_all(cgroup_root.join("containerd/second"))
        .expect("create second fake cgroup");
    let script = r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    count_file="@PS_COUNT@"
    count=0
    test ! -f "$count_file" || count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" > "$count_file"
    if test "$count" -eq 1; then
      printf '%s\n' '{"containers":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-first"}},{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-second"}}]}'
    else
      printf '%s\n' '{"containers":[{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-first"}},{"id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-replacement"}}]}'
    fi
    ;;
  *" inspect -o json aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa "*)
    printf '%s\n' '{"status":{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"CONTAINER_RUNNING","startedAt":101,"labels":{"apolysis.session_id":"agent-run-first"}},"info":{"pid":6060,"runtimeSpec":{"linux":{"cgroupsPath":"/containerd/first"}}}}'
    ;;
  *" inspect -o json bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb "*)
    printf '%s\n' '{"status":{"id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","state":"CONTAINER_RUNNING","startedAt":202,"labels":{"apolysis.session_id":"agent-run-second"}},"info":{"pid":7070,"runtimeSpec":{"linux":{"cgroupsPath":"/containerd/second"}}}}'
    ;;
  *) exit 64 ;;
esac
"#
    .replace("@PS_COUNT@", &root.join("ps-count").to_string_lossy());
    write_executable_fixture(&crictl, &script);
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("unused-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("containerd inventory adapter");

    let result = RuntimeInventoryAdapter::scan_inventory(&adapter).await;
    let _ = std::fs::remove_dir_all(&root);
    let error = result.expect_err("candidate replacement must invalidate the complete inventory");

    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    assert_eq!(
        error.inventory_invalid_category(),
        Some(RuntimeInventoryInvalidCategory::DoubleInspect)
    );
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    assert!(!format!("{error:?}").contains("agent-run-replacement"));
}

#[tokio::test]
async fn containerd_inventory_does_not_authorize_absence_when_a_candidate_disappears_after_qualification(
) {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-candidate-disappeared-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let crictl = root.join("crictl-fixture");
    write_runtime_identity_fixture(&proc_root, 8080, 383, "/containerd/stable");
    std::fs::create_dir_all(cgroup_root.join("containerd/stable"))
        .expect("create stable fake cgroup");
    let script = r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    count_file="@PS_COUNT@"
    count=0
    test ! -f "$count_file" || count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" > "$count_file"
    if test "$count" -eq 1; then
      printf '%s\n' '{"containers":[{"id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-stable"}}]}'
    else
      printf '%s\n' '{"containers":[]}'
    fi
    ;;
  *" inspect -o json dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd "*)
    printf '%s\n' '{"status":{"id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","state":"CONTAINER_RUNNING","startedAt":303,"labels":{"apolysis.session_id":"agent-run-stable"}},"info":{"pid":8080,"runtimeSpec":{"linux":{"cgroupsPath":"/containerd/stable"}}}}'
    ;;
  *) exit 64 ;;
esac
"#
    .replace("@PS_COUNT@", &root.join("ps-count").to_string_lossy());
    write_executable_fixture(&crictl, &script);
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("unused-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("containerd inventory adapter");

    let result = RuntimeInventoryAdapter::scan_inventory(&adapter).await;
    let _ = std::fs::remove_dir_all(&root);
    let error =
        result.expect_err("candidate disappearance must not authorize an absence transition");

    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    assert_eq!(
        error.inventory_invalid_category(),
        Some(RuntimeInventoryInvalidCategory::DoubleInspect)
    );
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
}

#[tokio::test]
async fn k3s_inventory_fails_closed_when_an_inherited_session_label_changes_after_qualification() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-k3s-inherited-label-churn-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let crictl = root.join("crictl-fixture");
    write_runtime_identity_fixture(&proc_root, 6060, 181, "/k3s/qualified");
    std::fs::create_dir_all(cgroup_root.join("k3s/qualified")).expect("create fake k3s cgroup");
    let script = r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    printf '%s\n' '{"containers":[{"id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","podSandboxId":"sandbox-k3s-inherited","state":"CONTAINER_RUNNING","labels":{}}]}'
    ;;
  *" pods -o json "*)
    count_file="@PODS_COUNT@"
    count=0
    test ! -f "$count_file" || count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" > "$count_file"
    if test "$count" -eq 1; then owner=agent-run-before; else owner=agent-run-after; fi
    printf '%s\n' "{\"items\":[{\"id\":\"sandbox-k3s-inherited\",\"state\":\"SANDBOX_READY\",\"labels\":{\"apolysis.session_id\":\"$owner\"}}]}"
    ;;
  *" inspect -o json cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc "*)
    printf '%s\n' '{"status":{"id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","state":"CONTAINER_RUNNING","startedAt":1754874123000000000,"labels":{}},"info":{"pid":6060,"runtimeSpec":{"linux":{"cgroupsPath":"/k3s/qualified"}}}}'
    ;;
  *) exit 64 ;;
esac
"#
    .replace(
        "@PODS_COUNT@",
        &root.join("pods-count").to_string_lossy(),
    );
    write_executable_fixture(&crictl, &script);
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::K3sContainerd,
        CriRuntimeClient::new(root.join("unused-k3s.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("k3s inventory adapter");

    let error = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .expect_err("inherited ownership churn must invalidate the complete inventory");

    assert_eq!(
        error.inventory_invalid_category(),
        Some(RuntimeInventoryInvalidCategory::DoubleInspect)
    );
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn containerd_inventory_fails_closed_when_inspect_generation_changes_at_the_same_pid() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-inspect-churn-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let crictl = root.join("crictl-fixture");
    write_runtime_identity_fixture(&proc_root, 7777, 303, "/containerd/reused");
    std::fs::create_dir_all(cgroup_root.join("containerd/reused")).expect("create fake cgroup");
    let script = r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    printf '%s\n' '{"containers":[{"id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-reused"}}]}'
    ;;
  *" inspect -o json dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd "*)
    count_file="@INSPECT_COUNT@"
    count=0
    test ! -f "$count_file" || count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" > "$count_file"
    if test "$count" -eq 1; then marker=1754874123000000000; else marker=1754874999000000000; fi
    printf '%s\n' "{\"status\":{\"id\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\",\"state\":\"CONTAINER_RUNNING\",\"startedAt\":$marker,\"labels\":{\"apolysis.session_id\":\"agent-run-reused\",\"io.kubernetes.pod.namespace\":\"agents\"}},\"info\":{\"pid\":7777,\"runtimeType\":\"io.containerd.runc.v2\",\"runtimeSpec\":{\"linux\":{\"cgroupsPath\":\"/containerd/reused\"}}}}"
    ;;
  *) exit 64 ;;
esac
"#
    .replace(
        "@INSPECT_COUNT@",
        &root.join("inspect-count").to_string_lossy(),
    );
    write_executable_fixture(&crictl, &script);
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("unused-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("containerd inventory adapter");

    let error = adapter
        .scan_inventory()
        .await
        .expect_err("CRI inspect churn must invalidate the inventory");

    assert_eq!(error, "runtime inventory scan failed: inventory_invalid");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn containerd_inventory_fails_closed_when_the_pid_start_generation_changes_mid_scan() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-pid-reuse-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let crictl = root.join("crictl-fixture");
    write_runtime_identity_fixture(&proc_root, 8888, 501, "/containerd/pid-reuse");
    std::fs::create_dir_all(cgroup_root.join("containerd/pid-reuse")).expect("create fake cgroup");
    std::fs::write(
        root.join("crictl-fixture.replacement-stat"),
        format!(
            "8888 (replacement init) S {} 502\n",
            vec!["0"; 18].join(" ")
        ),
    )
    .expect("write replacement stat fixture");
    let script = r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    printf '%s\n' '{"containers":[{"id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-pid-reuse"}}]}'
    ;;
  *" inspect -o json eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee "*)
    count_file="@INSPECT_COUNT@"
    count=0
    test ! -f "$count_file" || count=$(cat "$count_file")
    count=$((count + 1))
    printf '%s' "$count" > "$count_file"
    if test "$count" -eq 2; then
      cp "@REPLACEMENT_STAT@" "@PROCESS_STAT@"
    fi
    printf '%s\n' '{"status":{"id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","state":"CONTAINER_RUNNING","startedAt":1754874123000000000,"labels":{"apolysis.session_id":"agent-run-pid-reuse","io.kubernetes.pod.namespace":"agents"}},"info":{"pid":8888,"runtimeSpec":{"linux":{"cgroupsPath":"/containerd/pid-reuse"}}}}'
    ;;
  *) exit 64 ;;
esac
"#
    .replace(
        "@INSPECT_COUNT@",
        &root.join("inspect-count").to_string_lossy(),
    )
    .replace(
        "@REPLACEMENT_STAT@",
        &root.join("crictl-fixture.replacement-stat").to_string_lossy(),
    )
    .replace(
        "@PROCESS_STAT@",
        &proc_root.join("8888/stat").to_string_lossy(),
    );
    write_executable_fixture(&crictl, &script);
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("unused-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("containerd inventory adapter");

    let error = adapter
        .scan_inventory()
        .await
        .expect_err("PID reuse during CRI proof must invalidate the inventory");

    assert_eq!(error, "runtime inventory scan failed: inventory_invalid");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn containerd_inventory_exposes_new_process_and_cgroup_generations_for_the_same_workload_id()
{
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-runtime-generation-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let cgroup = cgroup_root.join("containerd/generation");
    let crictl = root.join("crictl-fixture");
    write_runtime_identity_fixture(&proc_root, 9999, 601, "/containerd/generation");
    std::fs::create_dir_all(&cgroup).expect("create first cgroup generation");
    let script = r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    printf '%s\n' '{"containers":[{"id":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-generation"}}]}'
    ;;
  *" inspect -o json ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff "*)
    if test -f "@PHASE_TWO@"; then marker=202; else marker=101; fi
    printf '%s\n' "{\"status\":{\"id\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"state\":\"CONTAINER_RUNNING\",\"startedAt\":$marker,\"labels\":{\"apolysis.session_id\":\"agent-run-generation\",\"io.kubernetes.pod.namespace\":\"agents\"}},\"info\":{\"pid\":9999,\"runtimeSpec\":{\"linux\":{\"cgroupsPath\":\"/containerd/generation\"}}}}"
    ;;
  *) exit 64 ;;
esac
"#
    .replace(
        "@PHASE_TWO@",
        &root.join("crictl-fixture.phase-two").to_string_lossy(),
    );
    write_executable_fixture(&crictl, &script);
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("unused-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("containerd inventory adapter");

    let first = adapter.scan_inventory().await.expect("first inventory");
    let old_cgroup = cgroup_root.join("containerd/generation-retired");
    std::fs::rename(&cgroup, &old_cgroup).expect("retain old cgroup inode");
    std::fs::create_dir(&cgroup).expect("create replacement cgroup generation");
    write_runtime_identity_fixture(&proc_root, 9999, 602, "/containerd/generation");
    std::fs::write(root.join("crictl-fixture.phase-two"), "phase two")
        .expect("advance CRI fixture generation");
    let second = adapter.scan_inventory().await.expect("second inventory");

    let first_identity = &first.bindings[0].identity;
    let second_identity = &second.bindings[0].identity;
    assert_eq!(first_identity.workload_id, second_identity.workload_id);
    assert_ne!(first_identity.start_marker, second_identity.start_marker);
    assert_ne!(
        first_identity.init_process_start_time_ticks,
        second_identity.init_process_start_time_ticks
    );
    assert_eq!(first_identity.cgroup.device, second_identity.cgroup.device);
    assert_ne!(first_identity.cgroup.inode, second_identity.cgroup.inode);
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn containerd_inventory_does_not_return_a_partial_snapshot_when_one_candidate_is_invalid() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-containerd-invalid-inventory-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let crictl = root.join("crictl-fixture");
    write_runtime_identity_fixture(&proc_root, 8001, 11, "/containerd/valid");
    write_runtime_identity_fixture(&proc_root, 8002, 22, "/containerd/invalid");
    std::fs::create_dir_all(cgroup_root.join("containerd/valid")).expect("create valid cgroup");
    std::fs::create_dir_all(cgroup_root.join("containerd/invalid")).expect("create invalid cgroup");
    write_executable_fixture(
        &crictl,
        r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    printf '%s\n' '{"containers":[{"id":"9999999999999999999999999999999999999999999999999999999999999999","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-valid"}},{"id":"abababababababababababababababababababababababababababababababab","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-invalid"}}]}'
    ;;
  *" inspect -o json 9999999999999999999999999999999999999999999999999999999999999999 "*)
    printf '%s\n' '{"status":{"id":"9999999999999999999999999999999999999999999999999999999999999999","state":"CONTAINER_RUNNING","startedAt":101,"labels":{"apolysis.session_id":"agent-run-valid","io.kubernetes.pod.namespace":"agents"}},"info":{"pid":8001,"runtimeSpec":{"linux":{"cgroupsPath":"/containerd/valid"}}}}'
    ;;
  *" inspect -o json abababababababababababababababababababababababababababababababab "*)
    printf '%s\n' '{"status":{"id":"abababababababababababababababababababababababababababababababab","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-invalid","io.kubernetes.pod.namespace":"agents"}},"info":{"pid":8002,"runtimeSpec":{"linux":{"cgroupsPath":"/containerd/invalid"}}}}'
    ;;
  *) exit 64 ;;
esac
"#,
    );
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("unused-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("containerd inventory adapter");

    let error = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .expect_err("one invalid candidate invalidates the complete inventory");

    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn containerd_inventory_rejects_nonpositive_fractional_empty_and_oversized_start_markers() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let oversized = format!("\"{}\"", "1".repeat(160));
    for (case, started_at_json) in [
        ("numeric-zero", "0".to_string()),
        ("string-zero", "\"0\"".to_string()),
        ("negative", "-1".to_string()),
        ("fractional", "1.5".to_string()),
        ("empty", "\"\"".to_string()),
        ("whitespace", "\"   \"".to_string()),
        ("oversized", oversized),
        (
            "rfc3339-malformed-offset",
            "\"2026-08-11T01:02:03.123456789+8:00\"".to_string(),
        ),
        (
            "rfc3339-invalid-offset-hour",
            "\"2026-08-11T01:02:03.123456789+24:00\"".to_string(),
        ),
        (
            "rfc3339-invalid-offset-minute",
            "\"2026-08-11T01:02:03.123456789+08:60\"".to_string(),
        ),
        (
            "rfc3339-signed-zero-offset",
            "\"2026-08-11T01:02:03.123456789+00:00\"".to_string(),
        ),
        (
            "rfc3339-unknown-local-offset",
            "\"2026-08-11T01:02:03.123456789-00:00\"".to_string(),
        ),
        (
            "rfc3339-invalid-calendar",
            "\"2026-02-30T01:02:03.123456789Z\"".to_string(),
        ),
        (
            "rfc3339-too-many-fraction-digits",
            "\"2026-08-11T01:02:03.1234567890Z\"".to_string(),
        ),
        (
            "rfc3339-before-unix-epoch",
            "\"1969-12-31T23:59:59.999999999Z\"".to_string(),
        ),
        (
            "rfc3339-after-u64-nanoseconds",
            "\"9999-12-31T23:59:59.999999999Z\"".to_string(),
        ),
        (
            "rfc3339-unix-epoch-zero",
            "\"1970-01-01T00:00:00Z\"".to_string(),
        ),
        (
            "rfc3339-offset-before-unix-epoch",
            "\"1970-01-01T00:30:00+01:00\"".to_string(),
        ),
        (
            "rfc3339-negative-offset-after-u64-nanoseconds",
            "\"2554-07-21T23:34:33.709551615-00:01\"".to_string(),
        ),
    ] {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "apolysis-containerd-start-marker-{case}-{}-{id}",
            std::process::id()
        ));
        let proc_root = root.join("proc");
        let crictl = root.join("crictl-fixture");
        std::fs::create_dir_all(proc_root.join("sys/kernel/random")).expect("create fake proc sys");
        std::fs::write(
            proc_root.join("sys/kernel/random/boot_id"),
            "82b46386-b87a-4d86-93f6-232bb04c37fb\n",
        )
        .expect("write fake host boot id");
        std::fs::write(root.join("crictl-fixture.marker"), started_at_json)
            .expect("write CRI marker fixture");
        let script = r#"#!/bin/sh
case " $* " in
  *" ps -o json "*)
    printf '%s\n' '{"containers":[{"id":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","state":"CONTAINER_RUNNING","labels":{"apolysis.session_id":"agent-run-invalid-start"}}]}'
    ;;
  *" inspect -o json cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd "*)
    marker=$(cat "@MARKER_FIXTURE@")
    printf '{"status":{"id":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","state":"CONTAINER_RUNNING","startedAt":%s,"labels":{"apolysis.session_id":"agent-run-invalid-start"}},"info":{"pid":1234}}\n' "$marker"
    ;;
  *) exit 64 ;;
esac
"#
        .replace(
            "@MARKER_FIXTURE@",
            &root.join("crictl-fixture.marker").to_string_lossy(),
        );
        write_executable_fixture(&crictl, &script);
        let adapter = ContainerdCriRuntimeAdapter::new(
            AdapterKind::Containerd,
            CriRuntimeClient::new(root.join("missing-containerd.sock"))
                .with_crictl_path(&crictl)
                .with_image_endpoint(None),
            &proc_root,
            root.join("sys/fs/cgroup"),
            Duration::from_millis(1),
            32,
        )
        .expect("containerd adapter");

        let error = match RuntimeInventoryAdapter::scan_inventory(&adapter).await {
            Err(error) => error,
            Ok(_) => panic!("invalid CRI start marker unexpectedly qualified"),
        };

        assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
        assert_eq!(
            error.inventory_invalid_category(),
            Some(RuntimeInventoryInvalidCategory::InspectStartMarker),
            "case={case}"
        );
        assert_eq!(
            error.to_string(),
            "runtime inventory scan failed: inventory_invalid"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[tokio::test]
async fn docker_and_containerd_inventory_scans_classify_unreachable_sources_as_socket_gaps() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-runtime-source-unavailable-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    std::fs::create_dir_all(proc_root.join("sys/kernel/random")).expect("create fake proc sys");
    std::fs::write(
        proc_root.join("sys/kernel/random/boot_id"),
        "82b46386-b87a-4d86-93f6-232bb04c37fb\n",
    )
    .expect("write fake host boot id");
    let crictl = root.join("crictl-unavailable");
    write_executable_fixture(
        &crictl,
        "#!/bin/sh\nprintf '%s\\n' 'rpc error: code = Unavailable' >&2\nexit 1\n",
    );
    let docker = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(root.join("missing-docker.sock")),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    );
    let containerd = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("missing-containerd.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        &proc_root,
        &cgroup_root,
        Duration::from_millis(1),
        32,
    )
    .expect("containerd adapter");

    let docker_error = RuntimeInventoryAdapter::scan_inventory(&docker)
        .await
        .expect_err("missing Docker socket");
    let containerd_error = RuntimeInventoryAdapter::scan_inventory(&containerd)
        .await
        .expect_err("missing containerd source");

    assert_eq!(
        docker_error.reason(),
        RuntimeSourceGapReason::SocketUnavailable
    );
    assert_eq!(
        containerd_error.reason(),
        RuntimeSourceGapReason::SocketUnavailable
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "subprocess helper for isolated APOLYSIS_CRICTL environment validation"]
async fn apolysis_crictl_override_helper() {
    let client = CriRuntimeClient::new("/missing/containerd.sock").with_image_endpoint(None);
    match std::env::var("APOLYSIS_TEST_CRICTL_MODE").as_deref() {
        Ok("valid") => assert_eq!(
            client
                .list_marked_running_container_ids()
                .await
                .expect("validated APOLYSIS_CRICTL override"),
            vec!["override-container".to_string()]
        ),
        Ok("invalid") => {
            let error = client
                .list_marked_running_container_ids()
                .await
                .expect_err("invalid APOLYSIS_CRICTL must be rejected");
            assert!(error.contains("APOLYSIS_CRICTL"), "{error}");
        }
        Ok("changed") => {
            let error = client
                .list_marked_running_container_ids()
                .await
                .expect_err("replaced APOLYSIS_CRICTL must be rejected after execution");
            assert!(error.contains("identity changed"), "{error}");
        }
        Ok("default_path") => {
            let error = client
                .list_marked_running_container_ids()
                .await
                .expect_err("an unset APOLYSIS_CRICTL must fail closed before PATH lookup");
            assert_eq!(
                error,
                "APOLYSIS_CRICTL must be an absolute secure executable file"
            );
        }
        mode => panic!("unexpected APOLYSIS_TEST_CRICTL_MODE {mode:?}"),
    }
}

#[test]
fn crictl_client_rejects_default_path_lookup_when_not_configured() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-crictl-default-path-{}-{id}",
        std::process::id()
    ));
    let bin = root.join("bin");
    let executable = bin.join("crictl");
    let canary = root.join("path-lookup-ran");
    write_executable_fixture(
        &executable,
        "#!/bin/sh\nprintf invoked > \"$APOLYSIS_TEST_CRICTL_CANARY_MARKER\"\nprintf '%s\\n' '{\"containers\":[]}'\n",
    );

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "apolysis_crictl_override_helper",
            "--ignored",
            "--nocapture",
        ])
        .env("APOLYSIS_TEST_CRICTL_MODE", "default_path")
        .env_remove("APOLYSIS_CRICTL")
        .env("PATH", &bin)
        .env("APOLYSIS_TEST_CRICTL_CANARY_MARKER", &canary)
        .output()
        .expect("run isolated default crictl configuration helper");

    assert!(
        output.status.success(),
        "default crictl configuration helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !canary.exists(),
        "an unset APOLYSIS_CRICTL must not execute a PATH-selected binary"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn apolysis_crictl_override_accepts_only_absolute_regular_executables() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-crictl-override-{}-{id}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("create crictl override fixture directory");
    let executable = root.join("crictl");
    write_executable_fixture(
        &executable,
        "#!/bin/sh\nprintf '%s\\n' '{\"containers\":[{\"id\":\"override-container\",\"state\":\"CONTAINER_RUNNING\",\"labels\":{\"apolysis.session_id\":\"agent-run-override\"}}]}'\n",
    );
    let non_executable = root.join("non-executable-crictl");
    std::fs::write(&non_executable, "#!/bin/sh\nexit 0\n")
        .expect("write non-executable crictl fixture");
    std::fs::set_permissions(&non_executable, std::fs::Permissions::from_mode(0o644))
        .expect("chmod non-executable fixture");
    let world_writable = root.join("world-writable-crictl");
    write_executable_fixture(&world_writable, "#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(&world_writable, std::fs::Permissions::from_mode(0o777))
        .expect("chmod world-writable fixture");
    let special_mode = root.join("special-mode-crictl");
    write_executable_fixture(&special_mode, "#!/bin/sh\nexit 0\n");
    std::fs::set_permissions(&special_mode, std::fs::Permissions::from_mode(0o4755))
        .expect("chmod special-mode fixture");
    let symlink = root.join("symlink-crictl");
    std::os::unix::fs::symlink(&executable, &symlink).expect("create crictl symlink fixture");
    let hardlink_source = root.join("hardlink-source-crictl");
    let hardlink = root.join("hardlink-crictl");
    write_executable_fixture(&hardlink_source, "#!/bin/sh\nexit 0\n");
    std::fs::hard_link(&hardlink_source, &hardlink).expect("create crictl hardlink fixture");
    let replaced_during_execution = root.join("replaced-during-execution-crictl");
    let replacement_canary = root.join("replacement-canary-crictl");
    let replacement_canary_marker = root.join("replacement-canary-ran");
    write_executable_fixture(
        &replacement_canary,
        "#!/bin/sh\nprintf ran > \"$APOLYSIS_TEST_CRICTL_CANARY_MARKER\"\nprintf '%s\\n' '{\"containers\":[]}'\n",
    );
    write_executable_fixture(
        &replaced_during_execution,
        "#!/bin/sh\nmv \"$APOLYSIS_TEST_CRICTL_TARGET\" \"$APOLYSIS_TEST_CRICTL_TARGET.old\"\ncp \"$APOLYSIS_TEST_CRICTL_CANARY\" \"$APOLYSIS_TEST_CRICTL_TARGET\"\nchmod 700 \"$APOLYSIS_TEST_CRICTL_TARGET\"\nprintf '%s\\n' '{\"containers\":[]}'\n",
    );

    let run_helper = |mode: &str, path: &std::path::Path| {
        Command::new(std::env::current_exe().expect("current test executable"))
            .args([
                "--exact",
                "apolysis_crictl_override_helper",
                "--ignored",
                "--nocapture",
            ])
            .env("APOLYSIS_TEST_CRICTL_MODE", mode)
            .env("APOLYSIS_CRICTL", path)
            .env("APOLYSIS_TEST_CRICTL_TARGET", path)
            .env("APOLYSIS_TEST_CRICTL_CANARY", &replacement_canary)
            .env(
                "APOLYSIS_TEST_CRICTL_CANARY_MARKER",
                &replacement_canary_marker,
            )
            .output()
            .expect("run APOLYSIS_CRICTL helper")
    };

    let valid = run_helper("valid", &executable);
    assert!(
        valid.status.success(),
        "valid override failed: {}",
        String::from_utf8_lossy(&valid.stderr)
    );
    for invalid in [
        std::path::Path::new("relative-crictl"),
        non_executable.as_path(),
        world_writable.as_path(),
        special_mode.as_path(),
        symlink.as_path(),
        hardlink.as_path(),
        root.as_path(),
    ] {
        let output = run_helper("invalid", invalid);
        assert!(
            output.status.success(),
            "invalid override helper failed for {}: {}",
            invalid.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let changed = run_helper("changed", &replaced_during_execution);
    assert!(
        changed.status.success(),
        "replacement override helper failed: {}",
        String::from_utf8_lossy(&changed.stderr)
    );
    assert!(
        !replacement_canary_marker.exists(),
        "replacement canary must never execute in place of the descriptor-qualified file"
    );
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    if unsafe { libc::geteuid() } == 0 {
        use std::os::unix::ffi::OsStrExt;

        let wrong_owner = root.join("wrong-owner-crictl");
        write_executable_fixture(&wrong_owner, "#!/bin/sh\nexit 0\n");
        let path = std::ffi::CString::new(wrong_owner.as_os_str().as_bytes())
            .expect("wrong-owner path has no NUL");
        // SAFETY: path is a valid NUL-terminated pathname; uid 1 is used only in the temp fixture.
        assert_eq!(
            unsafe { libc::chown(path.as_ptr(), 1, libc::gid_t::MAX) },
            0
        );
        let output = run_helper("invalid", &wrong_owner);
        assert!(
            output.status.success(),
            "wrong-owner override helper failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn crictl_client_rejects_a_relative_explicit_executable_before_execution() {
    let error = CriRuntimeClient::new("/missing/containerd.sock")
        .with_crictl_path("relative-crictl")
        .with_image_endpoint(None)
        .list_marked_running_container_ids()
        .await
        .expect_err("relative crictl paths must fail closed before PATH lookup");

    assert_eq!(
        error,
        "APOLYSIS_CRICTL must be an absolute secure executable file"
    );
}

#[tokio::test]
async fn crictl_client_returns_a_canonical_error_without_stderr_or_path_payloads() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-crictl-private-errors-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("private-path-token-crictl");
    write_executable_fixture(
        &crictl,
        "#!/bin/sh\nprintf '%s\\n' 'private-stderr-payload-token' >&2\nexit 1\n",
    );

    let error = CriRuntimeClient::new(root.join("unused.sock"))
        .with_crictl_path(&crictl)
        .with_image_endpoint(None)
        .list_marked_running_container_ids()
        .await
        .expect_err("a non-zero crictl result must fail closed");

    assert_eq!(error, "crictl command failed");
    assert!(!error.contains("private-stderr-payload-token"), "{error}");
    assert!(!error.contains("private-path-token-crictl"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn crictl_client_accepts_an_owner_controlled_absolute_executable() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-crictl-absolute-path-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    write_executable_fixture(&crictl, "#!/bin/sh\nprintf '%s\\n' '{\"containers\":[]}'\n");

    let ids = CriRuntimeClient::new(root.join("unused.sock"))
        .with_crictl_path(&crictl)
        .with_image_endpoint(None)
        .list_marked_running_container_ids()
        .await
        .expect("an owner-controlled absolute executable must remain supported");

    assert!(ids.is_empty());
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn absolute_crictl_fixture_path_rejects_a_symlinked_ancestor() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-crictl-ancestor-symlink-{}-{id}",
        std::process::id()
    ));
    let real_directory = root.join("real");
    let linked_directory = root.join("linked");
    let executable = real_directory.join("crictl");
    write_executable_fixture(
        &executable,
        "#!/bin/sh\nprintf '%s\\n' '{\"containers\":[]}'\n",
    );
    std::os::unix::fs::symlink(&real_directory, &linked_directory)
        .expect("create crictl ancestor symlink");

    let error = CriRuntimeClient::new(root.join("unused.sock"))
        .with_crictl_path(linked_directory.join("crictl"))
        .with_image_endpoint(None)
        .list_marked_running_container_ids()
        .await
        .expect_err("absolute crictl fixtures must use descriptor-qualified paths");

    assert!(error.contains("symbolic link"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn crictl_client_rejects_oversized_stdout() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-crictl-response-bound-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    write_executable_fixture(
        &crictl,
        "#!/bin/sh\nhead -c 8388609 /dev/zero | tr '\\0' x\n",
    );

    let error = CriRuntimeClient::new(root.join("unused.sock"))
        .with_crictl_path(&crictl)
        .with_image_endpoint(None)
        .list_marked_running_container_ids()
        .await
        .expect_err("oversized crictl stdout must fail closed");

    assert!(error.contains("stdout exceeds"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn crictl_client_stops_a_continuous_writer_at_the_output_bound() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-crictl-continuous-output-bound-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    write_executable_fixture(
        &crictl,
        "#!/bin/sh\nwhile :; do head -c 1048576 /dev/zero; done\n",
    );
    let started = Instant::now();

    let error = CriRuntimeClient::new(root.join("unused.sock"))
        .with_crictl_path(&crictl)
        .with_image_endpoint(None)
        .with_timeout(Duration::from_secs(2))
        .list_marked_running_container_ids()
        .await
        .expect_err("continuous crictl output must stop at the byte bound");

    assert!(error.contains("stdout exceeds"), "{error}");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "output overflow must not wait for the command timeout"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn crictl_client_times_out_a_stalled_process() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-crictl-timeout-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    write_executable_fixture(&crictl, "#!/bin/sh\nexec sleep 10\n");

    let error = CriRuntimeClient::new(root.join("unused.sock"))
        .with_crictl_path(&crictl)
        .with_image_endpoint(None)
        .with_timeout(Duration::from_millis(20))
        .list_marked_running_container_ids()
        .await
        .expect_err("stalled crictl must time out");

    assert!(error.contains("timed out"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

fn write_executable_fixture(path: &Path, contents: &str) {
    std::fs::create_dir_all(path.parent().expect("fixture parent"))
        .expect("create executable fixture parent");
    std::fs::write(path, contents).expect("write executable fixture");
    let mut permissions = std::fs::metadata(path)
        .expect("stat executable fixture")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(path, permissions).expect("make fixture executable");
}

async fn executable_fixture_test_lease() -> tokio::sync::MutexGuard<'static, ()> {
    EXECUTABLE_FIXTURE_TEST_LEASE.lock().await
}

fn write_runtime_identity_fixture(
    proc_root: &Path,
    pid: u32,
    start_time_ticks: u64,
    cgroup_path: &str,
) {
    std::fs::create_dir_all(proc_root.join(pid.to_string())).expect("create fake proc pid");
    std::fs::create_dir_all(proc_root.join("sys/kernel/random")).expect("create fake proc sys");
    std::fs::write(
        proc_root.join("sys/kernel/random/boot_id"),
        "82b46386-b87a-4d86-93f6-232bb04c37fb\n",
    )
    .expect("write fake host boot id");
    std::fs::write(
        proc_root.join(pid.to_string()).join("cgroup"),
        format!("0::{cgroup_path}\n"),
    )
    .expect("write fake proc cgroup");
    std::fs::write(
        proc_root.join(pid.to_string()).join("stat"),
        format!(
            "{pid} (container init) S {} {start_time_ticks}\n",
            vec!["0"; 18].join(" ")
        ),
    )
    .expect("write fake proc stat");
}

async fn scan_containerd_diagnostic_fixture(
    root: &Path,
    ps: serde_json::Value,
    first_inspect: serde_json::Value,
    second_inspect: Option<serde_json::Value>,
) -> RuntimeInventoryScanError {
    let ps_path = root.join("ps.json");
    let first_path = root.join("inspect-first.json");
    let second_path = root.join("inspect-second.json");
    let count_path = root.join("inspect-count");
    let crictl = root.join("crictl");
    std::fs::create_dir_all(root).expect("create diagnostic fixture root");
    std::fs::write(&ps_path, ps.to_string()).expect("write diagnostic ps fixture");
    std::fs::write(&first_path, first_inspect.to_string())
        .expect("write first diagnostic inspect fixture");
    if let Some(second_inspect) = second_inspect {
        std::fs::write(&second_path, second_inspect.to_string())
            .expect("write second diagnostic inspect fixture");
    }
    let script = r#"#!/bin/sh
case " $* " in
  *" ps -o json "*) cat "@PS@" ;;
  *" inspect -o json "*)
    count=0
    test ! -f "@COUNT@" || count=$(cat "@COUNT@")
    count=$((count + 1))
    printf '%s' "$count" > "@COUNT@"
    if test "$count" -ge 2 && test -f "@SECOND@"; then
      cat "@SECOND@"
    else
      cat "@FIRST@"
    fi
    ;;
  *) printf '%s\n' 'hostile-private-unexpected-command' >&2; exit 97 ;;
esac
"#
    .replace("@PS@", &ps_path.to_string_lossy())
    .replace("@FIRST@", &first_path.to_string_lossy())
    .replace("@SECOND@", &second_path.to_string_lossy())
    .replace("@COUNT@", &count_path.to_string_lossy());
    write_executable_fixture(&crictl, &script);
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(root.join("hostile-private-runtime.sock"))
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        root.join("proc"),
        root.join("sys/fs/cgroup"),
        Duration::from_millis(1),
        32,
    )
    .expect("containerd diagnostic fixture adapter");
    let error = match RuntimeInventoryAdapter::scan_inventory(&adapter).await {
        Err(error) => error,
        Ok(_) => panic!("diagnostic fixture unexpectedly passed inventory validation"),
    };
    let _ = std::fs::remove_dir_all(root);
    error
}

const CONTAINERD_DIAGNOSTIC_ID: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn prepare_containerd_diagnostic_identity(root: &Path) {
    write_runtime_identity_fixture(&root.join("proc"), 4242, 77, "/containerd/private");
    std::fs::create_dir_all(root.join("sys/fs/cgroup/containerd/private"))
        .expect("create diagnostic cgroup identity");
}

fn containerd_diagnostic_ps() -> serde_json::Value {
    json!({"containers":[{
        "id": CONTAINERD_DIAGNOSTIC_ID,
        "state": "CONTAINER_RUNNING",
        "labels": {"apolysis.session_id": "hostile-private-label"}
    }]})
}

fn containerd_diagnostic_inspect() -> serde_json::Value {
    json!({
        "status": {
            "id": CONTAINERD_DIAGNOSTIC_ID,
            "state": "CONTAINER_RUNNING",
            "startedAt": 101,
            "labels": {"apolysis.session_id": "hostile-private-label"}
        },
        "info": {
            "pid": 4242,
            "runtimeType": "io.containerd.runc.v2",
            "runtimeSpec": {"linux": {"cgroupsPath": "/containerd/private"}}
        }
    })
}

fn assert_fixed_containerd_inventory_error(
    error: &RuntimeInventoryScanError,
    expected: RuntimeInventoryInvalidCategory,
    expected_code: &str,
) {
    assert_eq!(error.reason(), RuntimeSourceGapReason::InventoryInvalid);
    assert_eq!(error.inventory_invalid_category(), Some(expected));
    assert_eq!(expected.code(), expected_code);
    assert_eq!(
        error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    let debug = format!("{error:?}");
    for private_value in [
        "hostile-private",
        "/private/",
        "stderr-payload",
        CONTAINERD_DIAGNOSTIC_ID,
    ] {
        assert!(!error.to_string().contains(private_value));
        assert!(!debug.contains(private_value));
        assert!(!expected.code().contains(private_value));
    }
}

async fn serve_fake_docker_responses(
    listener: UnixListener,
    responses: Vec<(String, serde_json::Value)>,
) {
    serve_fake_docker_responses_inner(listener, responses, None).await;
}

async fn serve_fake_docker_responses_with_file_replacement(
    listener: UnixListener,
    responses: Vec<(String, serde_json::Value)>,
    response_index: usize,
    path: std::path::PathBuf,
    contents: String,
) {
    serve_fake_docker_responses_inner(listener, responses, Some((response_index, path, contents)))
        .await;
}

async fn serve_fake_docker_responses_inner(
    listener: UnixListener,
    responses: Vec<(String, serde_json::Value)>,
    replacement: Option<(usize, std::path::PathBuf, String)>,
) {
    for (index, (expected_path, body)) in responses.into_iter().enumerate() {
        let (mut stream, _) = listener.accept().await.expect("accept Docker request");
        let mut request = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream
                .read_exact(&mut byte)
                .await
                .expect("read Docker request");
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).expect("Docker request is UTF-8");
        assert!(
            request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")),
            "unexpected Docker request: {request}"
        );
        if let Some((response_index, path, contents)) = &replacement {
            if index == *response_index {
                std::fs::write(path, contents).expect("replace runtime identity fixture");
            }
        }
        let body = serde_json::to_string(&body).expect("encode fake Docker response");
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .expect("write Docker response");
    }
}

#[test]
fn docker_snapshot_with_session_label_becomes_runtime_workload() {
    let mut labels = BTreeMap::new();
    labels.insert(
        "apolysis.session_id".to_string(),
        "session-docker".to_string(),
    );
    labels.insert("owner".to_string(), "ignored".to_string());

    let workload = docker_workload_from_snapshot(DockerContainerSnapshot {
        container_id: "0123456789abcdef".to_string(),
        labels,
        cgroup_id: 42,
        image: Some("alpine:3.20".to_string()),
        runtime_handler: Some("runsc".to_string()),
    })
    .expect("valid docker snapshot")
    .expect("marked workload");

    assert_eq!(workload.adapter, AdapterKind::Docker);
    assert_eq!(workload.session_id, "session-docker");
    assert_eq!(workload.workload_id, "0123456789abcdef");
    assert_eq!(workload.cgroup_id, 42);
    assert_eq!(workload.runtime_handler.as_deref(), Some("runsc"));
    assert_eq!(workload.image.as_deref(), Some("alpine:3.20"));
}

#[test]
fn docker_snapshot_without_session_label_is_ignored() {
    let workload = docker_workload_from_snapshot(DockerContainerSnapshot {
        container_id: "0123456789abcdef".to_string(),
        labels: BTreeMap::new(),
        cgroup_id: 42,
        image: Some("alpine:3.20".to_string()),
        runtime_handler: Some("runc".to_string()),
    })
    .expect("valid docker snapshot");

    assert!(workload.is_none());
}

#[test]
fn docker_engine_inspect_json_becomes_snapshot() {
    let snapshot = docker_snapshot_from_engine_inspect(
        &json!({
            "Id": "abcdef0123456789",
            "Config": {
                "Image": "ghcr.io/example/workload:2026-06-16",
                "Labels": {
                    "apolysis.session_id": "session-docker",
                    "com.example.owner": "runtime-team"
                }
            },
            "HostConfig": {
                "Runtime": "runsc"
            }
        }),
        123,
    )
    .expect("docker inspect snapshot");

    assert_eq!(snapshot.container_id, "abcdef0123456789");
    assert_eq!(snapshot.cgroup_id, 123);
    assert_eq!(
        snapshot
            .labels
            .get("apolysis.session_id")
            .map(String::as_str),
        Some("session-docker")
    );
    assert_eq!(
        snapshot.image.as_deref(),
        Some("ghcr.io/example/workload:2026-06-16")
    );
    assert_eq!(snapshot.runtime_handler.as_deref(), Some("runsc"));
}

#[test]
fn docker_engine_inspect_json_exposes_container_init_pid() {
    let pid = docker_container_pid_from_engine_inspect(&json!({
        "State": {
            "Pid": 38124,
            "Running": true
        }
    }))
    .expect("container init pid");

    assert_eq!(pid, 38124);
}

#[test]
fn proc_cgroup_entry_resolves_to_cgroup_directory_inode() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-cgroup-resolver-{}-{id}",
        std::process::id()
    ));
    let cgroup = root.join("system.slice/docker-abc.scope");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&cgroup).expect("create fake cgroup");

    let resolved = cgroup_id_from_proc_cgroup("0::/system.slice/docker-abc.scope\n", &root)
        .expect("resolve cgroup id");

    assert_eq!(resolved, std::fs::metadata(&cgroup).unwrap().ino());

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn proc_cgroup_entry_rejects_parent_components() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-cgroup-resolver-hostpid-{}-{id}",
        std::process::id()
    ));
    let relative = "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-workload.scope";
    let cgroup = root.join(relative);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&cgroup).expect("create fake k3s cgroup");

    let proc_cgroup = format!("1:net_cls:/\n0::/../../{relative}\n");
    let error = cgroup_id_from_proc_cgroup(&proc_cgroup, &root)
        .expect_err("parent cgroup path must fail closed");

    assert!(error.contains("parent component"), "{error}");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn proc_cgroup_entry_rejects_a_symbolic_link_boundary() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-cgroup-resolver-symlink-{}-{id}",
        std::process::id()
    ));
    let outside = root.join("outside");
    let link = root.join("linked-cgroup");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&outside).expect("create symlink target");
    std::os::unix::fs::symlink(&outside, &link).expect("create cgroup symlink fixture");

    let error = cgroup_id_from_proc_cgroup("0::/linked-cgroup\n", &root)
        .expect_err("symbolic-link cgroup boundary must fail closed");

    assert!(error.contains("symbolic link"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn proc_cgroup_entry_rejects_a_symbolic_link_cgroup_root() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let fixture = std::env::temp_dir().join(format!(
        "apolysis-cgroup-root-symlink-{}-{id}",
        std::process::id()
    ));
    let outside = fixture.join("outside");
    let root_link = fixture.join("cgroup-root");
    let _ = std::fs::remove_dir_all(&fixture);
    std::fs::create_dir_all(outside.join("agent.scope")).expect("create outside cgroup canary");
    std::os::unix::fs::symlink(&outside, &root_link).expect("create cgroup root symlink");

    let error = cgroup_id_from_proc_cgroup("0::/agent.scope\n", &root_link)
        .expect_err("symbolic-link cgroup root must fail closed");

    assert!(error.contains("symbolic link"), "{error}");
    let _ = std::fs::remove_dir_all(&fixture);
}

#[test]
fn proc_cgroup_entry_never_crosses_an_intermediate_directory_replacement() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let fixture = std::env::temp_dir().join(format!(
        "apolysis-cgroup-intermediate-race-{}-{id}",
        std::process::id()
    ));
    let cgroup_root = fixture.join("root");
    let boundary = cgroup_root.join("switch");
    let held = cgroup_root.join("held");
    let outside = fixture.join("canary");
    let _ = std::fs::remove_dir_all(&fixture);
    std::fs::create_dir_all(boundary.join("agent.scope")).expect("create legitimate cgroup");
    std::fs::create_dir_all(outside.join("agent.scope")).expect("create outside canary cgroup");
    let legitimate_inode = std::fs::metadata(boundary.join("agent.scope"))
        .expect("legitimate cgroup metadata")
        .ino();
    let canary_inode = std::fs::metadata(outside.join("agent.scope"))
        .expect("outside canary metadata")
        .ino();
    assert_ne!(legitimate_inode, canary_inode);

    let running = Arc::new(AtomicBool::new(true));
    let toggler_running = Arc::clone(&running);
    let toggler_boundary = boundary.clone();
    let toggler_held = held.clone();
    let toggler_outside = outside.clone();
    let toggler = std::thread::spawn(move || {
        while toggler_running.load(Ordering::Acquire) {
            if std::fs::rename(&toggler_boundary, &toggler_held).is_ok() {
                std::os::unix::fs::symlink(&toggler_outside, &toggler_boundary)
                    .expect("publish cgroup canary symlink");
                std::thread::yield_now();
                std::fs::remove_file(&toggler_boundary).expect("remove cgroup canary symlink");
                std::fs::rename(&toggler_held, &toggler_boundary)
                    .expect("restore legitimate cgroup boundary");
            }
        }
    });

    for _ in 0..10_000 {
        if let Ok(inode) = cgroup_id_from_proc_cgroup("0::/switch/agent.scope\n", &cgroup_root) {
            assert_eq!(
                inode, legitimate_inode,
                "resolver crossed into the replacement canary directory"
            );
        }
    }
    running.store(false, Ordering::Release);
    toggler.join().expect("cgroup boundary toggler");

    assert_eq!(
        cgroup_id_from_proc_cgroup("0::/switch/agent.scope\n", &cgroup_root)
            .expect("restored legitimate cgroup"),
        legitimate_inode
    );
    let _ = std::fs::remove_dir_all(&fixture);
}

#[test]
fn cri_runtime_spec_systemd_cgroups_path_resolves_to_cgroup_inode() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-cri-cgroup-resolver-{}-{id}",
        std::process::id()
    ));
    let relative = "kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podabc.slice/cri-containerd-workload.scope";
    let cgroup = root.join(relative);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&cgroup).expect("create fake CRI cgroup");

    let inspect = json!({
        "info": {
            "runtimeSpec": {
                "linux": {
                    "cgroupsPath": "kubepods-burstable-podabc.slice:cri-containerd:workload"
                }
            }
        }
    });
    let resolved = cgroup_id_from_cri_inspect_cgroups_path(&inspect, &root)
        .expect("parse CRI cgroupsPath")
        .expect("CRI cgroupsPath exists");

    assert_eq!(resolved, std::fs::metadata(&cgroup).unwrap().ino());

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_engine_client_reads_inspect_json_over_unix_socket() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-engine-client-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create socket directory");
    let listener = UnixListener::bind(&socket).expect("bind fake docker socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let mut request = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.expect("read request");
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).expect("UTF-8 request");
        assert!(request.starts_with("GET /containers/container-abc/json HTTP/1.1\r\n"));
        let body = r#"{"Id":"container-abc","State":{"Pid":1234}}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .expect("write response");
    });

    let inspect = DockerEngineClient::new(&socket)
        .inspect_container("container-abc")
        .await
        .expect("inspect container");

    assert_eq!(inspect["Id"], "container-abc");
    assert_eq!(inspect["State"]["Pid"], 1234);
    server.await.expect("fake docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_engine_client_rejects_an_oversized_response() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-response-bound-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create socket directory");
    let listener = UnixListener::bind(&socket).expect("bind fake Docker socket");
    let server = tokio::spawn(serve_fake_docker_responses(
        listener,
        vec![(
            "/containers/bounded/json".to_string(),
            json!({"padding": "x".repeat(8 * 1024 * 1024)}),
        )],
    ));

    let error = DockerEngineClient::new(&socket)
        .inspect_container("bounded")
        .await
        .expect_err("oversized Docker response must fail closed");

    assert!(error.contains("response exceeds"), "{error}");
    server.await.expect("oversized fake Docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_engine_client_times_out_a_stalled_response() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-response-timeout-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create socket directory");
    let listener = UnixListener::bind(&socket).expect("bind fake Docker socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept Docker request");
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            stream
                .read_exact(&mut byte)
                .await
                .expect("read Docker request");
            request.push(byte[0]);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    });

    let error = DockerEngineClient::new(&socket)
        .with_timeout(Duration::from_millis(20))
        .inspect_container("stalled")
        .await
        .expect_err("stalled Docker response must time out");

    assert!(error.contains("timed out"), "{error}");
    server.abort();
    let _ = server.await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_engine_client_lists_only_marked_running_containers() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-engine-list-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create socket directory");
    let listener = UnixListener::bind(&socket).expect("bind fake docker socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let mut request = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.expect("read request");
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8(request).expect("UTF-8 request");
        assert!(request.starts_with("GET /containers/json HTTP/1.1\r\n"));
        let body = r#"[
            {"Id":"marked-1","Labels":{"apolysis.session_id":"session-a"}},
            {"Id":"unmarked","Labels":{"owner":"other"}},
            {"Id":"marked-2","Labels":{"apolysis.session_id":"session-b"}}
        ]"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .expect("write response");
    });

    let ids = DockerEngineClient::new(&socket)
        .list_marked_running_container_ids()
        .await
        .expect("list containers");

    assert_eq!(ids, vec!["marked-1", "marked-2"]);
    server.await.expect("fake docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_engine_client_decodes_chunked_json_response() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-engine-chunked-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create socket directory");
    let listener = UnixListener::bind(&socket).expect("bind fake docker socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let mut request = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.expect("read request");
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let body = r#"[{"Id":"marked-1","Labels":{"apolysis.session_id":"session-a"}}]"#;
        let split = 12;
        let chunked = format!(
            "{:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            split,
            &body[..split],
            body.len() - split,
            &body[split..]
        );
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n{}",
                    chunked
                )
                .as_bytes(),
            )
            .await
            .expect("write response");
    });

    let ids = DockerEngineClient::new(&socket)
        .list_marked_running_container_ids()
        .await
        .expect("list containers");

    assert_eq!(ids, vec!["marked-1"]);
    server.await.expect("fake docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn docker_engine_runtime_adapter_inspects_container_and_resolves_cgroup() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-docker-engine-adapter-{}-{id}",
        std::process::id()
    ));
    let socket = root.join("docker.sock");
    let proc_root = root.join("proc");
    let cgroup_root = root.join("sys/fs/cgroup");
    let cgroup = cgroup_root.join("system.slice/docker-container-abc.scope");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&cgroup).expect("create fake cgroup");
    std::fs::create_dir_all(proc_root.join("1234")).expect("create fake proc pid");
    std::fs::write(
        proc_root.join("1234/cgroup"),
        "0::/system.slice/docker-container-abc.scope\n",
    )
    .expect("write fake proc cgroup");
    let listener = UnixListener::bind(&socket).expect("bind fake docker socket");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept client");
        let mut request = Vec::new();
        loop {
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).await.expect("read request");
            request.push(byte[0]);
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let body = r#"{
            "Id":"container-abc",
            "State":{"Pid":1234},
            "Config":{
                "Image":"alpine:3.20",
                "Labels":{"apolysis.session_id":"session-docker"}
            },
            "HostConfig":{"Runtime":"runsc"}
        }"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .expect("write response");
    });
    let mut adapter = DockerEngineRuntimeAdapter::new(
        DockerEngineClient::new(&socket),
        &proc_root,
        &cgroup_root,
        vec!["container-abc".to_string()],
    );

    let workload = adapter
        .next_workload()
        .await
        .expect("adapter poll")
        .expect("marked workload");

    assert_eq!(workload.adapter, AdapterKind::Docker);
    assert_eq!(workload.session_id, "session-docker");
    assert_eq!(workload.workload_id, "container-abc");
    assert_eq!(
        workload.cgroup_id,
        std::fs::metadata(&cgroup).unwrap().ino()
    );
    assert_eq!(workload.runtime_handler.as_deref(), Some("runsc"));
    server.await.expect("fake docker server");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
#[ignore = "requires Docker Engine socket access and the ability to run containers"]
async fn live_docker_engine_adapter_discovers_labelled_container() {
    require_command("docker");
    if !docker_image_is_present_without_pull("alpine:3.20") {
        eprintln!("skipped: alpine:3.20 is not present locally (this gate never pulls images)");
        return;
    }
    for runtime in live_docker_runtimes() {
        let session_id = format!(
            "live-docker-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        );
        let container_id = start_labelled_docker_container(runtime, &session_id, "sleep 30");
        let cleanup = DockerContainerCleanup {
            container_id: container_id.clone(),
        };

        let client = DockerEngineClient::new("/var/run/docker.sock");
        let marked_ids = client
            .list_marked_running_container_ids()
            .await
            .expect("list marked containers");
        assert!(
            marked_ids.iter().any(|id| id.starts_with(&container_id)),
            "marked containers did not include {container_id}: {marked_ids:?}"
        );
        let adapter = DockerEnginePollingRuntimeAdapter::new(
            client,
            "/proc",
            "/sys/fs/cgroup",
            Duration::from_millis(100),
            1024,
        );
        let inventory = tokio::time::timeout(Duration::from_secs(15), adapter.scan_inventory())
            .await
            .expect("Docker inventory timeout")
            .expect("complete Docker inventory");
        let binding = inventory
            .bindings
            .iter()
            .find(|binding| binding.identity.workload_id == container_id)
            .expect("target labelled Docker binding");

        assert_eq!(binding.identity.adapter, AdapterKind::Docker);
        assert_eq!(binding.agent_run_id, session_id);
        assert!(!binding.identity.start_marker.is_empty());
        assert!(!binding.identity.host_boot_id.is_empty());
        assert!(binding.identity.init_process_start_time_ticks > 0);
        assert!(binding.identity.cgroup.device > 0);
        assert!(binding.identity.cgroup.inode > 0);
        if let Some(runtime) = runtime {
            assert_eq!(binding.runtime_handler.as_deref(), Some(runtime));
        }

        drop(cleanup);
    }
}

#[tokio::test]
#[ignore = "requires Docker Engine socket access and an already-present Alpine image; never restarts Docker"]
async fn live_docker_daemon_restart_requalifies_a_stable_binding_from_fresh_complete_inventory() {
    if !docker_image_is_present_without_pull("alpine:3.20") {
        eprintln!(
            "skipped: Docker is unavailable or alpine:3.20 is not present locally (this gate never pulls images)"
        );
        return;
    }

    let unrelated_before = running_docker_container_ids();
    let session_id = random_live_session_id("live-docker-daemon-restart");
    let mut config = config("live-docker-daemon-restart");
    config.docker_socket = Some("/var/run/docker.sock".into());
    config.proc_root = "/proc".into();
    config.cgroup_root = "/sys/fs/cgroup".into();
    config.runtime_adapter_scan_interval = Duration::from_millis(50);
    config.shutdown_drain_timeout = Duration::from_secs(5);
    let state_cleanup = DaemonStateRootCleanup::new(&config);
    {
        let bootstrap = DaemonState::new(&config).expect("bootstrap daemon state");
        bootstrap
            .register(intent(&session_id), 1_700_000_000_000)
            .await
            .expect("register live Agent Run before adapter startup");
    }
    let container_id = start_labelled_docker_container(None, &session_id, "sleep 120");
    let container_cleanup = DockerContainerCleanup {
        container_id: container_id.clone(),
    };

    let first_daemon = LiveDaemonServer::start(config.clone()).await;
    let (first_session, first_binding) = wait_for_live_daemon_binding(
        &config.socket_path,
        &session_id,
        &container_id,
        Duration::from_secs(20),
    )
    .await;
    assert_eq!(first_session.status, SessionStatus::Active);
    first_daemon.stop().await;
    let timeline_path = config
        .state_dir
        .join(format!("sessions/{session_id}/timeline.jsonl"));
    let timeline_before_restart =
        std::fs::read_to_string(&timeline_path).expect("first daemon timeline");

    let restarted_daemon = LiveDaemonServer::start(config.clone()).await;
    let (restarted_session, restarted_binding) = wait_for_live_daemon_binding(
        &config.socket_path,
        &session_id,
        &container_id,
        Duration::from_secs(20),
    )
    .await;
    assert_eq!(restarted_session.status, SessionStatus::Active);
    assert_eq!(restarted_binding.identity, first_binding.identity);
    restarted_daemon.stop().await;

    let timeline_after_restart =
        std::fs::read_to_string(&timeline_path).expect("restarted daemon timeline");
    assert!(timeline_after_restart.starts_with(&timeline_before_restart));
    assert_eq!(
        target_runtime_recovery_sequence(
            &timeline_after_restart[timeline_before_restart.len()..],
            &session_id,
            &container_id,
            "daemon_restart",
        ),
        ["gap", "retired", "observed"]
    );

    drop(container_cleanup);
    assert_eq!(running_docker_container_ids(), unrelated_before);
    drop(state_cleanup);
}

#[tokio::test]
#[ignore = "requires Docker Engine socket access and an already-present Alpine image; never restarts Docker"]
async fn live_docker_container_restart_transitions_the_same_full_runtime_id() {
    if !docker_image_is_present_without_pull("alpine:3.20") {
        eprintln!(
            "skipped: Docker is unavailable or alpine:3.20 is not present locally (this gate never pulls images)"
        );
        return;
    }

    let unrelated_before = running_docker_container_ids();
    let session_id = random_live_session_id("live-docker-container-restart");
    let mut config = config("live-docker-container-restart");
    config.docker_socket = Some("/var/run/docker.sock".into());
    config.proc_root = "/proc".into();
    config.cgroup_root = "/sys/fs/cgroup".into();
    config.runtime_adapter_scan_interval = Duration::from_millis(50);
    config.shutdown_drain_timeout = Duration::from_secs(5);
    let state_cleanup = DaemonStateRootCleanup::new(&config);

    {
        let bootstrap = DaemonState::new(&config).expect("bootstrap daemon state");
        bootstrap
            .register(intent(&session_id), 1_700_000_000_000)
            .await
            .expect("register live Agent Run before adapter startup");
    }

    let container_id = start_labelled_docker_container(None, &session_id, "sleep 120");
    let container_cleanup = DockerContainerCleanup {
        container_id: container_id.clone(),
    };

    let daemon = LiveDaemonServer::start(config.clone()).await;
    let (first_session, first_binding) = wait_for_live_daemon_binding(
        &config.socket_path,
        &session_id,
        &container_id,
        Duration::from_secs(20),
    )
    .await;
    assert_eq!(first_session.status, SessionStatus::Active);
    assert_eq!(
        first_session.cgroup_ids,
        vec![first_binding.identity.cgroup.inode]
    );
    let timeline_path = config
        .state_dir
        .join(format!("sessions/{session_id}/timeline.jsonl"));
    let timeline_before_restart =
        std::fs::read_to_string(&timeline_path).expect("first daemon timeline");
    assert_eq!(
        timeline_before_restart
            .matches(r#""record_type":"runtime_binding_observed""#)
            .count(),
        1,
        "the initial inventory must durably attach the target exactly once"
    );

    let restart = Command::new("docker")
        .args(["restart", "--timeout", "1", &container_id])
        .output()
        .expect("restart the test-owned Docker container");
    assert!(
        restart.status.success(),
        "test-owned Docker restart failed: {}",
        String::from_utf8_lossy(&restart.stderr)
    );
    assert_eq!(
        String::from_utf8(restart.stdout)
            .expect("Docker restart output is UTF-8")
            .trim(),
        container_id,
        "Docker restart must preserve the exact full container ID"
    );
    let (restarted_session, restarted_binding) = wait_for_live_daemon_binding_transition(
        &config.socket_path,
        &session_id,
        &container_id,
        &first_binding.identity,
        Duration::from_secs(20),
    )
    .await;
    assert_eq!(restarted_session.status, SessionStatus::Active);
    assert_eq!(
        restarted_session.cgroup_ids,
        vec![restarted_binding.identity.cgroup.inode]
    );
    assert_eq!(
        restarted_binding.identity.workload_id,
        first_binding.identity.workload_id
    );
    assert_ne!(restarted_binding.identity, first_binding.identity);
    assert_ne!(
        restarted_binding.identity.cgroup.inode, first_binding.identity.cgroup.inode,
        "container restart must create a new cgroup proof generation"
    );
    assert!(
        !restarted_session
            .cgroup_ids
            .contains(&first_binding.identity.cgroup.inode),
        "old cgroup ownership must be cleared"
    );
    daemon.stop().await;

    let timeline_after_restart =
        std::fs::read_to_string(&timeline_path).expect("restarted daemon timeline");
    assert!(
        timeline_after_restart.starts_with(&timeline_before_restart),
        "container restart must append to the existing private state root"
    );
    assert_eq!(
        target_runtime_recovery_sequence(
            &timeline_after_restart[timeline_before_restart.len()..],
            &session_id,
            &container_id,
            "identity_transition",
        ),
        ["gap", "retired", "observed"]
    );

    drop(container_cleanup);
    assert_eq!(
        running_docker_container_ids(),
        unrelated_before,
        "the live gate must leave every unrelated running container unchanged"
    );
    drop(state_cleanup);
}

#[tokio::test]
#[ignore = "requires Docker Engine socket access and the ability to run containers"]
async fn live_docker_engine_adapter_recovers_after_socket_disconnect() {
    require_command("docker");
    if !docker_image_is_present_without_pull("alpine:3.20") {
        eprintln!("skipped: alpine:3.20 is not present locally (this gate never pulls images)");
        return;
    }
    let session_id = format!(
        "live-docker-recovery-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let container_id = start_labelled_docker_container(None, &session_id, "sleep 30");
    let container_cleanup = DockerContainerCleanup {
        container_id: container_id.clone(),
    };
    let config = config("live-docker-socket-recovery");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent(&session_id), 1_700_000_000_000)
        .await
        .expect("register intent");
    let proxy_socket = config.state_dir.join("docker-proxy.sock");
    let proxy = start_controllable_unix_socket_proxy(
        &proxy_socket,
        std::path::Path::new("/var/run/docker.sock"),
        false,
    );
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&proxy_socket),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    );
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 10,
            max_delay_ms: 10,
            jitter_ms: 0,
        },
    ));

    wait_for_session_cgroup(&state, &session_id, Duration::from_secs(15)).await;
    let initial_binding = state
        .runtime_bindings_for_agent_run(&session_id)
        .await
        .into_iter()
        .find(|binding| binding.identity.workload_id == container_id)
        .expect("initial Docker runtime binding");
    let timeline_path = config
        .state_dir
        .join(format!("sessions/{session_id}/timeline.jsonl"));
    let timeline_before_outage =
        std::fs::read_to_string(&timeline_path).expect("initial Docker binding timeline");
    proxy.disconnect();
    wait_for_runtime_binding_gap(
        &state,
        AdapterKind::Docker,
        &session_id,
        initial_binding.identity.cgroup.inode,
        Duration::from_secs(15),
    )
    .await;
    proxy.reconnect();
    wait_for_same_runtime_binding(
        &state,
        AdapterKind::Docker,
        &session_id,
        &initial_binding,
        Duration::from_secs(15),
    )
    .await;
    shutdown.send(()).expect("stop Docker adapter");
    let summary = runner.await.expect("Docker adapter task");

    assert!(summary.backend_errors > 0);
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(summary.discovered, 2);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Docker),
        ComponentState::Ready
    );
    let timeline =
        std::fs::read_to_string(&timeline_path).expect("Docker socket recovery timeline");
    assert!(
        timeline.starts_with(&timeline_before_outage),
        "socket recovery must append to the existing target timeline"
    );
    assert_eq!(
        target_runtime_socket_recovery_sequence(
            &timeline[timeline_before_outage.len()..],
            &session_id,
            "docker",
            &container_id,
        ),
        ["gap", "suspended", "observed"]
    );

    proxy.abort();
    drop(container_cleanup);
    cleanup(&config);
}

#[tokio::test]
#[ignore = "requires Docker Engine socket access, systemd access, and permission to restart Docker"]
async fn live_docker_engine_adapter_recovers_after_systemd_restart() {
    if !destructive_runtime_restart_enabled() {
        eprintln!("skipped: set APOLYSIS_DESTRUCTIVE_RUNTIME_RESTART=1 only on a disposable host");
        return;
    }
    require_command("docker");
    require_command("systemctl");
    require_command("systemd-run");
    ensure_docker_alpine_image();
    wait_for_systemd_service_active("docker.service", Duration::from_secs(60));
    wait_for_docker_engine(Duration::from_secs(60));
    let session_id = format!(
        "live-docker-systemd-restart-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let first_container = start_labelled_docker_container(None, &session_id, "sleep 120");
    let first_cleanup = DockerContainerCleanup {
        container_id: first_container,
    };
    let config = config("live-docker-systemd-restart");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent(&session_id), 1_700_000_000_000)
        .await
        .expect("register intent");
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new("/var/run/docker.sock"),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(10),
        1024,
    );
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 10,
            max_delay_ms: 10,
            jitter_ms: 0,
        },
    ));

    wait_for_session_cgroup_count(&state, &session_id, 1, Duration::from_secs(20)).await;
    let docker_systemd = SystemdUnitRestoreGuard::capture(["docker.socket", "docker.service"]);
    stop_docker_systemd_units();
    assert!(
        wait_for_docker_engine_unavailable(Duration::from_secs(30)),
        "Docker Engine stayed responsive after systemd stop"
    );
    let adapter_degraded = adapter_reaches_state(
        &state,
        AdapterKind::Docker,
        ComponentState::Degraded,
        Duration::from_secs(30),
    )
    .await;
    start_docker_systemd_units();
    assert!(
        adapter_degraded,
        "Docker adapter did not report degraded health during Docker stop"
    );
    wait_for_docker_engine(Duration::from_secs(90));
    let second_container = start_labelled_docker_container(None, &session_id, "sleep 60");
    let second_cleanup = DockerContainerCleanup {
        container_id: second_container,
    };
    wait_for_session_cgroup_count(&state, &session_id, 2, Duration::from_secs(30)).await;

    shutdown.send(()).expect("stop Docker adapter");
    let summary = runner.await.expect("Docker adapter task");

    assert!(
        summary.discovered >= 2,
        "Docker restart should reattach a complete inventory: {summary:?}"
    );
    assert!(
        summary.backend_errors > 0,
        "Docker restart should produce at least one backend error: {summary:?}"
    );
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Docker),
        ComponentState::Ready
    );
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join(format!("sessions/{session_id}/timeline.jsonl")),
    )
    .expect("Docker restart Agent Run timeline");
    assert!(timeline.contains("reason=socket_unavailable"));

    drop(second_cleanup);
    drop(first_cleanup);
    cleanup(&config);
    drop(docker_systemd);
}

#[tokio::test]
#[ignore = "requires root access to standalone containerd CRI socket and local Alpine image"]
async fn live_containerd_cri_adapter_discovers_labelled_containers() {
    live_cri_adapter_matrix(
        AdapterKind::Containerd,
        "/run/containerd/containerd.sock",
        Some("unix:///run/containerd/containerd.sock"),
    )
    .await;
}

#[tokio::test]
#[ignore = "requires standalone containerd CRI socket, systemd access, Docker helper access, and permission to restart containerd"]
async fn live_containerd_cri_adapter_recovers_after_systemd_restart() {
    if !destructive_runtime_restart_enabled() {
        eprintln!("skipped: set APOLYSIS_DESTRUCTIVE_RUNTIME_RESTART=1 only on a disposable host");
        return;
    }
    require_command("docker");
    require_command("systemctl");
    require_command("systemd-run");
    ensure_docker_alpine_image();
    let runtime_socket = "/run/containerd/containerd.sock";
    let image_endpoint = Some("unix:///run/containerd/containerd.sock");
    let configured_crictl = std::env::var_os("APOLYSIS_CRICTL").map(|_| live_crictl_path());
    if configured_crictl.is_none() {
        require_command("crictl");
    }
    let crictl_wrapper = configured_crictl
        .is_none()
        .then(|| create_host_chroot_crictl_wrapper("containerd-systemd-restart"));
    let crictl_path = configured_crictl.as_deref().unwrap_or_else(|| {
        crictl_wrapper
            .as_ref()
            .expect("default host-chroot crictl wrapper")
            .path()
    });
    wait_for_systemd_service_active("containerd.service", Duration::from_secs(60));
    wait_for_cri_runtime(
        crictl_path,
        runtime_socket,
        image_endpoint,
        Duration::from_secs(60),
    );
    if !standalone_cri_network_ready_or_skip(crictl_path, runtime_socket, image_endpoint) {
        return;
    }
    let session_id = format!("live-containerd-systemd-restart-{}", kernel_random_uuid());
    let first_workload = create_cri_workload_with_crictl(
        crictl_path,
        runtime_socket,
        image_endpoint,
        "runc",
        &session_id,
    );
    let config = config("live-containerd-systemd-restart");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent(&session_id), 1_700_000_000_000)
        .await
        .expect("register intent");
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(runtime_socket)
            .with_crictl_path(crictl_path)
            .with_image_endpoint(image_endpoint.map(ToOwned::to_owned)),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    )
    .expect("containerd CRI adapter");
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 20,
            max_delay_ms: 20,
            jitter_ms: 0,
        },
    ));

    wait_for_session_cgroup_count(&state, &session_id, 1, Duration::from_secs(30)).await;
    let containerd_systemd = SystemdUnitRestoreGuard::capture(["containerd.service"]);
    stop_systemd_unit("containerd.service");
    assert!(
        wait_for_cri_runtime_unavailable(
            crictl_path,
            runtime_socket,
            image_endpoint,
            Duration::from_secs(30),
        ),
        "standalone containerd CRI stayed responsive after systemd stop"
    );
    let adapter_degraded = adapter_reaches_state(
        &state,
        AdapterKind::Containerd,
        ComponentState::Degraded,
        Duration::from_secs(30),
    )
    .await;
    start_systemd_unit("containerd.service");
    wait_for_systemd_service_active("containerd.service", Duration::from_secs(90));
    assert!(
        adapter_degraded,
        "containerd adapter did not report degraded health during containerd stop"
    );
    wait_for_cri_runtime(
        crictl_path,
        runtime_socket,
        image_endpoint,
        Duration::from_secs(90),
    );
    let second_workload = create_cri_workload_with_crictl(
        crictl_path,
        runtime_socket,
        image_endpoint,
        "runc",
        &session_id,
    );
    wait_for_session_cgroup_count(&state, &session_id, 2, Duration::from_secs(30)).await;

    shutdown.send(()).expect("stop containerd adapter");
    let summary = runner.await.expect("containerd adapter task");

    assert!(
        summary.discovered >= 2,
        "containerd restart should reattach a complete inventory: {summary:?}"
    );
    assert!(
        summary.backend_errors > 0,
        "containerd restart should produce at least one backend error: {summary:?}"
    );
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Containerd),
        ComponentState::Ready
    );
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join(format!("sessions/{session_id}/timeline.jsonl")),
    )
    .expect("containerd restart Agent Run timeline");
    assert!(timeline.contains("reason=socket_unavailable"));

    second_workload
        .cleanup()
        .expect("strictly clean second owned containerd fixture");
    first_workload
        .cleanup()
        .expect("strictly clean first owned containerd fixture");
    cleanup(&config);
    drop(containerd_systemd);
}

#[tokio::test]
#[ignore = "requires root access to standalone containerd CRI socket and local Alpine image"]
async fn live_containerd_cri_adapter_recovers_after_socket_disconnect() {
    let crictl = live_crictl_path();
    let runtime_socket = "/run/containerd/containerd.sock";
    let image_endpoint = Some("unix:///run/containerd/containerd.sock");
    if !standalone_cri_network_ready_or_skip(&crictl, runtime_socket, image_endpoint) {
        return;
    }
    let session_id = format!("live-cri-recovery-{}", kernel_random_uuid());
    let workload_cleanup = create_cri_workload_with_crictl(
        &crictl,
        runtime_socket,
        image_endpoint,
        "runc",
        &session_id,
    );
    let config = config("live-containerd-cri-socket-recovery");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent(&session_id), 1_700_000_000_000)
        .await
        .expect("register intent");
    let proxy_socket = config.state_dir.join("containerd-cri-proxy.sock");
    let proxy = start_controllable_unix_socket_proxy(
        &proxy_socket,
        std::path::Path::new(runtime_socket),
        false,
    );
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(&proxy_socket)
            .with_crictl_path(&crictl)
            .with_image_endpoint(image_endpoint.map(ToOwned::to_owned)),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    )
    .expect("CRI adapter");
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 10,
            max_delay_ms: 10,
            jitter_ms: 0,
        },
    ));

    wait_for_session_cgroup(&state, &session_id, Duration::from_secs(20)).await;
    let expected_workload_id = format!("containerd/{}", workload_cleanup.container_id);
    let initial_binding = state
        .runtime_bindings_for_agent_run(&session_id)
        .await
        .into_iter()
        .find(|binding| binding.identity.workload_id == expected_workload_id)
        .expect("initial containerd runtime binding");
    let timeline_path = config
        .state_dir
        .join(format!("sessions/{session_id}/timeline.jsonl"));
    let timeline_before_outage =
        std::fs::read_to_string(&timeline_path).expect("initial containerd binding timeline");
    proxy.disconnect();
    wait_for_runtime_binding_gap(
        &state,
        AdapterKind::Containerd,
        &session_id,
        initial_binding.identity.cgroup.inode,
        Duration::from_secs(20),
    )
    .await;
    proxy.reconnect();
    wait_for_same_runtime_binding(
        &state,
        AdapterKind::Containerd,
        &session_id,
        &initial_binding,
        Duration::from_secs(20),
    )
    .await;
    shutdown.send(()).expect("stop CRI adapter");
    let summary = runner.await.expect("CRI adapter task");

    assert!(summary.backend_errors > 0);
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(summary.discovered, 2);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Containerd),
        ComponentState::Ready
    );
    let timeline =
        std::fs::read_to_string(&timeline_path).expect("containerd socket recovery timeline");
    assert!(
        timeline.starts_with(&timeline_before_outage),
        "socket recovery must append to the existing target timeline"
    );
    assert_eq!(
        target_runtime_socket_recovery_sequence(
            &timeline[timeline_before_outage.len()..],
            &session_id,
            "containerd",
            &expected_workload_id,
        ),
        ["gap", "suspended", "observed"]
    );

    proxy.abort();
    workload_cleanup
        .cleanup()
        .expect("strictly clean owned containerd socket fixture");
    cleanup(&config);
}

#[test]
fn private_live_proxy_path_stays_short_when_daemon_state_root_is_long() {
    use std::os::unix::ffi::OsStrExt;

    let private_root = Path::new("/tmp/apolysis-private-containerd-live.ABC123");
    let long_state_root = private_root.join("state").join("s".repeat(96));
    let old_proxy_path = long_state_root.join("private-containerd-cri-proxy.sock");
    assert!(
        old_proxy_path.as_os_str().as_bytes().len() > 107,
        "fixture must reproduce Linux sockaddr_un pathname overflow"
    );

    let proxy_socket = private_containerd_live_proxy_socket(private_root, &long_state_root);

    assert_eq!(proxy_socket, private_root.join("run/proxy.sock"));
    assert_ne!(proxy_socket, private_root.join("run/containerd.sock"));
    assert!(proxy_socket.as_os_str().as_bytes().len() <= 107);
}

#[tokio::test]
async fn controllable_unix_socket_proxy_abort_and_drop_unlink_only_their_owned_sockets() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-owned-proxy-socket-{}-{id}",
        std::process::id()
    ));
    let run_dir = root.join("run");
    let abort_socket = run_dir.join("abort.sock");
    let drop_socket = run_dir.join("drop.sock");
    let upstream_socket = run_dir.join("upstream.sock");
    let canary = run_dir.join("operator-canary");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&run_dir).expect("create owned proxy fixture root");
    std::fs::write(&canary, b"operator-owned\n").expect("write proxy cleanup canary");

    let abort_proxy = start_controllable_unix_socket_proxy(&abort_socket, &upstream_socket, false);
    assert!(std::fs::symlink_metadata(&abort_socket)
        .expect("abort proxy socket metadata")
        .file_type()
        .is_socket());
    abort_proxy.abort();
    let abort_absence = std::fs::symlink_metadata(&abort_socket)
        .err()
        .map(|error| error.kind());

    let drop_proxy = start_controllable_unix_socket_proxy(&drop_socket, &upstream_socket, false);
    assert!(std::fs::symlink_metadata(&drop_socket)
        .expect("drop proxy socket metadata")
        .file_type()
        .is_socket());
    drop(drop_proxy);
    let drop_absence = std::fs::symlink_metadata(&drop_socket)
        .err()
        .map(|error| error.kind());
    let canary_contents = std::fs::read(&canary).expect("read proxy cleanup canary");
    let _ = std::fs::remove_dir_all(&root);

    assert_eq!(abort_absence, Some(std::io::ErrorKind::NotFound));
    assert_eq!(drop_absence, Some(std::io::ErrorKind::NotFound));
    assert_eq!(canary_contents, b"operator-owned\n");
}

#[tokio::test]
async fn controllable_unix_socket_proxy_never_removes_an_unowned_path() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-unowned-proxy-path-{}-{id}",
        std::process::id()
    ));
    let run_dir = root.join("run");
    let proxy_socket = run_dir.join("proxy.sock");
    let upstream_socket = run_dir.join("upstream.sock");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&run_dir).expect("create unowned proxy fixture root");
    std::fs::write(&proxy_socket, b"operator-owned\n")
        .expect("write preexisting proxy-path canary");

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        start_controllable_unix_socket_proxy(&proxy_socket, &upstream_socket, false)
    }));
    let canary_contents = std::fs::read(&proxy_socket).ok();
    let rejected = match result {
        Ok(proxy) => {
            proxy.abort();
            false
        }
        Err(_) => true,
    };
    let _ = std::fs::remove_dir_all(&root);

    assert!(rejected, "a preexisting proxy path must be rejected");
    assert_eq!(
        canary_contents.as_deref(),
        Some(b"operator-owned\n".as_slice())
    );
}

#[tokio::test]
#[ignore = "requires the opt-in private containerd runner, root namespaces, cached Alpine, and a verified crictl binary"]
async fn live_private_containerd_cri_qualifies_inventory_identity_and_socket_recovery() {
    if std::env::var("APOLYSIS_PRIVATE_CONTAINERD_LIVE")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!(
            "skipped: use scripts/run-private-containerd-live.sh; never run this with a naked --ignored"
        );
        return;
    }
    assert_eq!(
        std::env::var("APOLYSIS_PRIVATE_CONTAINERD_DIAGNOSTIC")
            .ok()
            .as_deref(),
        Some("1"),
        "private inventory diagnostics require the root-owned runner handshake"
    );
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "private containerd live gate requires root"
    );
    let private_root = private_containerd_live_root();
    let runtime_socket = private_root.join("run/containerd.sock");
    prove_private_containerd_socket(&private_root, &runtime_socket);
    let crictl = live_crictl_path();
    assert_eq!(
        crictl,
        private_root.join("bin/crictl"),
        "private gate must use the root-owned crictl copy"
    );
    let endpoint = format!("unix://{}", runtime_socket.display());
    assert_eq!(
        private_cri_node_network_mutation_preflight(&crictl, &endpoint)
            .expect("private CRI NODE-network preflight"),
        CriMutationPreflight::Ready
    );
    begin_private_container_mutation_proof(&private_root)
        .expect("publish private containerd mutation-started proof");

    let first_session = format!("live-private-containerd-first-{}", kernel_random_uuid());
    let second_session = format!("live-private-containerd-second-{}", kernel_random_uuid());
    let first = create_private_cri_workload_with_crictl(
        &private_root,
        &crictl,
        runtime_socket.to_str().expect("private socket UTF-8"),
        Some(&endpoint),
        "runc",
        &first_session,
    );
    let second = create_private_cri_workload_with_crictl(
        &private_root,
        &crictl,
        runtime_socket.to_str().expect("private socket UTF-8"),
        Some(&endpoint),
        "runc",
        &second_session,
    );
    let first_workload_id = format!("containerd/{}", first.container_id);
    let second_workload_id = format!("containerd/{}", second.container_id);
    let adapter = private_containerd_adapter(&runtime_socket, &crictl);
    let initial_inventory = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "initial private containerd inventory failed: category={}",
                private_inventory_failure_category(&error)
            )
        });
    assert_eq!(
        initial_inventory.bindings.len(),
        2,
        "the create-new private runtime must contain exactly its two marked workloads"
    );
    let stable_inventory = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "stable private containerd inventory failed: category={}",
                private_inventory_failure_category(&error)
            )
        });
    assert_eq!(
        stable_inventory, initial_inventory,
        "unchanged private containerd workloads must retain their complete runtime identities"
    );
    let initial_first = initial_inventory
        .bindings
        .iter()
        .find(|binding| binding.identity.workload_id == first_workload_id)
        .expect("first private containerd binding")
        .clone();
    let initial_second = initial_inventory
        .bindings
        .iter()
        .find(|binding| binding.identity.workload_id == second_workload_id)
        .expect("second private containerd binding")
        .clone();

    first
        .cleanup()
        .expect("strictly remove first private containerd generation");
    let replacement = create_private_cri_workload_with_crictl(
        &private_root,
        &crictl,
        runtime_socket.to_str().expect("private socket UTF-8"),
        Some(&endpoint),
        "runc",
        &first_session,
    );
    let replacement_workload_id = format!("containerd/{}", replacement.container_id);
    assert_ne!(
        replacement_workload_id, first_workload_id,
        "CRI create must allocate a fresh full container identity"
    );
    let replacement_inventory = RuntimeInventoryAdapter::scan_inventory(&adapter)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "replacement private containerd inventory failed: category={}",
                private_inventory_failure_category(&error)
            )
        });
    assert_eq!(replacement_inventory.bindings.len(), 2);
    assert!(replacement_inventory
        .bindings
        .iter()
        .all(|binding| binding.identity.workload_id != first_workload_id));
    assert!(replacement_inventory
        .bindings
        .iter()
        .any(
            |binding| binding.identity.workload_id == replacement_workload_id
                && binding.identity != initial_first.identity
        ));
    assert!(replacement_inventory
        .bindings
        .iter()
        .any(|binding| binding == &initial_second));

    let config = config("live-private-containerd-cri-socket-recovery");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent(&first_session), 1_700_000_000_000)
        .await
        .expect("register first private runtime intent");
    state
        .register(intent(&second_session), 1_700_000_000_001)
        .await
        .expect("register second private runtime intent");
    let proxy_socket = private_containerd_live_proxy_socket(&private_root, &config.state_dir);
    let proxy = start_controllable_unix_socket_proxy(&proxy_socket, &runtime_socket, false);
    let runner_adapter = private_containerd_adapter(&proxy_socket, &crictl);
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        runner_adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 10,
            max_delay_ms: 10,
            jitter_ms: 0,
        },
    ));

    wait_for_session_cgroup(&state, &first_session, Duration::from_secs(20)).await;
    wait_for_session_cgroup(&state, &second_session, Duration::from_secs(20)).await;
    let active_replacement = state
        .runtime_bindings_for_agent_run(&first_session)
        .await
        .into_iter()
        .find(|binding| binding.identity.workload_id == replacement_workload_id)
        .expect("runner observed replacement private containerd binding");
    let timeline_path = config
        .state_dir
        .join(format!("sessions/{first_session}/timeline.jsonl"));
    let timeline_before_outage =
        std::fs::read_to_string(&timeline_path).expect("initial private containerd timeline");
    proxy.disconnect();
    wait_for_runtime_binding_gap(
        &state,
        AdapterKind::Containerd,
        &first_session,
        active_replacement.identity.cgroup.inode,
        Duration::from_secs(20),
    )
    .await;
    proxy.reconnect();
    wait_for_same_runtime_binding(
        &state,
        AdapterKind::Containerd,
        &first_session,
        &active_replacement,
        Duration::from_secs(20),
    )
    .await;
    shutdown.send(()).expect("stop private CRI adapter");
    let summary = runner.await.expect("private CRI adapter task");
    assert!(summary.discovered >= 4, "{summary:?}");
    assert!(summary.backend_errors > 0, "{summary:?}");
    assert_eq!(summary.backend_recoveries, 1, "{summary:?}");
    assert_eq!(
        state.health().await.adapter(AdapterKind::Containerd),
        ComponentState::Ready
    );
    let timeline =
        std::fs::read_to_string(&timeline_path).expect("private containerd recovery timeline");
    assert!(timeline.starts_with(&timeline_before_outage));
    assert_eq!(
        target_runtime_socket_recovery_sequence(
            &timeline[timeline_before_outage.len()..],
            &first_session,
            "containerd",
            &replacement_workload_id,
        ),
        ["gap", "suspended", "observed"]
    );

    proxy.abort();
    assert_eq!(
        std::fs::symlink_metadata(&proxy_socket)
            .expect_err("private proxy socket must be absent after abort")
            .kind(),
        std::io::ErrorKind::NotFound
    );
    replacement
        .cleanup()
        .expect("strictly clean replacement private containerd fixture");
    second
        .cleanup()
        .expect("strictly clean second private containerd fixture");
    cleanup(&config);
}

fn private_containerd_live_proxy_socket(
    private_root: &Path,
    _state_dir: &Path,
) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let proxy_socket = private_root.join("run/proxy.sock");
    assert_ne!(
        proxy_socket,
        private_root.join("run/containerd.sock"),
        "private proxy socket must differ from its upstream"
    );
    assert!(
        proxy_socket.as_os_str().as_bytes().len() <= 107,
        "private proxy socket path exceeds Linux sockaddr_un pathname capacity"
    );
    proxy_socket
}

fn private_containerd_live_root() -> std::path::PathBuf {
    let root = std::env::var_os("APOLYSIS_PRIVATE_CONTAINERD_ROOT")
        .map(std::path::PathBuf::from)
        .expect("private runner must set APOLYSIS_PRIVATE_CONTAINERD_ROOT");
    assert_eq!(
        root.parent(),
        Some(std::path::Path::new("/tmp")),
        "private containerd root must be a direct /tmp child"
    );
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .expect("private containerd root name UTF-8");
    let suffix = name
        .strip_prefix("apolysis-private-containerd-live.")
        .expect("private containerd root prefix");
    assert_eq!(suffix.len(), 6, "mktemp private root suffix length");
    assert!(
        suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()),
        "mktemp private root suffix"
    );
    assert_eq!(
        std::fs::canonicalize(&root).expect("canonical private containerd root"),
        root,
        "private containerd root must not traverse symlinks"
    );
    let metadata = std::fs::symlink_metadata(&root).expect("private containerd root metadata");
    assert!(
        metadata.file_type().is_dir(),
        "private root must be a directory"
    );
    assert_eq!(metadata.uid(), 0, "private root owner");
    assert_eq!(metadata.gid(), 0, "private root group");
    assert_eq!(metadata.mode() & 0o7777, 0o700, "private root mode");
    root
}

fn prove_private_containerd_socket(root: &Path, socket: &Path) {
    assert_eq!(socket, root.join("run/containerd.sock"));
    let run_directory = root.join("run");
    let run_metadata =
        std::fs::symlink_metadata(&run_directory).expect("private runtime directory metadata");
    assert!(run_metadata.file_type().is_dir());
    assert_eq!(run_metadata.uid(), 0);
    assert_eq!(run_metadata.gid(), 0);
    assert_eq!(run_metadata.mode() & 0o7777, 0o700);
    let socket_metadata =
        std::fs::symlink_metadata(socket).expect("private containerd socket metadata");
    assert!(
        socket_metadata.file_type().is_socket(),
        "private endpoint must be a Unix socket"
    );
    assert_eq!(socket_metadata.uid(), 0);
    assert_eq!(socket_metadata.gid(), 0);
    assert_eq!(socket_metadata.mode() & 0o7000, 0);
    assert_eq!(
        socket_metadata.mode() & 0o007,
        0,
        "private socket must not grant world access"
    );
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateContainerResidueState {
    NotStarted,
    Clear,
    Residue,
}

fn private_proof_root_owner(root: &Path) -> Result<u32, String> {
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|_| "private qualification root metadata unavailable".to_string())?;
    if !metadata.file_type().is_dir() || metadata.mode() & 0o7777 != 0o700 || metadata.nlink() < 2 {
        return Err("private qualification root is not a private directory".to_string());
    }
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        return Err("private qualification root owner changed".to_string());
    }
    Ok(effective_uid)
}

fn validate_private_proof_file(
    path: &Path,
    expected_uid: u32,
) -> Result<std::fs::Metadata, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| "private qualification proof metadata unavailable".to_string())?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != 0 && expected_uid == 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err("private qualification proof metadata changed".to_string());
    }
    Ok(metadata)
}

fn sync_private_proof_root(root: &Path) -> Result<(), String> {
    std::fs::File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| "failed to sync private qualification root".to_string())
}

fn begin_private_container_mutation_proof(root: &Path) -> Result<(), String> {
    let expected_uid = private_proof_root_owner(root)?;
    let marker = root.join("qualification-mutation-started");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&marker)
        .map_err(|_| "failed to publish private mutation-started proof".to_string())?;
    file.write_all(b"started\n")
        .and_then(|_| file.sync_all())
        .map_err(|_| "failed to sync private mutation-started proof".to_string())?;
    validate_private_proof_file(&marker, expected_uid)?;
    sync_private_proof_root(root)
}

fn is_full_container_id(container_id: &str) -> bool {
    container_id.len() == 64
        && container_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn persisted_private_container_ids(root: &Path, expected_uid: u32) -> Result<Vec<String>, String> {
    let proof = root.join("qualification-container-ids");
    validate_private_proof_file(&proof, expected_uid)?;
    let contents = std::fs::read_to_string(&proof)
        .map_err(|_| "failed to read private full-ID proof".to_string())?;
    let ids: Vec<_> = contents.lines().map(ToOwned::to_owned).collect();
    if !(1..=6).contains(&ids.len())
        || !contents.ends_with('\n')
        || ids
            .iter()
            .any(|container_id| !is_full_container_id(container_id))
        || ids
            .iter()
            .enumerate()
            .any(|(index, container_id)| ids[..index].contains(container_id))
    {
        return Err("private full-ID proof is malformed".to_string());
    }
    Ok(ids)
}

fn append_private_container_id_proof(root: &Path, container_id: &str) -> Result<(), String> {
    if !is_full_container_id(container_id) {
        return Err("runtime returned a noncanonical full container ID".to_string());
    }
    let expected_uid = private_proof_root_owner(root)?;
    let marker = root.join("qualification-mutation-started");
    validate_private_proof_file(&marker, expected_uid)?;
    if std::fs::read(&marker).ok().as_deref() != Some(b"started\n") {
        return Err("private mutation-started proof is malformed".to_string());
    }
    let proof = root.join("qualification-container-ids");
    if proof.exists() {
        let ids = persisted_private_container_ids(root, expected_uid)?;
        if ids.len() >= 6 || ids.iter().any(|existing| existing == container_id) {
            return Err("private full-ID proof is duplicate or over capacity".to_string());
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&proof)
        .map_err(|_| "failed to open private full-ID proof".to_string())?;
    file.write_all(format!("{container_id}\n").as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| "failed to sync private full-ID proof".to_string())?;
    validate_private_proof_file(&proof, expected_uid)?;
    persisted_private_container_ids(root, expected_uid)?;
    sync_private_proof_root(root)
}

fn byte_slice_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|candidate| candidate == needle)
}

fn private_container_residue_state(
    root: &Path,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<PrivateContainerResidueState, String> {
    let expected_uid = private_proof_root_owner(root)?;
    let marker = root.join("qualification-mutation-started");
    let proof = root.join("qualification-container-ids");
    let authoritative_sweep = root.join("qualification-authoritative-sweep");
    if authoritative_sweep.exists() && !marker.exists() {
        return Err("authoritative sweep proof exists without a mutation marker".to_string());
    }
    let authoritative_sweep_complete = if authoritative_sweep.exists() {
        validate_private_proof_file(&authoritative_sweep, expected_uid)?;
        if std::fs::read(&authoritative_sweep).ok().as_deref() != Some(b"complete\n") {
            return Err("authoritative private-runtime sweep proof is malformed".to_string());
        }
        true
    } else {
        false
    };
    match (marker.exists(), proof.exists()) {
        (false, false) => return Ok(PrivateContainerResidueState::NotStarted),
        (false, true) => return Err("full-ID proof exists without a mutation marker".to_string()),
        (true, false) => {
            validate_private_proof_file(&marker, expected_uid)?;
            if std::fs::read(&marker).ok().as_deref() != Some(b"started\n") {
                return Err("private mutation-started proof is malformed".to_string());
            }
            if authoritative_sweep_complete {
                return Ok(PrivateContainerResidueState::Clear);
            }
            return Err("known mutation has no persisted full container ID".to_string());
        }
        (true, true) => {}
    }
    validate_private_proof_file(&marker, expected_uid)?;
    if std::fs::read(&marker).ok().as_deref() != Some(b"started\n") {
        return Err("private mutation-started proof is malformed".to_string());
    }
    let ids = persisted_private_container_ids(root, expected_uid)?;
    let needles: Vec<_> = ids.iter().map(|id| id.as_bytes()).collect();

    let proc_entries = std::fs::read_dir(proc_root)
        .map_err(|_| "failed to inspect process root for private residue".to_string())?;
    for entry in proc_entries {
        let entry = entry.map_err(|_| "failed to inspect a process entry".to_string())?;
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        for leaf in ["cmdline", "cgroup"] {
            match std::fs::read(entry.path().join(leaf)) {
                Ok(contents)
                    if needles
                        .iter()
                        .any(|needle| byte_slice_contains(&contents, needle)) =>
                {
                    return Ok(PrivateContainerResidueState::Residue);
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err("failed to inspect a process residue file".to_string()),
            }
        }
    }

    let mut pending = VecDeque::from([cgroup_root.to_path_buf()]);
    let mut inspected = 0usize;
    while let Some(directory) = pending.pop_front() {
        for entry in std::fs::read_dir(&directory)
            .map_err(|_| "failed to inspect cgroup root for private residue".to_string())?
        {
            let entry = entry.map_err(|_| "failed to inspect a cgroup entry".to_string())?;
            inspected += 1;
            if inspected > 100_000 {
                return Err("private cgroup residue scan exceeded its bound".to_string());
            }
            let metadata = std::fs::symlink_metadata(entry.path())
                .map_err(|_| "failed to inspect cgroup entry metadata".to_string())?;
            if metadata.file_type().is_symlink() {
                return Err("private cgroup residue scan encountered a symlink".to_string());
            }
            if metadata.is_dir() {
                let name = entry.file_name();
                if needles
                    .iter()
                    .any(|needle| byte_slice_contains(name.as_encoded_bytes(), needle))
                {
                    return Ok(PrivateContainerResidueState::Residue);
                }
                pending.push_back(entry.path());
            }
        }
    }
    if ids.len() < 6 && !authoritative_sweep_complete {
        return Err(
            "incomplete full-ID journal lacks an authoritative private-runtime sweep".to_string(),
        );
    }
    Ok(PrivateContainerResidueState::Clear)
}

#[test]
#[ignore = "subprocess helper for private container process/cgroup residue checks"]
fn private_container_residue_check_helper() {
    if std::env::var("APOLYSIS_PRIVATE_CONTAINERD_RESIDUE_CHECK")
        .ok()
        .as_deref()
        != Some("1")
    {
        eprintln!("skipped: private container residue helper is runner-only");
        return;
    }
    let root = private_containerd_live_root();
    let state =
        private_container_residue_state(&root, Path::new("/proc"), Path::new("/sys/fs/cgroup"))
            .expect("fail-closed private container residue proof");
    if let Some(required) = std::env::var("APOLYSIS_PRIVATE_CONTAINERD_REQUIRE_IDS")
        .ok()
        .map(|required| {
            required
                .parse::<usize>()
                .expect("required private ID count")
        })
    {
        assert_eq!(
            persisted_private_container_ids(&root, 0)
                .expect("persisted private sandbox/workload IDs")
                .len(),
            required
        );
        assert_eq!(state, PrivateContainerResidueState::Clear);
        return;
    }
    assert!(
        matches!(
            state,
            PrivateContainerResidueState::NotStarted | PrivateContainerResidueState::Clear
        ),
        "private container process/cgroup residue remains"
    );
}

fn private_containerd_adapter(socket: &Path, crictl: &Path) -> ContainerdCriRuntimeAdapter {
    let endpoint = format!("unix://{}", socket.display());
    ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(socket)
            .with_crictl_path(crictl)
            .with_image_endpoint(Some(endpoint)),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    )
    .expect("private containerd CRI adapter")
}

fn private_inventory_failure_category(error: &RuntimeInventoryScanError) -> &'static str {
    error
        .inventory_invalid_category()
        .map(RuntimeInventoryInvalidCategory::code)
        .unwrap_or(match error.reason() {
            RuntimeSourceGapReason::SocketUnavailable => "source_unavailable",
            RuntimeSourceGapReason::InventoryInvalid => "inventory_invalid",
        })
}

#[tokio::test]
#[ignore = "requires root access to k3s containerd CRI socket and local Alpine image"]
async fn live_k3s_containerd_cri_adapter_discovers_labelled_containers() {
    live_k3s_cri_adapter_matrix().await;
}

#[tokio::test]
#[ignore = "requires k3s/kubectl access, k3s CRI socket access, Docker helper access, and permission to terminate k3s for systemd restart"]
async fn live_k3s_containerd_cri_adapter_recovers_after_systemd_restart() {
    if !destructive_runtime_restart_enabled() {
        eprintln!("skipped: set APOLYSIS_DESTRUCTIVE_RUNTIME_RESTART=1 only on a disposable host");
        return;
    }
    require_command("docker");
    require_command("systemctl");
    let kubectl = std::env::var("APOLYSIS_KUBECTL").unwrap_or_else(|_| "kubectl".to_string());
    require_kubectl(&kubectl);
    let runtime_socket = std::env::var("APOLYSIS_K3S_CRI_ENDPOINT")
        .unwrap_or_else(|_| "/run/k3s/containerd/containerd.sock".to_string());
    let configured_crictl = std::env::var_os("APOLYSIS_CRICTL").map(|_| live_crictl_path());
    if configured_crictl.is_none() {
        require_command("crictl");
    }
    let crictl_wrapper = configured_crictl
        .is_none()
        .then(|| create_host_chroot_crictl_wrapper("k3s-systemd-restart"));
    let crictl_path = configured_crictl.as_deref().unwrap_or_else(|| {
        crictl_wrapper
            .as_ref()
            .expect("default host-chroot crictl wrapper")
            .path()
    });
    wait_for_systemd_service_active("k3s.service", Duration::from_secs(90));
    wait_for_kubernetes_api(&kubectl, Duration::from_secs(90));
    wait_for_cri_runtime(crictl_path, &runtime_socket, None, Duration::from_secs(90));
    let session_id = random_kubernetes_value("live-k3s-systemd-restart");
    let namespace = random_kubernetes_value("apolysis-live");
    let first_pod = "apolysis-k3s-systemd-restart-a";
    let second_pod = "apolysis-k3s-systemd-restart-b";
    let workload_cleanup =
        create_kubernetes_pod(&kubectl, &namespace, first_pod, &session_id, None, None);
    wait_for_kubernetes_container_id(&kubectl, &namespace, first_pod);
    let config = config("live-k3s-systemd-restart");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent(&session_id), 1_700_000_000_000)
        .await
        .expect("register intent");
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::K3sContainerd,
        CriRuntimeClient::new(&runtime_socket)
            .with_crictl_path(crictl_path)
            .with_image_endpoint(None),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    )
    .expect("k3s CRI adapter");
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 20,
            max_delay_ms: 20,
            jitter_ms: 0,
        },
    ));

    wait_for_session_cgroup_count(&state, &session_id, 1, Duration::from_secs(30)).await;
    let k3s_systemd = SystemdUnitRestoreGuard::capture(["k3s.service"]);
    let previous_main_pid = terminate_k3s_processes_for_systemd_restart();
    assert!(
        wait_for_cri_runtime_unavailable(
            crictl_path,
            &runtime_socket,
            None,
            Duration::from_secs(45)
        ),
        "k3s containerd CRI stayed responsive after k3s process termination"
    );
    let adapter_degraded = adapter_reaches_state(
        &state,
        AdapterKind::K3sContainerd,
        ComponentState::Degraded,
        Duration::from_secs(45),
    )
    .await;
    wait_for_systemd_service_main_pid_change(
        "k3s.service",
        previous_main_pid,
        Duration::from_secs(180),
    );
    wait_for_systemd_service_active("k3s.service", Duration::from_secs(120));
    assert!(
        adapter_degraded,
        "k3s containerd adapter did not report degraded health during k3s process termination"
    );
    wait_for_kubernetes_api(&kubectl, Duration::from_secs(180));
    wait_for_cri_runtime(crictl_path, &runtime_socket, None, Duration::from_secs(120));
    create_kubernetes_pod_in_owned_namespace(&workload_cleanup, second_pod, &session_id);
    wait_for_kubernetes_container_id(&kubectl, &namespace, second_pod);
    wait_for_session_cgroup_count(&state, &session_id, 2, Duration::from_secs(45)).await;

    shutdown.send(()).expect("stop k3s CRI adapter");
    let summary = runner.await.expect("k3s CRI adapter task");

    assert!(
        summary.discovered >= 2,
        "k3s restart should reattach a complete inventory: {summary:?}"
    );
    assert!(
        summary.backend_errors > 0,
        "k3s restart should produce at least one backend error: {summary:?}"
    );
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::K3sContainerd),
        ComponentState::Ready
    );
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join(format!("sessions/{session_id}/timeline.jsonl")),
    )
    .expect("k3s restart Agent Run timeline");
    assert!(timeline.contains("reason=socket_unavailable"));

    drop(workload_cleanup);
    cleanup_cri_workloads_for_session(crictl_path, &runtime_socket, None, &session_id);
    cleanup(&config);
    drop(k3s_systemd);
}

#[tokio::test]
#[ignore = "requires root access to k3s containerd CRI socket and local Alpine image"]
async fn live_k3s_containerd_cri_adapter_recovers_after_socket_disconnect() {
    let crictl = live_crictl_path();
    let kubectl = std::env::var("APOLYSIS_KUBECTL").unwrap_or_else(|_| "kubectl".to_string());
    require_kubectl(&kubectl);
    let runtime_socket = std::env::var("APOLYSIS_K3S_CRI_ENDPOINT")
        .unwrap_or_else(|_| "/run/k3s/containerd/containerd.sock".to_string());
    let session_id = random_kubernetes_value("live-k3s-cri-recovery");
    let namespace = random_kubernetes_value("apolysis-live");
    let pod_name = "apolysis-k3s-cri-recovery";
    let workload_cleanup =
        create_kubernetes_pod(&kubectl, &namespace, pod_name, &session_id, None, None);
    wait_for_kubernetes_container_id(&kubectl, &namespace, pod_name);
    let config = config("k3s-cri-recovery");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent(&session_id), 1_700_000_000_000)
        .await
        .expect("register intent");
    let proxy_socket = config.state_dir.join("k3s-cri.sock");
    let proxy = start_unix_socket_proxy_with_initial_disconnect(
        &proxy_socket,
        std::path::Path::new(&runtime_socket),
    );
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::K3sContainerd,
        CriRuntimeClient::new(&proxy_socket)
            .with_crictl_path(&crictl)
            .with_image_endpoint(None),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    )
    .expect("k3s CRI adapter");
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 10,
            max_delay_ms: 10,
            jitter_ms: 0,
        },
    ));

    let attach_result = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if state
                .query(&session_id)
                .await
                .map(|session| !session.cgroup_ids.is_empty())
                .unwrap_or(false)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if attach_result.is_err() {
        shutdown
            .send(())
            .expect("stop k3s CRI adapter after timeout");
        let summary = runner.await.expect("k3s CRI adapter task after timeout");
        panic!("session {session_id} did not attach a cgroup; summary={summary:?}");
    }
    shutdown.send(()).expect("stop k3s CRI adapter");
    let summary = runner.await.expect("k3s CRI adapter task");

    assert_eq!(summary.backend_errors, 1);
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(summary.discovered, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::K3sContainerd),
        ComponentState::Ready
    );

    proxy.abort();
    drop(workload_cleanup);
    cleanup_cri_workloads_for_session(&crictl, &runtime_socket, None, &session_id);
    cleanup(&config);
}

#[tokio::test]
#[ignore = "requires k3s/kubectl access, RuntimeClasses, and root access to k3s CRI socket"]
async fn live_kubernetes_cli_adapter_discovers_annotated_pods() {
    require_command("crictl");
    let kubectl = std::env::var("APOLYSIS_KUBECTL").unwrap_or_else(|_| "kubectl".to_string());
    require_kubectl(&kubectl);
    let endpoint = std::env::var("APOLYSIS_K3S_CRI_ENDPOINT")
        .unwrap_or_else(|_| "/run/k3s/containerd/containerd.sock".to_string());
    let runtimes = live_kubernetes_runtimes();

    for (name, runtime_handler) in runtimes {
        let session_id = random_kubernetes_value(&format!("live-k8s-{name}"));
        let namespace = random_kubernetes_value("apolysis-live");
        let pod_name = format!("apolysis-{name}");
        let runtime_class =
            runtime_handler.map(|_| random_kubernetes_value(&format!("apolysis-{name}")));
        let cleanup = create_kubernetes_pod(
            &kubectl,
            &namespace,
            &pod_name,
            &session_id,
            runtime_class.as_deref(),
            runtime_handler,
        );
        wait_for_kubernetes_container_id(&kubectl, &namespace, &pod_name);

        let mut adapter = KubernetesCliRuntimeAdapter::new(
            KubernetesCliClient::new(&kubectl),
            CriRuntimeClient::new(&endpoint).with_image_endpoint(None),
            "/proc",
            "/sys/fs/cgroup",
            Duration::from_millis(100),
            1024,
        );
        let workload = tokio::time::timeout(
            Duration::from_secs(20),
            next_workload_for_session(&mut adapter, &session_id),
        )
        .await
        .expect("Kubernetes adapter timeout")
        .expect("target annotated Kubernetes workload");

        assert_eq!(workload.adapter, AdapterKind::Kubernetes);
        assert_eq!(workload.session_id, session_id);
        assert!(workload.cgroup_id > 0);
        assert_eq!(
            workload.runtime_handler.as_deref(),
            runtime_class.as_deref()
        );
        drop(cleanup);
    }
}

#[tokio::test]
#[ignore = "requires k3s/kubectl access and root access to k3s CRI socket"]
async fn live_kubernetes_cli_adapter_recovers_after_cri_socket_disconnect() {
    require_command("crictl");
    let kubectl = std::env::var("APOLYSIS_KUBECTL").unwrap_or_else(|_| "kubectl".to_string());
    require_kubectl(&kubectl);
    let endpoint = std::env::var("APOLYSIS_K3S_CRI_ENDPOINT")
        .unwrap_or_else(|_| "/run/k3s/containerd/containerd.sock".to_string());
    let session_id = random_kubernetes_value("live-k8s-cri-recovery");
    let namespace = random_kubernetes_value("apolysis-live");
    let pod_name = "apolysis-k8s-cri-recovery";
    let workload_cleanup =
        create_kubernetes_pod(&kubectl, &namespace, pod_name, &session_id, None, None);
    wait_for_kubernetes_container_id(&kubectl, &namespace, pod_name);
    let config = config("k8s-cri-recovery");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent(&session_id), 1_700_000_000_000)
        .await
        .expect("register intent");
    let proxy_socket = config.state_dir.join("k8s-cri.sock");
    let proxy = start_unix_socket_proxy_with_initial_disconnect(
        &proxy_socket,
        std::path::Path::new(&endpoint),
    );
    let adapter = KubernetesCliRuntimeAdapter::new(
        KubernetesCliClient::new(&kubectl),
        CriRuntimeClient::new(&proxy_socket).with_image_endpoint(None),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    );
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 10,
            max_delay_ms: 10,
            jitter_ms: 0,
        },
    ));

    let attach_result = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if state
                .query(&session_id)
                .await
                .map(|session| !session.cgroup_ids.is_empty())
                .unwrap_or(false)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if attach_result.is_err() {
        shutdown
            .send(())
            .expect("stop Kubernetes adapter after timeout");
        let summary = runner.await.expect("Kubernetes adapter task after timeout");
        panic!("session {session_id} did not attach a cgroup; summary={summary:?}");
    }
    shutdown.send(()).expect("stop Kubernetes adapter");
    let summary = runner.await.expect("Kubernetes adapter task");

    assert_eq!(summary.backend_errors, 1);
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(summary.discovered, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Kubernetes),
        ComponentState::Ready
    );

    proxy.abort();
    drop(workload_cleanup);
    cleanup_cri_workloads_for_session(std::path::Path::new("crictl"), &endpoint, None, &session_id);
    cleanup(&config);
}

async fn next_workload_for_session<B: RuntimeAdapterBackend>(
    adapter: &mut B,
    session_id: &str,
) -> Result<RuntimeWorkload, String> {
    loop {
        match adapter.next_workload().await? {
            Some(workload) if workload.session_id == session_id => return Ok(workload),
            Some(_) => {}
            None => {
                return Err(format!(
                    "runtime adapter ended before discovering {session_id}"
                ))
            }
        }
    }
}

#[test]
fn containerd_task_snapshot_becomes_runtime_workload_for_standalone_and_k3s() {
    let mut labels = BTreeMap::new();
    labels.insert(
        "apolysis.session_id".to_string(),
        "session-containerd".to_string(),
    );

    let standalone = containerd_workload_from_snapshot(ContainerdTaskSnapshot {
        adapter: AdapterKind::Containerd,
        namespace: "default".to_string(),
        container_id: "task-standalone".to_string(),
        labels: labels.clone(),
        cgroup_id: 202,
        image: Some("docker.io/library/alpine:3.20".to_string()),
        runtime_handler: Some("io.containerd.runsc.v1".to_string()),
    })
    .expect("standalone containerd snapshot")
    .expect("marked standalone workload");

    assert_eq!(standalone.adapter, AdapterKind::Containerd);
    assert_eq!(standalone.session_id, "session-containerd");
    assert_eq!(standalone.workload_id, "default/task-standalone");
    assert_eq!(standalone.cgroup_id, 202);
    assert_eq!(
        standalone.runtime_handler.as_deref(),
        Some("io.containerd.runsc.v1")
    );

    let k3s = containerd_workload_from_snapshot(ContainerdTaskSnapshot {
        adapter: AdapterKind::K3sContainerd,
        namespace: "k8s.io".to_string(),
        container_id: "task-k3s".to_string(),
        labels,
        cgroup_id: 303,
        image: Some("docker.io/library/alpine:3.20".to_string()),
        runtime_handler: Some("io.containerd.kata.v2".to_string()),
    })
    .expect("k3s containerd snapshot")
    .expect("marked k3s workload");

    assert_eq!(k3s.adapter, AdapterKind::K3sContainerd);
    assert_eq!(k3s.session_id, "session-containerd");
    assert_eq!(k3s.workload_id, "k8s.io/task-k3s");
    assert_eq!(k3s.cgroup_id, 303);
    assert_eq!(
        k3s.runtime_handler.as_deref(),
        Some("io.containerd.kata.v2")
    );
}

#[test]
fn containerd_metadata_json_becomes_task_snapshot() {
    let snapshot = containerd_task_snapshot_from_metadata(
        AdapterKind::K3sContainerd,
        &json!({
            "namespace": "k8s.io",
            "id": "task-k3s",
            "image": "docker.io/library/alpine:3.20",
            "runtime": {
                "name": "io.containerd.kata.v2"
            },
            "labels": {
                "apolysis.session_id": "session-containerd",
                "io.kubernetes.pod.uid": "pod-uid-123"
            }
        }),
        606,
    )
    .expect("containerd task snapshot");

    assert_eq!(snapshot.adapter, AdapterKind::K3sContainerd);
    assert_eq!(snapshot.namespace, "k8s.io");
    assert_eq!(snapshot.container_id, "task-k3s");
    assert_eq!(snapshot.cgroup_id, 606);
    assert_eq!(
        snapshot
            .labels
            .get("apolysis.session_id")
            .map(String::as_str),
        Some("session-containerd")
    );
    assert_eq!(
        snapshot.runtime_handler.as_deref(),
        Some("io.containerd.kata.v2")
    );
}

#[test]
fn crictl_ps_lists_only_marked_running_containers() {
    let ids = crictl_marked_container_ids_from_ps(json!({
        "containers": [
            {
                "id": "container-marked",
                "state": "CONTAINER_RUNNING",
                "labels": {"apolysis.session_id": "session-containerd"}
            },
            {
                "id": "container-stopped",
                "state": "CONTAINER_EXITED",
                "labels": {"apolysis.session_id": "session-containerd"}
            },
            {
                "id": "container-unmarked",
                "state": "CONTAINER_RUNNING",
                "labels": {"owner": "platform"}
            }
        ]
    }))
    .expect("marked CRI containers");

    assert_eq!(ids, vec!["container-marked"]);
}

#[test]
fn crictl_pod_sandbox_labels_mark_running_containers_in_same_sandbox() {
    let candidates = crictl_marked_container_candidates_from_ps_and_pods(
        json!({
            "containers": [
                {
                    "id": "container-from-pod-label",
                    "state": "CONTAINER_RUNNING",
                    "podSandboxId": "sandbox-marked",
                    "labels": {
                        "io.kubernetes.pod.name": "apolysis-k3s"
                    }
                },
                {
                    "id": "container-direct-label",
                    "state": "CONTAINER_RUNNING",
                    "podSandboxId": "sandbox-unmarked",
                    "labels": {
                        "apolysis.session_id": "session-direct"
                    }
                },
                {
                    "id": "container-unmarked",
                    "state": "CONTAINER_RUNNING",
                    "podSandboxId": "sandbox-unmarked",
                    "labels": {}
                }
            ]
        }),
        json!({
            "items": [
                {
                    "id": "sandbox-marked",
                    "state": "SANDBOX_READY",
                    "labels": {
                        "apolysis.session_id": "session-from-pod",
                        "io.kubernetes.pod.namespace": "apolysis-observation"
                    }
                },
                {
                    "id": "sandbox-unmarked",
                    "state": "SANDBOX_READY",
                    "labels": {}
                }
            ]
        }),
    )
    .expect("CRI candidates from Pod labels");

    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].container_id, "container-from-pod-label");
    assert_eq!(
        candidates[0]
            .inherited_labels
            .get("apolysis.session_id")
            .map(String::as_str),
        Some("session-from-pod")
    );
    assert_eq!(candidates[1].container_id, "container-direct-label");
    assert!(candidates[1].inherited_labels.is_empty());
}

#[test]
fn containerd_cri_inspect_json_becomes_task_snapshot() {
    let snapshot = containerd_task_snapshot_from_cri_inspect(
        AdapterKind::Containerd,
        &json!({
            "status": {
                "id": "containerd-task-1",
                "labels": {
                    "apolysis.session_id": "session-containerd",
                    "io.kubernetes.pod.namespace": "apolysis-observation"
                },
                "image": {
                    "userSpecifiedImage": "docker.io/library/alpine:3.20",
                    "runtimeHandler": "runsc"
                }
            },
            "info": {
                "pid": 48123,
                "runtimeType": "io.containerd.runsc.v1"
            }
        }),
        707,
    )
    .expect("containerd CRI snapshot");

    assert_eq!(snapshot.adapter, AdapterKind::Containerd);
    assert_eq!(snapshot.namespace, "apolysis-observation");
    assert_eq!(snapshot.container_id, "containerd-task-1");
    assert_eq!(snapshot.cgroup_id, 707);
    assert_eq!(
        snapshot
            .labels
            .get("apolysis.session_id")
            .map(String::as_str),
        Some("session-containerd")
    );
    assert_eq!(
        snapshot.image.as_deref(),
        Some("docker.io/library/alpine:3.20")
    );
    assert_eq!(
        snapshot.runtime_handler.as_deref(),
        Some("io.containerd.runsc.v1")
    );
}

#[test]
fn kubernetes_pod_snapshot_uses_session_annotation_and_pod_uid() {
    let mut annotations = BTreeMap::new();
    annotations.insert(
        APOLYSIS_SESSION_ANNOTATION.to_string(),
        "session-kubernetes".to_string(),
    );

    let workload = kubernetes_workload_from_pod_snapshot(KubernetesPodSnapshot {
        namespace: "agent-jobs".to_string(),
        pod_name: "apolysis-worker".to_string(),
        pod_uid: Some("pod-uid-123".to_string()),
        annotations,
        cgroup_id: 404,
        runtime_class_name: Some("kata-qemu".to_string()),
    })
    .expect("kubernetes pod snapshot")
    .expect("marked kubernetes workload");

    assert_eq!(workload.adapter, AdapterKind::Kubernetes);
    assert_eq!(workload.session_id, "session-kubernetes");
    assert_eq!(workload.workload_id, "pod-uid-123");
    assert_eq!(workload.cgroup_id, 404);
    assert_eq!(workload.runtime_handler.as_deref(), Some("kata-qemu"));
}

#[test]
fn kubernetes_api_pod_object_becomes_pod_snapshot() {
    let snapshot = kubernetes_pod_snapshot_from_api_object(
        &json!({
            "metadata": {
                "namespace": "agent-jobs",
                "name": "apolysis-worker",
                "uid": "pod-uid-123",
                "annotations": {
                    "apolysis.dev/session-id": "session-kubernetes",
                    "owner": "ignored"
                }
            },
            "spec": {
                "runtimeClassName": "gvisor"
            }
        }),
        505,
    )
    .expect("pod snapshot");

    assert_eq!(snapshot.namespace, "agent-jobs");
    assert_eq!(snapshot.pod_name, "apolysis-worker");
    assert_eq!(snapshot.pod_uid.as_deref(), Some("pod-uid-123"));
    assert_eq!(snapshot.cgroup_id, 505);
    assert_eq!(
        snapshot
            .annotations
            .get(APOLYSIS_SESSION_ANNOTATION)
            .map(String::as_str),
        Some("session-kubernetes")
    );
    assert_eq!(snapshot.runtime_class_name.as_deref(), Some("gvisor"));
}

#[test]
fn kubernetes_pod_list_uses_annotation_and_container_cgroup_map() {
    let snapshots = kubernetes_marked_pod_snapshots_from_api_list(
        &json!({
            "items": [
                {
                    "metadata": {
                        "namespace": "agent-jobs",
                        "name": "apolysis-worker",
                        "uid": "pod-uid-123",
                        "resourceVersion": "2001",
                        "annotations": {
                            "apolysis.dev/session-id": "session-kubernetes"
                        }
                    },
                    "spec": {
                        "nodeName": "mactavish",
                        "serviceAccountName": "agent-runner",
                        "runtimeClassName": "gvisor"
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {
                                "name": "worker",
                                "containerID": "containerd://containerd-task-1"
                            }
                        ]
                    }
                },
                {
                    "metadata": {
                        "namespace": "kube-system",
                        "name": "unmarked",
                        "uid": "pod-uid-ignored"
                    },
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [
                            {
                                "containerID": "containerd://containerd-task-ignored"
                            }
                        ]
                    }
                }
            ]
        }),
        &BTreeMap::from([("containerd-task-1".to_string(), 808)]),
    )
    .expect("marked pod snapshots");

    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].namespace, "agent-jobs");
    assert_eq!(snapshots[0].pod_name, "apolysis-worker");
    assert_eq!(snapshots[0].pod_uid.as_deref(), Some("pod-uid-123"));
    assert_eq!(snapshots[0].cgroup_id, 808);
    assert_eq!(snapshots[0].runtime_class_name.as_deref(), Some("gvisor"));

    let workload = kubernetes_workload_from_pod_snapshot(snapshots[0].clone())
        .expect("kubernetes workload")
        .expect("marked workload");
    assert_eq!(workload.session_id, "session-kubernetes");
    assert_eq!(workload.workload_id, "pod-uid-123");
}

#[test]
fn adapter_backoff_is_bounded_and_has_deterministic_jitter() {
    let policy = AdapterBackoffPolicy {
        initial_delay_ms: 100,
        max_delay_ms: 1_000,
        jitter_ms: 50,
    };

    let first = adapter_backoff_delay(policy, AdapterKind::Containerd, 1);
    let later = adapter_backoff_delay(policy, AdapterKind::Containerd, 8);
    let different_adapter = adapter_backoff_delay(policy, AdapterKind::Kubernetes, 1);

    assert!((100..=150).contains(&first.as_millis()));
    assert!((1_000..=1_050).contains(&later.as_millis()));
    assert_ne!(first, different_adapter);
}

#[tokio::test]
async fn complete_inventory_runner_gaps_suspends_and_recovers_only_after_a_fresh_inventory() {
    let config = config("complete-inventory-runner-recovery");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-inventory"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    let binding = RuntimeBinding {
        agent_run_id: "agent-run-inventory".to_string(),
        identity: RuntimeWorkloadIdentity {
            adapter: AdapterKind::Docker,
            workload_id: "1010101010101010101010101010101010101010101010101010101010101010"
                .to_string(),
            start_marker: "2026-08-11T01:02:03.000000000Z".to_string(),
            host_boot_id: "82b46386-b87a-4d86-93f6-232bb04c37fb".to_string(),
            init_process_start_time_ticks: 123,
            cgroup: CgroupIdentity {
                device: 7,
                inode: 909,
            },
        },
        runtime_handler: Some("runc".to_string()),
    };
    let mut missing_intent = binding.clone();
    missing_intent.agent_run_id = "agent-run-not-registered".to_string();
    missing_intent.identity.workload_id =
        "1212121212121212121212121212121212121212121212121212121212121212".to_string();
    missing_intent.identity.cgroup.inode = 911;
    let scan_count = Arc::new(AtomicU64::new(0));
    let adapter = FakeRuntimeInventoryAdapter::new(
        AdapterKind::Docker,
        Arc::clone(&scan_count),
        vec![
            Ok(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![binding.clone(), missing_intent.clone()],
            )),
            Err(RuntimeInventoryScanError::socket_unavailable(
                "Docker socket disconnected",
            )),
            Ok(RuntimeInventory::new(
                AdapterKind::Docker,
                vec![binding.clone(), missing_intent],
            )),
        ],
    );
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 1,
            max_delay_ms: 1,
            jitter_ms: 0,
        },
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if scan_count.load(Ordering::Acquire) >= 3
                && state.session_for_cgroup(909).await.as_deref() == Some("agent-run-inventory")
                && state.health().await.adapter(AdapterKind::Docker) == ComponentState::Ready
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("complete inventory recovery");
    shutdown.send(()).expect("stop inventory runner");
    let summary = runner.await.expect("inventory runner task");

    assert_eq!(summary.adapter, AdapterKind::Docker);
    assert_eq!(summary.discovered, 2);
    assert_eq!(summary.missing_intent, 2);
    assert_eq!(summary.backend_errors, 1);
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(summary.ingest_errors, 0);
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions/agent-run-inventory/timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    assert_eq!(timeline.matches("reason=socket_unavailable").count(), 1);
    assert!(timeline.contains("runtime_binding_suspended"));
    assert_eq!(timeline.matches("runtime_binding_observed").count(), 2);
    assert_eq!(
        state.session_for_cgroup(911).await.as_deref(),
        Some("agent-run-not-registered")
    );

    cleanup(&config);
}

#[tokio::test]
async fn complete_inventory_runner_records_invalid_inventory_as_a_typed_gap() {
    let config = config("complete-inventory-runner-invalid");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("agent-run-invalid-inventory"), 1_700_000_000_000)
        .await
        .expect("register Agent Run");
    let binding = RuntimeBinding {
        agent_run_id: "agent-run-invalid-inventory".to_string(),
        identity: RuntimeWorkloadIdentity {
            adapter: AdapterKind::Containerd,
            workload_id:
                "containerd/1313131313131313131313131313131313131313131313131313131313131313"
                    .to_string(),
            start_marker: "1754874123000000000".to_string(),
            host_boot_id: "82b46386-b87a-4d86-93f6-232bb04c37fb".to_string(),
            init_process_start_time_ticks: 456,
            cgroup: CgroupIdentity {
                device: 7,
                inode: 910,
            },
        },
        runtime_handler: Some("io.containerd.runc.v2".to_string()),
    };
    state
        .reconcile_runtime_inventory(RuntimeInventory::new(
            AdapterKind::Containerd,
            vec![binding],
        ))
        .await
        .expect("seed complete runtime inventory");
    let scan_count = Arc::new(AtomicU64::new(0));
    let adapter = FakeRuntimeInventoryAdapter::new(
        AdapterKind::Containerd,
        Arc::clone(&scan_count),
        vec![Err(RuntimeInventoryScanError::inventory_invalid(
            "one marked candidate changed during qualification",
        ))],
    );
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 1,
            max_delay_ms: 1,
            jitter_ms: 0,
        },
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if scan_count.load(Ordering::Acquire) >= 1
                && state.session_for_cgroup(910).await.is_none()
                && state.health().await.adapter(AdapterKind::Containerd) == ComponentState::Degraded
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("invalid inventory gap");
    shutdown.send(()).expect("stop inventory runner");
    let summary = runner.await.expect("inventory runner task");

    assert_eq!(summary.backend_errors, 1);
    assert_eq!(summary.backend_recoveries, 0);
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions/agent-run-invalid-inventory/timeline.jsonl"),
    )
    .expect("Agent Run timeline");
    assert_eq!(timeline.matches("reason=inventory_invalid").count(), 1);
    assert!(timeline.contains("runtime_binding_suspended"));

    cleanup(&config);
}

#[tokio::test]
#[ignore = "subprocess helper used to capture production runner stderr"]
async fn inventory_runner_stderr_redaction_helper() {
    let config = config("inventory-runner-stderr-redaction");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    let scan_count = Arc::new(AtomicU64::new(0));
    let adapter = FakeRuntimeInventoryAdapter::new(
        AdapterKind::Docker,
        Arc::clone(&scan_count),
        (0..5)
            .map(|_| {
                Err(RuntimeInventoryScanError::socket_unavailable(
                    "/private/runtime.sock private-container-id stderr-payload private-team-namespace",
                ))
            })
            .collect(),
    );
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_inventory_adapter_with_policy(
        adapter,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 1,
            max_delay_ms: 1,
            jitter_ms: 0,
        },
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        while scan_count.load(Ordering::Acquire) < 5 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("runner attempted inventory scan");
    shutdown.send(()).expect("stop inventory runner");
    runner.await.expect("inventory runner task");
    cleanup(&config);
}

#[test]
fn production_inventory_runner_stderr_contains_only_canonical_failure_metadata() {
    let opaque_error = RuntimeInventoryScanError::inventory_invalid(
        "/private/runtime.sock private-container-id stderr-payload private-team-namespace",
    );
    assert_eq!(
        opaque_error.to_string(),
        "runtime inventory scan failed: inventory_invalid"
    );
    let debug = format!("{opaque_error:?}");
    assert!(debug.contains("InventoryInvalid"), "{debug}");
    assert!(!debug.contains("Unclassified"), "{debug}");
    assert!(!opaque_error.to_string().contains("unclassified"));
    assert_eq!(
        private_inventory_failure_category(&opaque_error),
        "unclassified"
    );

    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "inventory_runner_stderr_redaction_helper",
            "--ignored",
            "--nocapture",
        ])
        .output()
        .expect("run inventory stderr capture helper");

    assert!(
        output.status.success(),
        "stderr capture helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8(output.stderr).expect("runner stderr UTF-8");
    assert!(stderr.contains("adapter=Docker"), "{stderr}");
    assert!(stderr.contains("code=scan_failed"), "{stderr}");
    assert!(stderr.contains("reason=socket_unavailable"), "{stderr}");
    assert_eq!(
        stderr.matches("code=scan_failed").count(),
        1,
        "one continuous outage must emit one canonical failure line: {stderr}"
    );
    for private_value in [
        "/private/runtime.sock",
        "private-container-id",
        "stderr-payload",
        "private-team-namespace",
    ] {
        assert!(!debug.contains(private_value), "{private_value}: {debug}");
        assert!(!stderr.contains(private_value), "{private_value}: {stderr}");
    }
}

#[test]
fn degraded_runtime_constructor_logging_does_not_interpolate_internal_errors() {
    let source = include_str!("../src/server.rs");
    let degraded = source
        .split_once("async fn degraded_summary")
        .expect("degraded_summary source")
        .1
        .split_once("async fn handle_connection")
        .expect("degraded_summary boundary")
        .0;

    assert!(degraded.contains("code=constructor_failed reason=inventory_invalid"));
    assert!(degraded.contains("code=gap_persist_failed reason=inventory_invalid"));
    assert!(!degraded.contains("{error}"), "{degraded}");
    assert!(!degraded.contains("{gap_error}"), "{degraded}");
}

#[tokio::test]
async fn daemon_ingests_runtime_workload_and_persists_metadata() {
    let config = config("registered-runtime-workload");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("session-docker"), 1_700_000_000_000)
        .await
        .expect("register intent");

    let outcome = state
        .ingest_runtime_workload(RuntimeWorkload {
            adapter: AdapterKind::Docker,
            session_id: "session-docker".to_string(),
            workload_id: "container-123".to_string(),
            cgroup_id: 77,
            image: Some("alpine:3.20".to_string()),
            runtime_handler: Some("runsc".to_string()),
        })
        .await
        .expect("ingest workload");

    assert_eq!(outcome, AssociationOutcome::Attached);
    assert_eq!(
        state.session_for_cgroup(77).await.as_deref(),
        Some("session-docker")
    );
    assert_eq!(
        state.health().await.adapter(AdapterKind::Docker),
        ComponentState::Ready
    );
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions/session-docker/timeline.jsonl"),
    )
    .expect("session timeline");
    assert!(timeline.contains(r#""record_type":"runtime_workload_discovered""#));
    assert!(timeline.contains(r#""adapter":"docker""#));
    assert!(timeline.contains(r#""workload_id":"container-123""#));
    assert!(timeline.contains(r#""runtime_handler":"runsc""#));
    assert!(timeline.contains(r#""outcome":"attached""#));

    cleanup(&config);
}

#[tokio::test]
async fn daemon_records_missing_intent_for_marked_runtime_workload() {
    let config = config("missing-runtime-intent");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));

    let outcome = state
        .ingest_runtime_workload(RuntimeWorkload {
            adapter: AdapterKind::Docker,
            session_id: "missing-intent".to_string(),
            workload_id: "container-456".to_string(),
            cgroup_id: 88,
            image: Some("alpine:3.20".to_string()),
            runtime_handler: Some("runc".to_string()),
        })
        .await
        .expect("ingest workload");

    assert_eq!(outcome, AssociationOutcome::MissingIntent);
    assert_eq!(
        state.session_for_cgroup(88).await.as_deref(),
        Some("missing-intent")
    );
    let timeline = std::fs::read_to_string(
        config
            .state_dir
            .join("sessions/missing-intent/timeline.jsonl"),
    )
    .expect("pending session timeline");
    assert!(timeline.contains(r#""record_type":"runtime_workload_discovered""#));
    assert!(timeline.contains(r#""outcome":"missing_intent""#));
    assert!(timeline.contains(r#""record_type":"accountability_finding""#));
    assert!(timeline.contains(r#""kind":"missing_intent""#));
    assert!(timeline.contains(r#""decision":"review""#));
    assert!(timeline.contains(r#""runtime":"docker""#));
    assert!(timeline.contains(r#""container_id":"container-456""#));

    cleanup(&config);
}

#[tokio::test]
async fn runtime_adapter_continues_after_transient_backend_error() {
    let config = config("adapter-transient-error");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("session-docker"), 1_700_000_000_000)
        .await
        .expect("register intent");
    let (_shutdown, receiver) = oneshot::channel();
    let backend = FakeRuntimeAdapter::new(
        AdapterKind::Docker,
        vec![
            Err("docker event stream disconnected".to_string()),
            Err("docker event stream still disconnected".to_string()),
            Ok(Some(RuntimeWorkload {
                adapter: AdapterKind::Docker,
                session_id: "session-docker".to_string(),
                workload_id: "container-after-reconnect".to_string(),
                cgroup_id: 99,
                image: Some("alpine:3.20".to_string()),
                runtime_handler: Some("runc".to_string()),
            })),
            Ok(None),
        ],
    );

    let summary = run_runtime_adapter_with_policy(
        backend,
        Arc::clone(&state),
        receiver,
        AdapterBackoffPolicy {
            initial_delay_ms: 1,
            max_delay_ms: 1,
            jitter_ms: 0,
        },
    )
    .await;

    assert_eq!(summary.adapter, AdapterKind::Docker);
    assert_eq!(summary.discovered, 1);
    assert_eq!(summary.backend_errors, 2);
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(summary.ingest_errors, 0);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Docker),
        ComponentState::Ready
    );
    assert_eq!(
        state.session_for_cgroup(99).await.as_deref(),
        Some("session-docker")
    );

    cleanup(&config);
}

#[tokio::test]
async fn one_runtime_adapter_recovery_does_not_stop_another_adapter() {
    let config = config("adapter-isolation");
    let state = Arc::new(DaemonState::new(&config).expect("daemon state"));
    state
        .register(intent("session-docker"), 1_700_000_000_000)
        .await
        .expect("register docker intent");
    state
        .register(intent("session-kubernetes"), 1_700_000_000_000)
        .await
        .expect("register kubernetes intent");
    let (_docker_shutdown, docker_receiver) = oneshot::channel();
    let (_kubernetes_shutdown, kubernetes_receiver) = oneshot::channel();
    let policy = AdapterBackoffPolicy {
        initial_delay_ms: 1,
        max_delay_ms: 1,
        jitter_ms: 0,
    };
    let docker_backend = FakeRuntimeAdapter::new(
        AdapterKind::Docker,
        vec![
            Err("docker socket disconnected".to_string()),
            Ok(Some(RuntimeWorkload {
                adapter: AdapterKind::Docker,
                session_id: "session-docker".to_string(),
                workload_id: "docker-after-reconnect".to_string(),
                cgroup_id: 101,
                image: Some("alpine:3.20".to_string()),
                runtime_handler: Some("runc".to_string()),
            })),
            Ok(None),
        ],
    );
    let kubernetes_backend = FakeRuntimeAdapter::new(
        AdapterKind::Kubernetes,
        vec![
            Ok(Some(RuntimeWorkload {
                adapter: AdapterKind::Kubernetes,
                session_id: "session-kubernetes".to_string(),
                workload_id: "pod-after-docker-failure".to_string(),
                cgroup_id: 202,
                image: None,
                runtime_handler: Some("runc".to_string()),
            })),
            Ok(None),
        ],
    );
    let docker = tokio::spawn(run_runtime_adapter_with_policy(
        docker_backend,
        Arc::clone(&state),
        docker_receiver,
        policy,
    ));
    let kubernetes = tokio::spawn(run_runtime_adapter_with_policy(
        kubernetes_backend,
        Arc::clone(&state),
        kubernetes_receiver,
        policy,
    ));

    let docker_summary = docker.await.expect("docker adapter task");
    let kubernetes_summary = kubernetes.await.expect("kubernetes adapter task");

    assert_eq!(docker_summary.backend_errors, 1);
    assert_eq!(docker_summary.backend_recoveries, 1);
    assert_eq!(docker_summary.discovered, 1);
    assert_eq!(kubernetes_summary.backend_errors, 0);
    assert_eq!(kubernetes_summary.backend_recoveries, 0);
    assert_eq!(kubernetes_summary.discovered, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Docker),
        ComponentState::Ready
    );
    assert_eq!(
        state.health().await.adapter(AdapterKind::Kubernetes),
        ComponentState::Ready
    );
    assert_eq!(
        state.session_for_cgroup(101).await.as_deref(),
        Some("session-docker")
    );
    assert_eq!(
        state.session_for_cgroup(202).await.as_deref(),
        Some("session-kubernetes")
    );

    cleanup(&config);
}

struct FakeRuntimeInventoryAdapter {
    adapter: AdapterKind,
    scan_count: Arc<AtomicU64>,
    responses: StdMutex<VecDeque<Result<RuntimeInventory, RuntimeInventoryScanError>>>,
}

impl FakeRuntimeInventoryAdapter {
    fn new(
        adapter: AdapterKind,
        scan_count: Arc<AtomicU64>,
        responses: Vec<Result<RuntimeInventory, RuntimeInventoryScanError>>,
    ) -> Self {
        Self {
            adapter,
            scan_count,
            responses: StdMutex::new(responses.into()),
        }
    }
}

impl RuntimeInventoryAdapter for FakeRuntimeInventoryAdapter {
    fn kind(&self) -> AdapterKind {
        self.adapter
    }

    fn scan_interval(&self) -> Duration {
        Duration::from_millis(1)
    }

    fn scan_inventory(
        &self,
    ) -> Pin<
        Box<dyn Future<Output = Result<RuntimeInventory, RuntimeInventoryScanError>> + Send + '_>,
    > {
        self.scan_count.fetch_add(1, Ordering::Release);
        let response = self.responses.lock().unwrap().pop_front();
        Box::pin(async move {
            match response {
                Some(response) => response,
                None => std::future::pending().await,
            }
        })
    }
}

struct FakeRuntimeAdapter {
    adapter: AdapterKind,
    responses: VecDeque<Result<Option<RuntimeWorkload>, String>>,
}

impl FakeRuntimeAdapter {
    fn new(adapter: AdapterKind, responses: Vec<Result<Option<RuntimeWorkload>, String>>) -> Self {
        Self {
            adapter,
            responses: responses.into(),
        }
    }
}

impl RuntimeAdapterBackend for FakeRuntimeAdapter {
    fn kind(&self) -> AdapterKind {
        self.adapter
    }

    fn next_workload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RuntimeWorkload>, String>> + Send + '_>> {
        Box::pin(async move { self.responses.pop_front().unwrap_or(Ok(None)) })
    }
}

struct DockerContainerCleanup {
    container_id: String,
}

impl Drop for DockerContainerCleanup {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .output();
    }
}

struct DaemonStateRootCleanup {
    config: DaemonConfig,
}

impl DaemonStateRootCleanup {
    fn new(config: &DaemonConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

impl Drop for DaemonStateRootCleanup {
    fn drop(&mut self) {
        cleanup(&self.config);
    }
}

struct LiveDaemonServer {
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), String>>>,
}

impl LiveDaemonServer {
    async fn start(config: DaemonConfig) -> Self {
        let socket = config.socket_path.clone();
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(serve(config, receiver));
        for _ in 0..1_000 {
            if socket.exists() {
                return Self {
                    shutdown: Some(shutdown),
                    task: Some(task),
                };
            }
            if task.is_finished() {
                let result = task.await.expect("live daemon task join");
                panic!("live daemon exited before creating its socket: {result:?}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        panic!("live daemon did not create {}", socket.display());
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task = self.task.take().expect("live daemon task");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("live daemon shutdown timeout")
            .expect("live daemon task join")
            .expect("clean live daemon shutdown");
    }
}

impl Drop for LiveDaemonServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn docker_image_is_present_without_pull(image: &str) -> bool {
    Command::new("docker")
        .args(["image", "inspect", image])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn running_docker_container_ids() -> Vec<String> {
    let output = Command::new("docker")
        .args(["ps", "--no-trunc", "--format", "{{.ID}}"])
        .output()
        .expect("list running Docker containers");
    assert!(
        output.status.success(),
        "docker ps failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut ids = String::from_utf8(output.stdout)
        .expect("Docker container IDs are UTF-8")
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    ids.sort();
    ids
}

fn random_live_session_id(prefix: &str) -> String {
    let random = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            format!(
                "{}-{}",
                std::process::id(),
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            )
        });
    format!("{prefix}-{random}")
}

fn random_kubernetes_value(prefix: &str) -> String {
    let uuid = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .expect("Linux kernel random UUID source for isolated Kubernetes live fixture");
    let uuid = uuid.trim();
    assert_eq!(uuid.len(), 36, "kernel UUID length");
    assert!(
        uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        }),
        "kernel UUID must be canonical lowercase"
    );
    let value = format!("{prefix}-{uuid}");
    assert!(value.len() <= 63, "Kubernetes live fixture name too long");
    value
}

fn destructive_runtime_restart_enabled() -> bool {
    std::env::var("APOLYSIS_DESTRUCTIVE_RUNTIME_RESTART")
        .ok()
        .as_deref()
        == Some("1")
}

async fn live_daemon_request(path: &Path, payload: &[u8]) -> DaemonResponse {
    let mut stream = UnixStream::connect(path)
        .await
        .expect("connect to live daemon");
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .expect("write live daemon request length");
    stream
        .write_all(payload)
        .await
        .expect("write live daemon request");
    let length = stream
        .read_u32()
        .await
        .expect("read live daemon response length") as usize;
    let mut response = vec![0_u8; length];
    stream
        .read_exact(&mut response)
        .await
        .expect("read live daemon response");
    serde_json::from_slice(&response).expect("decode live daemon response")
}

async fn wait_for_live_daemon_binding(
    socket: &Path,
    session_id: &str,
    container_id: &str,
    timeout: Duration,
) -> (apolysis_accountability::SessionState, RuntimeBinding) {
    let request = serde_json::to_vec(&json!({
        "type": "query",
        "session_id": session_id,
    }))
    .expect("encode live daemon query");
    tokio::time::timeout(timeout, async {
        loop {
            if let DaemonResponse::Session {
                session: Some(session),
                runtime_bindings,
                ..
            } = live_daemon_request(socket, &request).await
            {
                if let Some(binding) = runtime_bindings
                    .iter()
                    .find(|binding| binding.identity.workload_id == container_id)
                {
                    assert_eq!(
                        runtime_bindings.len(),
                        1,
                        "the random live Agent Run must have exactly one runtime binding"
                    );
                    return (session, binding.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("live daemon did not qualify Docker binding {container_id} for {session_id}")
    })
}

async fn wait_for_live_daemon_binding_transition(
    socket: &Path,
    session_id: &str,
    container_id: &str,
    previous_identity: &RuntimeWorkloadIdentity,
    timeout: Duration,
) -> (apolysis_accountability::SessionState, RuntimeBinding) {
    let request = serde_json::to_vec(&json!({
        "type": "query",
        "session_id": session_id,
    }))
    .expect("encode live daemon query");
    tokio::time::timeout(timeout, async {
        loop {
            if let DaemonResponse::Session {
                session: Some(session),
                runtime_bindings,
                ..
            } = live_daemon_request(socket, &request).await
            {
                if let Some(binding) = runtime_bindings.iter().find(|binding| {
                    binding.identity.workload_id == container_id
                        && binding.identity != *previous_identity
                }) {
                    return (session, binding.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("live daemon did not qualify a new Docker generation for {container_id}")
    })
}

fn target_runtime_recovery_sequence(
    timeline_delta: &str,
    session_id: &str,
    container_id: &str,
    expected_gap_reason: &str,
) -> Vec<&'static str> {
    let expected_gap_detail = format!("source=docker,reason={expected_gap_reason}");
    timeline_delta
        .lines()
        .filter_map(|line| {
            let record: serde_json::Value =
                serde_json::from_str(line).expect("decode live daemon hash-chain record");
            let payload = record
                .get("payload")
                .expect("hash-chain record contains payload");
            if payload.get("agent_run_id").and_then(|value| value.as_str()) != Some(session_id) {
                return None;
            }
            match payload.get("record_type").and_then(|value| value.as_str()) {
                Some("observation_gap") => {
                    assert_eq!(
                        payload.get("operation").and_then(|value| value.as_str()),
                        Some("runtime_metadata")
                    );
                    assert_eq!(
                        payload.get("kind").and_then(|value| value.as_str()),
                        Some("runtime_metadata_unavailable")
                    );
                    assert_eq!(
                        payload.get("count").and_then(|value| value.as_u64()),
                        Some(1)
                    );
                    assert_eq!(
                        payload.get("detail").and_then(|value| value.as_str()),
                        Some(expected_gap_detail.as_str())
                    );
                    Some("gap")
                }
                Some("runtime_binding_retired")
                    if payload.get("workload_id").and_then(|value| value.as_str())
                        == Some(container_id) =>
                {
                    Some("retired")
                }
                Some("runtime_binding_observed")
                    if payload.get("workload_id").and_then(|value| value.as_str())
                        == Some(container_id) =>
                {
                    Some("observed")
                }
                Some(record_type) if record_type.starts_with("runtime_binding_") => {
                    panic!("unexpected target recovery record: {record_type}")
                }
                _ => None,
            }
        })
        .collect()
}

fn target_runtime_socket_recovery_sequence(
    timeline_delta: &str,
    session_id: &str,
    source: &str,
    workload_id: &str,
) -> Vec<&'static str> {
    let expected_gap_detail = format!("source={source},reason=socket_unavailable");
    timeline_delta
        .lines()
        .filter_map(|line| {
            let record: serde_json::Value =
                serde_json::from_str(line).expect("decode socket recovery hash-chain record");
            let payload = record
                .get("payload")
                .expect("hash-chain record contains payload");
            if payload.get("agent_run_id").and_then(|value| value.as_str()) != Some(session_id) {
                return None;
            }
            match payload.get("record_type").and_then(|value| value.as_str()) {
                Some("observation_gap") => {
                    assert_eq!(
                        payload.get("operation").and_then(|value| value.as_str()),
                        Some("runtime_metadata")
                    );
                    assert_eq!(
                        payload.get("kind").and_then(|value| value.as_str()),
                        Some("runtime_metadata_unavailable")
                    );
                    assert_eq!(
                        payload.get("count").and_then(|value| value.as_u64()),
                        Some(1)
                    );
                    assert_eq!(
                        payload.get("detail").and_then(|value| value.as_str()),
                        Some(expected_gap_detail.as_str())
                    );
                    Some("gap")
                }
                Some("runtime_binding_suspended")
                    if payload.get("workload_id").and_then(|value| value.as_str())
                        == Some(workload_id) =>
                {
                    Some("suspended")
                }
                Some("runtime_binding_observed")
                    if payload.get("workload_id").and_then(|value| value.as_str())
                        == Some(workload_id) =>
                {
                    Some("observed")
                }
                Some(record_type) if record_type.starts_with("runtime_binding_") => {
                    panic!("unexpected target socket recovery record: {record_type}")
                }
                _ => None,
            }
        })
        .collect()
}

fn ensure_docker_alpine_image() {
    let image_status = Command::new("docker")
        .args(["image", "inspect", "alpine:3.20"])
        .output()
        .expect("inspect alpine image");
    if !image_status.status.success() {
        let pull_output = Command::new("docker")
            .args(["pull", "alpine:3.20"])
            .output()
            .expect("pull alpine image");
        assert!(
            pull_output.status.success(),
            "docker pull alpine:3.20 failed: {}",
            String::from_utf8_lossy(&pull_output.stderr)
        );
    }
}

fn start_labelled_docker_container(
    runtime: Option<&str>,
    session_id: &str,
    command: &str,
) -> String {
    let mut args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--rm".to_string(),
        "--label".to_string(),
        format!("apolysis.session_id={session_id}"),
        "--cpus".to_string(),
        "0.5".to_string(),
        "--memory".to_string(),
        "64m".to_string(),
        "--pids-limit".to_string(),
        "64".to_string(),
        "--read-only".to_string(),
        "--network".to_string(),
        "none".to_string(),
        "--cap-drop".to_string(),
        "ALL".to_string(),
        "--security-opt".to_string(),
        "no-new-privileges".to_string(),
    ];
    if let Some(runtime) = runtime {
        args.push("--runtime".to_string());
        args.push(runtime.to_string());
    }
    args.extend([
        "alpine:3.20".to_string(),
        "sh".to_string(),
        "-c".to_string(),
        command.to_string(),
    ]);
    let output = Command::new("docker")
        .args(args.iter().map(String::as_str))
        .output()
        .expect("start labelled container");
    assert!(
        output.status.success(),
        "docker run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

struct ControllableUnixSocketProxy {
    disconnected: Arc<AtomicBool>,
    task: Option<tokio::task::JoinHandle<()>>,
    owned_socket: Option<OwnedUnixSocketPath>,
}

struct OwnedUnixSocketPath {
    path: std::path::PathBuf,
    device: u64,
    inode: u64,
}

impl ControllableUnixSocketProxy {
    fn disconnect(&self) {
        self.disconnected.store(true, Ordering::Release);
    }

    fn reconnect(&self) {
        self.disconnected.store(false, Ordering::Release);
    }

    fn abort(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        self.unlink_owned_socket()
            .expect("unlink exact owned proxy socket");
    }

    fn unlink_owned_socket(&mut self) -> std::io::Result<()> {
        let Some(owned_socket) = self.owned_socket.as_ref() else {
            return Ok(());
        };
        let metadata = match std::fs::symlink_metadata(&owned_socket.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.owned_socket = None;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if !metadata.file_type().is_socket()
            || metadata.dev() != owned_socket.device
            || metadata.ino() != owned_socket.inode
        {
            self.owned_socket = None;
            return Ok(());
        }
        std::fs::remove_file(&owned_socket.path)?;
        self.owned_socket = None;
        Ok(())
    }
}

impl Drop for ControllableUnixSocketProxy {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = self.unlink_owned_socket();
    }
}

fn start_controllable_unix_socket_proxy(
    proxy_socket: &Path,
    upstream_socket: &Path,
    initially_disconnected: bool,
) -> ControllableUnixSocketProxy {
    if let Some(parent) = proxy_socket.parent() {
        std::fs::create_dir_all(parent).expect("create proxy socket directory");
    }
    match std::fs::symlink_metadata(proxy_socket) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => panic!("failed to inspect proxy socket path"),
        Ok(_) => panic!("proxy socket path must be absent before bind"),
    }
    let listener = UnixListener::bind(proxy_socket).expect("bind proxy socket");
    let metadata = std::fs::symlink_metadata(proxy_socket).expect("inspect bound proxy socket");
    assert!(
        metadata.file_type().is_socket(),
        "bound proxy path must be a Unix socket"
    );
    let owned_socket = OwnedUnixSocketPath {
        path: proxy_socket.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let upstream_socket = upstream_socket.to_path_buf();
    let disconnected = Arc::new(AtomicBool::new(initially_disconnected));
    let proxy_disconnected = Arc::clone(&disconnected);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                break;
            };
            let upstream_socket = upstream_socket.clone();
            let disconnected = Arc::clone(&proxy_disconnected);
            tokio::spawn(async move {
                if disconnected.load(Ordering::Acquire) {
                    return;
                }
                let Ok(mut upstream) = UnixStream::connect(&upstream_socket).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    ControllableUnixSocketProxy {
        disconnected,
        task: Some(task),
        owned_socket: Some(owned_socket),
    }
}

fn start_unix_socket_proxy_with_initial_disconnect(
    proxy_socket: &Path,
    upstream_socket: &Path,
) -> tokio::task::JoinHandle<()> {
    if let Some(parent) = proxy_socket.parent() {
        std::fs::create_dir_all(parent).expect("create proxy socket directory");
    }
    let _ = std::fs::remove_file(proxy_socket);
    let listener = UnixListener::bind(proxy_socket).expect("bind proxy socket");
    let upstream_socket = upstream_socket.to_path_buf();
    let disconnect_next = Arc::new(AtomicBool::new(true));
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                break;
            };
            let upstream_socket = upstream_socket.clone();
            let disconnect_next = Arc::clone(&disconnect_next);
            tokio::spawn(async move {
                if disconnect_next.swap(false, Ordering::AcqRel) {
                    return;
                }
                let Ok(mut upstream) = UnixStream::connect(&upstream_socket).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    })
}

async fn wait_for_session_cgroup(state: &Arc<DaemonState>, session_id: &str, timeout: Duration) {
    tokio::time::timeout(timeout, async {
        loop {
            if state
                .query(session_id)
                .await
                .map(|session| !session.cgroup_ids.is_empty())
                .unwrap_or(false)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("session {session_id} did not attach a cgroup"));
}

async fn wait_for_runtime_binding_gap(
    state: &Arc<DaemonState>,
    adapter: AdapterKind,
    session_id: &str,
    previous_cgroup: u64,
    timeout: Duration,
) {
    tokio::time::timeout(timeout, async {
        loop {
            let session = state.query(session_id).await;
            let bindings = state.runtime_bindings_for_agent_run(session_id).await;
            if state.health().await.adapter(adapter) == ComponentState::Degraded
                && state.session_for_cgroup(previous_cgroup).await.is_none()
                && bindings.is_empty()
                && session
                    .as_ref()
                    .map(|session| {
                        session.status == SessionStatus::Active && session.cgroup_ids.is_empty()
                    })
                    .unwrap_or(false)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("runtime {adapter:?} did not suspend {session_id} during outage"));
}

async fn wait_for_same_runtime_binding(
    state: &Arc<DaemonState>,
    adapter: AdapterKind,
    session_id: &str,
    expected: &RuntimeBinding,
    timeout: Duration,
) {
    tokio::time::timeout(timeout, async {
        loop {
            let bindings = state.runtime_bindings_for_agent_run(session_id).await;
            if state.health().await.adapter(adapter) == ComponentState::Ready
                && bindings.iter().any(|binding| binding == expected)
                && state
                    .session_for_cgroup(expected.identity.cgroup.inode)
                    .await
                    .as_deref()
                    == Some(session_id)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!("runtime {adapter:?} did not reattach stable binding for {session_id}")
    });
}

async fn wait_for_session_cgroup_count(
    state: &Arc<DaemonState>,
    session_id: &str,
    minimum_count: usize,
    timeout: Duration,
) {
    tokio::time::timeout(timeout, async {
        loop {
            if state
                .query(session_id)
                .await
                .map(|session| session.cgroup_ids.len() >= minimum_count)
                .unwrap_or(false)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("session {session_id} did not attach {minimum_count} cgroups"));
}

async fn adapter_reaches_state(
    state: &Arc<DaemonState>,
    adapter: AdapterKind,
    expected: ComponentState,
    timeout: Duration,
) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            if state.health().await.adapter(adapter) == expected {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or(false)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CriFixtureRootProof {
    path: std::path::PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

fn try_create_private_cri_fixture_root(
    path: &std::path::Path,
) -> std::io::Result<CriFixtureRootProof> {
    std::fs::DirBuilder::new().mode(0o700).create(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_dir() || metadata.uid() != effective_uid || mode != 0o700 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "new CRI fixture root is not a private owner-controlled directory",
        ));
    }
    Ok(CriFixtureRootProof {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode,
    })
}

fn create_private_cri_fixture_root() -> CriFixtureRootProof {
    let parent = std::env::temp_dir();
    for _ in 0..16 {
        let uuid = kernel_random_uuid();
        let path = parent.join(format!("apolysis-cri-live-{uuid}"));
        match try_create_private_cri_fixture_root(&path) {
            Ok(proof) => return proof,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create private CRI fixture root: {error}"),
        }
    }
    panic!("kernel UUID source repeatedly collided while creating a CRI fixture root")
}

fn kernel_random_uuid() -> String {
    let uuid = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .expect("Linux kernel random UUID source for isolated CRI live fixture");
    let uuid = uuid.trim();
    assert_eq!(uuid.len(), 36, "kernel UUID length");
    assert!(
        uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        }),
        "kernel UUID must be canonical lowercase"
    );
    uuid.to_string()
}

struct CriWorkloadCleanup {
    crictl_path: std::path::PathBuf,
    endpoint: String,
    image_endpoint: Option<String>,
    container_id: String,
    container_proof: CriObjectProof,
    pod_proof: CriObjectProof,
    fixture_root: CriFixtureRootProof,
    cleanup_complete: bool,
}

struct PartialCriWorkloadCleanup {
    crictl_path: std::path::PathBuf,
    endpoint: String,
    image_endpoint: Option<String>,
    container_proof: Option<CriObjectProof>,
    pod_proof: Option<CriObjectProof>,
    fixture_root: CriFixtureRootProof,
    armed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CriObjectKind {
    Container,
    Pod,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CriObjectProof {
    kind: CriObjectKind,
    id: String,
    session_id: String,
    fixture_uid: String,
    owner_token: String,
}

struct CriOwnershipClaim<'a> {
    session_id: &'a str,
    fixture_uid: &'a str,
    owner_token: &'a str,
}

impl PartialCriWorkloadCleanup {
    fn into_full(mut self) -> CriWorkloadCleanup {
        let container_proof = self
            .container_proof
            .take()
            .expect("successful CRI fixture owns a container");
        let pod_proof = self
            .pod_proof
            .take()
            .expect("successful CRI fixture owns a pod");
        self.armed = false;
        CriWorkloadCleanup {
            crictl_path: self.crictl_path.clone(),
            endpoint: self.endpoint.clone(),
            image_endpoint: self.image_endpoint.clone(),
            container_id: container_proof.id.clone(),
            container_proof,
            pod_proof,
            fixture_root: self.fixture_root.clone(),
            cleanup_complete: false,
        }
    }
}

impl Drop for PartialCriWorkloadCleanup {
    fn drop(&mut self) {
        if self.armed {
            best_effort_cleanup_cri_fixture(
                &self.crictl_path,
                &self.endpoint,
                self.image_endpoint.as_deref(),
                self.container_proof.as_ref(),
                self.pod_proof.as_ref(),
                &self.fixture_root,
            );
        }
    }
}

impl CriWorkloadCleanup {
    fn cleanup(mut self) -> Result<(), String> {
        strict_cleanup_cri_fixture(
            &self.crictl_path,
            &self.endpoint,
            self.image_endpoint.as_deref(),
            &self.container_proof,
            &self.pod_proof,
            &self.fixture_root,
        )?;
        self.cleanup_complete = true;
        Ok(())
    }
}

impl Drop for CriWorkloadCleanup {
    fn drop(&mut self) {
        if !self.cleanup_complete {
            best_effort_cleanup_cri_fixture(
                &self.crictl_path,
                &self.endpoint,
                self.image_endpoint.as_deref(),
                Some(&self.container_proof),
                Some(&self.pod_proof),
                &self.fixture_root,
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CriOwnedObjectState {
    Present,
    Absent,
}

fn prove_cri_object(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    kind: CriObjectKind,
    id: &str,
    ownership: &CriOwnershipClaim<'_>,
) -> Result<CriObjectProof, String> {
    if id.len() != 64
        || id
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !matches!(byte, b'a'..=b'f'))
    {
        return Err("CRI fixture returned a noncanonical object ID".to_string());
    }
    let proof = CriObjectProof {
        kind,
        id: id.to_string(),
        session_id: ownership.session_id.to_string(),
        fixture_uid: ownership.fixture_uid.to_string(),
        owner_token: ownership.owner_token.to_string(),
    };
    let output = inspect_cri_object(crictl_path, endpoint, image_endpoint, &proof)?;
    validate_cri_object_inspect(&output, &proof)?;
    Ok(proof)
}

fn inspect_cri_object(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    proof: &CriObjectProof,
) -> Result<String, String> {
    match proof.kind {
        CriObjectKind::Container => run_crictl_with_command(
            crictl_path,
            endpoint,
            image_endpoint,
            &["inspect", "-o", "json", &proof.id],
        ),
        CriObjectKind::Pod => run_crictl_with_command(
            crictl_path,
            endpoint,
            image_endpoint,
            &["inspectp", "-o", "json", &proof.id],
        ),
    }
}

fn validate_cri_object_inspect(output: &str, proof: &CriObjectProof) -> Result<(), String> {
    let object: serde_json::Value = serde_json::from_str(output)
        .map_err(|_| "CRI fixture ownership inspect returned invalid JSON".to_string())?;
    let status = object
        .get("status")
        .ok_or_else(|| "CRI fixture ownership inspect omitted status".to_string())?;
    if status.get("id").and_then(serde_json::Value::as_str) != Some(proof.id.as_str()) {
        return Err("CRI fixture ownership inspect returned a different object ID".to_string());
    }
    let labels = status
        .get("labels")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "CRI fixture ownership inspect omitted labels".to_string())?;
    for (key, expected) in [
        ("apolysis.session_id", proof.session_id.as_str()),
        ("apolysis.fixture_uid", proof.fixture_uid.as_str()),
        ("apolysis.fixture_owner", proof.owner_token.as_str()),
    ] {
        if labels.get(key).and_then(serde_json::Value::as_str) != Some(expected) {
            return Err("CRI fixture ownership labels did not match this invocation".to_string());
        }
    }
    if proof.kind == CriObjectKind::Pod
        && status
            .get("metadata")
            .and_then(|metadata| metadata.get("uid"))
            .and_then(serde_json::Value::as_str)
            != Some(proof.fixture_uid.as_str())
    {
        return Err("CRI pod sandbox UID did not match this invocation".to_string());
    }
    Ok(())
}

fn cri_owned_object_state(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    proof: &CriObjectProof,
) -> Result<CriOwnedObjectState, String> {
    match inspect_cri_object(crictl_path, endpoint, image_endpoint, proof) {
        Ok(output) => {
            validate_cri_object_inspect(&output, proof)?;
            Ok(CriOwnedObjectState::Present)
        }
        Err(inspect_error) => {
            for (key, value) in [
                ("apolysis.session_id", proof.session_id.as_str()),
                ("apolysis.fixture_uid", proof.fixture_uid.as_str()),
                ("apolysis.fixture_owner", proof.owner_token.as_str()),
            ] {
                let label = format!("{key}={value}");
                let listed = match proof.kind {
                    CriObjectKind::Container => run_crictl_with_command(
                        crictl_path,
                        endpoint,
                        image_endpoint,
                        &["ps", "-a", "-q", "--label", &label],
                    ),
                    CriObjectKind::Pod => run_crictl_with_command(
                        crictl_path,
                        endpoint,
                        image_endpoint,
                        &["pods", "-q", "--label", &label],
                    ),
                }
                .map_err(|_| "CRI ownership could not be revalidated before cleanup".to_string())?;
                if listed.lines().map(str::trim).any(|id| id == proof.id) {
                    return Err(format!(
                        "CRI ownership inspect failed while the exact labelled object remains: {inspect_error}"
                    ));
                }
            }
            Ok(CriOwnedObjectState::Absent)
        }
    }
}

fn strict_cleanup_cri_fixture(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    container: &CriObjectProof,
    pod: &CriObjectProof,
    fixture_root: &CriFixtureRootProof,
) -> Result<(), String> {
    let container_state = cri_owned_object_state(crictl_path, endpoint, image_endpoint, container)?;
    let pod_state = cri_owned_object_state(crictl_path, endpoint, image_endpoint, pod)?;
    let mut errors = Vec::new();
    if container_state == CriOwnedObjectState::Present {
        for command in ["stop", "rm"] {
            if run_crictl_with_command(
                crictl_path,
                endpoint,
                image_endpoint,
                &[command, &container.id],
            )
            .is_err()
            {
                errors.push(format!("CRI {command} failed for owned container"));
            }
        }
    }
    if pod_state == CriOwnedObjectState::Present {
        for command in ["stopp", "rmp"] {
            if run_crictl_with_command(crictl_path, endpoint, image_endpoint, &[command, &pod.id])
                .is_err()
            {
                errors.push(format!("CRI {command} failed for owned pod sandbox"));
            }
        }
    }
    for proof in [container, pod] {
        if cri_owned_object_state(crictl_path, endpoint, image_endpoint, proof)?
            != CriOwnedObjectState::Absent
        {
            errors.push("owned CRI object still exists after cleanup".to_string());
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    remove_owned_cri_fixture_root(fixture_root)
}

fn best_effort_cleanup_cri_fixture(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    container: Option<&CriObjectProof>,
    pod: Option<&CriObjectProof>,
    fixture_root: &CriFixtureRootProof,
) {
    if let Some(container) = container {
        if cri_owned_object_state(crictl_path, endpoint, image_endpoint, container)
            == Ok(CriOwnedObjectState::Present)
        {
            let _ = run_crictl_with_command(
                crictl_path,
                endpoint,
                image_endpoint,
                &["stop", &container.id],
            );
            let _ = run_crictl_with_command(
                crictl_path,
                endpoint,
                image_endpoint,
                &["rm", &container.id],
            );
        }
    }
    if let Some(pod) = pod {
        if cri_owned_object_state(crictl_path, endpoint, image_endpoint, pod)
            == Ok(CriOwnedObjectState::Present)
        {
            let _ =
                run_crictl_with_command(crictl_path, endpoint, image_endpoint, &["stopp", &pod.id]);
            let _ =
                run_crictl_with_command(crictl_path, endpoint, image_endpoint, &["rmp", &pod.id]);
        }
    }
    let objects_absent = container.into_iter().chain(pod).all(|proof| {
        cri_owned_object_state(crictl_path, endpoint, image_endpoint, proof)
            == Ok(CriOwnedObjectState::Absent)
    });
    if objects_absent {
        let _ = remove_owned_cri_fixture_root(fixture_root);
    }
}

fn cri_fixture_root_matches(proof: &CriFixtureRootProof) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(&proof.path) else {
        return false;
    };
    metadata.file_type().is_dir()
        && metadata.dev() == proof.device
        && metadata.ino() == proof.inode
        && metadata.uid() == proof.uid
        && metadata.mode() & 0o7777 == proof.mode
}

fn remove_owned_cri_fixture_root(proof: &CriFixtureRootProof) -> Result<(), String> {
    if !cri_fixture_root_matches(proof) {
        return Err("CRI fixture root identity changed before cleanup".to_string());
    }
    for file_name in ["pod.json", "container.json", "workload.log"] {
        let path = proof.path.join(file_name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("failed to remove an owned CRI fixture file".to_string()),
        }
    }
    std::fs::remove_dir(&proof.path)
        .map_err(|_| "failed to remove the empty owned CRI fixture root".to_string())?;
    match std::fs::symlink_metadata(&proof.path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("owned CRI fixture root still exists after cleanup".to_string()),
    }
}

struct KubernetesNamespaceCleanup {
    kubectl: String,
    objects: Vec<KubernetesObjectProof>,
}

struct KubernetesObjectProof {
    resource: &'static str,
    raw_uri_prefix: &'static str,
    name: String,
    uid: String,
    owner_token: String,
}

impl Drop for KubernetesNamespaceCleanup {
    fn drop(&mut self) {
        for object in self.objects.iter().rev() {
            delete_kubernetes_object_if_owned(&self.kubectl, object);
        }
    }
}

fn delete_kubernetes_object_if_owned(kubectl: &str, proof: &KubernetesObjectProof) {
    let Ok(current) = Command::new(kubectl)
        .args(["get", proof.resource, &proof.name, "-o", "json"])
        .output()
    else {
        return;
    };
    if !current.status.success() {
        return;
    }
    let Ok(current) = serde_json::from_slice::<serde_json::Value>(&current.stdout) else {
        return;
    };
    if current
        .pointer("/metadata/uid")
        .and_then(|value| value.as_str())
        != Some(&proof.uid)
        || current
            .pointer("/metadata/annotations/apolysis.dev~1live-test-owner")
            .and_then(|value| value.as_str())
            != Some(&proof.owner_token)
    {
        return;
    }
    let uri = format!("{}/{}", proof.raw_uri_prefix, proof.name);
    let Ok(mut child) = Command::new(kubectl)
        .args(["delete", "--raw", &uri, "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = write!(
            stdin,
            "{{\"apiVersion\":\"v1\",\"kind\":\"DeleteOptions\",\"preconditions\":{{\"uid\":\"{}\"}},\"propagationPolicy\":\"Foreground\"}}",
            proof.uid
        );
    }
    let _ = child.wait();
}

fn kubernetes_object_proof(
    kubectl: &str,
    resource: &'static str,
    raw_uri_prefix: &'static str,
    name: &str,
    owner_token: &str,
) -> Option<KubernetesObjectProof> {
    let output = Command::new(kubectl)
        .args(["get", resource, name, "-o", "json"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let object: serde_json::Value = serde_json::from_slice(&output.stdout).ok()?;
    if object
        .pointer("/metadata/annotations/apolysis.dev~1live-test-owner")
        .and_then(|value| value.as_str())
        != Some(owner_token)
    {
        return None;
    }
    let uid = object
        .pointer("/metadata/uid")
        .and_then(|value| value.as_str())?
        .trim();
    if uid.is_empty() {
        return None;
    }
    Some(KubernetesObjectProof {
        resource,
        raw_uri_prefix,
        name: name.to_string(),
        uid: uid.to_string(),
        owner_token: owner_token.to_string(),
    })
}

struct TempScript {
    path: std::path::PathBuf,
}

impl TempScript {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempScript {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn live_cri_adapter_matrix(
    adapter_kind: AdapterKind,
    socket_path: &str,
    image_endpoint: Option<&str>,
) {
    let crictl = live_crictl_path();
    if !standalone_cri_network_ready_or_skip(&crictl, socket_path, image_endpoint) {
        return;
    }
    for runtime in live_cri_runtimes() {
        let session_id = format!("live-cri-{runtime}-{}", kernel_random_uuid());
        let cleanup = create_cri_workload_with_crictl(
            &crictl,
            socket_path,
            image_endpoint,
            runtime,
            &session_id,
        );
        let adapter = ContainerdCriRuntimeAdapter::new(
            adapter_kind,
            CriRuntimeClient::new(socket_path)
                .with_crictl_path(&crictl)
                .with_image_endpoint(image_endpoint.map(ToOwned::to_owned)),
            "/proc",
            "/sys/fs/cgroup",
            Duration::from_millis(100),
            1024,
        )
        .expect("CRI adapter");
        let inventory = tokio::time::timeout(Duration::from_secs(15), adapter.scan_inventory())
            .await
            .expect("CRI inventory timeout")
            .expect("complete CRI inventory");
        let identity_domain = match adapter_kind {
            AdapterKind::Containerd => "containerd",
            AdapterKind::K3sContainerd => "k3s_containerd",
            _ => panic!("live CRI matrix requires a containerd adapter"),
        };
        let workload_id = format!("{identity_domain}/{}", cleanup.container_id);
        let binding = inventory
            .bindings
            .iter()
            .find(|binding| binding.identity.workload_id == workload_id)
            .expect("labelled CRI binding");

        assert_eq!(binding.identity.adapter, adapter_kind);
        assert_eq!(binding.agent_run_id, session_id);
        assert_eq!(binding.identity.workload_id, workload_id);
        assert!(!binding.identity.start_marker.is_empty());
        assert!(!binding.identity.host_boot_id.is_empty());
        assert!(binding.identity.init_process_start_time_ticks > 0);
        assert!(binding.identity.cgroup.device > 0);
        assert!(binding.identity.cgroup.inode > 0);
        assert!(
            binding
                .runtime_handler
                .as_deref()
                .unwrap_or_default()
                .contains(expected_cri_runtime_type(runtime)),
            "runtime handler {:?} did not contain expected type {}",
            binding.runtime_handler,
            expected_cri_runtime_type(runtime)
        );
        cleanup
            .cleanup()
            .expect("strictly clean owned CRI discovery fixture");
    }
}

async fn live_k3s_cri_adapter_matrix() {
    let crictl = live_crictl_path();
    let kubectl = std::env::var("APOLYSIS_KUBECTL").unwrap_or_else(|_| "kubectl".to_string());
    require_kubectl(&kubectl);
    let endpoint = std::env::var("APOLYSIS_K3S_CRI_ENDPOINT")
        .unwrap_or_else(|_| "/run/k3s/containerd/containerd.sock".to_string());

    for (name, runtime_handler) in live_kubernetes_runtimes() {
        let session_id = random_kubernetes_value(&format!("live-k3s-cri-{name}"));
        let namespace = random_kubernetes_value("apolysis-live");
        let pod_name = format!("apolysis-k3s-cri-{name}");
        let runtime_class =
            runtime_handler.map(|_| random_kubernetes_value(&format!("apolysis-k3s-cri-{name}")));
        let cleanup = create_kubernetes_pod(
            &kubectl,
            &namespace,
            &pod_name,
            &session_id,
            runtime_class.as_deref(),
            runtime_handler,
        );
        wait_for_kubernetes_container_id(&kubectl, &namespace, &pod_name);

        let mut adapter = ContainerdCriRuntimeAdapter::new(
            AdapterKind::K3sContainerd,
            CriRuntimeClient::new(&endpoint)
                .with_crictl_path(&crictl)
                .with_image_endpoint(None),
            "/proc",
            "/sys/fs/cgroup",
            Duration::from_millis(100),
            1024,
        )
        .expect("k3s CRI adapter");
        let workload = tokio::time::timeout(
            Duration::from_secs(20),
            next_workload_for_session(&mut adapter, &session_id),
        )
        .await
        .expect("k3s CRI adapter timeout")
        .expect("target labelled k3s CRI workload");

        assert_eq!(workload.adapter, AdapterKind::K3sContainerd);
        assert_eq!(workload.session_id, session_id);
        assert!(workload.cgroup_id > 0);
        assert_eq!(
            workload.image.as_deref(),
            Some("docker.io/library/alpine:3.20")
        );
        let expected_runtime = runtime_handler.unwrap_or("runc");
        assert!(
            workload
                .runtime_handler
                .as_deref()
                .unwrap_or_default()
                .contains(expected_cri_runtime_type(expected_runtime)),
            "runtime handler {:?} did not contain expected type {}",
            workload.runtime_handler,
            expected_cri_runtime_type(expected_runtime)
        );
        drop(cleanup);
        cleanup_cri_workloads_for_session(&crictl, &endpoint, None, &session_id);
    }
}

fn live_cri_runtimes() -> Vec<&'static str> {
    if std::env::var("APOLYSIS_REQUIRE_FULL_RUNTIME_ADAPTERS")
        .ok()
        .as_deref()
        == Some("1")
    {
        vec!["runc", "runsc", "kata"]
    } else {
        vec!["runc"]
    }
}

fn live_docker_runtimes() -> Vec<Option<&'static str>> {
    if std::env::var("APOLYSIS_REQUIRE_FULL_RUNTIME_ADAPTERS")
        .ok()
        .as_deref()
        == Some("1")
    {
        vec![None, Some("runsc")]
    } else {
        vec![None]
    }
}

fn live_kubernetes_runtimes() -> Vec<(&'static str, Option<&'static str>)> {
    if std::env::var("APOLYSIS_REQUIRE_FULL_RUNTIME_ADAPTERS")
        .ok()
        .as_deref()
        == Some("1")
    {
        vec![
            ("runc", None),
            ("gvisor", Some("runsc")),
            ("kata", Some("kata")),
        ]
    } else {
        vec![("runc", None)]
    }
}

fn expected_cri_runtime_type(runtime: &str) -> &'static str {
    match runtime {
        "runsc" => "io.containerd.runsc.v1",
        "kata" => "io.containerd.kata.v2",
        _ => "io.containerd.runc.v2",
    }
}

#[test]
fn standalone_cri_pod_fixture_uses_node_network_without_changing_k3s_contract() {
    let standalone = cri_pod_linux_config("/run/containerd/containerd.sock");
    assert_eq!(
        standalone.pointer("/security_context/namespace_options/network"),
        Some(&json!(2)),
        "CRI NamespaceMode.NODE must use the stable numeric protobuf enum representation"
    );
    assert!(
        standalone.get("resources").is_none(),
        "standalone NODE sandboxes must not request unavailable delegated cgroup controllers"
    );

    let k3s = cri_pod_linux_config("/run/k3s/containerd/containerd.sock");
    assert_eq!(k3s.get("cgroup_parent"), Some(&json!("system.slice")));
    assert_eq!(
        k3s.pointer("/resources/cpu_period"),
        Some(&json!(100000)),
        "k3s sandbox resource behavior must remain unchanged"
    );
    assert!(
        k3s.pointer("/security_context/namespace_options/network")
            .is_none(),
        "k3s pod fixture must retain its existing pod-network contract"
    );
}

#[test]
fn private_cri_failure_diagnostic_exposes_only_canonical_code_and_class() {
    let cases = [
        (
            "rpc error: code = Unknown desc = failed to get sandbox image private-image-token",
            "CRI live command failed (grpc=Unknown, class=image)",
        ),
        (
            "rpc error: code = Internal desc = failed to create shim task at /private/root/token",
            "CRI live command failed (grpc=Internal, class=runtime)",
        ),
        (
            "rpc error: code = InvalidArgument desc = invalid cgroup parent private-cgroup-token",
            "CRI live command failed (grpc=InvalidArgument, class=cgroup, detail=parent)",
        ),
        (
            "arbitrary private-stderr-token",
            "CRI live command failed (grpc=unclassified, class=unknown)",
        ),
    ];

    for (stderr, expected) in cases {
        let diagnostic = canonical_private_cri_failure(stderr.as_bytes());
        assert_eq!(diagnostic, expected);
        for forbidden in [
            "private-image-token",
            "/private/root/token",
            "private-cgroup-token",
            "private-stderr-token",
        ] {
            assert!(!diagnostic.contains(forbidden), "{diagnostic}");
        }
    }
}

#[test]
fn private_cri_cgroup_diagnostic_uses_only_fixed_detail_tokens() {
    let cases = [
        ("cgroup /hostile/a: read-only file system", "permission"),
        ("cgroup mountpoint /hostile/b was invalid", "mountpoint"),
        ("cgroup parent /hostile/c was rejected", "parent"),
        (
            "cgroup controller private-controller-token unavailable",
            "controller, controller=unknown",
        ),
        ("cgroup v2 unified mode rejected private-mode-token", "mode"),
        ("systemd cgroup private-unit-token failed", "systemd"),
        ("cgroup /hostile/d: no such file or directory", "missing"),
        ("cgroup private-unknown-token failed", "unknown"),
    ];

    for (stderr, detail) in cases {
        let diagnostic = canonical_private_cri_failure(stderr.as_bytes());
        assert_eq!(
            diagnostic,
            format!("CRI live command failed (grpc=unclassified, class=cgroup, detail={detail})")
        );
        for forbidden in [
            "/hostile/a",
            "/hostile/b",
            "/hostile/c",
            "/hostile/d",
            "private-controller-token",
            "private-mode-token",
            "private-unit-token",
            "private-unknown-token",
        ] {
            assert!(!diagnostic.contains(forbidden), "{diagnostic}");
        }
    }
}

#[test]
fn private_cri_controller_diagnostic_uses_only_explicit_fixed_tokens() {
    let cases = [
        ("cgroup cpu controller rejected /hostile/cpu", "cpu"),
        ("cgroup controller io failed /hostile/io", "io"),
        (
            "cgroup memory.max controller failed /hostile/memory",
            "memory",
        ),
        ("cgroup pids.max controller failed /hostile/pids", "pids"),
        ("cgroup cpuset controller failed /hostile/cpuset", "cpuset"),
        (
            "cgroup devices.allow controller failed /hostile/devices",
            "devices",
        ),
        (
            "cgroup controller failed while applying memory limit /hostile/unknown",
            "unknown",
        ),
    ];

    for (stderr, controller) in cases {
        let diagnostic = canonical_private_cri_failure(stderr.as_bytes());
        assert_eq!(
            diagnostic,
            format!(
                "CRI live command failed (grpc=unclassified, class=cgroup, detail=controller, controller={controller})"
            )
        );
        assert!(!diagnostic.contains("/hostile/"), "{diagnostic}");
        assert!(!diagnostic.contains("memory limit"), "{diagnostic}");
    }
}

#[tokio::test]
async fn live_crictl_helper_enforces_an_outer_deadline_and_reaps_the_process() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-live-crictl-deadline-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    let pid_file = root.join("pid");
    write_executable_fixture(
        &crictl,
        "#!/bin/sh\nprintf '%s' \"$$\" > \"$4\"\nexec sleep 1\n",
    );
    let started = Instant::now();

    let error = run_crictl_with_command_deadline(
        &crictl,
        pid_file.to_str().expect("pid fixture path UTF-8"),
        None,
        &["info"],
        Duration::from_millis(50),
    )
    .expect_err("a crictl process that ignores --timeout must hit the outer deadline");

    assert_eq!(error, "CRI live command timed out");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the outer deadline must bound a crictl process that ignores --timeout"
    );
    let pid = std::fs::read_to_string(&pid_file)
        .expect("read fake crictl pid")
        .parse::<libc::pid_t>()
        .expect("parse fake crictl pid");
    // SAFETY: signal 0 performs a liveness check and does not deliver a signal.
    let liveness = unsafe { libc::kill(pid, 0) };
    assert_eq!(liveness, -1, "the timed-out crictl process must be reaped");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH),
        "the timed-out crictl process must no longer exist"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn live_crictl_helper_rejects_oversized_stdout_without_echoing_it() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-live-crictl-stdout-bound-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("private-path-token-crictl");
    write_executable_fixture(
        &crictl,
        "#!/bin/sh\nhead -c 1048577 /dev/zero | tr '\\0' q\n",
    );

    let result = run_crictl_with_command_deadline(
        &crictl,
        "unix:///missing/containerd.sock",
        None,
        &["info"],
        Duration::from_secs(3),
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("oversized CRI live stdout was accepted"),
    };

    assert_eq!(error, "CRI live command stdout exceeded byte limit");
    assert!(!error.contains("qqqqqq"), "{error}");
    assert!(!error.contains("private-path-token-crictl"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn live_crictl_helper_rejects_oversized_stderr_without_echoing_it() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-live-crictl-stderr-bound-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("private-path-token-crictl");
    write_executable_fixture(
        &crictl,
        "#!/bin/sh\nhead -c 1048577 /dev/zero | tr '\\0' q >&2\n",
    );

    let result = run_crictl_with_command_deadline(
        &crictl,
        "unix:///missing/containerd.sock",
        None,
        &["info"],
        Duration::from_secs(3),
    );
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("oversized CRI live stderr was accepted"),
    };

    assert_eq!(error, "CRI live command stderr exceeded byte limit");
    assert!(!error.contains("qqqqqq"), "{error}");
    assert!(!error.contains("private-path-token-crictl"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn standalone_cri_network_preflight_skips_before_any_runp_mutation() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-cri-network-preflight-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    let command_log = root.join("commands.log");
    let script = r#"#!/bin/sh
printf '%s\n' "$*" >> "@COMMAND_LOG@"
case " $* " in
  *" info "*) printf '{"status":{"conditions":[{"type":"RuntimeReady","status":true},{"type":"NetworkReady","status":false,"reason":"NetworkPluginNotReady","message":"cni plugin not initialized"}]}}\n' ;;
  *" runp "*) printf '%s\n' mutation-was-attempted; exit 97 ;;
  *) exit 64 ;;
esac
"#
    .replace("@COMMAND_LOG@", &command_log.to_string_lossy());
    write_executable_fixture(&crictl, &script);

    let preflight =
        standalone_cri_mutation_preflight(&crictl, "unix:///run/containerd/fake.sock", None)
            .expect("typed standalone CRI preflight");

    assert_eq!(preflight, CriMutationPreflight::SkipNetworkUnavailable);
    let commands = std::fs::read_to_string(&command_log).expect("read preflight command log");
    assert!(commands.contains(" info "), "{commands}");
    assert!(!commands.contains(" runp "), "{commands}");
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn private_cri_node_network_preflight_accepts_runtime_ready_without_cni() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-private-cri-network-preflight-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    let command_log = root.join("commands.log");
    let script = r#"#!/bin/sh
printf '%s\n' "$*" >> "@COMMAND_LOG@"
case " $* " in
  *" info "*) printf '{"status":{"conditions":[{"type":"RuntimeReady","status":true},{"type":"NetworkReady","status":false,"reason":"NetworkPluginNotReady","message":"private runtime has no CNI"}]}}\n' ;;
  *" runp "*) printf '%s\n' mutation-was-attempted; exit 97 ;;
  *) exit 64 ;;
esac
"#
    .replace("@COMMAND_LOG@", &command_log.to_string_lossy());
    write_executable_fixture(&crictl, &script);

    let preflight = private_cri_node_network_mutation_preflight(
        &crictl,
        "unix:///private/apolysis/containerd.sock",
    )
    .expect("typed private CRI preflight");

    assert_eq!(preflight, CriMutationPreflight::Ready);
    let commands = std::fs::read_to_string(&command_log).expect("read preflight command log");
    assert!(commands.contains(" info "), "{commands}");
    assert!(!commands.contains(" runp "), "{commands}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn private_container_proof_rejects_a_started_mutation_without_a_full_id() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-private-container-proof-missing-id-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("cgroup");
    std::fs::create_dir_all(&proc_root).expect("create fake proc root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("make proof root private");
    std::fs::create_dir(&cgroup_root).expect("create fake cgroup root");
    begin_private_container_mutation_proof(&root).expect("publish private mutation-started proof");

    let error = private_container_residue_state(&root, &proc_root, &cgroup_root)
        .expect_err("a known mutation without a persisted full ID must fail closed");

    assert!(error.contains("no persisted full container ID"), "{error}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn private_container_proof_requires_authoritative_sweep_for_a_partial_id_journal() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-private-container-proof-partial-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("cgroup");
    std::fs::create_dir_all(&proc_root).expect("create fake proc root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("make proof root private");
    std::fs::create_dir(&cgroup_root).expect("create fake cgroup root");
    begin_private_container_mutation_proof(&root).expect("publish private mutation-started proof");
    append_private_container_id_proof(
        &root,
        "1111111111111111111111111111111111111111111111111111111111111111",
    )
    .expect("persist partial full-ID journal");

    let error = private_container_residue_state(&root, &proc_root, &cgroup_root)
        .expect_err("a partial journal without a sweep must fail closed");
    assert!(error.contains("incomplete full-ID journal"), "{error}");

    let mut sweep = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("qualification-authoritative-sweep"))
        .expect("create authoritative sweep proof");
    sweep
        .write_all(b"complete\n")
        .and_then(|_| sweep.sync_all())
        .expect("persist authoritative sweep proof");
    assert_eq!(
        private_container_residue_state(&root, &proc_root, &cgroup_root)
            .expect("accept partial journal only after authoritative empty sweep"),
        PrivateContainerResidueState::Clear
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn private_container_proof_detects_cleanup_failure_after_each_persisted_full_id() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-private-container-proof-residue-{}-{id}",
        std::process::id()
    ));
    let proc_root = root.join("proc");
    let cgroup_root = root.join("cgroup");
    std::fs::create_dir_all(proc_root.join("101")).expect("create fake process");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("make proof root private");
    std::fs::create_dir(&cgroup_root).expect("create fake cgroup root");
    begin_private_container_mutation_proof(&root).expect("publish private mutation-started proof");
    let first_id = "1111111111111111111111111111111111111111111111111111111111111111";
    let second_id = "2222222222222222222222222222222222222222222222222222222222222222";

    append_private_container_id_proof(&root, first_id).expect("persist first full container ID");
    std::fs::write(proc_root.join("101/cgroup"), format!("0::/{first_id}\n"))
        .expect("inject first cleanup residue");
    assert_eq!(
        private_container_residue_state(&root, &proc_root, &cgroup_root)
            .expect("inspect first cleanup failure"),
        PrivateContainerResidueState::Residue
    );

    std::fs::remove_file(proc_root.join("101/cgroup")).expect("clear first fake residue");
    append_private_container_id_proof(&root, second_id).expect("persist second full container ID");
    std::fs::create_dir(cgroup_root.join(format!("cri-containerd-{second_id}.scope")))
        .expect("inject second cleanup residue");
    assert_eq!(
        private_container_residue_state(&root, &proc_root, &cgroup_root)
            .expect("inspect second cleanup failure"),
        PrivateContainerResidueState::Residue
    );
    let proof = std::fs::read_to_string(root.join("qualification-container-ids"))
        .expect("read durable full-ID proof");
    assert_eq!(proof, format!("{first_id}\n{second_id}\n"));
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn cri_live_fixture_cleans_the_owned_pod_when_container_creation_fails() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-cri-partial-cleanup-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    let command_log = root.join("commands.log");
    let pod_config_path = root.join("pod-config-path");
    let pod_removed = root.join("pod-removed");
    let pod_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let script = r#"#!/bin/sh
printf '%s\n' "$*" >> "@COMMAND_LOG@"
case " $* " in
  *" runp "*)
    for argument in "$@"; do case "$argument" in */pod.json) printf '%s\n' "$argument" > "@POD_CONFIG_PATH@" ;; esac; done
    printf '%s\n' @POD_ID@
    ;;
  *" inspectp "*" @POD_ID@ "*)
    test ! -e "@POD_REMOVED@" || exit 1
    config=$(cat "@POD_CONFIG_PATH@")
    session=$(sed -n 's/.*"apolysis.session_id": "\([^"]*\)".*/\1/p' "$config" | head -n 1)
    uid=$(sed -n 's/.*"uid": "\([^"]*\)".*/\1/p' "$config" | head -n 1)
    owner=$(sed -n 's/.*"apolysis.fixture_owner": "\([^"]*\)".*/\1/p' "$config" | head -n 1)
    printf '{"status":{"id":"@POD_ID@","metadata":{"uid":"%s"},"labels":{"apolysis.session_id":"%s","apolysis.fixture_uid":"%s","apolysis.fixture_owner":"%s"}}}\n' "$uid" "$session" "$uid" "$owner"
    ;;
  *" create "*) exit 64 ;;
  *" stopp @POD_ID@ "*) exit 0 ;;
  *" rmp @POD_ID@ "*) touch "@POD_REMOVED@" ;;
  *" pods -q "*) test -e "@POD_REMOVED@" || printf '%s\n' @POD_ID@ ;;
  *) exit 64 ;;
esac
"#
    .replace("@COMMAND_LOG@", &command_log.to_string_lossy())
    .replace("@POD_CONFIG_PATH@", &pod_config_path.to_string_lossy())
    .replace("@POD_REMOVED@", &pod_removed.to_string_lossy())
    .replace("@POD_ID@", pod_id);
    write_executable_fixture(&crictl, &script);

    let result = std::panic::catch_unwind(|| {
        create_cri_workload_with_crictl(
            &crictl,
            "/run/containerd/fake.sock",
            None,
            "runc",
            "agent-run-partial-cleanup",
        )
    });

    assert!(result.is_err(), "injected create failure must propagate");
    let commands = std::fs::read_to_string(&command_log).expect("read fake crictl command log");
    assert!(commands.contains(&format!("stopp {pod_id}")), "{commands}");
    assert!(commands.contains(&format!("rmp {pod_id}")), "{commands}");
    assert!(
        !cri_fixture_root_from_commands(&commands).exists(),
        "partial failure cleanup must remove its exact private root"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cri_live_fixture_never_reuses_or_removes_a_preexisting_operator_root() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let outer = std::env::temp_dir().join(format!(
        "apolysis-cri-root-canary-{}-{id}",
        std::process::id()
    ));
    let candidate = outer.join("preexisting");
    let canary = candidate.join("operator-canary");
    std::fs::create_dir_all(&candidate).expect("create operator-owned candidate root");
    std::fs::write(&canary, b"preserve").expect("write operator canary");

    let error = try_create_private_cri_fixture_root(&candidate)
        .expect_err("a create-new fixture root must reject a preexisting path");

    assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(
        std::fs::read(&canary).expect("operator canary must remain"),
        b"preserve"
    );
    let _ = std::fs::remove_dir_all(&outer);
}

#[tokio::test]
async fn cri_live_fixture_cleans_owned_container_and_pod_when_start_fails() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-cri-partial-start-cleanup-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    let command_log = root.join("commands.log");
    let pod_config_path = root.join("pod-config-path");
    let container_config_path = root.join("container-config-path");
    let pod_removed = root.join("pod-removed");
    let container_removed = root.join("container-removed");
    let pod_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let container_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let script = r#"#!/bin/sh
printf '%s\n' "$*" >> "@COMMAND_LOG@"
case " $* " in
  *" runp "*)
    for argument in "$@"; do case "$argument" in */pod.json) printf '%s\n' "$argument" > "@POD_CONFIG_PATH@" ;; esac; done
    printf '%s\n' @POD_ID@
    ;;
  *" inspectp "*" @POD_ID@ "*)
    test ! -e "@POD_REMOVED@" || exit 1
    config=$(cat "@POD_CONFIG_PATH@")
    session=$(sed -n 's/.*"apolysis.session_id": "\([^"]*\)".*/\1/p' "$config" | head -n 1)
    uid=$(sed -n 's/.*"uid": "\([^"]*\)".*/\1/p' "$config" | head -n 1)
    owner=$(sed -n 's/.*"apolysis.fixture_owner": "\([^"]*\)".*/\1/p' "$config" | head -n 1)
    printf '{"status":{"id":"@POD_ID@","metadata":{"uid":"%s"},"labels":{"apolysis.session_id":"%s","apolysis.fixture_uid":"%s","apolysis.fixture_owner":"%s"}}}\n' "$uid" "$session" "$uid" "$owner"
    ;;
  *" create "*)
    for argument in "$@"; do case "$argument" in */container.json) printf '%s\n' "$argument" > "@CONTAINER_CONFIG_PATH@" ;; esac; done
    printf '%s\n' @CONTAINER_ID@
    ;;
  *" inspect "*" @CONTAINER_ID@ "*)
    test ! -e "@CONTAINER_REMOVED@" || exit 1
    config=$(cat "@CONTAINER_CONFIG_PATH@")
    session=$(sed -n 's/.*"apolysis.session_id": "\([^"]*\)".*/\1/p' "$config" | head -n 1)
    uid=$(sed -n 's/.*"apolysis.fixture_uid": "\([^"]*\)".*/\1/p' "$config" | head -n 1)
    owner=$(sed -n 's/.*"apolysis.fixture_owner": "\([^"]*\)".*/\1/p' "$config" | head -n 1)
    printf '{"status":{"id":"@CONTAINER_ID@","labels":{"apolysis.session_id":"%s","apolysis.fixture_uid":"%s","apolysis.fixture_owner":"%s"}},"info":{"pid":1}}\n' "$session" "$uid" "$owner"
    ;;
  *" start @CONTAINER_ID@ "*) exit 64 ;;
  *" stop @CONTAINER_ID@ "*|*" stopp @POD_ID@ "*) exit 0 ;;
  *" rm @CONTAINER_ID@ "*) touch "@CONTAINER_REMOVED@" ;;
  *" rmp @POD_ID@ "*) touch "@POD_REMOVED@" ;;
  *" ps -a -q "*) test -e "@CONTAINER_REMOVED@" || printf '%s\n' @CONTAINER_ID@ ;;
  *" pods -q "*) test -e "@POD_REMOVED@" || printf '%s\n' @POD_ID@ ;;
  *) exit 64 ;;
esac
"#
    .replace("@COMMAND_LOG@", &command_log.to_string_lossy())
    .replace("@POD_CONFIG_PATH@", &pod_config_path.to_string_lossy())
    .replace(
        "@CONTAINER_CONFIG_PATH@",
        &container_config_path.to_string_lossy(),
    )
    .replace("@POD_REMOVED@", &pod_removed.to_string_lossy())
    .replace("@CONTAINER_REMOVED@", &container_removed.to_string_lossy())
    .replace("@POD_ID@", pod_id)
    .replace("@CONTAINER_ID@", container_id);
    write_executable_fixture(&crictl, &script);

    let result = std::panic::catch_unwind(|| {
        create_cri_workload_with_crictl(
            &crictl,
            "/run/containerd/fake.sock",
            None,
            "runc",
            "agent-run-partial-start-cleanup",
        )
    });

    assert!(result.is_err(), "injected start failure must propagate");
    let commands = std::fs::read_to_string(&command_log).expect("read fake crictl command log");
    for cleanup in [
        format!("stop {container_id}"),
        format!("rm {container_id}"),
        format!("stopp {pod_id}"),
        format!("rmp {pod_id}"),
    ] {
        assert!(commands.contains(&cleanup), "missing {cleanup}: {commands}");
    }
    assert!(
        !cri_fixture_root_from_commands(&commands).exists(),
        "start failure cleanup must remove its exact private root"
    );
    let _ = std::fs::remove_dir_all(&root);
}

fn cri_fixture_root_from_commands(commands: &str) -> std::path::PathBuf {
    let pod_config = commands
        .split_whitespace()
        .find(|argument| argument.ends_with("/pod.json"))
        .expect("fake crictl command log contains a pod config path");
    std::path::Path::new(pod_config)
        .parent()
        .expect("pod config has a fixture root")
        .to_path_buf()
}

#[tokio::test]
async fn cri_live_fixture_never_deletes_an_unproven_returned_object_id() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-cri-unproven-cleanup-{}-{id}",
        std::process::id()
    ));
    let crictl = root.join("crictl");
    let command_log = root.join("commands.log");
    let pod_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let script = r#"#!/bin/sh
printf '%s\n' "$*" >> "@COMMAND_LOG@"
case " $* " in
  *" runp "*) printf '%s\n' @POD_ID@ ;;
  *" inspectp "*) printf '{"status":{"id":"@POD_ID@","metadata":{"uid":"attacker"},"labels":{"apolysis.session_id":"attacker","apolysis.fixture_uid":"attacker","apolysis.fixture_owner":"attacker"}}}\n' ;;
  *) exit 64 ;;
esac
"#
    .replace("@COMMAND_LOG@", &command_log.to_string_lossy())
    .replace("@POD_ID@", pod_id);
    write_executable_fixture(&crictl, &script);

    let result = std::panic::catch_unwind(|| {
        create_cri_workload_with_crictl(
            &crictl,
            "/run/containerd/fake.sock",
            None,
            "runc",
            "agent-run-proof-mismatch",
        )
    });

    assert!(
        result.is_err(),
        "mismatched ownership proof must fail closed"
    );
    let commands = std::fs::read_to_string(&command_log).expect("read fake crictl command log");
    assert!(!commands.contains(" stopp "), "{commands}");
    assert!(!commands.contains(" rmp "), "{commands}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cri_fixture_root_replacement_preserves_the_operator_canary() {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let outer = std::env::temp_dir().join(format!(
        "apolysis-cri-root-replacement-{}-{id}",
        std::process::id()
    ));
    std::fs::create_dir(&outer).expect("create root replacement test parent");
    let candidate = outer.join("fixture");
    let parked = outer.join("parked-owned-fixture");
    let proof = try_create_private_cri_fixture_root(&candidate).expect("create owned fixture root");
    assert_eq!(proof.mode, 0o700, "fixture root must be private");
    let original = std::fs::symlink_metadata(&candidate).expect("owned root metadata");
    assert_eq!(
        (original.dev(), original.ino()),
        (proof.device, proof.inode)
    );
    std::fs::rename(&candidate, &parked).expect("park owned fixture root");
    std::fs::create_dir(&candidate).expect("create operator replacement");
    let canary = candidate.join("operator-canary");
    std::fs::write(&canary, b"preserve").expect("write operator canary");

    let error = remove_owned_cri_fixture_root(&proof)
        .expect_err("changed root identity must block fixture cleanup");

    assert!(error.contains("identity changed"), "{error}");
    assert_eq!(
        std::fs::read(&canary).expect("preserved canary"),
        b"preserve"
    );
    let _ = std::fs::remove_dir_all(&outer);
}

#[tokio::test]
async fn cri_live_fixture_strict_cleanup_failure_cannot_pass_the_gate() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let outer = std::env::temp_dir().join(format!(
        "apolysis-cri-strict-cleanup-{}-{id}",
        std::process::id()
    ));
    std::fs::create_dir(&outer).expect("create strict cleanup test parent");
    let crictl = outer.join("crictl");
    let command_log = outer.join("commands.log");
    let pod_removed = outer.join("pod-removed");
    let fixture_root =
        try_create_private_cri_fixture_root(&outer.join("fixture")).expect("create fixture root");
    let container_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let pod_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let session_id = "agent-run-strict-cleanup";
    let fixture_uid = "11111111-1111-4111-8111-111111111111";
    let owner_token = "22222222-2222-4222-8222-222222222222";
    let script = r#"#!/bin/sh
printf '%s\n' "$*" >> "@COMMAND_LOG@"
case " $* " in
  *" inspect "*" @CONTAINER_ID@ "*) printf '{"status":{"id":"@CONTAINER_ID@","labels":{"apolysis.session_id":"@SESSION_ID@","apolysis.fixture_uid":"@FIXTURE_UID@","apolysis.fixture_owner":"@OWNER_TOKEN@"}}}\n' ;;
  *" inspectp "*" @POD_ID@ "*)
    test ! -e "@POD_REMOVED@" || exit 1
    printf '{"status":{"id":"@POD_ID@","metadata":{"uid":"@FIXTURE_UID@"},"labels":{"apolysis.session_id":"@SESSION_ID@","apolysis.fixture_uid":"@FIXTURE_UID@","apolysis.fixture_owner":"@OWNER_TOKEN@"}}}\n'
    ;;
  *" stop @CONTAINER_ID@ "*|*" stopp @POD_ID@ "*) exit 0 ;;
  *" rm @CONTAINER_ID@ "*) exit 64 ;;
  *" rmp @POD_ID@ "*) touch "@POD_REMOVED@" ;;
  *" ps -a -q "*) printf '%s\n' @CONTAINER_ID@ ;;
  *" pods -q "*) test -e "@POD_REMOVED@" || printf '%s\n' @POD_ID@ ;;
  *) exit 64 ;;
esac
"#
    .replace("@COMMAND_LOG@", &command_log.to_string_lossy())
    .replace("@POD_REMOVED@", &pod_removed.to_string_lossy())
    .replace("@CONTAINER_ID@", container_id)
    .replace("@POD_ID@", pod_id)
    .replace("@SESSION_ID@", session_id)
    .replace("@FIXTURE_UID@", fixture_uid)
    .replace("@OWNER_TOKEN@", owner_token);
    write_executable_fixture(&crictl, &script);
    let container_proof = CriObjectProof {
        kind: CriObjectKind::Container,
        id: container_id.to_string(),
        session_id: session_id.to_string(),
        fixture_uid: fixture_uid.to_string(),
        owner_token: owner_token.to_string(),
    };
    let pod_proof = CriObjectProof {
        kind: CriObjectKind::Pod,
        id: pod_id.to_string(),
        session_id: session_id.to_string(),
        fixture_uid: fixture_uid.to_string(),
        owner_token: owner_token.to_string(),
    };
    let cleanup = CriWorkloadCleanup {
        crictl_path: crictl,
        endpoint: "unix:///run/containerd/fake.sock".to_string(),
        image_endpoint: None,
        container_id: container_id.to_string(),
        container_proof,
        pod_proof,
        fixture_root: fixture_root.clone(),
        cleanup_complete: false,
    };

    let error = cleanup
        .cleanup()
        .expect_err("a failed exact rm must fail the live gate");

    assert!(error.contains("CRI rm failed"), "{error}");
    assert!(
        fixture_root.path.exists(),
        "failed cleanup must not report root removal"
    );
    let commands = std::fs::read_to_string(&command_log).expect("read strict cleanup log");
    assert!(
        commands.contains(&format!("rm {container_id}")),
        "{commands}"
    );
    let _ = std::fs::remove_dir_all(&outer);
}

#[tokio::test]
async fn cri_live_fixture_strict_cleanup_confirms_objects_and_root_are_absent() {
    let _fixture_lease = executable_fixture_test_lease().await;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let outer = std::env::temp_dir().join(format!(
        "apolysis-cri-strict-cleanup-success-{}-{id}",
        std::process::id()
    ));
    std::fs::create_dir(&outer).expect("create strict cleanup success parent");
    let crictl = outer.join("crictl");
    let command_log = outer.join("commands.log");
    let pod_removed = outer.join("pod-removed");
    let container_removed = outer.join("container-removed");
    let fixture_root =
        try_create_private_cri_fixture_root(&outer.join("fixture")).expect("create fixture root");
    let container_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let pod_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let session_id = "agent-run-strict-cleanup-success";
    let fixture_uid = "11111111-1111-4111-8111-111111111111";
    let owner_token = "22222222-2222-4222-8222-222222222222";
    let script = r#"#!/bin/sh
printf '%s\n' "$*" >> "@COMMAND_LOG@"
case " $* " in
  *" inspect "*" @CONTAINER_ID@ "*)
    test ! -e "@CONTAINER_REMOVED@" || exit 1
    printf '{"status":{"id":"@CONTAINER_ID@","labels":{"apolysis.session_id":"@SESSION_ID@","apolysis.fixture_uid":"@FIXTURE_UID@","apolysis.fixture_owner":"@OWNER_TOKEN@"}}}\n'
    ;;
  *" inspectp "*" @POD_ID@ "*)
    test ! -e "@POD_REMOVED@" || exit 1
    printf '{"status":{"id":"@POD_ID@","metadata":{"uid":"@FIXTURE_UID@"},"labels":{"apolysis.session_id":"@SESSION_ID@","apolysis.fixture_uid":"@FIXTURE_UID@","apolysis.fixture_owner":"@OWNER_TOKEN@"}}}\n'
    ;;
  *" stop @CONTAINER_ID@ "*|*" stopp @POD_ID@ "*) exit 0 ;;
  *" rm @CONTAINER_ID@ "*) touch "@CONTAINER_REMOVED@" ;;
  *" rmp @POD_ID@ "*) touch "@POD_REMOVED@" ;;
  *" ps -a -q "*) test -e "@CONTAINER_REMOVED@" || printf '%s\n' @CONTAINER_ID@ ;;
  *" pods -q "*) test -e "@POD_REMOVED@" || printf '%s\n' @POD_ID@ ;;
  *) exit 64 ;;
esac
"#
    .replace("@COMMAND_LOG@", &command_log.to_string_lossy())
    .replace("@POD_REMOVED@", &pod_removed.to_string_lossy())
    .replace("@CONTAINER_REMOVED@", &container_removed.to_string_lossy())
    .replace("@CONTAINER_ID@", container_id)
    .replace("@POD_ID@", pod_id)
    .replace("@SESSION_ID@", session_id)
    .replace("@FIXTURE_UID@", fixture_uid)
    .replace("@OWNER_TOKEN@", owner_token);
    write_executable_fixture(&crictl, &script);
    let cleanup = CriWorkloadCleanup {
        crictl_path: crictl,
        endpoint: "unix:///run/containerd/fake.sock".to_string(),
        image_endpoint: None,
        container_id: container_id.to_string(),
        container_proof: CriObjectProof {
            kind: CriObjectKind::Container,
            id: container_id.to_string(),
            session_id: session_id.to_string(),
            fixture_uid: fixture_uid.to_string(),
            owner_token: owner_token.to_string(),
        },
        pod_proof: CriObjectProof {
            kind: CriObjectKind::Pod,
            id: pod_id.to_string(),
            session_id: session_id.to_string(),
            fixture_uid: fixture_uid.to_string(),
            owner_token: owner_token.to_string(),
        },
        fixture_root: fixture_root.clone(),
        cleanup_complete: false,
    };

    cleanup
        .cleanup()
        .expect("strict cleanup must prove exact object and root absence");

    assert!(
        !fixture_root.path.exists(),
        "owned fixture root must be absent"
    );
    let commands = std::fs::read_to_string(&command_log).expect("read strict cleanup log");
    for command in [" stop ", " rm ", " stopp ", " rmp "] {
        assert!(commands.contains(command), "missing {command}: {commands}");
    }
    let _ = std::fs::remove_dir_all(&outer);
}

fn live_crictl_path() -> std::path::PathBuf {
    let configured = std::env::var_os("APOLYSIS_CRICTL")
        .expect("live CRI gates require an absolute owner-controlled APOLYSIS_CRICTL");
    let path = std::path::PathBuf::from(configured);
    assert!(path.is_absolute(), "APOLYSIS_CRICTL must be absolute");
    let mut current = std::path::PathBuf::from("/");
    let components: Vec<_> = path.components().collect();
    assert!(
        components.iter().all(|component| matches!(
            component,
            std::path::Component::RootDir | std::path::Component::Normal(_)
        )),
        "APOLYSIS_CRICTL must not contain traversal components"
    );
    for (index, component) in components.iter().enumerate().skip(1) {
        current.push(component.as_os_str());
        let metadata =
            std::fs::symlink_metadata(&current).expect("APOLYSIS_CRICTL path component metadata");
        assert!(
            !metadata.file_type().is_symlink(),
            "APOLYSIS_CRICTL must not contain symlinks"
        );
        if index + 1 < components.len() {
            assert!(
                metadata.is_dir(),
                "APOLYSIS_CRICTL ancestor must be a directory"
            );
        } else {
            // SAFETY: geteuid has no preconditions and does not dereference pointers.
            let effective_uid = unsafe { libc::geteuid() };
            let mode = metadata.mode();
            assert!(metadata.is_file(), "APOLYSIS_CRICTL must be a regular file");
            assert_eq!(metadata.nlink(), 1, "APOLYSIS_CRICTL must have one link");
            assert_eq!(metadata.uid(), effective_uid, "APOLYSIS_CRICTL owner");
            assert_ne!(mode & 0o111, 0, "APOLYSIS_CRICTL must be executable");
            assert_eq!(
                mode & 0o022,
                0,
                "APOLYSIS_CRICTL must not be group/world writable"
            );
            assert_eq!(
                mode & 0o7000,
                0,
                "APOLYSIS_CRICTL must not use special mode bits"
            );
        }
    }
    path
}

fn create_cri_workload_with_crictl(
    crictl_path: impl AsRef<std::path::Path>,
    socket_path: &str,
    image_endpoint: Option<&str>,
    runtime: &str,
    session_id: &str,
) -> CriWorkloadCleanup {
    create_cri_workload_with_optional_proof(
        None,
        crictl_path.as_ref(),
        socket_path,
        image_endpoint,
        runtime,
        session_id,
    )
}

fn create_private_cri_workload_with_crictl(
    qualification_root: &Path,
    crictl_path: &Path,
    socket_path: &str,
    image_endpoint: Option<&str>,
    runtime: &str,
    session_id: &str,
) -> CriWorkloadCleanup {
    create_cri_workload_with_optional_proof(
        Some(qualification_root),
        crictl_path,
        socket_path,
        image_endpoint,
        runtime,
        session_id,
    )
}

fn create_cri_workload_with_optional_proof(
    qualification_root: Option<&Path>,
    crictl_path: &Path,
    socket_path: &str,
    image_endpoint: Option<&str>,
    runtime: &str,
    session_id: &str,
) -> CriWorkloadCleanup {
    let endpoint = format!("unix://{socket_path}");
    let fixture_root = create_private_cri_fixture_root();
    let root = &fixture_root.path;
    let pod_path = root.join("pod.json");
    let container_path = root.join("container.json");
    let fixture_uid = kernel_random_uuid();
    let owner_token = kernel_random_uuid();
    let ownership = CriOwnershipClaim {
        session_id,
        fixture_uid: &fixture_uid,
        owner_token: &owner_token,
    };
    let pod_linux = cri_pod_linux_config(socket_path);
    let readonly_rootfs = !(socket_path.contains("/k3s/") && runtime == "runsc");
    write_private_cri_fixture_file(
        &fixture_root,
        "pod.json",
        &pod_path,
        &serde_json::to_vec_pretty(&json!({
            "metadata": {
                "name": format!("apolysis-{runtime}"),
                "namespace": "apolysis-observation",
                "uid": fixture_uid,
                "attempt": 0
            },
            "labels": {
                "apolysis.session_id": session_id,
                "apolysis.fixture_uid": fixture_uid,
                "apolysis.fixture_owner": owner_token
            },
            "log_directory": root.to_string_lossy(),
            "linux": pod_linux
        }))
        .expect("serialize CRI pod config"),
    )
    .expect("write CRI pod config");
    write_private_cri_fixture_file(
        &fixture_root,
        "container.json",
        &container_path,
        &serde_json::to_vec_pretty(&json!({
            "metadata": {
                "name": "workload",
                "attempt": 0
            },
            "image": {
                "image": "docker.io/library/alpine:3.20"
            },
            "command": ["sh", "-c", "sleep 60"],
            "labels": {
                "apolysis.session_id": session_id,
                "apolysis.fixture_uid": fixture_uid,
                "apolysis.fixture_owner": owner_token
            },
            "log_path": "workload.log",
            "linux": {
                "resources": {
                    "cpu_period": 100000,
                    "cpu_quota": 50000,
                    "memory_limit_in_bytes": 67108864
                },
                "security_context": {
                    "readonly_rootfs": readonly_rootfs,
                    "no_new_privs": true
                }
            }
        }))
        .expect("serialize CRI container config"),
    )
    .expect("write CRI container config");
    let mut partial_cleanup = PartialCriWorkloadCleanup {
        crictl_path: crictl_path.to_path_buf(),
        endpoint: endpoint.clone(),
        image_endpoint: image_endpoint.map(ToOwned::to_owned),
        container_proof: None,
        pod_proof: None,
        fixture_root,
        armed: true,
    };
    let pod = run_crictl_with_command(
        crictl_path,
        &endpoint,
        image_endpoint,
        &[
            "runp",
            "--runtime",
            runtime,
            pod_path.to_str().expect("pod path UTF-8"),
        ],
    )
    .unwrap_or_else(|error| panic!("run CRI pod with runtime {runtime}: {error}"));
    if let Some(qualification_root) = qualification_root {
        append_private_container_id_proof(qualification_root, &pod)
            .unwrap_or_else(|error| panic!("persist returned private CRI pod full ID: {error}"));
    }
    let pod_proof = prove_cri_object(
        crictl_path,
        &endpoint,
        image_endpoint,
        CriObjectKind::Pod,
        &pod,
        &ownership,
    )
    .unwrap_or_else(|error| panic!("prove CRI pod ownership: {error}"));
    partial_cleanup.pod_proof = Some(pod_proof);
    let container = run_crictl_with_command(
        crictl_path,
        &endpoint,
        image_endpoint,
        &[
            "create",
            "--no-pull",
            &pod,
            container_path.to_str().expect("container path UTF-8"),
            pod_path.to_str().expect("pod path UTF-8"),
        ],
    )
    .unwrap_or_else(|error| panic!("create CRI container with runtime {runtime}: {error}"));
    if let Some(qualification_root) = qualification_root {
        append_private_container_id_proof(qualification_root, &container).unwrap_or_else(|error| {
            panic!("persist returned private CRI container full ID: {error}")
        });
    }
    let container_proof = prove_cri_object(
        crictl_path,
        &endpoint,
        image_endpoint,
        CriObjectKind::Container,
        &container,
        &ownership,
    )
    .unwrap_or_else(|error| panic!("prove CRI container ownership: {error}"));
    partial_cleanup.container_proof = Some(container_proof);
    run_crictl_with_command(
        crictl_path,
        &endpoint,
        image_endpoint,
        &["start", &container],
    )
    .unwrap_or_else(|error| panic!("start CRI container with runtime {runtime}: {error}"));
    wait_for_cri_container_observable(crictl_path, &endpoint, image_endpoint, &container);
    partial_cleanup.into_full()
}

fn write_private_cri_fixture_file(
    root: &CriFixtureRootProof,
    expected_name: &str,
    path: &std::path::Path,
    contents: &[u8],
) -> Result<(), String> {
    if path != root.path.join(expected_name) || !cri_fixture_root_matches(root) {
        return Err("CRI fixture root identity changed before config publication".to_string());
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| "failed to create a private CRI fixture config".to_string())?;
    file.write_all(contents)
        .map_err(|_| "failed to write a private CRI fixture config".to_string())?;
    file.sync_all()
        .map_err(|_| "failed to sync a private CRI fixture config".to_string())?;
    if !cri_fixture_root_matches(root) {
        return Err("CRI fixture root identity changed after config publication".to_string());
    }
    Ok(())
}

fn cri_pod_linux_config(socket_path: &str) -> serde_json::Value {
    if socket_path.contains("/k3s/") {
        let mut pod_linux = json!({
            "resources": {
                "cpu_period": 100000,
                "cpu_quota": 50000,
                "memory_limit_in_bytes": 67108864
            }
        });
        pod_linux.as_object_mut().expect("pod linux object").insert(
            "cgroup_parent".to_string(),
            serde_json::Value::String("system.slice".to_string()),
        );
        pod_linux
    } else {
        json!({
            "security_context": {
            // CRI v1 NamespaceMode.NODE is enum value 2. crictl config files are decoded into
            // the Go protobuf struct with encoding/json, which requires the numeric enum value.
                "namespace_options": {"network": 2}
            }
        })
    }
}

fn run_crictl_with_command(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    command_args: &[&str],
) -> Result<String, String> {
    run_crictl_with_command_deadline(
        crictl_path,
        endpoint,
        image_endpoint,
        command_args,
        LIVE_CRICTL_COMMAND_TIMEOUT,
    )
}

fn canonical_private_cri_failure(stderr: &[u8]) -> String {
    let detail = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    let grpc_code = [
        "Canceled",
        "Unknown",
        "InvalidArgument",
        "DeadlineExceeded",
        "NotFound",
        "AlreadyExists",
        "PermissionDenied",
        "ResourceExhausted",
        "FailedPrecondition",
        "Aborted",
        "OutOfRange",
        "Unimplemented",
        "Internal",
        "Unavailable",
        "DataLoss",
        "Unauthenticated",
    ]
    .into_iter()
    .find(|code| detail.contains(&format!("code = {}", code.to_ascii_lowercase())))
    .unwrap_or("unclassified");
    let is_cgroup = ["cgroup", "cpu quota", "memory limit"]
        .into_iter()
        .any(|needle| detail.contains(needle));
    let class = if is_cgroup {
        "cgroup"
    } else if [
        "sandbox image",
        "pull image",
        "image not found",
        "image pull",
    ]
    .into_iter()
    .any(|needle| detail.contains(needle))
    {
        "image"
    } else if ["cni", "network plugin", "network namespace"]
        .into_iter()
        .any(|needle| detail.contains(needle))
    {
        "network"
    } else if ["namespace", "setns", "unshare"]
        .into_iter()
        .any(|needle| detail.contains(needle))
    {
        "namespace"
    } else if ["snapshot", "overlay", "mount", "rootfs"]
        .into_iter()
        .any(|needle| detail.contains(needle))
    {
        "storage"
    } else if ["runc", "shim", "oci runtime", "runtime task"]
        .into_iter()
        .any(|needle| detail.contains(needle))
    {
        "runtime"
    } else if ["configuration", "config", "invalid argument"]
        .into_iter()
        .any(|needle| detail.contains(needle))
    {
        "config"
    } else {
        "unknown"
    };
    if is_cgroup {
        let cgroup_detail = if [
            "read-only file system",
            "permission denied",
            "operation not permitted",
        ]
        .into_iter()
        .any(|needle| detail.contains(needle))
        {
            "permission"
        } else if ["mountpoint", "cgroup mount"]
            .into_iter()
            .any(|needle| detail.contains(needle))
        {
            "mountpoint"
        } else if detail.contains("cgroup parent") {
            "parent"
        } else if ["controller", "subtree_control", "subtree control"]
            .into_iter()
            .any(|needle| detail.contains(needle))
        {
            "controller"
        } else if ["unified", "cgroup v2", "cgroup2", "cgroup mode"]
            .into_iter()
            .any(|needle| detail.contains(needle))
        {
            "mode"
        } else if detail.contains("systemd") {
            "systemd"
        } else if ["no such file", "not found", "does not exist", "missing"]
            .into_iter()
            .any(|needle| detail.contains(needle))
        {
            "missing"
        } else {
            "unknown"
        };
        if cgroup_detail == "controller" {
            let controller = if [
                "cpu controller",
                "controller cpu",
                "controller \"cpu\"",
                "controller 'cpu'",
                "controllers [cpu",
                "cpu.max",
                "cpu.weight",
                "cpu.stat",
            ]
            .into_iter()
            .any(|needle| detail.contains(needle))
            {
                "cpu"
            } else if [
                "io controller",
                "controller io",
                "controller \"io\"",
                "controller 'io'",
                "io.max",
                "io.weight",
                "io.stat",
            ]
            .into_iter()
            .any(|needle| detail.contains(needle))
            {
                "io"
            } else if [
                "memory controller",
                "controller memory",
                "controller \"memory\"",
                "controller 'memory'",
                "memory.max",
                "memory.high",
                "memory.current",
            ]
            .into_iter()
            .any(|needle| detail.contains(needle))
            {
                "memory"
            } else if [
                "pids controller",
                "controller pids",
                "controller \"pids\"",
                "controller 'pids'",
                "pids.max",
                "pids.current",
            ]
            .into_iter()
            .any(|needle| detail.contains(needle))
            {
                "pids"
            } else if [
                "cpuset controller",
                "controller cpuset",
                "controller \"cpuset\"",
                "controller 'cpuset'",
                "cpuset.cpus",
                "cpuset.mems",
            ]
            .into_iter()
            .any(|needle| detail.contains(needle))
            {
                "cpuset"
            } else if [
                "devices controller",
                "controller devices",
                "controller \"devices\"",
                "controller 'devices'",
                "devices.allow",
                "devices.deny",
            ]
            .into_iter()
            .any(|needle| detail.contains(needle))
            {
                "devices"
            } else {
                "unknown"
            };
            format!(
                "CRI live command failed (grpc={grpc_code}, class=cgroup, detail=controller, controller={controller})"
            )
        } else {
            format!(
                "CRI live command failed (grpc={grpc_code}, class=cgroup, detail={cgroup_detail})"
            )
        }
    } else {
        format!("CRI live command failed (grpc={grpc_code}, class={class})")
    }
}

fn run_crictl_with_command_deadline(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    command_args: &[&str],
    hard_deadline: Duration,
) -> Result<String, String> {
    let mut command = Command::new(crictl_path);
    command
        .arg("--config")
        .arg("/dev/null")
        .arg("--runtime-endpoint")
        .arg(endpoint)
        .arg("--timeout")
        .arg("10s");
    if let Some(image_endpoint) = image_endpoint {
        command.arg("--image-endpoint").arg(image_endpoint);
    }
    command
        .args(command_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: setpgid is async-signal-safe and creates an isolated process group so timeout
    // cleanup can terminate the command and any children before waiting for the group leader.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = SupervisedLiveCommand::new(
        command
            .spawn()
            .map_err(|_| "failed to start CRI live command".to_string())?,
    );
    let mut stdout = child
        .child
        .stdout
        .take()
        .ok_or_else(|| "CRI live command supervision failed".to_string())?;
    let mut stderr = child
        .child
        .stderr
        .take()
        .ok_or_else(|| "CRI live command supervision failed".to_string())?;
    set_nonblocking(stdout.as_raw_fd())?;
    set_nonblocking(stderr.as_raw_fd())?;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut status = None;
    let deadline = Instant::now()
        .checked_add(hard_deadline)
        .ok_or_else(|| "CRI live command deadline is invalid".to_string())?;

    loop {
        if stdout_open {
            match read_live_command_pipe(
                &mut stdout,
                &mut stdout_bytes,
                MAX_LIVE_CRICTL_OUTPUT_BYTES,
            )? {
                LiveCommandPipeState::Open => {}
                LiveCommandPipeState::Closed => stdout_open = false,
                LiveCommandPipeState::Oversized => {
                    child.terminate_and_reap()?;
                    return Err("CRI live command stdout exceeded byte limit".to_string());
                }
            }
        }
        if stderr_open {
            match read_live_command_pipe(
                &mut stderr,
                &mut stderr_bytes,
                MAX_LIVE_CRICTL_OUTPUT_BYTES,
            )? {
                LiveCommandPipeState::Open => {}
                LiveCommandPipeState::Closed => stderr_open = false,
                LiveCommandPipeState::Oversized => {
                    child.terminate_and_reap()?;
                    return Err("CRI live command stderr exceeded byte limit".to_string());
                }
            }
        }
        if status.is_none() {
            status = child.try_wait()?;
        }
        if status.is_some() && !stdout_open && !stderr_open {
            break;
        }
        if Instant::now() >= deadline {
            child.terminate_and_reap()?;
            return Err("CRI live command timed out".to_string());
        }
        std::thread::sleep(Duration::from_millis(5));
    }

    let status = status.ok_or_else(|| "CRI live command supervision failed".to_string())?;
    if !status.success() {
        if std::env::var("APOLYSIS_PRIVATE_CONTAINERD_DIAGNOSTIC")
            .ok()
            .as_deref()
            == Some("1")
        {
            return Err(canonical_private_cri_failure(&stderr_bytes));
        }
        return Err("CRI live command failed".to_string());
    }
    Ok(String::from_utf8_lossy(&stdout_bytes).trim().to_string())
}

fn set_nonblocking(descriptor: std::os::fd::RawFd) -> Result<(), String> {
    // SAFETY: descriptor belongs to an open child pipe and fcntl does not outlive this call.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags == -1 {
        return Err("CRI live command supervision failed".to_string());
    }
    // SAFETY: descriptor is still open and the new flags preserve all existing status flags.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err("CRI live command supervision failed".to_string());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveCommandPipeState {
    Open,
    Closed,
    Oversized,
}

fn read_live_command_pipe(
    pipe: &mut impl Read,
    output: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<LiveCommandPipeState, String> {
    let mut buffer = [0_u8; 8192];
    match pipe.read(&mut buffer) {
        Ok(0) => Ok(LiveCommandPipeState::Closed),
        Ok(count) => {
            if count > max_bytes.saturating_sub(output.len()) {
                return Ok(LiveCommandPipeState::Oversized);
            }
            output.extend_from_slice(&buffer[..count]);
            Ok(LiveCommandPipeState::Open)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Ok(LiveCommandPipeState::Open)
        }
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
            Ok(LiveCommandPipeState::Open)
        }
        Err(_) => Err("CRI live command supervision failed".to_string()),
    }
}

struct SupervisedLiveCommand {
    child: Child,
    reaped: bool,
}

impl SupervisedLiveCommand {
    const fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
        }
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, String> {
        let status = self
            .child
            .try_wait()
            .map_err(|_| "CRI live command supervision failed".to_string())?;
        if status.is_some() {
            self.reaped = true;
        }
        Ok(status)
    }

    fn terminate_and_reap(&mut self) -> Result<ExitStatus, String> {
        terminate_live_process_group(&mut self.child)?;
        let status = self
            .child
            .wait()
            .map_err(|_| "CRI live command cleanup failed".to_string())?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for SupervisedLiveCommand {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = terminate_live_process_group(&mut self.child);
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
}

fn terminate_live_process_group(child: &mut Child) -> Result<(), String> {
    let process_group =
        i32::try_from(child.id()).map_err(|_| "CRI live command cleanup failed".to_string())?;
    // SAFETY: the child was placed in a process group whose id equals its pid. SIGKILL is used
    // only for the owned test command group after failure or its hard deadline expires.
    let killed = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if killed == -1 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err("CRI live command cleanup failed".to_string());
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CriMutationPreflight {
    Ready,
    SkipNetworkUnavailable,
}

fn standalone_cri_mutation_preflight(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
) -> Result<CriMutationPreflight, String> {
    cri_mutation_preflight(crictl_path, endpoint, image_endpoint, false)
}

fn private_cri_node_network_mutation_preflight(
    crictl_path: &std::path::Path,
    endpoint: &str,
) -> Result<CriMutationPreflight, String> {
    cri_mutation_preflight(crictl_path, endpoint, Some(endpoint), true)
}

fn cri_mutation_preflight(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    allow_node_network_without_cni: bool,
) -> Result<CriMutationPreflight, String> {
    let output = run_crictl_with_command(
        crictl_path,
        endpoint,
        image_endpoint,
        &["info", "-o", "json"],
    )?;
    let info: serde_json::Value = serde_json::from_str(&output)
        .map_err(|_| "standalone CRI info returned invalid JSON".to_string())?;
    let conditions = info
        .pointer("/status/conditions")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "standalone CRI info omitted status.conditions".to_string())?;
    let condition = |condition_type: &str| {
        conditions
            .iter()
            .find(|condition| {
                condition.get("type").and_then(serde_json::Value::as_str) == Some(condition_type)
            })
            .and_then(|condition| condition.get("status"))
            .and_then(serde_json::Value::as_bool)
    };
    if condition("RuntimeReady") != Some(true) {
        return Err("standalone CRI RuntimeReady must be true before mutation".to_string());
    }
    match condition("NetworkReady") {
        Some(true) => Ok(CriMutationPreflight::Ready),
        Some(false) if allow_node_network_without_cni => Ok(CriMutationPreflight::Ready),
        Some(false) => Ok(CriMutationPreflight::SkipNetworkUnavailable),
        None => Err("standalone CRI info omitted a boolean NetworkReady condition".to_string()),
    }
}

fn standalone_cri_network_ready_or_skip(
    crictl_path: &std::path::Path,
    socket_path: &str,
    image_endpoint: Option<&str>,
) -> bool {
    let endpoint = format!("unix://{socket_path}");
    match standalone_cri_mutation_preflight(crictl_path, &endpoint, image_endpoint)
        .expect("standalone CRI mutation preflight")
    {
        CriMutationPreflight::Ready => true,
        CriMutationPreflight::SkipNetworkUnavailable => {
            eprintln!("skipped: standalone CRI NetworkReady=false; no pod mutation attempted");
            false
        }
    }
}

fn wait_for_cri_container_observable(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    container_id: &str,
) {
    for _ in 0..100 {
        if let Ok(output) = run_crictl_with_command(
            crictl_path,
            endpoint,
            image_endpoint,
            &["inspect", "-o", "json", container_id],
        ) {
            let pid = serde_json::from_str::<serde_json::Value>(&output)
                .ok()
                .and_then(|value| {
                    value
                        .get("info")
                        .and_then(|info| info.get("pid"))
                        .and_then(serde_json::Value::as_u64)
                })
                .filter(|pid| *pid > 0);
            if let Some(pid) = pid {
                if std::fs::read_to_string(format!("/proc/{pid}/cgroup")).is_ok() {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("CRI container {container_id} did not become observable through /proc");
}

fn cleanup_cri_workloads_for_session(
    crictl_path: &std::path::Path,
    socket_path: &str,
    image_endpoint: Option<&str>,
    session_id: &str,
) {
    let endpoint = format!("unix://{socket_path}");
    let label = format!("apolysis.session_id={session_id}");
    for _ in 0..30 {
        let containers = run_crictl_with_command(
            crictl_path,
            &endpoint,
            image_endpoint,
            &["ps", "-a", "-q", "--label", &label],
        )
        .unwrap_or_default();
        let pods = run_crictl_with_command(
            crictl_path,
            &endpoint,
            image_endpoint,
            &["pods", "-q", "--label", &label],
        )
        .unwrap_or_default();
        let container_ids: Vec<&str> = containers
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        let pod_ids: Vec<&str> = pods
            .lines()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .collect();
        if container_ids.is_empty() && pod_ids.is_empty() {
            return;
        }
        for container_id in container_ids {
            let _ = run_crictl_with_command(
                crictl_path,
                &endpoint,
                image_endpoint,
                &["stop", container_id],
            );
            let _ = run_crictl_with_command(
                crictl_path,
                &endpoint,
                image_endpoint,
                &["rm", container_id],
            );
        }
        for pod_id in pod_ids {
            let _ =
                run_crictl_with_command(crictl_path, &endpoint, image_endpoint, &["stopp", pod_id]);
            let _ =
                run_crictl_with_command(crictl_path, &endpoint, image_endpoint, &["rmp", pod_id]);
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("CRI workloads for session {session_id} were not removed");
}

fn create_host_chroot_crictl_wrapper(name: &str) -> TempScript {
    let path = std::env::temp_dir().join(format!(
        "apolysis-{name}-crictl-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(
        &path,
        r#"#!/usr/bin/env bash
set -euo pipefail
exec docker run --rm --privileged --pid=host --cgroupns=host --network=host -v /:/host alpine:3.20 chroot /host /usr/local/bin/crictl "$@"
"#,
    )
    .expect("write crictl wrapper");
    let mut permissions = std::fs::metadata(&path)
        .expect("crictl wrapper metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&path, permissions).expect("chmod crictl wrapper");
    TempScript { path }
}

fn wait_for_cri_runtime(
    crictl_path: &std::path::Path,
    runtime_socket: &str,
    image_endpoint: Option<&str>,
    timeout: Duration,
) {
    let endpoint = format!("unix://{runtime_socket}");
    for _ in 0..timeout.as_secs().max(1) {
        if run_crictl_with_command(crictl_path, &endpoint, image_endpoint, &["info"]).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("CRI runtime {runtime_socket} did not become responsive");
}

fn wait_for_cri_runtime_unavailable(
    crictl_path: &std::path::Path,
    runtime_socket: &str,
    image_endpoint: Option<&str>,
    timeout: Duration,
) -> bool {
    let endpoint = format!("unix://{runtime_socket}");
    for _ in 0..timeout.as_secs().max(1) {
        if run_crictl_with_command(crictl_path, &endpoint, image_endpoint, &["info"]).is_err() {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

fn terminate_k3s_processes_for_systemd_restart() -> u32 {
    let main_pid = systemd_unit_main_pid("k3s.service");
    let mut pids = vec![main_pid.to_string()];
    pids.extend(
        k3s_containerd_child_pids(main_pid)
            .into_iter()
            .map(|pid| pid.to_string()),
    );
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--privileged",
            "--pid=host",
            "--cgroupns=host",
            "--network=host",
            "-v",
            "/:/host",
            "alpine:3.20",
            "chroot",
            "/host",
            "/bin/kill",
            "-TERM",
        ])
        .args(&pids)
        .output()
        .expect("host-root kill k3s processes");
    assert!(
        output.status.success(),
        "host-root kill k3s processes failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    main_pid
}

fn k3s_containerd_child_pids(main_pid: u32) -> Vec<u32> {
    let output = Command::new("ps")
        .args(["-eo", "pid=,ppid=,comm="])
        .output()
        .expect("list processes");
    assert!(
        output.status.success(),
        "ps failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pids: Vec<u32> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse::<u32>().ok()?;
            let ppid = fields.next()?.parse::<u32>().ok()?;
            let comm = fields.next()?;
            (ppid == main_pid && comm == "containerd").then_some(pid)
        })
        .collect();
    assert!(
        !pids.is_empty(),
        "k3s main process {main_pid} did not have a containerd child"
    );
    pids
}

struct SystemdUnitRestoreGuard {
    units: Vec<(&'static str, bool)>,
}

impl SystemdUnitRestoreGuard {
    fn capture<const N: usize>(units: [&'static str; N]) -> Self {
        let units = units
            .into_iter()
            .filter(|unit| systemd_unit_exists(unit))
            .map(|unit| (unit, systemd_unit_active(unit)))
            .collect();
        Self { units }
    }
}

impl Drop for SystemdUnitRestoreGuard {
    fn drop(&mut self) {
        for (unit, was_active) in &self.units {
            if systemd_unit_active(unit) == *was_active {
                continue;
            }
            let action = if *was_active { "start" } else { "stop" };
            let _ = Command::new("timeout")
                .args(["180s", "systemctl", action, *unit])
                .status();
        }
    }
}

fn stop_docker_systemd_units() {
    if systemd_unit_exists("docker.socket") {
        stop_systemd_unit("docker.socket");
    }
    stop_systemd_unit("docker.service");
}

fn start_docker_systemd_units() {
    if systemd_unit_exists("docker.socket") {
        start_systemd_unit("docker.socket");
    }
    start_systemd_unit("docker.service");
    wait_for_systemd_service_active("docker.service", Duration::from_secs(90));
}

fn stop_systemd_unit(unit: &str) {
    run_systemd_unit_action(unit, "stop");
    for _ in 0..30 {
        if !systemd_unit_active(unit) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("{unit} did not stop");
}

fn start_systemd_unit(unit: &str) {
    run_systemd_unit_action(unit, "start");
}

fn run_systemd_unit_action(target_unit: &str, action: &str) {
    let transient_unit = format!(
        "apolysis-live-{action}-{}-{}",
        target_unit.replace('.', "-"),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let command = format!("systemctl {action} {target_unit}");
    let output = Command::new("systemd-run")
        .args([
            "--unit",
            &transient_unit,
            "--collect",
            "--wait",
            "/bin/bash",
            "-lc",
        ])
        .arg(&command)
        .output()
        .unwrap_or_else(|error| panic!("systemd-run {action}: {error}"));
    if output.status.success() {
        return;
    }
    let fallback = Command::new("timeout")
        .args(["180s", "systemctl", action, target_unit])
        .output()
        .unwrap_or_else(|error| panic!("systemctl {action}: {error}"));
    assert!(
        fallback.status.success(),
        "systemd-run {action} failed: {}{}\ndirect systemctl {action} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&fallback.stdout),
        String::from_utf8_lossy(&fallback.stderr)
    );
}

fn wait_for_systemd_service_active(service: &str, timeout: Duration) {
    for _ in 0..timeout.as_secs().max(1) {
        if systemd_unit_active(service) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let status = Command::new("systemctl")
        .args(["--no-pager", "--full", "status", service])
        .output()
        .expect("systemctl status");
    panic!(
        "{service} did not become active:\n{}{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
}

fn wait_for_systemd_service_main_pid_change(service: &str, previous_pid: u32, timeout: Duration) {
    for _ in 0..timeout.as_secs().max(1) {
        if systemd_unit_active(service) {
            let current_pid = systemd_unit_main_pid(service);
            if current_pid != 0 && current_pid != previous_pid {
                return;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let status = Command::new("systemctl")
        .args(["--no-pager", "--full", "status", service])
        .output()
        .expect("systemctl status");
    panic!(
        "{service} did not restart away from main PID {previous_pid}:\n{}{}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
}

fn systemd_unit_main_pid(service: &str) -> u32 {
    let output = Command::new("systemctl")
        .args(["show", "--property=MainPID", "--value", service])
        .output()
        .expect("systemctl show MainPID");
    assert!(
        output.status.success(),
        "systemctl show MainPID failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let pid = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .expect("parse MainPID");
    assert!(pid > 0, "{service} has no active MainPID");
    pid
}

fn systemd_unit_exists(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["show", "--property=LoadState", "--value", unit])
        .output()
        .map(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() != "not-found"
        })
        .unwrap_or(false)
}

fn systemd_unit_active(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn wait_for_docker_engine(timeout: Duration) {
    for _ in 0..timeout.as_secs().max(1) {
        if Command::new("docker")
            .arg("info")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("Docker Engine did not become responsive");
}

fn wait_for_docker_engine_unavailable(timeout: Duration) -> bool {
    for _ in 0..timeout.as_secs().max(1) {
        let responsive = Command::new("docker")
            .arg("info")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false);
        if !responsive {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

fn create_kubernetes_pod(
    kubectl: &str,
    namespace: &str,
    pod_name: &str,
    session_id: &str,
    runtime_class: Option<&str>,
    runtime_handler: Option<&str>,
) -> KubernetesNamespaceCleanup {
    let owner_token = random_kubernetes_value("owner");
    let root = std::env::temp_dir().join(format!(
        "apolysis-k8s-live-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create Kubernetes manifest directory");
    let manifest = root.join("pod.yaml");
    let runtime_class_object = match (runtime_class, runtime_handler) {
        (Some(runtime_class), Some(runtime_handler)) => format!(
            r#"apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: {runtime_class}
  annotations:
    apolysis.dev/live-test-owner: {owner_token}
handler: {runtime_handler}
---
"#
        ),
        _ => String::new(),
    };
    let runtime_class_line = runtime_class
        .map(|runtime_class| format!("  runtimeClassName: {runtime_class}\n"))
        .unwrap_or_default();
    let readonly_rootfs = runtime_handler != Some("runsc");
    std::fs::write(
        &manifest,
        format!(
            r#"{runtime_class_object}apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
  annotations:
    apolysis.dev/live-test-owner: {owner_token}
---
apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
  namespace: {namespace}
  labels:
    apolysis.session_id: {session_id}
    agent-sandbox.sigs.k8s.io/sandbox: {pod_name}-sandbox
  annotations:
    apolysis.dev/session-id: {session_id}
    apolysis.dev/live-test-owner: {owner_token}
spec:
  restartPolicy: Never
  serviceAccountName: default
  automountServiceAccountToken: false
{runtime_class_line}  tolerations:
    - operator: Exists
  containers:
    - name: workload
      image: docker.io/library/alpine:3.20
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "sleep 60"]
      resources:
        requests:
          cpu: 10m
          memory: 16Mi
        limits:
          cpu: 500m
          memory: 64Mi
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: {readonly_rootfs}
"#
        ),
    )
    .expect("write Kubernetes manifest");
    let output = Command::new(kubectl)
        .args([
            "create",
            "-f",
            manifest.to_str().expect("manifest path UTF-8"),
        ])
        .output()
        .expect("kubectl create");
    let _ = std::fs::remove_dir_all(&root);
    let mut objects = Vec::new();
    if let Some(namespace_proof) = kubernetes_object_proof(
        kubectl,
        "namespace",
        "/api/v1/namespaces",
        namespace,
        &owner_token,
    ) {
        objects.push(namespace_proof);
    }
    if let Some(runtime_class) = runtime_class {
        if let Some(runtime_class_proof) = kubernetes_object_proof(
            kubectl,
            "runtimeclass",
            "/apis/node.k8s.io/v1/runtimeclasses",
            runtime_class,
            &owner_token,
        ) {
            objects.push(runtime_class_proof);
        }
    }
    let cleanup = KubernetesNamespaceCleanup {
        kubectl: kubectl.to_string(),
        objects,
    };
    assert!(
        output.status.success(),
        "kubectl create failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        cleanup
            .objects
            .iter()
            .any(|object| object.resource == "namespace"),
        "created namespace lacks exact owner/UID proof"
    );
    if runtime_class.is_some() {
        assert!(
            cleanup
                .objects
                .iter()
                .any(|object| object.resource == "runtimeclass"),
            "created RuntimeClass lacks exact owner/UID proof"
        );
    }
    cleanup
}

fn create_kubernetes_pod_in_owned_namespace(
    cleanup: &KubernetesNamespaceCleanup,
    pod_name: &str,
    session_id: &str,
) {
    let namespace = cleanup
        .objects
        .iter()
        .find(|object| object.resource == "namespace")
        .expect("owned Kubernetes namespace proof");
    let root = std::env::temp_dir().join(format!(
        "apolysis-k8s-live-pod-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).expect("create Kubernetes pod manifest directory");
    let manifest = root.join("pod.yaml");
    std::fs::write(
        &manifest,
        format!(
            r#"apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
  namespace: {namespace}
  labels:
    apolysis.session_id: {session_id}
  annotations:
    apolysis.dev/session-id: {session_id}
    apolysis.dev/live-test-owner: {owner}
spec:
  restartPolicy: Never
  automountServiceAccountToken: false
  containers:
    - name: workload
      image: docker.io/library/alpine:3.20
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "sleep 60"]
"#,
            namespace = namespace.name,
            owner = namespace.owner_token,
        ),
    )
    .expect("write additional Kubernetes pod manifest");
    let output = Command::new(&cleanup.kubectl)
        .args([
            "create",
            "-f",
            manifest.to_str().expect("manifest path UTF-8"),
        ])
        .output()
        .expect("kubectl create additional pod");
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        output.status.success(),
        "kubectl create additional pod failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn wait_for_kubernetes_container_id(kubectl: &str, namespace: &str, pod_name: &str) {
    for _ in 0..90 {
        let output = Command::new(kubectl)
            .args(["get", "pod", pod_name, "-n", namespace, "-o", "json"])
            .output()
            .expect("kubectl get pod");
        if output.status.success() {
            let pod: serde_json::Value =
                serde_json::from_slice(&output.stdout).expect("Kubernetes Pod JSON");
            let running = pod
                .get("status")
                .and_then(|status| status.get("phase"))
                .and_then(serde_json::Value::as_str)
                == Some("Running");
            let has_container_id = pod
                .get("status")
                .and_then(|status| status.get("containerStatuses"))
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|status| {
                    status
                        .get("containerID")
                        .and_then(serde_json::Value::as_str)
                        .map(|id| !id.trim().is_empty())
                        .unwrap_or(false)
                });
            if running && has_container_id {
                return;
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("Kubernetes Pod {namespace}/{pod_name} did not reach Running with a containerID");
}

fn wait_for_kubernetes_api(kubectl: &str, timeout: Duration) {
    for _ in 0..timeout.as_secs().max(1) {
        let output = Command::new(kubectl)
            .args(["get", "--raw=/readyz"])
            .output()
            .expect("kubectl readyz");
        if output.status.success() && String::from_utf8_lossy(&output.stdout).contains("ok") {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    panic!("Kubernetes API did not become ready");
}

fn require_command(command: &str) {
    let output = Command::new(command)
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("{command} is required: {error}"));
    assert!(
        output.status.success(),
        "{command} --version failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn require_kubectl(command: &str) {
    let output = Command::new(command)
        .args(["version", "--client"])
        .output()
        .unwrap_or_else(|error| panic!("{command} is required: {error}"));
    assert!(
        output.status.success(),
        "{command} version --client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn intent(session_id: &str) -> SessionIntent {
    SessionIntent {
        schema_version: 1,
        tenant_id: apolysis_accountability::DEFAULT_TENANT_ID.to_string(),
        retention_tier: apolysis_accountability::RetentionTier::Standard,
        session_id: session_id.to_string(),
        expires_at_unix_ms: 4_102_444_800_000,
        declared_actions: vec![ActionClass::Test],
        allowed_resources: vec![ResourceSelector {
            kind: ResourceKind::Workspace,
            value: "/workspace".to_string(),
        }],
        workload_selectors: Vec::new(),
    }
}

fn config(name: &str) -> DaemonConfig {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-observation-adapter-{name}-{}-{id}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        max_sessions: 32,
        max_pending: 32,
        ..DaemonConfig::default()
    }
}

fn cleanup(config: &DaemonConfig) {
    if let Some(root) = config.socket_path.parent().and_then(|path| path.parent()) {
        let _ = std::fs::remove_dir_all(root);
    }
}
