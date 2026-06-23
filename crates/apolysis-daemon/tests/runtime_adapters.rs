// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use apolysis_accountability::{
    ActionClass, AdapterKind, AssociationOutcome, ComponentState, ResourceKind, ResourceSelector,
    SessionIntent,
};
use apolysis_daemon::{
    adapter_backoff_delay, cgroup_id_from_proc_cgroup, containerd_task_snapshot_from_cri_inspect,
    containerd_task_snapshot_from_metadata, containerd_workload_from_snapshot,
    crictl_marked_container_candidates_from_ps_and_pods, crictl_marked_container_ids_from_ps,
    docker_container_pid_from_engine_inspect, docker_snapshot_from_engine_inspect,
    docker_workload_from_snapshot, f4_runtime_adapter_evidence_from_workload,
    kubernetes_marked_pod_snapshots_from_api_list, kubernetes_pod_snapshot_from_api_object,
    kubernetes_workload_from_pod_snapshot, run_runtime_adapter_with_policy, AdapterBackoffPolicy,
    ContainerdCriRuntimeAdapter, ContainerdTaskSnapshot, CriRuntimeClient, DaemonConfig,
    DaemonState, DockerContainerSnapshot, DockerEngineClient, DockerEnginePollingRuntimeAdapter,
    DockerEngineRuntimeAdapter, KubernetesCliClient, KubernetesCliRuntimeAdapter,
    KubernetesPodSnapshot, RuntimeAdapterBackend, RuntimeWorkload, APOLYSIS_SESSION_ANNOTATION,
};
use apolysis_validation::{F4RuntimeAdapterEvidenceSource, F4RuntimeGuardrailTarget};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

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
    ensure_docker_alpine_image();
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
        let mut adapter = DockerEnginePollingRuntimeAdapter::new(
            client,
            "/proc",
            "/sys/fs/cgroup",
            Duration::from_millis(100),
            1024,
        );
        let workload = tokio::time::timeout(
            Duration::from_secs(15),
            next_workload_for_session(&mut adapter, &session_id),
        )
        .await
        .expect("Docker polling adapter timeout")
        .expect("target labelled Docker workload");

        assert_eq!(workload.adapter, AdapterKind::Docker);
        assert_eq!(workload.session_id, session_id);
        assert_eq!(workload.workload_id, container_id);
        assert!(workload.cgroup_id > 0);
        assert_eq!(workload.image.as_deref(), Some("alpine:3.20"));
        if let Some(runtime) = runtime {
            assert_eq!(workload.runtime_handler.as_deref(), Some(runtime));
        }
        record_f4_runtime_adapter_evidence(&workload, f4_live_adapter_evidence_id(&workload))
            .expect("write live Docker F4 runtime adapter evidence");

        drop(cleanup);
    }
}

#[tokio::test]
#[ignore = "requires Docker Engine socket access and the ability to run containers"]
async fn live_docker_engine_adapter_recovers_after_socket_disconnect() {
    require_command("docker");
    ensure_docker_alpine_image();
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
    let proxy = start_unix_socket_proxy_with_initial_disconnect(
        &proxy_socket,
        std::path::Path::new("/var/run/docker.sock"),
    );
    let adapter = DockerEnginePollingRuntimeAdapter::new(
        DockerEngineClient::new(&proxy_socket),
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

    wait_for_session_cgroup(&state, &session_id, Duration::from_secs(15)).await;
    shutdown.send(()).expect("stop Docker adapter");
    let summary = runner.await.expect("Docker adapter task");

    assert_eq!(summary.backend_errors, 1);
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(summary.discovered, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Docker),
        ComponentState::Ready
    );

    proxy.abort();
    drop(container_cleanup);
    cleanup(&config);
}

#[tokio::test]
#[ignore = "requires Docker Engine socket access, systemd access, and permission to restart Docker"]
async fn live_docker_engine_adapter_recovers_after_systemd_restart() {
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

    assert_eq!(summary.discovered, 2);
    assert!(
        summary.backend_errors > 0,
        "Docker restart should produce at least one backend error: {summary:?}"
    );
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Docker),
        ComponentState::Ready
    );

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
    require_command("docker");
    require_command("crictl");
    require_command("systemctl");
    require_command("systemd-run");
    ensure_docker_alpine_image();
    let runtime_socket = "/run/containerd/containerd.sock";
    let image_endpoint = Some("unix:///run/containerd/containerd.sock");
    let crictl = create_host_chroot_crictl_wrapper("containerd-systemd-restart");
    wait_for_systemd_service_active("containerd.service", Duration::from_secs(60));
    wait_for_cri_runtime(
        crictl.path(),
        runtime_socket,
        image_endpoint,
        Duration::from_secs(60),
    );
    let session_id = format!(
        "live-containerd-systemd-restart-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let first_workload = create_cri_workload_with_crictl(
        crictl.path(),
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
            .with_crictl_path(crictl.path())
            .with_image_endpoint(image_endpoint.map(ToOwned::to_owned)),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    )
    .expect("containerd CRI adapter");
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_adapter_with_policy(
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
            crictl.path(),
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
        crictl.path(),
        runtime_socket,
        image_endpoint,
        Duration::from_secs(90),
    );
    let second_workload = create_cri_workload_with_crictl(
        crictl.path(),
        runtime_socket,
        image_endpoint,
        "runc",
        &session_id,
    );
    wait_for_session_cgroup_count(&state, &session_id, 2, Duration::from_secs(30)).await;

    shutdown.send(()).expect("stop containerd adapter");
    let summary = runner.await.expect("containerd adapter task");

    assert_eq!(summary.discovered, 2);
    assert!(
        summary.backend_errors > 0,
        "containerd restart should produce at least one backend error: {summary:?}"
    );
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Containerd),
        ComponentState::Ready
    );

    drop(second_workload);
    drop(first_workload);
    cleanup(&config);
    drop(containerd_systemd);
}

#[tokio::test]
#[ignore = "requires root access to standalone containerd CRI socket and local Alpine image"]
async fn live_containerd_cri_adapter_recovers_after_socket_disconnect() {
    require_command("crictl");
    let runtime_socket = "/run/containerd/containerd.sock";
    let image_endpoint = Some("unix:///run/containerd/containerd.sock");
    let session_id = format!(
        "live-cri-recovery-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let workload_cleanup = create_cri_workload_with_crictl(
        "crictl",
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
    let proxy = start_unix_socket_proxy_with_initial_disconnect(
        &proxy_socket,
        std::path::Path::new(runtime_socket),
    );
    let adapter = ContainerdCriRuntimeAdapter::new(
        AdapterKind::Containerd,
        CriRuntimeClient::new(&proxy_socket)
            .with_image_endpoint(image_endpoint.map(ToOwned::to_owned)),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    )
    .expect("CRI adapter");
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
        shutdown.send(()).expect("stop CRI adapter after timeout");
        let summary = runner.await.expect("CRI adapter task after timeout");
        panic!("session {session_id} did not attach a cgroup; summary={summary:?}");
    }
    shutdown.send(()).expect("stop CRI adapter");
    let summary = runner.await.expect("CRI adapter task");

    assert_eq!(summary.backend_errors, 1);
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(summary.discovered, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::Containerd),
        ComponentState::Ready
    );

    proxy.abort();
    drop(workload_cleanup);
    cleanup(&config);
}

#[tokio::test]
#[ignore = "requires root access to k3s containerd CRI socket and local Alpine image"]
async fn live_k3s_containerd_cri_adapter_discovers_labelled_containers() {
    live_k3s_cri_adapter_matrix().await;
}

#[tokio::test]
#[ignore = "requires k3s/kubectl access, k3s CRI socket access, Docker helper access, and permission to terminate k3s for systemd restart"]
async fn live_k3s_containerd_cri_adapter_recovers_after_systemd_restart() {
    require_command("docker");
    require_command("crictl");
    require_command("systemctl");
    let kubectl = std::env::var("APOLYSIS_KUBECTL").unwrap_or_else(|_| "kubectl".to_string());
    require_kubectl(&kubectl);
    let runtime_socket = std::env::var("APOLYSIS_K3S_CRI_ENDPOINT")
        .unwrap_or_else(|_| "/run/k3s/containerd/containerd.sock".to_string());
    let crictl = create_host_chroot_crictl_wrapper("k3s-systemd-restart");
    wait_for_systemd_service_active("k3s.service", Duration::from_secs(90));
    wait_for_kubernetes_api(&kubectl, Duration::from_secs(90));
    wait_for_cri_runtime(
        crictl.path(),
        &runtime_socket,
        None,
        Duration::from_secs(90),
    );
    let session_id = format!(
        "live-k3s-systemd-restart-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let namespace = format!("apolysis-live-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    let first_pod = "apolysis-k3s-systemd-restart-a";
    let second_pod = "apolysis-k3s-systemd-restart-b";
    let workload_cleanup = KubernetesNamespaceCleanup {
        kubectl: kubectl.clone(),
        namespace: namespace.clone(),
        runtime_class: None,
    };
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
            .with_crictl_path(crictl.path())
            .with_image_endpoint(None),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    )
    .expect("k3s CRI adapter");
    let (shutdown, receiver) = oneshot::channel();
    let runner = tokio::spawn(run_runtime_adapter_with_policy(
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
            crictl.path(),
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
    wait_for_cri_runtime(
        crictl.path(),
        &runtime_socket,
        None,
        Duration::from_secs(120),
    );
    create_kubernetes_pod(&kubectl, &namespace, second_pod, &session_id, None, None);
    wait_for_kubernetes_container_id(&kubectl, &namespace, second_pod);
    wait_for_session_cgroup_count(&state, &session_id, 2, Duration::from_secs(45)).await;

    shutdown.send(()).expect("stop k3s CRI adapter");
    let summary = runner.await.expect("k3s CRI adapter task");

    assert_eq!(summary.discovered, 2);
    assert!(
        summary.backend_errors > 0,
        "k3s restart should produce at least one backend error: {summary:?}"
    );
    assert_eq!(summary.backend_recoveries, 1);
    assert_eq!(
        state.health().await.adapter(AdapterKind::K3sContainerd),
        ComponentState::Ready
    );

    drop(workload_cleanup);
    cleanup_cri_workloads_for_session(crictl.path(), &runtime_socket, None, &session_id);
    cleanup(&config);
    drop(k3s_systemd);
}

#[tokio::test]
#[ignore = "requires root access to k3s containerd CRI socket and local Alpine image"]
async fn live_k3s_containerd_cri_adapter_recovers_after_socket_disconnect() {
    require_command("crictl");
    let kubectl = std::env::var("APOLYSIS_KUBECTL").unwrap_or_else(|_| "kubectl".to_string());
    require_kubectl(&kubectl);
    let runtime_socket = std::env::var("APOLYSIS_K3S_CRI_ENDPOINT")
        .unwrap_or_else(|_| "/run/k3s/containerd/containerd.sock".to_string());
    let session_id = format!(
        "live-k3s-cri-recovery-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let namespace = format!("apolysis-live-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    let pod_name = "apolysis-k3s-cri-recovery";
    let workload_cleanup = KubernetesNamespaceCleanup {
        kubectl: kubectl.clone(),
        namespace: namespace.clone(),
        runtime_class: None,
    };
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
        CriRuntimeClient::new(&proxy_socket).with_image_endpoint(None),
        "/proc",
        "/sys/fs/cgroup",
        Duration::from_millis(100),
        1024,
    )
    .expect("k3s CRI adapter");
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
    cleanup_cri_workloads_for_session(
        std::path::Path::new("crictl"),
        &runtime_socket,
        None,
        &session_id,
    );
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
        let session_id = format!(
            "live-k8s-{name}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        );
        let namespace = format!("apolysis-live-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let pod_name = format!("apolysis-{name}");
        let runtime_class = runtime_handler.map(|_| {
            format!(
                "apolysis-{name}-{}",
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            )
        });
        let cleanup = KubernetesNamespaceCleanup {
            kubectl: kubectl.clone(),
            namespace: namespace.clone(),
            runtime_class: runtime_class.clone(),
        };
        create_kubernetes_pod(
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
        record_f4_runtime_adapter_evidence(&workload, f4_live_adapter_evidence_id(&workload))
            .expect("write live Kubernetes F4 runtime adapter evidence");
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
    let session_id = format!(
        "live-k8s-cri-recovery-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    let namespace = format!("apolysis-live-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    let pod_name = "apolysis-k8s-cri-recovery";
    let workload_cleanup = KubernetesNamespaceCleanup {
        kubectl: kubectl.clone(),
        namespace: namespace.clone(),
        runtime_class: None,
    };
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

fn record_f4_runtime_adapter_evidence(
    workload: &RuntimeWorkload,
    evidence_id: impl Into<String>,
) -> Result<(), String> {
    let Ok(output_path) = std::env::var("APOLYSIS_F4_RUNTIME_ADAPTER_EVIDENCE_OUTPUT") else {
        return Ok(());
    };
    let evidence = f4_runtime_adapter_evidence_from_workload(
        workload,
        evidence_id,
        F4RuntimeAdapterEvidenceSource::LiveHost,
    )?;
    let mut output = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&output_path)
        .map_err(|error| format!("failed to open F4 runtime adapter evidence output: {error}"))?;
    serde_json::to_writer(&mut output, &evidence)
        .map_err(|error| format!("failed to serialize F4 runtime adapter evidence: {error}"))?;
    output
        .write_all(b"\n")
        .map_err(|error| format!("failed to write F4 runtime adapter evidence newline: {error}"))?;
    Ok(())
}

fn f4_live_adapter_evidence_id(workload: &RuntimeWorkload) -> String {
    format!(
        "live-{}-{}-cgroup",
        f4_live_adapter_name(workload.adapter),
        f4_live_runtime_name(workload.runtime_handler.as_deref())
    )
}

fn f4_live_adapter_name(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Docker => "docker",
        AdapterKind::Containerd => "containerd",
        AdapterKind::K3sContainerd => "k3s-containerd",
        AdapterKind::Kubernetes => "kubernetes",
    }
}

fn f4_live_runtime_name(runtime_handler: Option<&str>) -> &'static str {
    let handler = runtime_handler.unwrap_or("runc").to_ascii_lowercase();
    if handler.contains("runsc") || handler.contains("gvisor") {
        "gvisor"
    } else if handler.contains("kata") {
        "kata"
    } else if handler.contains("firecracker") {
        "firecracker"
    } else {
        "runc"
    }
}

fn temp_file_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "apolysis-{name}-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ))
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
fn runtime_workload_becomes_f4_runtime_adapter_evidence() {
    let docker = f4_runtime_adapter_evidence_from_workload(
        &RuntimeWorkload {
            adapter: AdapterKind::Docker,
            session_id: "session-docker".to_string(),
            workload_id: "container-123".to_string(),
            cgroup_id: 77,
            image: Some("alpine:3.20".to_string()),
            runtime_handler: Some("runc".to_string()),
        },
        "live-docker-runc-cgroup",
        F4RuntimeAdapterEvidenceSource::LiveHost,
    )
    .expect("docker evidence");

    assert_eq!(docker.runtime, F4RuntimeGuardrailTarget::Docker);
    assert_eq!(docker.adapter, "docker");
    assert_eq!(docker.evidence_id, "live-docker-runc-cgroup");
    assert_eq!(docker.runtime_handler.as_deref(), Some("runc"));
    assert!(docker.metadata_correlation);
    assert!(docker.cgroup_correlation);
    assert!(docker.host_boundary_visibility);
    assert!(!docker.guest_semantics_claimed);

    let gvisor = f4_runtime_adapter_evidence_from_workload(
        &RuntimeWorkload {
            adapter: AdapterKind::Containerd,
            session_id: "session-gvisor".to_string(),
            workload_id: "default/task-gvisor".to_string(),
            cgroup_id: 88,
            image: Some("alpine:3.20".to_string()),
            runtime_handler: Some("io.containerd.runsc.v1".to_string()),
        },
        "live-containerd-gvisor-cgroup",
        F4RuntimeAdapterEvidenceSource::LiveHost,
    )
    .expect("gvisor evidence");

    assert_eq!(gvisor.runtime, F4RuntimeGuardrailTarget::Gvisor);
    assert!(gvisor.host_boundary_visibility);
    assert!(!gvisor.guest_semantics_claimed);

    let kata = f4_runtime_adapter_evidence_from_workload(
        &RuntimeWorkload {
            adapter: AdapterKind::Kubernetes,
            session_id: "session-kata".to_string(),
            workload_id: "pod-uid-123".to_string(),
            cgroup_id: 99,
            image: None,
            runtime_handler: Some("kata".to_string()),
        },
        "live-kubernetes-kata-boundary",
        F4RuntimeAdapterEvidenceSource::LiveHost,
    )
    .expect("kata evidence");

    assert_eq!(kata.runtime, F4RuntimeGuardrailTarget::Kata);
    assert!(kata.host_boundary_visibility);
    assert!(!kata.guest_semantics_claimed);
}

#[test]
fn live_adapter_workload_writes_f4_runtime_adapter_evidence_output() {
    let output = temp_file_path("f4-runtime-adapter-evidence.jsonl");
    std::env::set_var("APOLYSIS_F4_RUNTIME_ADAPTER_EVIDENCE_OUTPUT", &output);
    let workload = RuntimeWorkload {
        adapter: AdapterKind::Docker,
        session_id: "session-output".to_string(),
        workload_id: "container-output".to_string(),
        cgroup_id: 4242,
        image: Some("alpine:3.20".to_string()),
        runtime_handler: Some("runc".to_string()),
    };

    record_f4_runtime_adapter_evidence(&workload, "live-docker-output-cgroup")
        .expect("write F4 evidence output");

    std::env::remove_var("APOLYSIS_F4_RUNTIME_ADAPTER_EVIDENCE_OUTPUT");
    let line = std::fs::read_to_string(&output).expect("read evidence output");
    let report: serde_json::Value = serde_json::from_str(line.trim()).expect("parse evidence");
    assert_eq!(report["evidence_id"], "live-docker-output-cgroup");
    assert_eq!(report["source"], "live_host");
    assert_eq!(report["adapter"], "docker");
    assert_eq!(report["runtime"], "docker");
    assert_eq!(report["cgroup_id"], 4242);
    let _ = std::fs::remove_file(output);
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
                        "io.kubernetes.pod.namespace": "apolysis-validation"
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
                    "io.kubernetes.pod.namespace": "apolysis-validation"
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
    assert_eq!(snapshot.namespace, "apolysis-validation");
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

struct CriWorkloadCleanup {
    crictl_path: std::path::PathBuf,
    endpoint: String,
    image_endpoint: Option<String>,
    container_id: String,
    pod_id: String,
}

impl Drop for CriWorkloadCleanup {
    fn drop(&mut self) {
        let _ = run_crictl_with_command(
            &self.crictl_path,
            &self.endpoint,
            self.image_endpoint.as_deref(),
            &["stop", &self.container_id],
        );
        let _ = run_crictl_with_command(
            &self.crictl_path,
            &self.endpoint,
            self.image_endpoint.as_deref(),
            &["rm", &self.container_id],
        );
        let _ = run_crictl_with_command(
            &self.crictl_path,
            &self.endpoint,
            self.image_endpoint.as_deref(),
            &["stopp", &self.pod_id],
        );
        let _ = run_crictl_with_command(
            &self.crictl_path,
            &self.endpoint,
            self.image_endpoint.as_deref(),
            &["rmp", &self.pod_id],
        );
    }
}

struct KubernetesNamespaceCleanup {
    kubectl: String,
    namespace: String,
    runtime_class: Option<String>,
}

impl Drop for KubernetesNamespaceCleanup {
    fn drop(&mut self) {
        let _ = Command::new(&self.kubectl)
            .args([
                "delete",
                "namespace",
                &self.namespace,
                "--ignore-not-found=true",
                "--wait=true",
                "--timeout=120s",
            ])
            .output();
        if let Some(runtime_class) = &self.runtime_class {
            let _ = Command::new(&self.kubectl)
                .args([
                    "delete",
                    "runtimeclass",
                    runtime_class,
                    "--ignore-not-found=true",
                    "--wait=false",
                ])
                .output();
        }
    }
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
    require_command("crictl");
    for runtime in live_cri_runtimes() {
        let session_id = format!(
            "live-cri-{runtime}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        );
        let cleanup = create_cri_workload(socket_path, image_endpoint, runtime, &session_id);
        let mut adapter = ContainerdCriRuntimeAdapter::new(
            adapter_kind,
            CriRuntimeClient::new(socket_path)
                .with_image_endpoint(image_endpoint.map(ToOwned::to_owned)),
            "/proc",
            "/sys/fs/cgroup",
            Duration::from_millis(100),
            1024,
        )
        .expect("CRI adapter");
        let workload = tokio::time::timeout(Duration::from_secs(15), adapter.next_workload())
            .await
            .expect("CRI adapter timeout")
            .expect("CRI adapter poll")
            .expect("labelled CRI workload");

        assert_eq!(workload.adapter, adapter_kind);
        assert_eq!(workload.session_id, session_id);
        assert_eq!(
            workload.workload_id,
            format!("apolysis-validation/{}", cleanup.container_id)
        );
        assert!(workload.cgroup_id > 0);
        assert_eq!(
            workload.image.as_deref(),
            Some("docker.io/library/alpine:3.20")
        );
        assert!(
            workload
                .runtime_handler
                .as_deref()
                .unwrap_or_default()
                .contains(expected_cri_runtime_type(runtime)),
            "runtime handler {:?} did not contain expected type {}",
            workload.runtime_handler,
            expected_cri_runtime_type(runtime)
        );
        record_f4_runtime_adapter_evidence(&workload, f4_live_adapter_evidence_id(&workload))
            .expect("write live CRI F4 runtime adapter evidence");
        drop(cleanup);
    }
}

async fn live_k3s_cri_adapter_matrix() {
    require_command("crictl");
    let kubectl = std::env::var("APOLYSIS_KUBECTL").unwrap_or_else(|_| "kubectl".to_string());
    require_kubectl(&kubectl);
    let endpoint = std::env::var("APOLYSIS_K3S_CRI_ENDPOINT")
        .unwrap_or_else(|_| "/run/k3s/containerd/containerd.sock".to_string());

    for (name, runtime_handler) in live_kubernetes_runtimes() {
        let session_id = format!(
            "live-k3s-cri-{name}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        );
        let namespace = format!("apolysis-live-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
        let pod_name = format!("apolysis-k3s-cri-{name}");
        let runtime_class = runtime_handler.map(|_| {
            format!(
                "apolysis-k3s-cri-{name}-{}",
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            )
        });
        let cleanup = KubernetesNamespaceCleanup {
            kubectl: kubectl.clone(),
            namespace: namespace.clone(),
            runtime_class: runtime_class.clone(),
        };
        create_kubernetes_pod(
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
            CriRuntimeClient::new(&endpoint).with_image_endpoint(None),
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
        record_f4_runtime_adapter_evidence(&workload, f4_live_adapter_evidence_id(&workload))
            .expect("write live k3s CRI F4 runtime adapter evidence");
        drop(cleanup);
        cleanup_cri_workloads_for_session(
            std::path::Path::new("crictl"),
            &endpoint,
            None,
            &session_id,
        );
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

fn create_cri_workload(
    socket_path: &str,
    image_endpoint: Option<&str>,
    runtime: &str,
    session_id: &str,
) -> CriWorkloadCleanup {
    create_cri_workload_with_crictl("crictl", socket_path, image_endpoint, runtime, session_id)
}

fn create_cri_workload_with_crictl(
    crictl_path: impl AsRef<std::path::Path>,
    socket_path: &str,
    image_endpoint: Option<&str>,
    runtime: &str,
    session_id: &str,
) -> CriWorkloadCleanup {
    let endpoint = format!("unix://{socket_path}");
    let root = std::env::temp_dir().join(format!(
        "apolysis-cri-live-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("create CRI config directory");
    let pod_path = root.join("pod.json");
    let container_path = root.join("container.json");
    let uid = format!("apolysis-cri-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    let mut pod_linux = json!({
        "resources": {
            "cpu_period": 100000,
            "cpu_quota": 50000,
            "memory_limit_in_bytes": 67108864
        }
    });
    if socket_path.contains("/k3s/") {
        pod_linux.as_object_mut().expect("pod linux object").insert(
            "cgroup_parent".to_string(),
            serde_json::Value::String("system.slice".to_string()),
        );
    }
    let readonly_rootfs = !(socket_path.contains("/k3s/") && runtime == "runsc");
    std::fs::write(
        &pod_path,
        serde_json::to_vec_pretty(&json!({
            "metadata": {
                "name": format!("apolysis-{runtime}"),
                "namespace": "apolysis-validation",
                "uid": uid,
                "attempt": 0
            },
            "labels": {
                "apolysis.session_id": session_id
            },
            "log_directory": root.to_string_lossy(),
            "linux": pod_linux
        }))
        .expect("serialize CRI pod config"),
    )
    .expect("write CRI pod config");
    std::fs::write(
        &container_path,
        serde_json::to_vec_pretty(&json!({
            "metadata": {
                "name": "workload",
                "attempt": 0
            },
            "image": {
                "image": "docker.io/library/alpine:3.20"
            },
            "command": ["sh", "-c", "sleep 60"],
            "labels": {
                "apolysis.session_id": session_id
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
    let pod = run_crictl_with_command(
        crictl_path.as_ref(),
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
    let container = run_crictl_with_command(
        crictl_path.as_ref(),
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
    run_crictl_with_command(
        crictl_path.as_ref(),
        &endpoint,
        image_endpoint,
        &["start", &container],
    )
    .unwrap_or_else(|error| panic!("start CRI container with runtime {runtime}: {error}"));
    wait_for_cri_container_observable(crictl_path.as_ref(), &endpoint, image_endpoint, &container);
    let _ = std::fs::remove_dir_all(&root);

    CriWorkloadCleanup {
        crictl_path: crictl_path.as_ref().to_path_buf(),
        endpoint,
        image_endpoint: image_endpoint.map(ToOwned::to_owned),
        container_id: container,
        pod_id: pod,
    }
}

fn run_crictl_with_command(
    crictl_path: &std::path::Path,
    endpoint: &str,
    image_endpoint: Option<&str>,
    command_args: &[&str],
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
    let output = command
        .args(command_args)
        .output()
        .map_err(|error| format!("failed to run crictl: {error}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
) {
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
---
apiVersion: v1
kind: Pod
metadata:
  name: {pod_name}
  namespace: {namespace}
  labels:
    apolysis.session_id: {session_id}
  annotations:
    apolysis.dev/session-id: {session_id}
spec:
  restartPolicy: Never
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
            "apply",
            "-f",
            manifest.to_str().expect("manifest path UTF-8"),
        ])
        .output()
        .expect("kubectl apply");
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        output.status.success(),
        "kubectl apply failed: {}",
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
        session_id: session_id.to_string(),
        expires_at_unix_ms: 4_102_444_800_000,
        declared_actions: vec![ActionClass::Test],
        allowed_resources: vec![ResourceSelector {
            kind: ResourceKind::Workspace,
            value: "/workspace".to_string(),
        }],
        policy_ref: "policy.yaml".to_string(),
        workload_selectors: Vec::new(),
    }
}

fn config(name: &str) -> DaemonConfig {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
        "apolysis-runtime-adapter-{name}-{}-{id}",
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
