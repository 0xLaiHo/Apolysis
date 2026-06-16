// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::future::Future;
use std::os::unix::fs::MetadataExt;
use std::pin::Pin;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use apolysis_accountability::{
    ActionClass, AdapterKind, AssociationOutcome, ComponentState, ResourceKind, ResourceSelector,
    SessionIntent,
};
use apolysis_daemon::{
    cgroup_id_from_proc_cgroup, containerd_task_snapshot_from_metadata,
    containerd_workload_from_snapshot, docker_container_pid_from_engine_inspect,
    docker_snapshot_from_engine_inspect, docker_workload_from_snapshot,
    kubernetes_pod_snapshot_from_api_object, kubernetes_workload_from_pod_snapshot,
    run_runtime_adapter, ContainerdTaskSnapshot, DaemonConfig, DaemonState,
    DockerContainerSnapshot, DockerEngineClient, DockerEngineRuntimeAdapter, KubernetesPodSnapshot,
    RuntimeAdapterBackend, RuntimeWorkload, APOLYSIS_SESSION_ANNOTATION,
};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
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
    let session_id = format!(
        "live-docker-{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, Ordering::Relaxed)
    );
    require_command("docker");
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
    let output = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--label",
            &format!("apolysis.session_id={session_id}"),
            "alpine:3.20",
            "sh",
            "-c",
            "sleep 30",
        ])
        .output()
        .expect("start labelled container");
    assert!(
        output.status.success(),
        "docker run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
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
    let mut adapter = DockerEngineRuntimeAdapter::new(
        client,
        "/proc",
        "/sys/fs/cgroup",
        vec![container_id.clone()],
    );
    let workload = adapter
        .next_workload()
        .await
        .expect("adapter poll")
        .expect("marked workload");

    assert_eq!(workload.adapter, AdapterKind::Docker);
    assert_eq!(workload.session_id, session_id);
    assert_eq!(workload.workload_id, container_id);
    assert!(workload.cgroup_id > 0);
    assert_eq!(workload.image.as_deref(), Some("alpine:3.20"));

    drop(cleanup);
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
    let backend = FakeRuntimeAdapter::new(vec![
        Err("docker event stream disconnected".to_string()),
        Ok(Some(RuntimeWorkload {
            adapter: AdapterKind::Docker,
            session_id: "session-docker".to_string(),
            workload_id: "container-after-reconnect".to_string(),
            cgroup_id: 99,
            image: Some("alpine:3.20".to_string()),
            runtime_handler: Some("runc".to_string()),
        })),
        Ok(None),
    ]);

    let summary = run_runtime_adapter(backend, Arc::clone(&state), receiver).await;

    assert_eq!(summary.adapter, AdapterKind::Docker);
    assert_eq!(summary.discovered, 1);
    assert_eq!(summary.backend_errors, 1);
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

struct FakeRuntimeAdapter {
    responses: VecDeque<Result<Option<RuntimeWorkload>, String>>,
}

impl FakeRuntimeAdapter {
    fn new(responses: Vec<Result<Option<RuntimeWorkload>, String>>) -> Self {
        Self {
            responses: responses.into(),
        }
    }
}

impl RuntimeAdapterBackend for FakeRuntimeAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Docker
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
