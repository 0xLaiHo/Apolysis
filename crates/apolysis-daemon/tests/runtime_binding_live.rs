// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use apolysis_accountability::{AdapterKind, ComponentState, SessionStatus};
use apolysis_daemon::{serve, DaemonConfig, DaemonResponse, RuntimeBinding};
use apolysis_observer::capabilities::validate_live_prerequisites;
use apolysis_observer::{AyaLoaderPlan, DaemonObserver, DaemonObserverConfig, LiveScope};
use apolysis_store::{ChainRecord, HashChainStore};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

const LIVE_OPT_IN: &str = "APOLYSIS_LIVE_DOCKER_EBPF";
const LIVE_BPF_OBJECT: &str = "APOLYSIS_LIVE_BPF_OBJECT";
const DOCKER_SOCKET: &str = "/var/run/docker.sock";
const DOCKER_HOST_ARG: &str = "--host=unix:///var/run/docker.sock";
const DOCKER_IMAGE: &str = "alpine:3.20";
const OWNER_LABEL: &str = "apolysis.live_gate";
const SESSION_LABEL: &str = "apolysis.session_id";
const WORKSPACE: &str = "/apolysis-live";
const SUBPROCESS_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires APOLYSIS_LIVE_DOCKER_EBPF=1, root, live eBPF prerequisites, Docker socket access, and an already-present Alpine image"]
async fn live_daemon_ebpf_attributes_a_docker_file_event_to_the_exact_runtime_binding() {
    let Some(preflight) = LiveDockerEbpfGate::preflight() else {
        return;
    };
    let mut temporary = PrivateTemporaryRoot::create(&preflight.id)
        .unwrap_or_else(|_| panic!("failed to create the private live-gate state root"));
    let config = daemon_config(temporary.path(), &preflight.bpf_object);
    let mut container = OwnedDockerContainer::new(
        preflight.container_name.clone(),
        preflight.id.clone(),
        preflight.agent_run_id.clone(),
    );
    let server = LiveDaemonServer::start(config.clone())
        .await
        .unwrap_or_else(|_| panic!("the live daemon failed to start"));

    assert!(
        wait_for_ready_daemon(&config.socket_path, Duration::from_secs(15)).await,
        "the live daemon did not reach eBPF, storage, and Docker readiness"
    );
    register_agent_run(&config.socket_path, &preflight.agent_run_id).await;

    let container_id = container
        .start()
        .unwrap_or_else(|_| panic!("failed to start the isolated live-gate container"));
    assert!(is_full_docker_id(&container_id));
    let binding = wait_for_binding(
        &config.socket_path,
        &preflight.agent_run_id,
        &container_id,
        Duration::from_secs(20),
    )
    .await;
    assert_exact_docker_binding(&binding, &preflight.agent_run_id, &container_id);

    let timeline_path = config
        .state_dir
        .join("sessions")
        .join(&preflight.agent_run_id)
        .join("timeline.jsonl");
    let baseline_sequence = latest_timeline_sequence(&timeline_path);
    let event_path = format!("{WORKSPACE}/e-{}", &preflight.id[..12]);
    container
        .create_file(&event_path)
        .unwrap_or_else(|_| panic!("failed to trigger the isolated file-create event"));
    assert!(
        wait_for_exact_attribution(
            &timeline_path,
            baseline_sequence,
            &container_id,
            binding.identity.cgroup.inode,
            Duration::from_secs(15),
        )
        .await,
        "the real eBPF file event was not attributed to the exact Docker binding"
    );

    server
        .stop()
        .await
        .unwrap_or_else(|_| panic!("the live daemon did not shut down cleanly"));
    verify_final_timeline(
        &timeline_path,
        baseline_sequence,
        &container_id,
        binding.identity.cgroup.inode,
    );
    container
        .cleanup()
        .unwrap_or_else(|_| panic!("failed to remove the exact live-gate container"));
    assert!(
        running_container_ids().is_some_and(|ids| ids == preflight.running_container_ids),
        "the live gate changed the unrelated running-container set"
    );
    assert!(
        docker_service_state().is_some_and(|state| state == preflight.docker_service_state),
        "the live gate changed docker.service state"
    );
    temporary
        .cleanup_strict()
        .unwrap_or_else(|_| panic!("failed to remove the unchanged private live-gate state root"));
}

struct LiveDockerEbpfGate;

impl LiveDockerEbpfGate {
    fn preflight() -> Option<LivePreflight> {
        if std::env::var(LIVE_OPT_IN).ok().as_deref() != Some("1") {
            eprintln!("skipped: set {LIVE_OPT_IN}=1 to opt in to the live Docker/eBPF gate");
            return None;
        }
        Some(
            Self::qualified_preflight()
                .unwrap_or_else(|reason| panic!("live Docker/eBPF preflight failed: {reason}")),
        )
    }

    fn qualified_preflight() -> Result<LivePreflight, &'static str> {
        if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
            return Err("Linux root privileges are required");
        }
        let id = live_id().ok_or("kernel random UUID source is unavailable")?;
        let bpf_object = private_live_bpf_object()?;
        let loader_plan = AyaLoaderPlan::audit_observer_default(&bpf_object);
        if validate_live_prerequisites(&LiveScope::Cgroup(1), &loader_plan).is_err() {
            return Err("live eBPF kernel prerequisites are unavailable");
        }
        if !Path::new(DOCKER_SOCKET)
            .metadata()
            .map(|metadata| metadata.file_type().is_socket())
            .unwrap_or(false)
        {
            return Err("the Docker Engine socket is unavailable");
        }
        if !docker_command_succeeds(&["version", "--format", "{{.Server.Version}}"])
            || !docker_command_succeeds(&["image", "inspect", DOCKER_IMAGE])
        {
            return Err("Docker or the already-present Alpine image is unavailable");
        }
        let docker_service_state =
            docker_service_state().ok_or("docker.service state cannot be captured")?;
        let running_container_ids =
            running_container_ids().ok_or("the running-container baseline cannot be captured")?;
        if !docker_output_lines(&[
            "ps",
            "--quiet",
            "--no-trunc",
            "--filter",
            &format!("label={SESSION_LABEL}"),
        ])
        .ok_or("the Apolysis-labelled container preflight failed")?
        .is_empty()
        {
            return Err("another Apolysis-labelled container is already running");
        }
        let container_name = format!("apolysis-live-{id}");
        if !docker_container_ids_by_exact_name(&container_name)
            .map_err(|_| "the random container-name preflight failed")?
            .is_empty()
        {
            return Err("the random live-gate container name is already in use");
        }
        if !docker_output_lines(&[
            "container",
            "ls",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            &format!("label={OWNER_LABEL}={id}"),
        ])
        .ok_or("the random ownership-label preflight failed")?
        .is_empty()
        {
            return Err("the random live-gate ownership label is already in use");
        }
        let observer = DaemonObserver::load(DaemonObserverConfig::new(&bpf_object))
            .map_err(|_| "the live eBPF object cannot be loaded on this host")?;
        drop(observer);
        Ok(LivePreflight {
            agent_run_id: format!("live-ebpf-docker-{id}"),
            bpf_object,
            container_name,
            docker_service_state,
            id,
            running_container_ids,
        })
    }
}

struct LivePreflight {
    agent_run_id: String,
    bpf_object: PathBuf,
    container_name: String,
    docker_service_state: Vec<u8>,
    id: String,
    running_container_ids: Vec<String>,
}

fn daemon_config(root: &Path, bpf_object: &Path) -> DaemonConfig {
    DaemonConfig {
        socket_path: root.join("run/apolysisd.sock"),
        state_dir: root.join("state"),
        bpf_object: Some(bpf_object.to_path_buf()),
        docker_socket: Some(DOCKER_SOCKET.into()),
        proc_root: "/proc".into(),
        cgroup_root: "/sys/fs/cgroup".into(),
        runtime_adapter_scan_interval: Duration::from_millis(50),
        runtime_adapter_seen_capacity: 128,
        max_sessions: 8,
        max_pending: 8,
        max_connections: 8,
        queue_capacity: 1024,
        scope_command_capacity: 32,
        request_timeout: Duration::from_secs(2),
        shutdown_drain_timeout: Duration::from_secs(10),
        collector_checkpoint_interval: Duration::from_secs(1),
        ..DaemonConfig::default()
    }
}

async fn wait_for_ready_daemon(socket: &Path, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            if let Ok(DaemonResponse::Health {
                readiness: true,
                health,
                ..
            }) = daemon_request(socket, &json!({"type": "health"})).await
            {
                if health.ebpf() == ComponentState::Ready
                    && health.storage() == ComponentState::Ready
                    && health.adapter(AdapterKind::Docker) == ComponentState::Ready
                {
                    return true;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or(false)
}

async fn register_agent_run(socket: &Path, agent_run_id: &str) {
    let response = daemon_request(
        socket,
        &json!({
            "type": "register",
            "intent": {
                "schema_version": 1,
                "session_id": agent_run_id,
                "expires_at_unix_ms": 4_102_444_800_000_u64,
                "declared_actions": ["write_file"],
                "allowed_resources": [{"kind": "workspace", "value": WORKSPACE}],
                "workload_selectors": []
            }
        }),
    )
    .await
    .unwrap_or_else(|_| panic!("failed to register the live Agent Run"));
    assert!(
        matches!(response, DaemonResponse::Ack { operation, session_id: Some(id), .. }
            if operation == "register" && id == agent_run_id),
        "the daemon rejected the live Agent Run registration"
    );
}

async fn wait_for_binding(
    socket: &Path,
    agent_run_id: &str,
    container_id: &str,
    timeout: Duration,
) -> RuntimeBinding {
    tokio::time::timeout(timeout, async {
        loop {
            if let Ok(DaemonResponse::Session {
                session: Some(session),
                runtime_bindings,
                ..
            }) = daemon_request(
                socket,
                &json!({"type": "query", "session_id": agent_run_id}),
            )
            .await
            {
                if let Some(binding) = runtime_bindings
                    .into_iter()
                    .find(|binding| binding.identity.workload_id == container_id)
                {
                    assert_eq!(session.status, SessionStatus::Active);
                    assert_eq!(session.cgroup_ids, vec![binding.identity.cgroup.inode]);
                    return binding;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the daemon did not discover the exact Docker binding"))
}

fn assert_exact_docker_binding(binding: &RuntimeBinding, agent_run_id: &str, container_id: &str) {
    assert_eq!(binding.agent_run_id, agent_run_id);
    assert_eq!(binding.identity.adapter, AdapterKind::Docker);
    assert_eq!(binding.identity.workload_id, container_id);
    assert!(is_full_docker_id(&binding.identity.workload_id));
    assert!(!binding.identity.start_marker.is_empty());
    assert!(!binding.identity.host_boot_id.is_empty());
    assert!(binding.identity.init_process_start_time_ticks > 0);
    assert!(binding.identity.cgroup.device > 0);
    assert!(binding.identity.cgroup.inode > 0);
}

async fn wait_for_exact_attribution(
    timeline_path: &Path,
    baseline_sequence: u64,
    container_id: &str,
    cgroup_id: u64,
    timeout: Duration,
) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            if timeline_records(timeline_path).iter().any(|record| {
                exact_attributed_file_event(record, baseline_sequence, container_id, cgroup_id)
            }) {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or(false)
}

fn verify_final_timeline(
    timeline_path: &Path,
    baseline_sequence: u64,
    container_id: &str,
    cgroup_id: u64,
) {
    let report = HashChainStore::verify(timeline_path)
        .unwrap_or_else(|_| panic!("failed to verify the live Agent Run hash chain"));
    assert!(report.passed, "the live Agent Run hash chain is invalid");
    let records = timeline_records(timeline_path);
    let capabilities = records
        .iter()
        .filter(|record| {
            record.payload.get("record_type").and_then(Value::as_str)
                == Some("collector_capability_manifest")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        capabilities.len(),
        1,
        "the live Agent Run must have one Collector Capability manifest"
    );
    let capability = capabilities[0];
    assert_eq!(
        capability
            .payload
            .get("observation_scope")
            .and_then(Value::as_str),
        Some("cgroup")
    );
    assert_eq!(
        capability
            .payload
            .get("privacy_profile")
            .and_then(Value::as_str),
        Some("content_off")
    );
    let started = records
        .iter()
        .find(|record| {
            record.payload.get("record_type").and_then(Value::as_str) == Some("collector_lifecycle")
                && record.payload.get("state").and_then(Value::as_str) == Some("started")
        })
        .unwrap_or_else(|| panic!("the live collector start boundary is missing"));
    let matching = records
        .iter()
        .filter(|record| {
            exact_attributed_file_event(record, baseline_sequence, container_id, cgroup_id)
        })
        .collect::<Vec<_>>();
    assert!(
        !matching.is_empty(),
        "the isolated file-create action must add an exact content-off attributed event"
    );
    assert!(
        capability.sequence < started.sequence && started.sequence < matching[0].sequence,
        "capability and collector start must precede attributed evidence"
    );
}

fn exact_attributed_file_event(
    record: &ChainRecord,
    baseline_sequence: u64,
    container_id: &str,
    cgroup_id: u64,
) -> bool {
    let payload = &record.payload;
    record.sequence > baseline_sequence
        && payload.get("record_type").and_then(Value::as_str) == Some("raw_kernel_event")
        && matches!(
            payload.get("event_name").and_then(Value::as_str),
            Some("creat" | "openat" | "openat2")
        )
        && payload
            .get("resource")
            .and_then(Value::as_str)
            .is_some_and(is_content_off_path_token)
        && payload
            .get("raw_payload")
            .and_then(Value::as_str)
            .is_some_and(|payload| payload.split(',').any(|part| part == "redacted:resource"))
        && payload.get("container_id").and_then(Value::as_str) == Some(container_id)
        && payload.get("cgroup_id").and_then(Value::as_str) == Some(&cgroup_id.to_string())
        && payload.get("relation_status").and_then(Value::as_str) == Some("exact")
        && payload.get("relation_reason").and_then(Value::as_str)
            == Some("host_boot_scope_process_start_exec_generation")
}

fn is_content_off_path_token(resource: &str) -> bool {
    resource.strip_prefix("path_token:").is_some_and(|token| {
        token.len() == 24
            && token
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn latest_timeline_sequence(path: &Path) -> u64 {
    timeline_records(path)
        .last()
        .map(|record| record.sequence)
        .unwrap_or(0)
}

fn timeline_records(path: &Path) -> Vec<ChainRecord> {
    std::fs::read_to_string(path)
        .ok()
        .into_iter()
        .flat_map(|timeline| {
            timeline
                .lines()
                .filter_map(|line| serde_json::from_str::<ChainRecord>(line).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

async fn daemon_request(socket: &Path, request: &Value) -> Result<DaemonResponse, String> {
    let bytes = serde_json::to_vec(request).map_err(|_| "encode request".to_string())?;
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|_| "connect daemon".to_string())?;
    let length = u32::try_from(bytes.len()).map_err(|_| "request too large".to_string())?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|_| "write request length".to_string())?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| "write request".to_string())?;
    let response_length = stream
        .read_u32()
        .await
        .map_err(|_| "read response length".to_string())? as usize;
    if response_length > 1024 * 1024 {
        return Err("response too large".to_string());
    }
    let mut response = vec![0_u8; response_length];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| "read response".to_string())?;
    serde_json::from_slice(&response).map_err(|_| "decode response".to_string())
}

struct LiveDaemonServer {
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<(), String>>>,
}

impl LiveDaemonServer {
    async fn start(config: DaemonConfig) -> Result<Self, String> {
        let socket = config.socket_path.clone();
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(serve(config, receiver));
        for _ in 0..1_000 {
            if socket.exists() {
                return Ok(Self {
                    shutdown: Some(shutdown),
                    task: Some(task),
                });
            }
            if task.is_finished() {
                return Err("daemon exited before socket creation".to_string());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        task.abort();
        Err("daemon socket creation timed out".to_string())
    }

    async fn stop(mut self) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task = self.task.take().ok_or_else(|| "missing task".to_string())?;
        tokio::time::timeout(Duration::from_secs(15), task)
            .await
            .map_err(|_| "daemon shutdown timed out".to_string())?
            .map_err(|_| "daemon task join failed".to_string())?
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

struct OwnedDockerContainer {
    agent_run_id: String,
    container_id: Option<String>,
    mutation_attempted: bool,
    name: String,
    owner_id: String,
}

impl OwnedDockerContainer {
    fn new(name: String, owner_id: String, agent_run_id: String) -> Self {
        Self {
            agent_run_id,
            container_id: None,
            mutation_attempted: false,
            name,
            owner_id,
        }
    }

    fn start(&mut self) -> Result<String, String> {
        self.mutation_attempted = true;
        let output = docker_output(&[
            "run",
            "--detach",
            "--pull=never",
            "--name",
            &self.name,
            "--label",
            &format!("{OWNER_LABEL}={}", self.owner_id),
            "--label",
            &format!("{SESSION_LABEL}={}", self.agent_run_id),
            "--cpus",
            "0.25",
            "--memory",
            "64m",
            "--pids-limit",
            "32",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--user",
            "65534:65534",
            "--tmpfs",
            &format!("{WORKSPACE}:rw,noexec,nosuid,nodev,size=64k,mode=0700,uid=65534,gid=65534"),
            DOCKER_IMAGE,
            "sh",
            "-c",
            "while :; do sleep 3600; done",
        ])?;
        if !output.status.success() {
            return Err("docker run failed".to_string());
        }
        let container_id = String::from_utf8(output.stdout)
            .map_err(|_| "docker run returned non-UTF-8 output".to_string())?
            .trim()
            .to_string();
        if !is_full_docker_id(&container_id) {
            return Err("docker run returned an invalid container ID".to_string());
        }
        self.container_id = Some(container_id.clone());
        if !self.is_exact_owner(&container_id) {
            return Err("Docker ownership proof failed".to_string());
        }
        Ok(container_id)
    }

    fn create_file(&self, event_path: &str) -> Result<(), String> {
        let container_id = self
            .container_id
            .as_deref()
            .ok_or_else(|| "container has not started".to_string())?;
        let output = docker_output(&[
            "exec",
            container_id,
            "sh",
            "-c",
            "printf x > \"$1\"",
            "apolysis-live-stage",
            event_path,
        ])?;
        if output.status.success() {
            Ok(())
        } else {
            Err("Docker exec failed".to_string())
        }
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let Some(container_id) = self.container_id.clone() else {
            if self.mutation_attempted {
                return self.cleanup_by_name();
            }
            return Ok(());
        };
        if !self.is_exact_owner(&container_id) {
            return Err("refusing ambiguous Docker cleanup".to_string());
        }
        let output = docker_output(&["rm", "--force", "--volumes", &container_id])?;
        if !output.status.success() {
            return Err("Docker removal failed".to_string());
        }
        self.verify_absent()?;
        self.container_id = None;
        self.mutation_attempted = false;
        Ok(())
    }

    fn cleanup_by_name(&mut self) -> Result<(), String> {
        let ids = docker_container_ids_by_exact_name(&self.name)?;
        if ids.is_empty() {
            self.mutation_attempted = false;
            return Ok(());
        }
        if ids.len() != 1 || !is_full_docker_id(&ids[0]) {
            return Err("refusing ambiguous Docker cleanup".to_string());
        }
        let container_id = &ids[0];
        let inspect = docker_inspect(container_id)?;
        if !self.inspect_is_exact_owner(&inspect, container_id) {
            return Err("refusing ambiguous Docker cleanup".to_string());
        }
        let output = docker_output(&["rm", "--force", "--volumes", container_id])?;
        if !output.status.success() {
            return Err("Docker removal failed".to_string());
        }
        self.verify_absent()?;
        self.mutation_attempted = false;
        Ok(())
    }

    fn is_exact_owner(&self, container_id: &str) -> bool {
        docker_inspect(container_id)
            .ok()
            .as_ref()
            .is_some_and(|inspect| self.inspect_is_exact_owner(inspect, container_id))
    }

    fn inspect_is_exact_owner(&self, inspect: &Value, container_id: &str) -> bool {
        inspect.get("Id").and_then(Value::as_str) == Some(container_id)
            && inspect.get("Name").and_then(Value::as_str) == Some(&format!("/{}", self.name))
            && inspect
                .pointer("/Config/Labels")
                .and_then(Value::as_object)
                .and_then(|labels| labels.get(OWNER_LABEL))
                .and_then(Value::as_str)
                == Some(self.owner_id.as_str())
            && inspect
                .pointer("/Config/Labels")
                .and_then(Value::as_object)
                .and_then(|labels| labels.get(SESSION_LABEL))
                .and_then(Value::as_str)
                == Some(self.agent_run_id.as_str())
    }

    fn verify_absent(&self) -> Result<(), String> {
        if !docker_container_ids_by_exact_name(&self.name)?.is_empty()
            || !docker_output_lines(&[
                "container",
                "ls",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                &format!("label={OWNER_LABEL}={}", self.owner_id),
            ])
            .ok_or_else(|| "failed to verify Docker cleanup".to_string())?
            .is_empty()
        {
            return Err("live-gate Docker resource still exists".to_string());
        }
        Ok(())
    }
}

impl Drop for OwnedDockerContainer {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct PrivateTemporaryRoot {
    cleaned: bool,
    device: u64,
    inode: u64,
    path: PathBuf,
    uid: u32,
}

impl PrivateTemporaryRoot {
    fn create(id: &str) -> std::io::Result<Self> {
        let path = std::env::temp_dir().join(format!("apolysis-live-ebpf-docker-{id}"));
        std::fs::create_dir(&path)?;
        if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        {
            let _ = std::fs::remove_dir(&path);
            return Err(error);
        }
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                let _ = std::fs::remove_dir(&path);
                return Err(error);
            }
        };
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            let _ = std::fs::remove_dir(&path);
            return Err(std::io::Error::other(
                "private live-gate root identity validation failed",
            ));
        }
        Ok(Self {
            cleaned: false,
            device: metadata.dev(),
            inode: metadata.ino(),
            path,
            uid: metadata.uid(),
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn cleanup_strict(&mut self) -> Result<(), String> {
        if self.cleaned {
            return Ok(());
        }
        let metadata = std::fs::symlink_metadata(&self.path)
            .map_err(|_| "private live-gate root is unavailable".to_string())?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err("private live-gate root identity changed".to_string());
        }
        std::fs::remove_dir_all(&self.path)
            .map_err(|_| "failed to remove private live-gate root".to_string())?;
        match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => return Err("private live-gate root still exists after cleanup".to_string()),
        }
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for PrivateTemporaryRoot {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup_strict();
        }
    }
}

fn docker_inspect(container: &str) -> Result<Value, String> {
    let output = docker_output(&["inspect", container])?;
    if !output.status.success() {
        return Err("Docker inspect failed".to_string());
    }
    serde_json::from_slice::<Vec<Value>>(&output.stdout)
        .map_err(|_| "Docker inspect returned invalid JSON".to_string())?
        .into_iter()
        .next()
        .ok_or_else(|| "Docker inspect returned no container".to_string())
}

fn docker_container_ids_by_exact_name(name: &str) -> Result<Vec<String>, String> {
    docker_output_lines(&[
        "container",
        "ls",
        "--all",
        "--quiet",
        "--no-trunc",
        "--filter",
        &format!("name=^/{name}$"),
    ])
    .ok_or_else(|| "failed to list the exact Docker container name".to_string())
}

fn docker_output(args: &[&str]) -> Result<Output, String> {
    let mut local_engine_args = Vec::with_capacity(args.len() + 1);
    local_engine_args.push(DOCKER_HOST_ARG);
    local_engine_args.extend_from_slice(args);
    command_output_bounded("docker", &local_engine_args, SUBPROCESS_TIMEOUT)
}

fn docker_command_succeeds(args: &[&str]) -> bool {
    docker_output(args)
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn docker_output_lines(args: &[&str]) -> Option<Vec<String>> {
    let output = docker_output(args).ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    Some(
        stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect(),
    )
}

fn running_container_ids() -> Option<Vec<String>> {
    let mut ids = docker_output_lines(&["ps", "--quiet", "--no-trunc"])?;
    if !ids.iter().all(|id| is_full_docker_id(id)) {
        return None;
    }
    ids.sort();
    Some(ids)
}

fn docker_service_state() -> Option<Vec<u8>> {
    let output = command_output_bounded(
        "systemctl",
        &[
            "show",
            "docker.service",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--value",
        ],
        SUBPROCESS_TIMEOUT,
    )
    .ok()?;
    output.status.success().then_some(output.stdout)
}

fn command_output_bounded(
    command: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Output, String> {
    let mut child = Command::new(command)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", "/tmp")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "failed to start bounded subprocess".to_string())?;
    let deadline = Instant::now() + timeout;
    loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                return Err("failed to poll bounded subprocess".to_string());
            }
        };
        match status {
            Some(_) => {
                return child
                    .wait_with_output()
                    .map_err(|_| "failed to collect bounded subprocess".to_string())
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                return Err("bounded subprocess timed out".to_string());
            }
            None => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn is_full_docker_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn live_id() -> Option<String> {
    let uuid = std::fs::read_to_string("/proc/sys/kernel/random/uuid").ok()?;
    let uuid = uuid.trim();
    if uuid.len() != 36
        || !uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'),
        })
    {
        return None;
    }
    Some(uuid.replace('-', ""))
}

fn private_live_bpf_object() -> Result<PathBuf, &'static str> {
    let path = std::env::var_os(LIVE_BPF_OBJECT)
        .map(PathBuf::from)
        .ok_or("the private live BPF object was not provided")?;
    if !path.is_absolute()
        || !path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
        || path.file_name().and_then(|name| name.to_str()) != Some("apolysis_observer.bpf.o")
    {
        return Err("the private live BPF object path is invalid");
    }
    let parent = path
        .parent()
        .ok_or("the private live BPF object parent is missing")?;
    let parent_name = parent
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("apolysis-runtime-binding-live."))
        .ok_or("the private live BPF object parent is invalid")?;
    if parent.parent() != Some(Path::new("/tmp"))
        || parent_name.len() != 8
        || !parent_name.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err("the private live BPF object parent is invalid");
    }
    let parent_metadata = std::fs::symlink_metadata(parent)
        .map_err(|_| "the private live BPF object parent is unavailable")?;
    let object_metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| "the private live BPF object is unavailable")?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.file_type().is_symlink()
        || parent_metadata.uid() != 0
        || parent_metadata.gid() != 0
        || parent_metadata.permissions().mode() & 0o7777 != 0o700
        || !object_metadata.file_type().is_file()
        || object_metadata.file_type().is_symlink()
        || object_metadata.nlink() != 1
        || object_metadata.uid() != 0
        || object_metadata.gid() != 0
        || object_metadata.permissions().mode() & 0o7777 != 0o400
    {
        return Err("the private live BPF object identity is unsafe");
    }
    Ok(path)
}
