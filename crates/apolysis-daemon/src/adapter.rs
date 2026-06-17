// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use apolysis_accountability::{AdapterKind, AssociationOutcome, ComponentState};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::oneshot;

use crate::DaemonState;

pub const APOLYSIS_SESSION_LABEL: &str = "apolysis.session_id";
pub const APOLYSIS_SESSION_ANNOTATION: &str = "apolysis.dev/session-id";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeWorkload {
    pub adapter: AdapterKind,
    pub session_id: String,
    pub workload_id: String,
    pub cgroup_id: u64,
    pub image: Option<String>,
    pub runtime_handler: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerContainerSnapshot {
    pub container_id: String,
    pub labels: BTreeMap<String, String>,
    pub cgroup_id: u64,
    pub image: Option<String>,
    pub runtime_handler: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContainerdTaskSnapshot {
    pub adapter: AdapterKind,
    pub namespace: String,
    pub container_id: String,
    pub labels: BTreeMap<String, String>,
    pub cgroup_id: u64,
    pub image: Option<String>,
    pub runtime_handler: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesPodSnapshot {
    pub namespace: String,
    pub pod_name: String,
    pub pod_uid: Option<String>,
    pub annotations: BTreeMap<String, String>,
    pub cgroup_id: u64,
    pub runtime_class_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerEngineClient {
    socket_path: PathBuf,
}

impl DockerEngineClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    pub async fn inspect_container(&self, container_id: &str) -> Result<Value, String> {
        let container_id = container_id.trim();
        if container_id.is_empty()
            || container_id
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == b'/')
        {
            return Err("Docker container id must be non-empty and path-safe".to_string());
        }
        self.get_json(&format!("/containers/{container_id}/json"))
            .await
    }

    pub async fn list_marked_running_container_ids(&self) -> Result<Vec<String>, String> {
        marked_container_ids_from_list(self.get_json("/containers/json").await?)
    }

    async fn get_json(&self, path: &str) -> Result<Value, String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|error| {
                format!(
                    "failed to connect Docker Engine socket {}: {error}",
                    self.socket_path.display()
                )
            })?;
        let request = format!("GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| format!("failed to write Docker Engine request: {error}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|error| format!("failed to read Docker Engine response: {error}"))?;
        parse_http_json_response(&response)
    }
}

fn marked_container_ids_from_list(value: Value) -> Result<Vec<String>, String> {
    let containers = value
        .as_array()
        .ok_or_else(|| "Docker Engine /containers/json response must be an array".to_string())?;
    let mut ids = Vec::new();
    for container in containers {
        let labels = container
            .get("Labels")
            .and_then(Value::as_object)
            .ok_or_else(|| "Docker container summary Labels must be an object".to_string())?;
        let marked = labels
            .get(APOLYSIS_SESSION_LABEL)
            .and_then(Value::as_str)
            .map(str::trim)
            .map(|session_id| !session_id.is_empty())
            .unwrap_or(false);
        if !marked {
            continue;
        }
        let id = container
            .get("Id")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| "Docker marked container summary Id must be non-empty".to_string())?;
        ids.push(id.to_string());
    }
    Ok(ids)
}

pub struct DockerEngineRuntimeAdapter {
    client: DockerEngineClient,
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    pending_container_ids: VecDeque<String>,
}

pub struct DockerEnginePollingRuntimeAdapter {
    client: DockerEngineClient,
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    pending_container_ids: VecDeque<String>,
    seen_container_ids: BTreeSet<String>,
    seen_capacity: usize,
    scan_interval: Duration,
}

impl DockerEnginePollingRuntimeAdapter {
    pub fn new(
        client: DockerEngineClient,
        proc_root: impl Into<PathBuf>,
        cgroup_root: impl Into<PathBuf>,
        scan_interval: Duration,
        seen_capacity: usize,
    ) -> Self {
        Self {
            client,
            proc_root: proc_root.into(),
            cgroup_root: cgroup_root.into(),
            pending_container_ids: VecDeque::new(),
            seen_container_ids: BTreeSet::new(),
            seen_capacity,
            scan_interval,
        }
    }

    async fn next_polled_workload(&mut self) -> Result<Option<RuntimeWorkload>, String> {
        loop {
            while let Some(container_id) = self.pending_container_ids.pop_front() {
                if let Some(workload) = docker_workload_from_client(
                    &self.client,
                    &self.proc_root,
                    &self.cgroup_root,
                    &container_id,
                )
                .await?
                {
                    return Ok(Some(workload));
                }
            }
            self.pending_container_ids = self
                .client
                .list_marked_running_container_ids()
                .await?
                .into_iter()
                .filter(|container_id| {
                    remember_seen(
                        &mut self.seen_container_ids,
                        self.seen_capacity,
                        container_id,
                    )
                })
                .collect();
            if self.pending_container_ids.is_empty() {
                tokio::time::sleep(self.scan_interval).await;
            }
        }
    }
}

impl RuntimeAdapterBackend for DockerEnginePollingRuntimeAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Docker
    }

    fn next_workload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RuntimeWorkload>, String>> + Send + '_>> {
        Box::pin(self.next_polled_workload())
    }
}

impl DockerEngineRuntimeAdapter {
    pub fn new(
        client: DockerEngineClient,
        proc_root: impl Into<PathBuf>,
        cgroup_root: impl Into<PathBuf>,
        container_ids: Vec<String>,
    ) -> Self {
        Self {
            client,
            proc_root: proc_root.into(),
            cgroup_root: cgroup_root.into(),
            pending_container_ids: container_ids.into(),
        }
    }

    async fn next_docker_workload(&mut self) -> Result<Option<RuntimeWorkload>, String> {
        while let Some(container_id) = self.pending_container_ids.pop_front() {
            if let Some(workload) = docker_workload_from_client(
                &self.client,
                &self.proc_root,
                &self.cgroup_root,
                &container_id,
            )
            .await?
            {
                return Ok(Some(workload));
            }
        }
        Ok(None)
    }
}

async fn docker_workload_from_client(
    client: &DockerEngineClient,
    proc_root: &Path,
    cgroup_root: &Path,
    container_id: &str,
) -> Result<Option<RuntimeWorkload>, String> {
    let inspect = client.inspect_container(container_id).await?;
    let pid = docker_container_pid_from_engine_inspect(&inspect)?;
    let cgroup_id = cgroup_id_from_pid(pid, proc_root, cgroup_root)?;
    let snapshot = docker_snapshot_from_engine_inspect(&inspect, cgroup_id)?;
    docker_workload_from_snapshot(snapshot)
}

impl RuntimeAdapterBackend for DockerEngineRuntimeAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Docker
    }

    fn next_workload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RuntimeWorkload>, String>> + Send + '_>> {
        Box::pin(self.next_docker_workload())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeAdapterSummary {
    pub adapter: AdapterKind,
    pub discovered: u64,
    pub missing_intent: u64,
    pub backend_errors: u64,
    pub ingest_errors: u64,
}

pub trait RuntimeAdapterBackend: Send + 'static {
    fn kind(&self) -> AdapterKind;
    fn next_workload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RuntimeWorkload>, String>> + Send + '_>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdapterBackoffPolicy {
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub jitter_ms: u64,
}

impl Default for AdapterBackoffPolicy {
    fn default() -> Self {
        Self {
            initial_delay_ms: 250,
            max_delay_ms: 5_000,
            jitter_ms: 100,
        }
    }
}

pub fn adapter_backoff_delay(
    policy: AdapterBackoffPolicy,
    adapter: AdapterKind,
    consecutive_errors: u64,
) -> Duration {
    let initial = policy.initial_delay_ms.max(1);
    let max_delay = policy.max_delay_ms.max(initial);
    let exponent = consecutive_errors.saturating_sub(1).min(16);
    let base = initial.saturating_mul(1_u64 << exponent).min(max_delay);
    let jitter = if policy.jitter_ms == 0 {
        0
    } else {
        let adapter_seed = match adapter {
            AdapterKind::Docker => 11,
            AdapterKind::Containerd => 23,
            AdapterKind::K3sContainerd => 37,
            AdapterKind::Kubernetes => 53,
        };
        (adapter_seed + consecutive_errors.saturating_mul(17)) % (policy.jitter_ms + 1)
    };
    Duration::from_millis(base.saturating_add(jitter))
}

pub fn crictl_marked_container_ids_from_ps(value: Value) -> Result<Vec<String>, String> {
    let containers = value
        .get("containers")
        .and_then(Value::as_array)
        .ok_or_else(|| "crictl ps JSON must contain containers array".to_string())?;
    let mut ids = Vec::new();
    for container in containers {
        if string_field(container, &["state"]).as_deref() != Some("CONTAINER_RUNNING") {
            continue;
        }
        let labels = string_map_field(container, &["labels"], "CRI container labels")?;
        let marked = labels
            .get(APOLYSIS_SESSION_LABEL)
            .map(String::as_str)
            .map(str::trim)
            .map(|session_id| !session_id.is_empty())
            .unwrap_or(false);
        if !marked {
            continue;
        }
        let id = string_field(container, &["id"])
            .ok_or_else(|| "marked CRI container id must be non-empty".to_string())?;
        ids.push(id);
    }
    Ok(ids)
}

pub fn containerd_task_snapshot_from_cri_inspect(
    adapter: AdapterKind,
    inspect: &Value,
    cgroup_id: u64,
) -> Result<ContainerdTaskSnapshot, String> {
    if !matches!(
        adapter,
        AdapterKind::Containerd | AdapterKind::K3sContainerd
    ) {
        return Err("CRI inspect adapter must be containerd or k3s_containerd".to_string());
    }
    if cgroup_id == 0 {
        return Err("CRI cgroup id must be non-zero".to_string());
    }
    let container_id = string_field(inspect, &["status", "id"])
        .ok_or_else(|| "CRI inspect status.id must be a non-empty string".to_string())?;
    let labels = string_map_field(inspect, &["status", "labels"], "CRI status.labels")?;
    let namespace = labels
        .get("io.kubernetes.pod.namespace")
        .cloned()
        .or_else(|| {
            string_field(
                inspect,
                &[
                    "info",
                    "runtimeSpec",
                    "annotations",
                    "io.kubernetes.cri.sandbox-namespace",
                ],
            )
        })
        .unwrap_or_else(|| "default".to_string());
    let image = string_field(inspect, &["status", "image", "userSpecifiedImage"])
        .or_else(|| string_field(inspect, &["status", "image", "image"]))
        .or_else(|| string_field(inspect, &["status", "imageRef"]));
    let runtime_handler = string_field(inspect, &["info", "runtimeType"])
        .or_else(|| string_field(inspect, &["status", "image", "runtimeHandler"]));

    Ok(ContainerdTaskSnapshot {
        adapter,
        namespace,
        container_id,
        labels,
        cgroup_id,
        image,
        runtime_handler,
    })
}

pub fn docker_workload_from_snapshot(
    snapshot: DockerContainerSnapshot,
) -> Result<Option<RuntimeWorkload>, String> {
    let Some(session_id) = snapshot.labels.get(APOLYSIS_SESSION_LABEL) else {
        return Ok(None);
    };
    let session_id = session_id.trim();
    if session_id.is_empty() {
        return Err(format!("{APOLYSIS_SESSION_LABEL} must not be empty"));
    }
    if snapshot.container_id.trim().is_empty() {
        return Err("Docker container id must not be empty".to_string());
    }
    if snapshot.cgroup_id == 0 {
        return Err("Docker cgroup id must be non-zero".to_string());
    }
    Ok(Some(RuntimeWorkload {
        adapter: AdapterKind::Docker,
        session_id: session_id.to_string(),
        workload_id: snapshot.container_id,
        cgroup_id: snapshot.cgroup_id,
        image: snapshot.image,
        runtime_handler: snapshot.runtime_handler,
    }))
}

pub fn containerd_workload_from_snapshot(
    snapshot: ContainerdTaskSnapshot,
) -> Result<Option<RuntimeWorkload>, String> {
    if !matches!(
        snapshot.adapter,
        AdapterKind::Containerd | AdapterKind::K3sContainerd
    ) {
        return Err("containerd snapshot adapter must be containerd or k3s_containerd".to_string());
    }
    let Some(session_id) = snapshot.labels.get(APOLYSIS_SESSION_LABEL) else {
        return Ok(None);
    };
    let session_id = session_id.trim();
    if session_id.is_empty() {
        return Err(format!("{APOLYSIS_SESSION_LABEL} must not be empty"));
    }
    let namespace = snapshot.namespace.trim();
    if namespace.is_empty() {
        return Err("containerd namespace must not be empty".to_string());
    }
    let container_id = snapshot.container_id.trim();
    if container_id.is_empty() {
        return Err("containerd container id must not be empty".to_string());
    }
    if snapshot.cgroup_id == 0 {
        return Err("containerd cgroup id must be non-zero".to_string());
    }

    Ok(Some(RuntimeWorkload {
        adapter: snapshot.adapter,
        session_id: session_id.to_string(),
        workload_id: format!("{namespace}/{container_id}"),
        cgroup_id: snapshot.cgroup_id,
        image: snapshot.image,
        runtime_handler: snapshot.runtime_handler,
    }))
}

pub fn containerd_task_snapshot_from_metadata(
    adapter: AdapterKind,
    metadata: &Value,
    cgroup_id: u64,
) -> Result<ContainerdTaskSnapshot, String> {
    if !matches!(
        adapter,
        AdapterKind::Containerd | AdapterKind::K3sContainerd
    ) {
        return Err("containerd metadata adapter must be containerd or k3s_containerd".to_string());
    }
    if cgroup_id == 0 {
        return Err("containerd cgroup id must be non-zero".to_string());
    }
    let namespace = string_field(metadata, &["namespace"])
        .ok_or_else(|| "containerd namespace must be a non-empty string".to_string())?;
    let container_id = string_field(metadata, &["id"])
        .ok_or_else(|| "containerd task id must be a non-empty string".to_string())?;
    Ok(ContainerdTaskSnapshot {
        adapter,
        namespace,
        container_id,
        labels: string_map_field(metadata, &["labels"], "containerd labels")?,
        cgroup_id,
        image: string_field(metadata, &["image"]),
        runtime_handler: string_field(metadata, &["runtime", "name"])
            .or_else(|| string_field(metadata, &["runtime", "runtime_type"])),
    })
}

pub fn kubernetes_workload_from_pod_snapshot(
    snapshot: KubernetesPodSnapshot,
) -> Result<Option<RuntimeWorkload>, String> {
    let Some(session_id) = snapshot.annotations.get(APOLYSIS_SESSION_ANNOTATION) else {
        return Ok(None);
    };
    let session_id = session_id.trim();
    if session_id.is_empty() {
        return Err(format!("{APOLYSIS_SESSION_ANNOTATION} must not be empty"));
    }
    let namespace = snapshot.namespace.trim();
    if namespace.is_empty() {
        return Err("Kubernetes namespace must not be empty".to_string());
    }
    let pod_name = snapshot.pod_name.trim();
    if pod_name.is_empty() {
        return Err("Kubernetes pod name must not be empty".to_string());
    }
    if snapshot.cgroup_id == 0 {
        return Err("Kubernetes cgroup id must be non-zero".to_string());
    }
    let workload_id = snapshot
        .pod_uid
        .as_deref()
        .map(str::trim)
        .filter(|uid| !uid.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("{namespace}/{pod_name}"));

    Ok(Some(RuntimeWorkload {
        adapter: AdapterKind::Kubernetes,
        session_id: session_id.to_string(),
        workload_id,
        cgroup_id: snapshot.cgroup_id,
        image: None,
        runtime_handler: snapshot.runtime_class_name,
    }))
}

pub fn kubernetes_pod_snapshot_from_api_object(
    pod: &Value,
    cgroup_id: u64,
) -> Result<KubernetesPodSnapshot, String> {
    if cgroup_id == 0 {
        return Err("Kubernetes cgroup id must be non-zero".to_string());
    }
    let namespace = string_field(pod, &["metadata", "namespace"]).ok_or_else(|| {
        "Kubernetes Pod metadata.namespace must be a non-empty string".to_string()
    })?;
    let pod_name = string_field(pod, &["metadata", "name"])
        .ok_or_else(|| "Kubernetes Pod metadata.name must be a non-empty string".to_string())?;
    Ok(KubernetesPodSnapshot {
        namespace,
        pod_name,
        pod_uid: string_field(pod, &["metadata", "uid"]),
        annotations: string_map_field(
            pod,
            &["metadata", "annotations"],
            "Kubernetes Pod metadata.annotations",
        )?,
        cgroup_id,
        runtime_class_name: string_field(pod, &["spec", "runtimeClassName"]),
    })
}

pub fn kubernetes_marked_pod_snapshots_from_api_list(
    pod_list: &Value,
    container_cgroups: &BTreeMap<String, u64>,
) -> Result<Vec<KubernetesPodSnapshot>, String> {
    let pods = pod_list
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "Kubernetes PodList must contain items array".to_string())?;
    let mut snapshots = Vec::new();
    for pod in pods {
        let annotations = string_map_field(
            pod,
            &["metadata", "annotations"],
            "Kubernetes Pod metadata.annotations",
        )?;
        let marked = annotations
            .get(APOLYSIS_SESSION_ANNOTATION)
            .map(String::as_str)
            .map(str::trim)
            .map(|session_id| !session_id.is_empty())
            .unwrap_or(false);
        if !marked {
            continue;
        }
        if string_field(pod, &["status", "phase"]).as_deref() != Some("Running") {
            continue;
        }
        let Some(cgroup_id) = kubernetes_container_ids(pod)
            .into_iter()
            .find_map(|container_id| container_cgroups.get(&container_id).copied())
        else {
            return Err(format!(
                "Kubernetes marked Pod {} has no known running container cgroup",
                string_field(pod, &["metadata", "name"]).unwrap_or_else(|| "<unknown>".to_string())
            ));
        };
        snapshots.push(kubernetes_pod_snapshot_from_api_object(pod, cgroup_id)?);
    }
    Ok(snapshots)
}

pub fn docker_snapshot_from_engine_inspect(
    inspect: &Value,
    cgroup_id: u64,
) -> Result<DockerContainerSnapshot, String> {
    if cgroup_id == 0 {
        return Err("Docker cgroup id must be non-zero".to_string());
    }
    let container_id = string_field(inspect, &["Id"])
        .ok_or_else(|| "Docker inspect field Id must be a non-empty string".to_string())?;
    let labels = labels_field(inspect, &["Config", "Labels"])?;
    let image =
        string_field(inspect, &["Config", "Image"]).or_else(|| string_field(inspect, &["Image"]));
    let runtime_handler = string_field(inspect, &["HostConfig", "Runtime"]);

    Ok(DockerContainerSnapshot {
        container_id,
        labels,
        cgroup_id,
        image,
        runtime_handler,
    })
}

pub fn docker_container_pid_from_engine_inspect(inspect: &Value) -> Result<u32, String> {
    let pid = inspect
        .get("State")
        .and_then(|state| state.get("Pid"))
        .and_then(Value::as_u64)
        .ok_or_else(|| "Docker inspect State.Pid must be a positive integer".to_string())?;
    if pid == 0 {
        return Err("Docker container is not running; State.Pid is zero".to_string());
    }
    u32::try_from(pid).map_err(|_| format!("Docker inspect State.Pid exceeds u32: {pid}"))
}

pub fn cgroup_id_from_proc_cgroup(proc_cgroup: &str, cgroup_root: &Path) -> Result<u64, String> {
    let relative = proc_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "process cgroup data does not contain a cgroup v2 entry".to_string())?
        .trim();
    let path = cgroup_root.join(relative.trim_start_matches('/'));
    std::fs::metadata(&path)
        .map_err(|error| format!("failed to stat cgroup path {}: {error}", path.display()))
        .map(|metadata| metadata.ino())
}

fn cgroup_id_from_pid(pid: u32, proc_root: &Path, cgroup_root: &Path) -> Result<u64, String> {
    let proc_cgroup_path = proc_root.join(pid.to_string()).join("cgroup");
    let proc_cgroup = std::fs::read_to_string(&proc_cgroup_path).map_err(|error| {
        format!(
            "failed to read process cgroup file {}: {error}",
            proc_cgroup_path.display()
        )
    })?;
    cgroup_id_from_proc_cgroup(&proc_cgroup, cgroup_root)
}

fn containerd_pid_from_cri_inspect(inspect: &Value) -> Result<u32, String> {
    let pid = inspect
        .get("info")
        .and_then(|info| info.get("pid"))
        .and_then(Value::as_u64)
        .ok_or_else(|| "CRI inspect info.pid must be a positive integer".to_string())?;
    if pid == 0 {
        return Err("CRI container is not running; info.pid is zero".to_string());
    }
    u32::try_from(pid).map_err(|_| format!("CRI inspect info.pid exceeds u32: {pid}"))
}

pub async fn run_runtime_adapter<B: RuntimeAdapterBackend>(
    backend: B,
    state: Arc<DaemonState>,
    shutdown: oneshot::Receiver<()>,
) -> RuntimeAdapterSummary {
    run_runtime_adapter_with_policy(backend, state, shutdown, AdapterBackoffPolicy::default()).await
}

pub async fn run_runtime_adapter_with_policy<B: RuntimeAdapterBackend>(
    mut backend: B,
    state: Arc<DaemonState>,
    mut shutdown: oneshot::Receiver<()>,
    backoff_policy: AdapterBackoffPolicy,
) -> RuntimeAdapterSummary {
    let adapter = backend.kind();
    let mut summary = RuntimeAdapterSummary {
        adapter,
        discovered: 0,
        missing_intent: 0,
        backend_errors: 0,
        ingest_errors: 0,
    };
    let mut consecutive_backend_errors = 0_u64;

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            workload = backend.next_workload() => {
                match workload {
                    Ok(Some(workload)) => {
                        consecutive_backend_errors = 0;
                        match state.ingest_runtime_workload(workload).await {
                            Ok(AssociationOutcome::Attached) => {
                                summary.discovered = summary.discovered.saturating_add(1);
                            }
                            Ok(AssociationOutcome::MissingIntent) => {
                                summary.discovered = summary.discovered.saturating_add(1);
                                summary.missing_intent = summary.missing_intent.saturating_add(1);
                            }
                            Err(_) => {
                                summary.ingest_errors = summary.ingest_errors.saturating_add(1);
                                state.set_adapter(adapter, ComponentState::Degraded).await;
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(_) => {
                        consecutive_backend_errors = consecutive_backend_errors.saturating_add(1);
                        summary.backend_errors = summary.backend_errors.saturating_add(1);
                        state.set_adapter(adapter, ComponentState::Degraded).await;
                        let delay = adapter_backoff_delay(
                            backoff_policy,
                            adapter,
                            consecutive_backend_errors,
                        );
                        tokio::select! {
                            _ = &mut shutdown => break,
                            _ = tokio::time::sleep(delay) => {}
                        }
                    }
                }
            }
        }
    }

    summary
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriRuntimeClient {
    crictl_path: PathBuf,
    runtime_endpoint: String,
    image_endpoint: Option<String>,
    timeout: Duration,
}

impl CriRuntimeClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        let endpoint = format!("unix://{}", socket_path.as_ref().display());
        Self {
            crictl_path: PathBuf::from("crictl"),
            runtime_endpoint: endpoint.clone(),
            image_endpoint: Some(endpoint),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_crictl_path(mut self, crictl_path: impl Into<PathBuf>) -> Self {
        self.crictl_path = crictl_path.into();
        self
    }

    pub fn with_image_endpoint(mut self, image_endpoint: Option<String>) -> Self {
        self.image_endpoint = image_endpoint;
        self
    }

    pub async fn list_marked_running_container_ids(&self) -> Result<Vec<String>, String> {
        crictl_marked_container_ids_from_ps(self.crictl_json(&["ps", "-o", "json"])?)
    }

    pub async fn inspect_container(&self, container_id: &str) -> Result<Value, String> {
        let container_id = container_id.trim();
        if container_id.is_empty()
            || container_id
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte == b'/')
        {
            return Err("CRI container id must be non-empty and path-safe".to_string());
        }
        self.crictl_json(&["inspect", "-o", "json", container_id])
    }

    fn crictl_json(&self, command_args: &[&str]) -> Result<Value, String> {
        let timeout = format!("{}s", self.timeout.as_secs().max(1));
        let mut command = Command::new(&self.crictl_path);
        command
            .arg("--config")
            .arg("/dev/null")
            .arg("--runtime-endpoint")
            .arg(&self.runtime_endpoint)
            .arg("--timeout")
            .arg(&timeout);
        if let Some(image_endpoint) = &self.image_endpoint {
            command.arg("--image-endpoint").arg(image_endpoint);
        }
        command.args(command_args);
        let output = command.output().map_err(|error| {
            format!(
                "failed to run {}: {error}",
                self.crictl_path.as_path().display()
            )
        })?;
        if !output.status.success() {
            return Err(format!(
                "crictl {:?} failed: {}",
                command_args,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("failed to decode crictl JSON: {error}"))
    }
}

pub struct ContainerdCriRuntimeAdapter {
    adapter: AdapterKind,
    client: CriRuntimeClient,
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    pending_container_ids: VecDeque<String>,
    seen_container_ids: BTreeSet<String>,
    seen_capacity: usize,
    scan_interval: Duration,
}

impl ContainerdCriRuntimeAdapter {
    pub fn new(
        adapter: AdapterKind,
        client: CriRuntimeClient,
        proc_root: impl Into<PathBuf>,
        cgroup_root: impl Into<PathBuf>,
        scan_interval: Duration,
        seen_capacity: usize,
    ) -> Result<Self, String> {
        if !matches!(
            adapter,
            AdapterKind::Containerd | AdapterKind::K3sContainerd
        ) {
            return Err("CRI runtime adapter must be containerd or k3s_containerd".to_string());
        }
        Ok(Self {
            adapter,
            client,
            proc_root: proc_root.into(),
            cgroup_root: cgroup_root.into(),
            pending_container_ids: VecDeque::new(),
            seen_container_ids: BTreeSet::new(),
            seen_capacity,
            scan_interval,
        })
    }

    async fn next_cri_workload(&mut self) -> Result<Option<RuntimeWorkload>, String> {
        loop {
            while let Some(container_id) = self.pending_container_ids.pop_front() {
                let inspect = self.client.inspect_container(&container_id).await?;
                let pid = containerd_pid_from_cri_inspect(&inspect)?;
                let cgroup_id = cgroup_id_from_pid(pid, &self.proc_root, &self.cgroup_root)?;
                let snapshot =
                    containerd_task_snapshot_from_cri_inspect(self.adapter, &inspect, cgroup_id)?;
                if let Some(workload) = containerd_workload_from_snapshot(snapshot)? {
                    return Ok(Some(workload));
                }
            }
            self.pending_container_ids = self
                .client
                .list_marked_running_container_ids()
                .await?
                .into_iter()
                .filter(|container_id| {
                    remember_seen(
                        &mut self.seen_container_ids,
                        self.seen_capacity,
                        container_id,
                    )
                })
                .collect();
            if self.pending_container_ids.is_empty() {
                tokio::time::sleep(self.scan_interval).await;
            }
        }
    }
}

impl RuntimeAdapterBackend for ContainerdCriRuntimeAdapter {
    fn kind(&self) -> AdapterKind {
        self.adapter
    }

    fn next_workload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RuntimeWorkload>, String>> + Send + '_>> {
        Box::pin(self.next_cri_workload())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesCliClient {
    kubectl_path: PathBuf,
}

impl KubernetesCliClient {
    pub fn new(kubectl_path: impl Into<PathBuf>) -> Self {
        Self {
            kubectl_path: kubectl_path.into(),
        }
    }

    pub async fn list_pods(&self) -> Result<Value, String> {
        let output = Command::new(&self.kubectl_path)
            .args(["get", "pods", "--all-namespaces", "-o", "json"])
            .output()
            .map_err(|error| {
                format!(
                    "failed to run {}: {error}",
                    self.kubectl_path.as_path().display()
                )
            })?;
        if !output.status.success() {
            return Err(format!(
                "kubectl get pods failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("failed to decode Kubernetes PodList JSON: {error}"))
    }
}

pub struct KubernetesCliRuntimeAdapter {
    kubernetes: KubernetesCliClient,
    cri: CriRuntimeClient,
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    seen_pod_uids: BTreeSet<String>,
    seen_capacity: usize,
    pending_snapshots: VecDeque<KubernetesPodSnapshot>,
    scan_interval: Duration,
}

impl KubernetesCliRuntimeAdapter {
    pub fn new(
        kubernetes: KubernetesCliClient,
        cri: CriRuntimeClient,
        proc_root: impl Into<PathBuf>,
        cgroup_root: impl Into<PathBuf>,
        scan_interval: Duration,
        seen_capacity: usize,
    ) -> Self {
        Self {
            kubernetes,
            cri,
            proc_root: proc_root.into(),
            cgroup_root: cgroup_root.into(),
            seen_pod_uids: BTreeSet::new(),
            seen_capacity,
            pending_snapshots: VecDeque::new(),
            scan_interval,
        }
    }

    async fn next_kubernetes_workload(&mut self) -> Result<Option<RuntimeWorkload>, String> {
        loop {
            while let Some(snapshot) = self.pending_snapshots.pop_front() {
                if let Some(workload) = kubernetes_workload_from_pod_snapshot(snapshot)? {
                    return Ok(Some(workload));
                }
            }
            let pod_list = self.kubernetes.list_pods().await?;
            let cgroups = self.container_cgroups_from_pod_list(&pod_list).await?;
            self.pending_snapshots =
                kubernetes_marked_pod_snapshots_from_api_list(&pod_list, &cgroups)?
                    .into_iter()
                    .filter(|snapshot| {
                        let key = snapshot
                            .pod_uid
                            .as_deref()
                            .unwrap_or(&snapshot.pod_name)
                            .to_string();
                        remember_seen(&mut self.seen_pod_uids, self.seen_capacity, &key)
                    })
                    .collect();
            if self.pending_snapshots.is_empty() {
                tokio::time::sleep(self.scan_interval).await;
            }
        }
    }

    async fn container_cgroups_from_pod_list(
        &self,
        pod_list: &Value,
    ) -> Result<BTreeMap<String, u64>, String> {
        let mut cgroups = BTreeMap::new();
        for container_id in kubernetes_marked_running_container_ids_from_list(pod_list)? {
            let inspect = self.cri.inspect_container(&container_id).await?;
            let pid = containerd_pid_from_cri_inspect(&inspect)?;
            let cgroup_id = cgroup_id_from_pid(pid, &self.proc_root, &self.cgroup_root)?;
            cgroups.insert(container_id, cgroup_id);
        }
        Ok(cgroups)
    }
}

impl RuntimeAdapterBackend for KubernetesCliRuntimeAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Kubernetes
    }

    fn next_workload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RuntimeWorkload>, String>> + Send + '_>> {
        Box::pin(self.next_kubernetes_workload())
    }
}

fn string_field(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(segment)?;
    }
    current
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(ToOwned::to_owned)
}

fn labels_field(value: &Value, path: &[&str]) -> Result<BTreeMap<String, String>, String> {
    string_map_field(value, path, "Docker inspect Config.Labels")
}

fn string_map_field(
    value: &Value,
    path: &[&str],
    field_name: &str,
) -> Result<BTreeMap<String, String>, String> {
    let mut current = value;
    for segment in path {
        let Some(next) = current.get(segment) else {
            return Ok(BTreeMap::new());
        };
        if next.is_null() {
            return Ok(BTreeMap::new());
        }
        current = next;
    }
    let object = current
        .as_object()
        .ok_or_else(|| format!("{field_name} must be an object when present"))?;
    let mut labels = BTreeMap::new();
    for (key, value) in object {
        let Some(label_value) = value.as_str() else {
            return Err(format!("{field_name} entry {key} must be a string"));
        };
        labels.insert(key.clone(), label_value.to_string());
    }
    Ok(labels)
}

fn kubernetes_marked_running_container_ids_from_list(
    pod_list: &Value,
) -> Result<BTreeSet<String>, String> {
    let pods = pod_list
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "Kubernetes PodList must contain items array".to_string())?;
    let mut ids = BTreeSet::new();
    for pod in pods {
        let annotations = string_map_field(
            pod,
            &["metadata", "annotations"],
            "Kubernetes Pod metadata.annotations",
        )?;
        let marked = annotations
            .get(APOLYSIS_SESSION_ANNOTATION)
            .map(String::as_str)
            .map(str::trim)
            .map(|session_id| !session_id.is_empty())
            .unwrap_or(false);
        if !marked || string_field(pod, &["status", "phase"]).as_deref() != Some("Running") {
            continue;
        }
        ids.extend(kubernetes_container_ids(pod));
    }
    Ok(ids)
}

fn kubernetes_container_ids(pod: &Value) -> Vec<String> {
    pod.get("status")
        .and_then(|status| status.get("containerStatuses"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|status| {
            status
                .get("containerID")
                .and_then(Value::as_str)
                .map(str::trim)
                .and_then(|container_id| {
                    container_id
                        .strip_prefix("containerd://")
                        .or_else(|| container_id.strip_prefix("cri-containerd://"))
                        .or_else(|| container_id.strip_prefix("docker://"))
                        .or(Some(container_id))
                })
                .map(str::trim)
                .filter(|container_id| !container_id.is_empty())
                .map(ToOwned::to_owned)
        })
        .collect()
}

fn remember_seen(seen: &mut BTreeSet<String>, seen_capacity: usize, id: &str) -> bool {
    if seen.contains(id) {
        return false;
    }
    if seen_capacity > 0 && seen.len() >= seen_capacity {
        if let Some(first) = seen.iter().next().cloned() {
            seen.remove(&first);
        }
    }
    seen.insert(id.to_string());
    true
}

fn parse_http_json_response(response: &[u8]) -> Result<Value, String> {
    let Some(split) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err("Docker Engine response missing header terminator".to_string());
    };
    let headers = std::str::from_utf8(&response[..split])
        .map_err(|error| format!("Docker Engine response headers are not UTF-8: {error}"))?;
    let status = headers
        .lines()
        .next()
        .ok_or_else(|| "Docker Engine response missing status line".to_string())?;
    if !status.contains(" 200 ") {
        return Err(format!("Docker Engine request failed: {status}"));
    }
    let body = &response[split + 4..];
    let decoded_body;
    let body = if has_header_value(headers, "transfer-encoding", "chunked") {
        decoded_body = decode_chunked_body(body)?;
        decoded_body.as_slice()
    } else if let Some(length) = content_length(headers)? {
        if body.len() < length {
            return Err(format!(
                "Docker Engine response body shorter than Content-Length: {} < {length}",
                body.len()
            ));
        }
        &body[..length]
    } else {
        body
    };
    serde_json::from_slice(body)
        .map_err(|error| format!("failed to decode Docker Engine JSON response: {error}"))
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::new();
    let mut index = 0;
    loop {
        let size_end = find_crlf(body, index).ok_or_else(|| {
            "Docker Engine chunked body missing chunk size terminator".to_string()
        })?;
        let size_line = std::str::from_utf8(&body[index..size_end])
            .map_err(|error| format!("Docker Engine chunk size is not UTF-8: {error}"))?;
        let size_token = size_line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_token, 16)
            .map_err(|error| format!("invalid Docker Engine chunk size {size_token:?}: {error}"))?;
        index = size_end + 2;
        if size == 0 {
            return Ok(decoded);
        }
        let chunk_end = index
            .checked_add(size)
            .ok_or_else(|| "Docker Engine chunk size overflow".to_string())?;
        if body.len() < chunk_end + 2 {
            return Err("Docker Engine chunked body ended inside a chunk".to_string());
        }
        decoded.extend_from_slice(&body[index..chunk_end]);
        if &body[chunk_end..chunk_end + 2] != b"\r\n" {
            return Err("Docker Engine chunk missing trailing CRLF".to_string());
        }
        index = chunk_end + 2;
    }
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

fn has_header_value(headers: &str, name: &str, expected_value: &str) -> bool {
    headers.lines().skip(1).any(|line| {
        line.split_once(':')
            .map(|(header_name, value)| {
                header_name.trim().eq_ignore_ascii_case(name)
                    && value
                        .split(',')
                        .any(|part| part.trim().eq_ignore_ascii_case(expected_value))
            })
            .unwrap_or(false)
    })
}

fn content_length(headers: &str) -> Result<Option<usize>, String> {
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .map(Some)
                .map_err(|error| format!("invalid Docker Engine Content-Length: {error}"));
        }
    }
    Ok(None)
}
