// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

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
            let inspect = self.client.inspect_container(&container_id).await?;
            let pid = docker_container_pid_from_engine_inspect(&inspect)?;
            let proc_cgroup_path = self.proc_root.join(pid.to_string()).join("cgroup");
            let proc_cgroup = std::fs::read_to_string(&proc_cgroup_path).map_err(|error| {
                format!(
                    "failed to read process cgroup file {}: {error}",
                    proc_cgroup_path.display()
                )
            })?;
            let cgroup_id = cgroup_id_from_proc_cgroup(&proc_cgroup, &self.cgroup_root)?;
            let snapshot = docker_snapshot_from_engine_inspect(&inspect, cgroup_id)?;
            if let Some(workload) = docker_workload_from_snapshot(snapshot)? {
                return Ok(Some(workload));
            }
        }
        Ok(None)
    }
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

pub async fn run_runtime_adapter<B: RuntimeAdapterBackend>(
    mut backend: B,
    state: Arc<DaemonState>,
    mut shutdown: oneshot::Receiver<()>,
) -> RuntimeAdapterSummary {
    let adapter = backend.kind();
    let mut summary = RuntimeAdapterSummary {
        adapter,
        discovered: 0,
        missing_intent: 0,
        backend_errors: 0,
        ingest_errors: 0,
    };

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            workload = backend.next_workload() => {
                match workload {
                    Ok(Some(workload)) => {
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
                        summary.backend_errors = summary.backend_errors.saturating_add(1);
                        state.set_adapter(adapter, ComponentState::Degraded).await;
                        tokio::task::yield_now().await;
                    }
                }
            }
        }
    }

    summary
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
