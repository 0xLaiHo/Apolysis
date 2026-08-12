// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{CStr, CString};
use std::future::Future;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use apolysis_accountability::{AdapterKind, AssociationOutcome, ComponentState};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::Command as TokioCommand;
use tokio::sync::oneshot;

use crate::runtime_binding::{
    canonical_cri_rfc3339_to_unix_nanos, validate_cri_start_marker, validate_docker_start_marker,
    validate_runtime_container_id, validate_runtime_workload_identity, CgroupIdentity,
    RuntimeBinding, RuntimeInventory, RuntimeWorkloadIdentity, MAX_RUNTIME_INVENTORY_BINDINGS,
};
use crate::{DaemonState, RuntimeSourceGapReason};

pub const APOLYSIS_SESSION_LABEL: &str = "apolysis.session_id";
pub const APOLYSIS_SESSION_ANNOTATION: &str = "apolysis.dev/session-id";
const APOLYSIS_KUBERNETES_OBSERVE_LABEL: &str = "apolysis.dev/observe";
const MAX_RUNTIME_ADAPTER_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_RUNTIME_ADAPTER_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const CRICTL_EXECUTABLE_CONFIGURATION_ERROR: &str =
    "APOLYSIS_CRICTL must be an absolute secure executable file";
const MAX_CRI_METADATA_MAP_ENTRIES: usize = 512;
const MAX_CRI_METADATA_MAP_BYTES: usize = 512 * 1024;
const MAX_CRI_METADATA_STRING_BYTES: usize = 256 * 1024;

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
pub struct CriContainerCandidate {
    pub container_id: String,
    pub inherited_labels: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CriSandboxMetadataMode {
    Disabled,
    LabelsOnly,
    Kubernetes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerEngineClient {
    socket_path: PathBuf,
    request_timeout: Duration,
}

impl DockerEngineClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            request_timeout: DEFAULT_RUNTIME_ADAPTER_REQUEST_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, request_timeout: Duration) -> Self {
        self.request_timeout = request_timeout;
        self
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
        let request = async {
            let mut stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|error| {
                    format!(
                        "failed to connect Docker Engine socket {}: {error}",
                        self.socket_path.display()
                    )
                })?;
            let request =
                format!("GET {path} HTTP/1.1\r\nHost: docker\r\nConnection: close\r\n\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .map_err(|error| format!("failed to write Docker Engine request: {error}"))?;
            let mut response = Vec::new();
            stream
                .take((MAX_RUNTIME_ADAPTER_RESPONSE_BYTES + 1) as u64)
                .read_to_end(&mut response)
                .await
                .map_err(|error| format!("failed to read Docker Engine response: {error}"))?;
            if response.len() > MAX_RUNTIME_ADAPTER_RESPONSE_BYTES {
                return Err(format!(
                    "Docker Engine response exceeds {MAX_RUNTIME_ADAPTER_RESPONSE_BYTES} bytes"
                ));
            }
            parse_http_json_response(&response)
        };
        tokio::time::timeout(self.request_timeout, request)
            .await
            .map_err(|_| "failed to read Docker Engine response: request timed out".to_string())?
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

    pub async fn scan_inventory(&self) -> Result<RuntimeInventory, String> {
        self.scan_inventory_typed()
            .await
            .map_err(|error| error.to_string())
    }

    async fn scan_inventory_typed(&self) -> Result<RuntimeInventory, RuntimeInventoryScanError> {
        let host_boot_id =
            host_boot_id(&self.proc_root).map_err(RuntimeInventoryScanError::inventory_invalid)?;
        let container_ids = self
            .client
            .list_marked_running_container_ids()
            .await
            .map_err(|error| {
                runtime_inventory_scan_error_with_category(
                    error,
                    RuntimeInventoryInvalidCategory::List,
                )
            })?;
        ensure_bounded_runtime_candidates(container_ids.len()).map_err(|_| {
            RuntimeInventoryScanError::inventory_invalid_with_category(
                RuntimeInventoryInvalidCategory::Count,
            )
        })?;
        for container_id in &container_ids {
            validate_runtime_container_id(container_id).map_err(|_| {
                RuntimeInventoryScanError::inventory_invalid_with_category(
                    RuntimeInventoryInvalidCategory::Id,
                )
            })?;
        }
        let initial_container_ids = canonical_docker_container_ids(container_ids);
        let mut bindings = Vec::with_capacity(initial_container_ids.len());
        for container_id in &initial_container_ids {
            bindings.push(
                docker_runtime_binding_from_client(
                    &self.client,
                    &self.proc_root,
                    &self.cgroup_root,
                    &host_boot_id,
                    container_id,
                )
                .await
                .map_err(runtime_inventory_scan_error)?,
            );
        }
        let fresh_container_ids = self
            .client
            .list_marked_running_container_ids()
            .await
            .map_err(|error| {
                runtime_inventory_scan_error_with_category(
                    error,
                    RuntimeInventoryInvalidCategory::List,
                )
            })?;
        ensure_bounded_runtime_candidates(fresh_container_ids.len()).map_err(|_| {
            RuntimeInventoryScanError::inventory_invalid_with_category(
                RuntimeInventoryInvalidCategory::Count,
            )
        })?;
        for container_id in &fresh_container_ids {
            validate_runtime_container_id(container_id).map_err(|_| {
                RuntimeInventoryScanError::inventory_invalid_with_category(
                    RuntimeInventoryInvalidCategory::Id,
                )
            })?;
        }
        if initial_container_ids != canonical_docker_container_ids(fresh_container_ids) {
            return Err(RuntimeInventoryScanError::inventory_invalid_with_category(
                RuntimeInventoryInvalidCategory::DoubleInspect,
            ));
        }
        Ok(RuntimeInventory::new(AdapterKind::Docker, bindings))
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

fn canonical_docker_container_ids(mut container_ids: Vec<String>) -> Vec<String> {
    container_ids.sort();
    container_ids
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DockerInspectIdentity {
    container_id: String,
    agent_run_id: String,
    pid: u32,
    start_marker: String,
    runtime_handler: Option<String>,
}

async fn docker_runtime_binding_from_client(
    client: &DockerEngineClient,
    proc_root: &Path,
    cgroup_root: &Path,
    host_boot_id: &str,
    candidate_id: &str,
) -> Result<RuntimeBinding, String> {
    let first = docker_inspect_identity(&client.inspect_container(candidate_id).await?)?;
    if first.container_id != candidate_id {
        return Err(format!(
            "Docker inspect identity changed from listed id {candidate_id} to {}",
            first.container_id
        ));
    }
    let first_start_time = process_start_time_ticks(proc_root, first.pid)?;
    let first_cgroup = cgroup_identity_from_pid(first.pid, proc_root, cgroup_root)?;

    let second = docker_inspect_identity(&client.inspect_container(candidate_id).await?)?;
    let second_start_time = process_start_time_ticks(proc_root, second.pid)?;
    let second_cgroup = cgroup_identity_from_pid(second.pid, proc_root, cgroup_root)?;
    if first != second || first_start_time != second_start_time || first_cgroup != second_cgroup {
        return Err(format!(
            "Docker runtime identity changed while qualifying container {candidate_id}"
        ));
    }

    let binding = RuntimeBinding {
        agent_run_id: first.agent_run_id,
        identity: RuntimeWorkloadIdentity {
            adapter: AdapterKind::Docker,
            workload_id: first.container_id,
            start_marker: first.start_marker,
            host_boot_id: host_boot_id.to_string(),
            init_process_start_time_ticks: first_start_time,
            cgroup: first_cgroup,
        },
        runtime_handler: first.runtime_handler,
    };
    validate_runtime_workload_identity(
        binding.identity.adapter,
        &binding.identity.workload_id,
        &binding.identity.start_marker,
    )
    .map_err(|error| error.to_string())?;
    Ok(binding)
}

fn docker_inspect_identity(inspect: &Value) -> Result<DockerInspectIdentity, String> {
    if inspect
        .get("State")
        .and_then(|state| state.get("Running"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err("Docker inspect State.Running must be true".to_string());
    }
    let labels = labels_field(inspect, &["Config", "Labels"])?;
    let agent_run_id = labels
        .get(APOLYSIS_SESSION_LABEL)
        .map(String::as_str)
        .map(str::trim)
        .filter(|agent_run_id| !agent_run_id.is_empty())
        .ok_or_else(|| format!("Docker inspect {APOLYSIS_SESSION_LABEL} must be non-empty"))?;
    Ok(DockerInspectIdentity {
        container_id: string_field(inspect, &["Id"])
            .ok_or_else(|| "Docker inspect Id must be non-empty".to_string())?,
        agent_run_id: agent_run_id.to_string(),
        pid: docker_container_pid_from_engine_inspect(inspect)?,
        start_marker: docker_start_marker(inspect).ok_or_else(|| {
            "Docker inspect State.StartedAt must be non-empty, bounded, and non-zero".to_string()
        })?,
        runtime_handler: string_field(inspect, &["HostConfig", "Runtime"]),
    })
}

fn docker_start_marker(inspect: &Value) -> Option<String> {
    let marker = string_field(inspect, &["State", "StartedAt"])?;
    validate_docker_start_marker(&marker).ok()?;
    Some(marker)
}

fn host_boot_id(proc_root: &Path) -> Result<String, String> {
    let path = proc_root.join("sys/kernel/random/boot_id");
    let value = std::fs::read_to_string(&path)
        .map_err(|error| format!("failed to read host boot id {}: {error}", path.display()))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("host boot id {} must not be empty", path.display()));
    }
    Ok(value.to_string())
}

fn process_start_time_ticks(proc_root: &Path, pid: u32) -> Result<u64, String> {
    let path = proc_root.join(pid.to_string()).join("stat");
    let stat = std::fs::read_to_string(&path)
        .map_err(|error| format!("failed to read process stat {}: {error}", path.display()))?;
    let command_end = stat
        .rfind(')')
        .ok_or_else(|| format!("process stat {} has no command terminator", path.display()))?;
    let fields = stat[command_end + 1..]
        .split_whitespace()
        .collect::<Vec<_>>();
    let start_time = fields.get(19).ok_or_else(|| {
        format!(
            "process stat {} does not contain field 22 starttime",
            path.display()
        )
    })?;
    start_time.parse::<u64>().map_err(|error| {
        format!(
            "process stat {} has invalid field 22 starttime: {error}",
            path.display()
        )
    })
}

fn cgroup_identity_from_pid(
    pid: u32,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<CgroupIdentity, String> {
    let proc_cgroup_path = proc_root.join(pid.to_string()).join("cgroup");
    let proc_cgroup = std::fs::read_to_string(&proc_cgroup_path).map_err(|error| {
        format!(
            "failed to read process cgroup file {}: {error}",
            proc_cgroup_path.display()
        )
    })?;
    let relative = proc_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "process cgroup data does not contain a cgroup v2 entry".to_string())?;
    cgroup_identity_from_relative_path(relative, cgroup_root)
}

fn cgroup_identity_from_relative_path(
    relative: &str,
    cgroup_root: &Path,
) -> Result<CgroupIdentity, String> {
    let mut directory = open_directory_path_no_follow(cgroup_root, "cgroup root")?;
    let mut saw_component = false;
    for component in Path::new(relative.trim()).components() {
        match component {
            Component::Normal(part) => {
                saw_component = true;
                directory = open_directory_at_no_follow(
                    directory.as_raw_fd(),
                    part,
                    "cgroup path must not contain a symbolic link or non-directory component",
                )?;
            }
            Component::ParentDir => {
                return Err("cgroup path must not contain a parent component".to_string());
            }
            Component::CurDir | Component::RootDir => {}
            Component::Prefix(_) => {
                return Err("cgroup path must not contain a platform prefix".to_string());
            }
        }
    }
    if !saw_component {
        return Err("cgroup path must identify a non-root cgroup".to_string());
    }
    let metadata = fd_metadata(directory.as_raw_fd(), "failed to stat cgroup directory")?;
    Ok(CgroupIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn open_directory_path_no_follow(path: &Path, description: &str) -> Result<OwnedFd, String> {
    let (anchor, components) = if path.is_absolute() {
        ("/", path.components().skip(1).collect::<Vec<_>>())
    } else {
        (".", path.components().collect::<Vec<_>>())
    };
    let anchor: &CStr = if anchor == "/" { c"/" } else { c"." };
    // SAFETY: anchor is a valid C string and the returned descriptor is uniquely owned.
    let raw = unsafe {
        libc::open(
            anchor.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(format!(
            "failed to open {description} anchor: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: raw is a newly opened descriptor owned by this function.
    let mut directory = unsafe { OwnedFd::from_raw_fd(raw) };
    for component in components {
        match component {
            Component::Normal(part) => {
                directory = open_directory_at_no_follow(
                    directory.as_raw_fd(),
                    part,
                    &format!(
                        "{description} must not contain a symbolic link or non-directory component"
                    ),
                )?;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!(
                    "{description} must not contain traversal components"
                ));
            }
        }
    }
    Ok(directory)
}

fn open_directory_at_no_follow(
    parent: RawFd,
    component: &std::ffi::OsStr,
    error_context: &str,
) -> Result<OwnedFd, String> {
    let component = CString::new(component.as_bytes())
        .map_err(|_| format!("{error_context}: path component contains NUL"))?;
    // SAFETY: parent is an open directory descriptor and component is a valid C string.
    let raw = unsafe {
        libc::openat(
            parent,
            component.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(format!(
            "{error_context}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: raw is a newly opened descriptor owned by this function.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn fd_metadata(fd: RawFd, context: &str) -> Result<libc::stat, String> {
    // SAFETY: zero initialization is valid for libc::stat before fstat fills it.
    let mut metadata = unsafe { std::mem::zeroed::<libc::stat>() };
    // SAFETY: fd is open and metadata points to writable storage.
    if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
        return Err(format!("{context}: {}", std::io::Error::last_os_error()));
    }
    Ok(metadata)
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

impl RuntimeInventoryAdapter for DockerEnginePollingRuntimeAdapter {
    fn kind(&self) -> AdapterKind {
        AdapterKind::Docker
    }

    fn scan_interval(&self) -> Duration {
        self.scan_interval
    }

    fn scan_inventory(
        &self,
    ) -> Pin<
        Box<dyn Future<Output = Result<RuntimeInventory, RuntimeInventoryScanError>> + Send + '_>,
    > {
        Box::pin(DockerEnginePollingRuntimeAdapter::scan_inventory_typed(
            self,
        ))
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
    pub backend_recoveries: u64,
    pub ingest_errors: u64,
}

pub trait RuntimeAdapterBackend: Send + 'static {
    fn kind(&self) -> AdapterKind;
    fn next_workload(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RuntimeWorkload>, String>> + Send + '_>>;
}

pub trait RuntimeInventoryAdapter: Send + Sync + 'static {
    fn kind(&self) -> AdapterKind;
    fn scan_interval(&self) -> Duration;
    fn scan_inventory(
        &self,
    ) -> Pin<
        Box<dyn Future<Output = Result<RuntimeInventory, RuntimeInventoryScanError>> + Send + '_>,
    >;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeInventoryInvalidCategory {
    HostBoot,
    List,
    Count,
    Id,
    InspectShape,
    InspectState,
    InspectLabel,
    InspectPid,
    InspectStartMarker,
    ProcStart,
    CgroupPath,
    CgroupIdentity,
    DoubleInspect,
    BindingValidation,
    Unclassified,
}

impl RuntimeInventoryInvalidCategory {
    pub const fn code(self) -> &'static str {
        match self {
            Self::HostBoot => "host_boot",
            Self::List => "list",
            Self::Count => "count",
            Self::Id => "id",
            Self::InspectShape => "inspect_shape",
            Self::InspectState => "inspect_state",
            Self::InspectLabel => "inspect_label",
            Self::InspectPid => "inspect_pid",
            Self::InspectStartMarker => "inspect_start_marker",
            Self::ProcStart => "proc_start",
            Self::CgroupPath => "cgroup_path",
            Self::CgroupIdentity => "cgroup_identity",
            Self::DoubleInspect => "double_inspect",
            Self::BindingValidation => "binding_validation",
            Self::Unclassified => "unclassified",
        }
    }
}

pub struct RuntimeInventoryScanError {
    reason: RuntimeSourceGapReason,
    invalid_category: Option<RuntimeInventoryInvalidCategory>,
}

impl RuntimeInventoryScanError {
    pub fn socket_unavailable(_diagnostic: impl Into<String>) -> Self {
        Self {
            reason: RuntimeSourceGapReason::SocketUnavailable,
            invalid_category: None,
        }
    }

    pub fn inventory_invalid(_diagnostic: impl Into<String>) -> Self {
        Self {
            reason: RuntimeSourceGapReason::InventoryInvalid,
            invalid_category: Some(RuntimeInventoryInvalidCategory::Unclassified),
        }
    }

    fn inventory_invalid_with_category(category: RuntimeInventoryInvalidCategory) -> Self {
        Self {
            reason: RuntimeSourceGapReason::InventoryInvalid,
            invalid_category: Some(category),
        }
    }

    pub const fn reason(&self) -> RuntimeSourceGapReason {
        self.reason
    }

    pub const fn inventory_invalid_category(&self) -> Option<RuntimeInventoryInvalidCategory> {
        self.invalid_category
    }
}

impl std::fmt::Display for RuntimeInventoryScanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "runtime inventory scan failed: {}",
            runtime_source_gap_reason_code(self.reason)
        )
    }
}

impl std::fmt::Debug for RuntimeInventoryScanError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeInventoryScanError")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}

impl std::error::Error for RuntimeInventoryScanError {}

fn runtime_inventory_scan_error(message: String) -> RuntimeInventoryScanError {
    runtime_inventory_scan_error_with_category(
        message,
        RuntimeInventoryInvalidCategory::Unclassified,
    )
}

fn runtime_inventory_scan_error_with_category(
    message: String,
    invalid_category: RuntimeInventoryInvalidCategory,
) -> RuntimeInventoryScanError {
    let normalized = message.to_ascii_lowercase();
    let source_unavailable = normalized.starts_with("failed to connect docker engine socket")
        || normalized.starts_with("failed to write docker engine request")
        || normalized.starts_with("failed to read docker engine response")
        || normalized.starts_with("failed to run ")
        || normalized.contains("code = unavailable")
        || normalized.contains("connection refused")
        || normalized.contains("connection reset")
        || normalized.contains("connection error")
        || normalized.contains("dial unix")
        || normalized.contains("deadline exceeded")
        || normalized == "crictl runtime source unavailable"
        || (normalized.starts_with("crictl ") && normalized.contains("no such file or directory"));
    if source_unavailable {
        RuntimeInventoryScanError::socket_unavailable(message)
    } else {
        RuntimeInventoryScanError::inventory_invalid_with_category(invalid_category)
    }
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

pub fn crictl_marked_container_candidates_from_ps_and_pods(
    ps_value: Value,
    pods_value: Value,
) -> Result<Vec<CriContainerCandidate>, String> {
    let mut marked_pod_labels = BTreeMap::new();
    let pods = pods_value
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "crictl pods JSON must contain items array".to_string())?;
    for pod in pods {
        if string_field(pod, &["state"]).as_deref() != Some("SANDBOX_READY") {
            continue;
        }
        let labels = string_map_field(pod, &["labels"], "CRI pod sandbox labels")?;
        let marked = labels
            .get(APOLYSIS_SESSION_LABEL)
            .map(String::as_str)
            .map(str::trim)
            .map(|session_id| !session_id.is_empty())
            .unwrap_or(false);
        if !marked {
            continue;
        }
        let id = string_field(pod, &["id"])
            .ok_or_else(|| "marked CRI pod sandbox id must be non-empty".to_string())?;
        marked_pod_labels.insert(id, labels);
    }

    let containers = ps_value
        .get("containers")
        .and_then(Value::as_array)
        .ok_or_else(|| "crictl ps JSON must contain containers array".to_string())?;
    let mut candidates = Vec::new();
    for container in containers {
        if string_field(container, &["state"]).as_deref() != Some("CONTAINER_RUNNING") {
            continue;
        }
        let labels = string_map_field(container, &["labels"], "CRI container labels")?;
        let id = string_field(container, &["id"])
            .ok_or_else(|| "marked CRI container id must be non-empty".to_string())?;
        let directly_marked = labels
            .get(APOLYSIS_SESSION_LABEL)
            .map(String::as_str)
            .map(str::trim)
            .map(|session_id| !session_id.is_empty())
            .unwrap_or(false);
        if directly_marked {
            candidates.push(CriContainerCandidate {
                container_id: id,
                inherited_labels: BTreeMap::new(),
            });
            continue;
        }
        let Some(pod_sandbox_id) = string_field(container, &["podSandboxId"]) else {
            continue;
        };
        let Some(labels) = marked_pod_labels.get(&pod_sandbox_id) else {
            continue;
        };
        candidates.push(CriContainerCandidate {
            container_id: id,
            inherited_labels: labels.clone(),
        });
    }
    Ok(candidates)
}

fn crictl_kubernetes_container_candidates_from_ps_and_pods(
    ps_value: Value,
    pods_value: Value,
    expected_kubernetes_namespace: &str,
) -> Result<Vec<CriContainerCandidate>, String> {
    let mut ready_pod_labels = BTreeMap::new();
    let pods = pods_value
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| "crictl pods JSON must contain items array".to_string())?;
    for pod in pods {
        if string_field(pod, &["state"]).as_deref() != Some("SANDBOX_READY") {
            continue;
        }
        if pod
            .get("labels")
            .and_then(Value::as_object)
            .and_then(|labels| labels.get(APOLYSIS_KUBERNETES_OBSERVE_LABEL))
            .and_then(Value::as_str)
            != Some("true")
        {
            continue;
        }
        let namespace = pod
            .get("metadata")
            .and_then(|metadata| metadata.get("namespace"))
            .and_then(Value::as_str)
            .filter(|namespace| !namespace.is_empty())
            .ok_or_else(|| {
                "CRI pod sandbox namespace metadata is missing or invalid".to_string()
            })?;
        if namespace != expected_kubernetes_namespace {
            continue;
        }
        let id = string_field(pod, &["id"])
            .ok_or_else(|| "ready CRI pod sandbox id must be non-empty".to_string())?;
        let mut labels = bounded_cri_string_map_field(pod, &["labels"], "CRI pod sandbox labels")?;
        if labels
            .get("io.kubernetes.pod.namespace")
            .map(String::as_str)
            != Some(expected_kubernetes_namespace)
        {
            return Err("CRI pod sandbox namespace metadata conflicts".to_string());
        }
        let label_session = validated_cri_session_metadata(
            labels.get(APOLYSIS_SESSION_LABEL),
            "CRI pod sandbox session metadata is invalid",
        )?;
        let annotations =
            bounded_cri_string_map_field(pod, &["annotations"], "CRI pod sandbox annotations")?;
        let annotation_session = validated_cri_session_metadata(
            annotations.get(APOLYSIS_SESSION_ANNOTATION),
            "CRI pod sandbox session metadata is invalid",
        )?;
        if label_session.is_some()
            && annotation_session.is_some()
            && label_session != annotation_session
        {
            return Err("CRI pod sandbox session metadata conflicts".to_string());
        }
        let session_id = label_session.or(annotation_session);
        labels.clear();
        if let Some(session_id) = session_id {
            labels.insert(APOLYSIS_SESSION_LABEL.to_string(), session_id);
        }
        if ready_pod_labels.insert(id, labels).is_some() {
            return Err("CRI pod sandbox inventory contains a duplicate id".to_string());
        }
    }

    let containers = ps_value
        .get("containers")
        .and_then(Value::as_array)
        .ok_or_else(|| "crictl ps JSON must contain containers array".to_string())?;
    let mut candidates = Vec::new();
    for container in containers {
        if string_field(container, &["state"]).as_deref() != Some("CONTAINER_RUNNING") {
            continue;
        }
        let inherited_labels = string_field(container, &["podSandboxId"])
            .and_then(|pod_sandbox_id| ready_pod_labels.get(&pod_sandbox_id));
        if inherited_labels.is_none() {
            continue;
        }
        let labels = bounded_cri_string_map_field(container, &["labels"], "CRI container labels")?;
        let id = string_field(container, &["id"])
            .ok_or_else(|| "marked CRI container id must be non-empty".to_string())?;
        let direct_session = validated_cri_session_metadata(
            labels.get(APOLYSIS_SESSION_LABEL),
            "CRI container session metadata is invalid",
        )?;
        let inherited_session = inherited_labels
            .and_then(|labels| labels.get(APOLYSIS_SESSION_LABEL))
            .cloned();
        let has_inherited_session = inherited_session.is_some();
        if direct_session.is_some()
            && inherited_session.is_some()
            && direct_session != inherited_session
        {
            return Err(
                "CRI container session metadata conflicts with its pod sandbox".to_string(),
            );
        }
        if direct_session.is_none() && inherited_session.is_none() {
            continue;
        }
        candidates.push(CriContainerCandidate {
            container_id: id,
            inherited_labels: if has_inherited_session {
                inherited_labels.cloned().unwrap_or_default()
            } else {
                BTreeMap::new()
            },
        });
    }
    Ok(candidates)
}

fn validated_cri_session_metadata(
    value: Option<&String>,
    error: &'static str,
) -> Result<Option<String>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(error.to_string());
    }
    Ok(Some(value.clone()))
}

fn valid_kubernetes_namespace(namespace: &str) -> bool {
    let bytes = namespace.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    let valid_edge = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    valid_edge(bytes[0])
        && valid_edge(bytes[bytes.len() - 1])
        && bytes.iter().all(|byte| valid_edge(*byte) || *byte == b'-')
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
    cgroup_identity_from_relative_path(relative, cgroup_root).map(|identity| identity.inode)
}

pub fn cgroup_id_from_cri_inspect_cgroups_path(
    inspect: &Value,
    cgroup_root: &Path,
) -> Result<Option<u64>, String> {
    let Some(cgroups_path) =
        string_field(inspect, &["info", "runtimeSpec", "linux", "cgroupsPath"])
    else {
        return Ok(None);
    };
    let relative = safe_relative_cgroup_path_from_cri(&cgroups_path)?;
    cgroup_identity_from_relative_path(
        relative
            .to_str()
            .ok_or_else(|| "CRI cgroupsPath must be UTF-8".to_string())?,
        cgroup_root,
    )
    .map(|identity| Some(identity.inode))
}

fn relative_cgroup_path_from_cri_cgroups_path(cgroups_path: &str) -> Result<PathBuf, String> {
    let cgroups_path = cgroups_path.trim();
    if cgroups_path.is_empty() {
        return Err("CRI runtimeSpec linux.cgroupsPath must not be empty".to_string());
    }
    if cgroups_path.contains('/') {
        return Ok(normalized_cgroup_relative_path(cgroups_path));
    }

    let parts = cgroups_path.split(':').collect::<Vec<_>>();
    if parts.len() == 3 && parts[0].ends_with(".slice") {
        let mut relative = systemd_slice_cgroup_path(parts[0])?;
        let scope_prefix = parts[1].trim();
        let scope_name = parts[2].trim();
        if scope_prefix.is_empty() || scope_name.is_empty() {
            return Err(format!(
                "CRI systemd cgroupsPath must include scope prefix and name: {cgroups_path}"
            ));
        }
        relative.push(format!("{scope_prefix}-{scope_name}.scope"));
        return Ok(relative);
    }

    Ok(normalized_cgroup_relative_path(cgroups_path))
}

fn systemd_slice_cgroup_path(slice: &str) -> Result<PathBuf, String> {
    let Some(name) = slice.strip_suffix(".slice") else {
        return Err(format!(
            "systemd slice cgroup must end with .slice: {slice}"
        ));
    };
    if name.is_empty() {
        return Err("systemd slice cgroup name must not be empty".to_string());
    }
    let mut relative = PathBuf::new();
    let mut current = String::new();
    for part in name.split('-') {
        if part.is_empty() {
            return Err(format!(
                "systemd slice cgroup has an empty component: {slice}"
            ));
        }
        if !current.is_empty() {
            current.push('-');
        }
        current.push_str(part);
        relative.push(format!("{current}.slice"));
    }
    Ok(relative)
}

fn normalized_cgroup_relative_path(relative: &str) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir | Component::RootDir => {}
            Component::Prefix(_) => {}
        }
    }
    normalized
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
        backend_recoveries: 0,
        ingest_errors: 0,
    };
    let mut consecutive_backend_errors = 0_u64;

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            workload = backend.next_workload() => {
                match workload {
                    Ok(Some(workload)) => {
                        let recovered_backend = consecutive_backend_errors > 0;
                        consecutive_backend_errors = 0;
                        match state.ingest_runtime_workload(workload).await {
                            Ok(AssociationOutcome::Attached) => {
                                summary.discovered = summary.discovered.saturating_add(1);
                                if recovered_backend {
                                    summary.backend_recoveries =
                                        summary.backend_recoveries.saturating_add(1);
                                }
                            }
                            Ok(AssociationOutcome::MissingIntent) => {
                                summary.discovered = summary.discovered.saturating_add(1);
                                summary.missing_intent = summary.missing_intent.saturating_add(1);
                                if recovered_backend {
                                    summary.backend_recoveries =
                                        summary.backend_recoveries.saturating_add(1);
                                }
                            }
                            Err(_error) => {
                                summary.ingest_errors = summary.ingest_errors.saturating_add(1);
                                eprintln!(
                                    "apolysisd: runtime adapter={adapter:?} code=ingest_failed"
                                );
                                state.set_adapter(adapter, ComponentState::Degraded).await;
                            }
                        }
                    }
                    Ok(None) => break,
                    Err(_error) => {
                        consecutive_backend_errors = consecutive_backend_errors.saturating_add(1);
                        summary.backend_errors = summary.backend_errors.saturating_add(1);
                        eprintln!(
                            "apolysisd: runtime adapter={adapter:?} code=backend_unavailable"
                        );
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

pub async fn run_runtime_inventory_adapter<B: RuntimeInventoryAdapter>(
    backend: B,
    state: Arc<DaemonState>,
    shutdown: oneshot::Receiver<()>,
) -> RuntimeAdapterSummary {
    run_runtime_inventory_adapter_with_policy(
        backend,
        state,
        shutdown,
        AdapterBackoffPolicy::default(),
    )
    .await
}

pub async fn run_runtime_inventory_adapter_with_policy<B: RuntimeInventoryAdapter>(
    backend: B,
    state: Arc<DaemonState>,
    mut shutdown: oneshot::Receiver<()>,
    backoff_policy: AdapterBackoffPolicy,
) -> RuntimeAdapterSummary {
    let adapter = backend.kind();
    let scan_interval = backend.scan_interval();
    let mut summary = RuntimeAdapterSummary {
        adapter,
        discovered: 0,
        missing_intent: 0,
        backend_errors: 0,
        backend_recoveries: 0,
        ingest_errors: 0,
    };
    let mut consecutive_errors = 0_u64;
    let mut outage_reported = false;

    loop {
        let scan = tokio::select! {
            _ = &mut shutdown => break,
            scan = backend.scan_inventory() => scan,
        };
        match scan {
            Ok(inventory) => match state.reconcile_runtime_inventory(inventory).await {
                Ok(reconciliation) => {
                    summary.discovered = summary
                        .discovered
                        .saturating_add(reconciliation.summary.attached as u64);
                    summary.missing_intent = summary
                        .missing_intent
                        .saturating_add(reconciliation.summary.missing_intent as u64);
                    if consecutive_errors > 0 {
                        summary.backend_recoveries = summary.backend_recoveries.saturating_add(1);
                    }
                    consecutive_errors = 0;
                    outage_reported = false;
                    if wait_for_runtime_scan(&mut shutdown, scan_interval).await {
                        break;
                    }
                }
                Err(_error) => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    summary.backend_errors = summary.backend_errors.saturating_add(1);
                    let report_outage = !outage_reported;
                    outage_reported = true;
                    if report_outage {
                        eprintln!(
                            "apolysisd: runtime inventory adapter={adapter:?} code=reconcile_failed reason=inventory_invalid"
                        );
                    }
                    if let Err(_gap_error) = state
                        .runtime_source_unavailable(
                            adapter,
                            RuntimeSourceGapReason::InventoryInvalid,
                        )
                        .await
                    {
                        summary.ingest_errors = summary.ingest_errors.saturating_add(1);
                        if report_outage {
                            eprintln!(
                                "apolysisd: runtime inventory adapter={adapter:?} code=gap_persist_failed reason=inventory_invalid"
                            );
                        }
                    }
                    state.set_adapter(adapter, ComponentState::Degraded).await;
                    let delay = adapter_backoff_delay(backoff_policy, adapter, consecutive_errors);
                    if wait_for_runtime_scan(&mut shutdown, delay).await {
                        break;
                    }
                }
            },
            Err(error) => {
                consecutive_errors = consecutive_errors.saturating_add(1);
                summary.backend_errors = summary.backend_errors.saturating_add(1);
                let reason = error.reason();
                let report_outage = !outage_reported;
                outage_reported = true;
                if report_outage {
                    eprintln!(
                        "apolysisd: runtime inventory adapter={adapter:?} code=scan_failed reason={}",
                        runtime_source_gap_reason_code(reason)
                    );
                }
                if let Err(_gap_error) = state.runtime_source_unavailable(adapter, reason).await {
                    summary.ingest_errors = summary.ingest_errors.saturating_add(1);
                    if report_outage {
                        eprintln!(
                            "apolysisd: runtime inventory adapter={adapter:?} code=gap_persist_failed reason={}",
                            runtime_source_gap_reason_code(reason)
                        );
                    }
                }
                state.set_adapter(adapter, ComponentState::Degraded).await;
                let delay = adapter_backoff_delay(backoff_policy, adapter, consecutive_errors);
                if wait_for_runtime_scan(&mut shutdown, delay).await {
                    break;
                }
            }
        }
    }

    summary
}

const fn runtime_source_gap_reason_code(reason: RuntimeSourceGapReason) -> &'static str {
    match reason {
        RuntimeSourceGapReason::SocketUnavailable => "socket_unavailable",
        RuntimeSourceGapReason::InventoryInvalid => "inventory_invalid",
    }
}

async fn wait_for_runtime_scan(shutdown: &mut oneshot::Receiver<()>, delay: Duration) -> bool {
    tokio::select! {
        _ = shutdown => true,
        _ = tokio::time::sleep(delay) => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CriRuntimeClient {
    crictl_path: PathBuf,
    crictl_proof: Option<CriExecutableProof>,
    configuration_error: Option<String>,
    runtime_endpoint: String,
    image_endpoint: Option<String>,
    timeout: Duration,
}

impl CriRuntimeClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        let endpoint = format!("unix://{}", socket_path.as_ref().display());
        let (crictl_path, crictl_proof, configuration_error) = match configured_crictl_path() {
            Ok((path, proof)) => (path, Some(proof), None),
            Err(error) => (PathBuf::new(), None, Some(error)),
        };
        Self {
            crictl_path,
            crictl_proof,
            configuration_error,
            runtime_endpoint: endpoint.clone(),
            image_endpoint: Some(endpoint),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_crictl_path(mut self, crictl_path: impl Into<PathBuf>) -> Self {
        self.crictl_path = crictl_path.into();
        match validate_crictl_override(&self.crictl_path) {
            Ok(proof) => {
                self.crictl_proof = Some(proof);
                self.configuration_error = None;
            }
            Err(error) => {
                self.crictl_proof = None;
                self.configuration_error = Some(error);
            }
        }
        self
    }

    pub fn with_image_endpoint(mut self, image_endpoint: Option<String>) -> Self {
        self.image_endpoint = image_endpoint;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn list_marked_running_container_ids(&self) -> Result<Vec<String>, String> {
        crictl_marked_container_ids_from_ps(self.crictl_json(&["ps", "-o", "json"]).await?)
    }

    pub async fn list_marked_running_container_candidates(
        &self,
        include_pod_sandbox_labels: bool,
    ) -> Result<Vec<CriContainerCandidate>, String> {
        let mode = if include_pod_sandbox_labels {
            CriSandboxMetadataMode::LabelsOnly
        } else {
            CriSandboxMetadataMode::Disabled
        };
        self.list_marked_running_container_candidates_with_mode(mode, None)
            .await
    }

    async fn list_marked_running_container_candidates_with_mode(
        &self,
        mode: CriSandboxMetadataMode,
        expected_kubernetes_namespace: Option<&str>,
    ) -> Result<Vec<CriContainerCandidate>, String> {
        let ps = self.crictl_json(&["ps", "-o", "json"]).await?;
        if mode == CriSandboxMetadataMode::Disabled {
            return crictl_marked_container_ids_from_ps(ps).map(|ids| {
                ids.into_iter()
                    .map(|container_id| CriContainerCandidate {
                        container_id,
                        inherited_labels: BTreeMap::new(),
                    })
                    .collect()
            });
        }
        let pods = self.crictl_json(&["pods", "-o", "json"]).await?;
        match mode {
            CriSandboxMetadataMode::LabelsOnly => {
                crictl_marked_container_candidates_from_ps_and_pods(ps, pods)
            }
            CriSandboxMetadataMode::Kubernetes => {
                let expected_namespace = expected_kubernetes_namespace
                    .ok_or_else(|| "CRI Kubernetes namespace is not configured".to_string())?;
                crictl_kubernetes_container_candidates_from_ps_and_pods(
                    ps,
                    pods,
                    expected_namespace,
                )
            }
            CriSandboxMetadataMode::Disabled => {
                Err("CRI sandbox metadata mode is inconsistent".to_string())
            }
        }
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
            .await
    }

    async fn crictl_json(&self, command_args: &[&str]) -> Result<Value, String> {
        if let Some(error) = &self.configuration_error {
            return Err(error.clone());
        }
        let executable = self.open_verified_crictl_override()?;
        let timeout = format!("{}s", self.timeout.as_secs().max(1));
        let executable_path = PathBuf::from(format!("/proc/self/fd/{}", executable.as_raw_fd()));
        let mut command = TokioCommand::new(&executable_path);
        let descriptor = executable.as_raw_fd();
        // SAFETY: the closure only clears FD_CLOEXEC on the already-open executable descriptor in
        // the child between fork and exec, using an async-signal-safe syscall.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(descriptor, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
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
        let output = run_bounded_command(&mut command, self.timeout, "crictl").await;
        let post_execution_proof = self.verify_crictl_override();
        let output = output?;
        post_execution_proof?;
        if !output.status.success() {
            return Err(crictl_command_failure(&output.stderr));
        }
        serde_json::from_slice(&output.stdout)
            .map_err(|error| format!("failed to decode crictl JSON: {error}"))
    }

    fn open_verified_crictl_override(&self) -> Result<OwnedFd, String> {
        let expected = self
            .crictl_proof
            .ok_or_else(|| CRICTL_EXECUTABLE_CONFIGURATION_ERROR.to_string())?;
        let executable = open_validated_crictl_override(&self.crictl_path)?;
        if executable.proof != expected {
            return Err("APOLYSIS_CRICTL executable identity changed".to_string());
        }
        Ok(executable.descriptor)
    }

    fn verify_crictl_override(&self) -> Result<(), String> {
        let expected = self
            .crictl_proof
            .ok_or_else(|| CRICTL_EXECUTABLE_CONFIGURATION_ERROR.to_string())?;
        let actual = validate_crictl_override(&self.crictl_path)?;
        if actual != expected {
            return Err("APOLYSIS_CRICTL executable identity changed".to_string());
        }
        Ok(())
    }
}

fn crictl_command_failure(stderr: &[u8]) -> String {
    let normalized = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    if normalized.contains("code = unavailable")
        || normalized.contains("connection refused")
        || normalized.contains("connection reset")
        || normalized.contains("connection error")
        || normalized.contains("dial unix")
        || normalized.contains("deadline exceeded")
    {
        "crictl runtime source unavailable".to_string()
    } else {
        "crictl command failed".to_string()
    }
}

struct BoundedCommandOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_bounded_command(
    command: &mut TokioCommand,
    timeout: Duration,
    command_name: &str,
) -> Result<BoundedCommandOutput, String> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|error| format!("failed to run {command_name}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("failed to run {command_name}: stdout pipe unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("failed to run {command_name}: stderr pipe unavailable"))?;
    enum Collection {
        Complete(Vec<u8>, Vec<u8>, ExitStatus),
        StdoutOversized,
        StderrOversized,
    }
    let collected = tokio::time::timeout(timeout, async {
        let mut stdout_read = Box::pin(read_bounded_output(stdout));
        let mut stderr_read = Box::pin(read_bounded_output(stderr));
        let mut child_wait = Box::pin(child.wait());
        let mut stdout = None;
        let mut stderr = None;
        let mut status = None;
        loop {
            tokio::select! {
                result = &mut stdout_read, if stdout.is_none() => {
                    let (bytes, oversized) = result?;
                    if oversized {
                        return Ok::<_, String>(Collection::StdoutOversized);
                    }
                    stdout = Some(bytes);
                }
                result = &mut stderr_read, if stderr.is_none() => {
                    let (bytes, oversized) = result?;
                    if oversized {
                        return Ok::<_, String>(Collection::StderrOversized);
                    }
                    stderr = Some(bytes);
                }
                result = &mut child_wait, if status.is_none() => {
                    status = Some(result.map_err(|error| error.to_string())?);
                }
            }
            if stdout.is_some() && stderr.is_some() && status.is_some() {
                return Ok(Collection::Complete(
                    stdout
                        .take()
                        .ok_or_else(|| "runtime stdout collection lost state".to_string())?,
                    stderr
                        .take()
                        .ok_or_else(|| "runtime stderr collection lost state".to_string())?,
                    status
                        .take()
                        .ok_or_else(|| "runtime status collection lost state".to_string())?,
                ));
            }
        }
    })
    .await;
    let collection = match collected {
        Ok(result) => result?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(format!("failed to run {command_name}: timed out"));
        }
    };
    let (stdout, stderr, status) = match collection {
        Collection::Complete(stdout, stderr, status) => (stdout, stderr, status),
        Collection::StdoutOversized => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(format!(
                "crictl stdout exceeds {MAX_RUNTIME_ADAPTER_RESPONSE_BYTES} bytes"
            ));
        }
        Collection::StderrOversized => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(format!(
                "crictl stderr exceeds {MAX_RUNTIME_ADAPTER_RESPONSE_BYTES} bytes"
            ));
        }
    };
    Ok(BoundedCommandOutput {
        status,
        stdout,
        stderr,
    })
}

async fn read_bounded_output<R>(reader: R) -> Result<(Vec<u8>, bool), String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    reader
        .take((MAX_RUNTIME_ADAPTER_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|error| format!("failed to read runtime command output: {error}"))?;
    let oversized = bytes.len() > MAX_RUNTIME_ADAPTER_RESPONSE_BYTES;
    Ok((bytes, oversized))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CriExecutableProof {
    device: u64,
    inode: u64,
}

fn configured_crictl_path() -> Result<(PathBuf, CriExecutableProof), String> {
    let Some(configured) = std::env::var_os("APOLYSIS_CRICTL") else {
        return Err(CRICTL_EXECUTABLE_CONFIGURATION_ERROR.to_string());
    };
    let path = PathBuf::from(configured);
    let proof = validate_crictl_override(&path)?;
    Ok((path, proof))
}

fn validate_crictl_override(path: &Path) -> Result<CriExecutableProof, String> {
    open_validated_crictl_override(path).map(|executable| executable.proof)
}

struct OpenCriExecutable {
    descriptor: OwnedFd,
    proof: CriExecutableProof,
}

fn open_validated_crictl_override(path: &Path) -> Result<OpenCriExecutable, String> {
    if !path.is_absolute() {
        return Err(CRICTL_EXECUTABLE_CONFIGURATION_ERROR.to_string());
    }
    let components: Vec<_> = path.components().collect();
    if components
        .iter()
        .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err("APOLYSIS_CRICTL path must not contain traversal components".to_string());
    }
    let file_name = path
        .file_name()
        .ok_or_else(|| "APOLYSIS_CRICTL must reference an executable file".to_string())?;
    let parent = path
        .parent()
        .ok_or_else(|| "APOLYSIS_CRICTL must reference an executable file".to_string())?;
    let directory = open_directory_path_no_follow(parent, "APOLYSIS_CRICTL path")?;
    let file_name = CString::new(file_name.as_bytes())
        .map_err(|_| "APOLYSIS_CRICTL path contains NUL".to_string())?;
    // SAFETY: directory is an open directory descriptor, file_name is a valid C string, and the
    // newly returned descriptor is uniquely owned below.
    let raw = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            file_name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(format!(
            "APOLYSIS_CRICTL path must not contain symbolic links and must reference an existing executable file: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: raw is a newly opened descriptor owned by this function.
    let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
    let metadata = fd_metadata(
        descriptor.as_raw_fd(),
        "failed to inspect APOLYSIS_CRICTL executable",
    )?;
    let mode = metadata.st_mode;
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_nlink != 1
        || metadata.st_uid != effective_uid
        || mode & 0o111 == 0
        || mode & 0o022 != 0
        || mode & 0o7000 != 0
    {
        return Err(
            "APOLYSIS_CRICTL must be a singly-linked, owner-controlled executable file".to_string(),
        );
    }
    Ok(OpenCriExecutable {
        proof: CriExecutableProof {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        },
        descriptor,
    })
}

pub struct ContainerdCriRuntimeAdapter {
    adapter: AdapterKind,
    client: CriRuntimeClient,
    kubernetes_sandbox_namespace: Option<String>,
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    pending_containers: VecDeque<CriContainerCandidate>,
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
            kubernetes_sandbox_namespace: None,
            proc_root: proc_root.into(),
            cgroup_root: cgroup_root.into(),
            pending_containers: VecDeque::new(),
            seen_container_ids: BTreeSet::new(),
            seen_capacity,
            scan_interval,
        })
    }

    pub fn with_kubernetes_sandbox_metadata(
        mut self,
        expected_namespace: impl Into<String>,
    ) -> Result<Self, String> {
        let expected_namespace = expected_namespace.into();
        if !valid_kubernetes_namespace(&expected_namespace) {
            return Err("Kubernetes sandbox namespace is invalid".to_string());
        }
        self.kubernetes_sandbox_namespace = Some(expected_namespace);
        Ok(self)
    }

    fn sandbox_metadata_mode(&self) -> CriSandboxMetadataMode {
        if self.kubernetes_sandbox_namespace.is_some() {
            CriSandboxMetadataMode::Kubernetes
        } else if self.adapter == AdapterKind::K3sContainerd {
            CriSandboxMetadataMode::LabelsOnly
        } else {
            CriSandboxMetadataMode::Disabled
        }
    }

    pub async fn scan_inventory(&self) -> Result<RuntimeInventory, String> {
        self.scan_inventory_typed()
            .await
            .map_err(|error| error.to_string())
    }

    async fn scan_inventory_typed(&self) -> Result<RuntimeInventory, RuntimeInventoryScanError> {
        let host_boot_id = host_boot_id(&self.proc_root).map_err(|_| {
            RuntimeInventoryScanError::inventory_invalid_with_category(
                RuntimeInventoryInvalidCategory::HostBoot,
            )
        })?;
        let sandbox_metadata_mode = self.sandbox_metadata_mode();
        let candidates = self
            .client
            .list_marked_running_container_candidates_with_mode(
                sandbox_metadata_mode,
                self.kubernetes_sandbox_namespace.as_deref(),
            )
            .await
            .map_err(|error| {
                runtime_inventory_scan_error_with_category(
                    error,
                    RuntimeInventoryInvalidCategory::List,
                )
            })?;
        ensure_bounded_runtime_candidates(candidates.len()).map_err(|_| {
            RuntimeInventoryScanError::inventory_invalid_with_category(
                RuntimeInventoryInvalidCategory::Count,
            )
        })?;
        for candidate in &candidates {
            validate_runtime_container_id(&candidate.container_id).map_err(|_| {
                RuntimeInventoryScanError::inventory_invalid_with_category(
                    RuntimeInventoryInvalidCategory::Id,
                )
            })?;
        }
        let initial_candidates = canonical_cri_candidates(candidates);
        let mut bindings = Vec::with_capacity(initial_candidates.len());
        for candidate in initial_candidates.iter().cloned() {
            bindings.push(
                cri_runtime_binding_from_client(
                    self.adapter,
                    &self.client,
                    &self.proc_root,
                    &self.cgroup_root,
                    &host_boot_id,
                    candidate,
                    self.kubernetes_sandbox_namespace.is_some(),
                )
                .await?,
            );
        }
        let fresh_candidates = self
            .client
            .list_marked_running_container_candidates_with_mode(
                sandbox_metadata_mode,
                self.kubernetes_sandbox_namespace.as_deref(),
            )
            .await
            .map_err(|error| {
                runtime_inventory_scan_error_with_category(
                    error,
                    RuntimeInventoryInvalidCategory::List,
                )
            })?;
        ensure_bounded_runtime_candidates(fresh_candidates.len()).map_err(|_| {
            RuntimeInventoryScanError::inventory_invalid_with_category(
                RuntimeInventoryInvalidCategory::Count,
            )
        })?;
        for candidate in &fresh_candidates {
            validate_runtime_container_id(&candidate.container_id).map_err(|_| {
                RuntimeInventoryScanError::inventory_invalid_with_category(
                    RuntimeInventoryInvalidCategory::Id,
                )
            })?;
        }
        if initial_candidates != canonical_cri_candidates(fresh_candidates) {
            return Err(RuntimeInventoryScanError::inventory_invalid_with_category(
                RuntimeInventoryInvalidCategory::DoubleInspect,
            ));
        }
        Ok(RuntimeInventory::new(self.adapter, bindings))
    }

    async fn next_cri_workload(&mut self) -> Result<Option<RuntimeWorkload>, String> {
        loop {
            while let Some(candidate) = self.pending_containers.pop_front() {
                let inspect = self
                    .client
                    .inspect_container(&candidate.container_id)
                    .await?;
                let cgroup_id = match cgroup_id_from_cri_inspect_cgroups_path(
                    &inspect,
                    &self.cgroup_root,
                ) {
                    Ok(Some(cgroup_id)) => cgroup_id,
                    Ok(None) => {
                        let pid = containerd_pid_from_cri_inspect(&inspect)?;
                        cgroup_id_from_pid(pid, &self.proc_root, &self.cgroup_root)?
                    }
                    Err(cgroups_path_error) => {
                        let pid = containerd_pid_from_cri_inspect(&inspect)?;
                        cgroup_id_from_pid(pid, &self.proc_root, &self.cgroup_root).map_err(
                                |pid_error| {
                                    format!(
                                        "{cgroups_path_error}; fallback via CRI pid {pid} failed: {pid_error}"
                                    )
                                },
                            )?
                    }
                };
                let mut snapshot =
                    containerd_task_snapshot_from_cri_inspect(self.adapter, &inspect, cgroup_id)?;
                merge_cri_inherited_labels(
                    &mut snapshot.labels,
                    &candidate.inherited_labels,
                    self.kubernetes_sandbox_namespace.is_some(),
                )
                .map_err(|_| "CRI container session metadata conflicts with its pod sandbox")?;
                if let Some(workload) = containerd_workload_from_snapshot(snapshot)? {
                    return Ok(Some(workload));
                }
            }
            self.pending_containers = self
                .client
                .list_marked_running_container_candidates_with_mode(
                    self.sandbox_metadata_mode(),
                    self.kubernetes_sandbox_namespace.as_deref(),
                )
                .await?
                .into_iter()
                .filter(|candidate| {
                    remember_seen(
                        &mut self.seen_container_ids,
                        self.seen_capacity,
                        &candidate.container_id,
                    )
                })
                .collect();
            if self.pending_containers.is_empty() {
                tokio::time::sleep(self.scan_interval).await;
            }
        }
    }
}

fn canonical_cri_candidates(
    mut candidates: Vec<CriContainerCandidate>,
) -> Vec<CriContainerCandidate> {
    candidates.sort_by(|left, right| {
        left.container_id
            .cmp(&right.container_id)
            .then_with(|| left.inherited_labels.cmp(&right.inherited_labels))
    });
    candidates
}

fn ensure_bounded_runtime_candidates(count: usize) -> Result<(), String> {
    if count > MAX_RUNTIME_INVENTORY_BINDINGS {
        return Err(format!(
            "runtime inventory candidate count {count} exceeds maximum {MAX_RUNTIME_INVENTORY_BINDINGS}"
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CriInspectIdentity {
    container_id: String,
    agent_run_id: String,
    pid: u32,
    start_marker: String,
    runtime_handler: Option<String>,
}

async fn cri_runtime_binding_from_client(
    adapter: AdapterKind,
    client: &CriRuntimeClient,
    proc_root: &Path,
    cgroup_root: &Path,
    host_boot_id: &str,
    candidate: CriContainerCandidate,
    strict_inherited_session: bool,
) -> Result<RuntimeBinding, RuntimeInventoryScanError> {
    let first_inspect = client
        .inspect_container(&candidate.container_id)
        .await
        .map_err(|error| {
            runtime_inventory_scan_error_with_category(
                error,
                RuntimeInventoryInvalidCategory::InspectShape,
            )
        })?;
    let first = cri_inspect_identity(
        &first_inspect,
        &candidate.inherited_labels,
        strict_inherited_session,
    )
    .map_err(RuntimeInventoryScanError::inventory_invalid_with_category)?;
    if first.container_id != candidate.container_id {
        return Err(RuntimeInventoryScanError::inventory_invalid_with_category(
            RuntimeInventoryInvalidCategory::Id,
        ));
    }
    let first_start_time = process_start_time_ticks(proc_root, first.pid).map_err(|_| {
        RuntimeInventoryScanError::inventory_invalid_with_category(
            RuntimeInventoryInvalidCategory::ProcStart,
        )
    })?;
    let first_cgroup =
        cgroup_identity_from_cri_inspect(&first_inspect, first.pid, proc_root, cgroup_root)
            .map_err(RuntimeInventoryScanError::inventory_invalid_with_category)?;

    let second_inspect = client
        .inspect_container(&candidate.container_id)
        .await
        .map_err(|error| {
            runtime_inventory_scan_error_with_category(
                error,
                RuntimeInventoryInvalidCategory::InspectShape,
            )
        })?;
    let second = cri_inspect_identity(
        &second_inspect,
        &candidate.inherited_labels,
        strict_inherited_session,
    )
    .map_err(RuntimeInventoryScanError::inventory_invalid_with_category)?;
    let second_start_time = process_start_time_ticks(proc_root, second.pid).map_err(|_| {
        RuntimeInventoryScanError::inventory_invalid_with_category(
            RuntimeInventoryInvalidCategory::ProcStart,
        )
    })?;
    let second_cgroup =
        cgroup_identity_from_cri_inspect(&second_inspect, second.pid, proc_root, cgroup_root)
            .map_err(RuntimeInventoryScanError::inventory_invalid_with_category)?;
    if first != second || first_start_time != second_start_time || first_cgroup != second_cgroup {
        return Err(RuntimeInventoryScanError::inventory_invalid_with_category(
            RuntimeInventoryInvalidCategory::DoubleInspect,
        ));
    }

    let binding = RuntimeBinding {
        agent_run_id: first.agent_run_id,
        identity: RuntimeWorkloadIdentity {
            adapter,
            workload_id: format!(
                "{}/{}",
                container_runtime_identity_domain(adapter),
                first.container_id
            ),
            start_marker: first.start_marker,
            host_boot_id: host_boot_id.to_string(),
            init_process_start_time_ticks: first_start_time,
            cgroup: first_cgroup,
        },
        runtime_handler: first.runtime_handler,
    };
    binding.validate().map_err(|_| {
        RuntimeInventoryScanError::inventory_invalid_with_category(
            RuntimeInventoryInvalidCategory::BindingValidation,
        )
    })?;
    Ok(binding)
}

fn cri_inspect_identity(
    inspect: &Value,
    inherited_labels: &BTreeMap<String, String>,
    strict_inherited_session: bool,
) -> Result<CriInspectIdentity, RuntimeInventoryInvalidCategory> {
    let state = string_field(inspect, &["status", "state"])
        .ok_or(RuntimeInventoryInvalidCategory::InspectShape)?;
    if state != "CONTAINER_RUNNING" {
        return Err(RuntimeInventoryInvalidCategory::InspectState);
    }
    let mut labels = string_map_field(inspect, &["status", "labels"], "CRI status.labels")
        .map_err(|_| RuntimeInventoryInvalidCategory::InspectLabel)?;
    merge_cri_inherited_labels(&mut labels, inherited_labels, strict_inherited_session)
        .map_err(|_| RuntimeInventoryInvalidCategory::InspectLabel)?;
    let agent_run_id = labels
        .get(APOLYSIS_SESSION_LABEL)
        .map(String::as_str)
        .map(str::trim)
        .filter(|agent_run_id| !agent_run_id.is_empty())
        .ok_or(RuntimeInventoryInvalidCategory::InspectLabel)?;
    Ok(CriInspectIdentity {
        container_id: string_field(inspect, &["status", "id"])
            .ok_or(RuntimeInventoryInvalidCategory::InspectShape)?,
        agent_run_id: agent_run_id.to_string(),
        pid: containerd_pid_from_cri_inspect(inspect)
            .map_err(|_| RuntimeInventoryInvalidCategory::InspectPid)?,
        start_marker: runtime_start_marker(inspect, &["status", "startedAt"])
            .ok_or(RuntimeInventoryInvalidCategory::InspectStartMarker)?,
        runtime_handler: string_field(inspect, &["info", "runtimeType"])
            .or_else(|| string_field(inspect, &["status", "image", "runtimeHandler"])),
    })
}

fn merge_cri_inherited_labels(
    labels: &mut BTreeMap<String, String>,
    inherited_labels: &BTreeMap<String, String>,
    strict_inherited_session: bool,
) -> Result<(), ()> {
    if !strict_inherited_session {
        for (key, value) in inherited_labels {
            labels.entry(key.clone()).or_insert_with(|| value.clone());
        }
        return Ok(());
    }
    if inherited_labels.is_empty() {
        return Ok(());
    }
    let direct_session = validated_cri_session_metadata(
        labels.get(APOLYSIS_SESSION_LABEL),
        "CRI container session metadata is invalid",
    )
    .map_err(|_| ())?;
    let inherited_session = validated_cri_session_metadata(
        inherited_labels.get(APOLYSIS_SESSION_LABEL),
        "CRI pod sandbox session metadata is invalid",
    )
    .map_err(|_| ())?;
    if direct_session.is_some()
        && inherited_session.is_some()
        && direct_session != inherited_session
    {
        return Err(());
    }
    for (key, value) in inherited_labels {
        labels.entry(key.clone()).or_insert_with(|| value.clone());
    }
    Ok(())
}

fn container_runtime_identity_domain(adapter: AdapterKind) -> &'static str {
    match adapter {
        AdapterKind::Containerd => "containerd",
        AdapterKind::K3sContainerd => "k3s_containerd",
        AdapterKind::Docker | AdapterKind::Kubernetes => unreachable!("validated CRI adapter"),
    }
}

fn runtime_start_marker(value: &Value, path: &[&str]) -> Option<String> {
    let mut value = value;
    for segment in path {
        value = value.get(segment)?;
    }
    match value {
        Value::String(value) => canonical_positive_decimal(value)
            .or_else(|| canonical_cri_rfc3339_to_unix_nanos(value).map(|value| value.to_string())),
        Value::Number(value) => value
            .as_u64()
            .filter(|value| *value > 0)
            .map(|value| value.to_string()),
        _ => None,
    }
}

fn canonical_positive_decimal(value: &str) -> Option<String> {
    let value = value.trim();
    validate_cri_start_marker(value).ok()?;
    Some(value.to_string())
}

fn cgroup_identity_from_cri_inspect(
    inspect: &Value,
    pid: u32,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<CgroupIdentity, RuntimeInventoryInvalidCategory> {
    let Some(cgroups_path) =
        string_field(inspect, &["info", "runtimeSpec", "linux", "cgroupsPath"])
    else {
        return cgroup_identity_from_pid_for_inventory(pid, proc_root, cgroup_root);
    };
    let relative = safe_relative_cgroup_path_from_cri(&cgroups_path)
        .map_err(|_| RuntimeInventoryInvalidCategory::CgroupPath)?;
    cgroup_identity_from_relative_path(
        relative
            .to_str()
            .ok_or(RuntimeInventoryInvalidCategory::CgroupPath)?,
        cgroup_root,
    )
    .map_err(|_| RuntimeInventoryInvalidCategory::CgroupIdentity)
}

fn cgroup_identity_from_pid_for_inventory(
    pid: u32,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<CgroupIdentity, RuntimeInventoryInvalidCategory> {
    let proc_cgroup_path = proc_root.join(pid.to_string()).join("cgroup");
    let proc_cgroup = std::fs::read_to_string(proc_cgroup_path)
        .map_err(|_| RuntimeInventoryInvalidCategory::CgroupPath)?;
    let relative = proc_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or(RuntimeInventoryInvalidCategory::CgroupPath)?;
    cgroup_identity_from_relative_path(relative, cgroup_root)
        .map_err(|_| RuntimeInventoryInvalidCategory::CgroupIdentity)
}

fn safe_relative_cgroup_path_from_cri(cgroups_path: &str) -> Result<PathBuf, String> {
    if cgroups_path.contains('/') {
        reject_parent_cgroup_components(cgroups_path)?;
    }
    relative_cgroup_path_from_cri_cgroups_path(cgroups_path)
}

fn reject_parent_cgroup_components(path: &str) -> Result<(), String> {
    if Path::new(path)
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err("cgroup path must not contain a parent component".to_string());
    }
    Ok(())
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

impl RuntimeInventoryAdapter for ContainerdCriRuntimeAdapter {
    fn kind(&self) -> AdapterKind {
        self.adapter
    }

    fn scan_interval(&self) -> Duration {
        self.scan_interval
    }

    fn scan_inventory(
        &self,
    ) -> Pin<
        Box<dyn Future<Output = Result<RuntimeInventory, RuntimeInventoryScanError>> + Send + '_>,
    > {
        Box::pin(ContainerdCriRuntimeAdapter::scan_inventory_typed(self))
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

fn bounded_cri_string_map_field(
    value: &Value,
    path: &[&str],
    field_name: &str,
) -> Result<BTreeMap<String, String>, String> {
    let values = string_map_field(value, path, field_name).map_err(|_| {
        format!("{field_name} must be a bounded object containing only string entries")
    })?;
    if values.len() > MAX_CRI_METADATA_MAP_ENTRIES {
        return Err(format!("{field_name} exceeds the metadata entry limit"));
    }
    let mut bytes = 0_usize;
    for (key, value) in &values {
        if key.len() > MAX_CRI_METADATA_STRING_BYTES || value.len() > MAX_CRI_METADATA_STRING_BYTES
        {
            return Err(format!("{field_name} contains an oversized metadata entry"));
        }
        bytes = bytes
            .checked_add(key.len())
            .and_then(|bytes| bytes.checked_add(value.len()))
            .ok_or_else(|| format!("{field_name} exceeds the metadata byte limit"))?;
        if bytes > MAX_CRI_METADATA_MAP_BYTES {
            return Err(format!("{field_name} exceeds the metadata byte limit"));
        }
    }
    Ok(values)
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
