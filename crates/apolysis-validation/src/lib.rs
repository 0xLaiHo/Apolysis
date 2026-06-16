// SPDX-License-Identifier: Apache-2.0

use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupCaptureRequest {
    pub output_dir: PathBuf,
    pub sources: Vec<BackupSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceCaptureRequest<'a> {
    pub service_name: String,
    pub systemctl_show: &'a str,
    pub runtime_sockets: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KubernetesCaptureRequest<'a> {
    pub runtimeclasses_json: &'a str,
    pub nodes_json: &'a str,
    pub pods_json: &'a str,
    pub validation_label_key: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RestorePlanRequest {
    pub backup_root: PathBuf,
    pub manifest: BackupManifest,
    pub services: Vec<ServiceState>,
    pub managed_service_inputs: Vec<ManagedServiceInputs>,
    pub validation_owned_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationReportRequest<'a> {
    pub output_dir: PathBuf,
    pub backup_sources: Vec<BackupSource>,
    pub service_requests: Vec<ServiceCaptureRequest<'a>>,
    pub kubernetes: KubernetesCaptureRequest<'a>,
    pub managed_service_inputs: Vec<ManagedServiceInputs>,
    pub validation_owned_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedServiceInputs {
    pub service_name: String,
    pub entry_ids: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceSpec {
    pub service_name: String,
    pub runtime_sockets: Vec<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidateHostArgs {
    pub dry_run: bool,
    pub output_dir: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupSource {
    pub id: String,
    pub path: PathBuf,
}

impl BackupSource {
    pub fn new(id: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            path: path.into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupManifest {
    pub schema_version: u32,
    pub entries: Vec<BackupEntry>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceState {
    pub service_name: String,
    pub load_state: String,
    pub active_state: String,
    pub unit_file_state: String,
    pub fragment_path: Option<PathBuf>,
    pub drop_in_paths: Vec<PathBuf>,
    pub runtime_sockets: Vec<RuntimeSocketState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeSocketState {
    pub path: PathBuf,
    pub present: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KubernetesRestoreContext {
    pub runtime_classes: Vec<RuntimeClassSnapshot>,
    pub nodes: Vec<NodeSnapshot>,
    pub workloads: Vec<KubernetesWorkloadSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeClassSnapshot {
    pub name: String,
    pub handler: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NodeSnapshot {
    pub name: String,
    pub ready: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KubernetesWorkloadSnapshot {
    pub namespace: String,
    pub name: String,
    pub service_account_name: Option<String>,
    pub runtime_class_name: Option<String>,
    pub node_name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RestorePlan {
    pub schema_version: u32,
    pub actions: Vec<RestoreAction>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostValidationReport {
    pub schema_version: u32,
    pub backup_manifest: BackupManifest,
    pub services: Vec<ServiceState>,
    pub kubernetes: KubernetesRestoreContext,
    pub restore_plan: RestorePlan,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RestoreAction {
    RestoreRegularFile {
        id: String,
        from_backup: PathBuf,
        to_path: PathBuf,
        uid: Option<u32>,
        gid: Option<u32>,
        mode: Option<u32>,
    },
    RestoreSymlink {
        id: String,
        target: PathBuf,
        link_path: PathBuf,
        uid: Option<u32>,
        gid: Option<u32>,
    },
    EnsureMissing {
        id: String,
        path: PathBuf,
    },
    RemoveValidationPath {
        path: PathBuf,
    },
    RestoreServiceState {
        service_name: String,
        active_state: String,
        unit_file_state: String,
    },
}

pub fn default_host_backup_sources() -> Vec<BackupSource> {
    vec![
        BackupSource::new("docker_daemon", "/etc/docker/daemon.json"),
        BackupSource::new("containerd_config", "/etc/containerd/config.toml"),
        BackupSource::new(
            "k3s_containerd_template",
            "/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl",
        ),
        BackupSource::new(
            "docker_http_proxy_dropin",
            "/etc/systemd/system/docker.service.d/http-proxy.conf",
        ),
        BackupSource::new(
            "k3s_http_proxy_dropin",
            "/etc/systemd/system/k3s.service.d/http-proxy.conf",
        ),
    ]
}

pub fn default_service_specs() -> Vec<ServiceSpec> {
    vec![
        ServiceSpec {
            service_name: "containerd.service".to_string(),
            runtime_sockets: vec![PathBuf::from("/run/containerd/containerd.sock")],
        },
        ServiceSpec {
            service_name: "docker.service".to_string(),
            runtime_sockets: vec![PathBuf::from("/run/docker.sock")],
        },
        ServiceSpec {
            service_name: "k3s.service".to_string(),
            runtime_sockets: vec![PathBuf::from("/run/k3s/containerd/containerd.sock")],
        },
    ]
}

pub fn parse_validate_host_args(
    args: impl IntoIterator<Item = String>,
) -> Result<ValidateHostArgs, String> {
    let args = args.into_iter().collect::<Vec<_>>();
    let mut dry_run = false;
    let mut output_dir = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--dry-run" => dry_run = true,
            "--output" => {
                index += 1;
                output_dir = args.get(index).map(PathBuf::from);
            }
            unknown => {
                return Err(format!(
                    "unknown argument: {unknown}\n{}",
                    validate_host_usage()
                ))
            }
        }
        index += 1;
    }
    if !dry_run {
        return Err(format!("{} requires --dry-run", validate_host_usage()));
    }
    let output_dir =
        output_dir.ok_or_else(|| format!("missing --output\n{}", validate_host_usage()))?;
    Ok(ValidateHostArgs {
        dry_run,
        output_dir,
    })
}

pub fn validate_host_usage() -> &'static str {
    "usage: apolysis-validate-host --dry-run --output <dir>"
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupEntry {
    pub id: String,
    pub original_path: PathBuf,
    pub kind: BackupEntryKind,
    pub backup_relative_path: Option<PathBuf>,
    pub sha256_hex: Option<String>,
    pub symlink_target: Option<PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub mode: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupEntryKind {
    RegularFile,
    Symlink,
    Missing,
}

pub fn capture_backup_manifest(request: BackupCaptureRequest) -> Result<BackupManifest, String> {
    std::fs::create_dir_all(request.output_dir.join("files"))
        .map_err(|error| format!("failed to create backup output directory: {error}"))?;
    let mut entries = Vec::with_capacity(request.sources.len());

    for source in request.sources {
        entries.push(capture_source(&request.output_dir, source)?);
    }

    Ok(BackupManifest {
        schema_version: 1,
        entries,
    })
}

pub fn capture_service_state(request: ServiceCaptureRequest<'_>) -> Result<ServiceState, String> {
    let load_state = required_systemctl_value(request.systemctl_show, "LoadState")?;
    let active_state = required_systemctl_value(request.systemctl_show, "ActiveState")?;
    let unit_file_state = required_systemctl_value(request.systemctl_show, "UnitFileState")?;
    let fragment_path = optional_path(systemctl_value(request.systemctl_show, "FragmentPath"));
    let drop_in_paths = systemctl_value(request.systemctl_show, "DropInPaths")
        .map(split_paths)
        .unwrap_or_default();
    let runtime_sockets = request
        .runtime_sockets
        .into_iter()
        .map(|path| RuntimeSocketState {
            present: std::fs::symlink_metadata(&path).is_ok(),
            path,
        })
        .collect();

    Ok(ServiceState {
        service_name: request.service_name,
        load_state,
        active_state,
        unit_file_state,
        fragment_path,
        drop_in_paths,
        runtime_sockets,
    })
}

pub fn capture_kubernetes_restore_context(
    request: KubernetesCaptureRequest<'_>,
) -> Result<KubernetesRestoreContext, String> {
    let runtimeclasses = parse_json(request.runtimeclasses_json, "runtimeclasses")?;
    let nodes = parse_json(request.nodes_json, "nodes")?;
    let pods = parse_json(request.pods_json, "pods")?;

    let mut runtime_classes = items(&runtimeclasses)
        .iter()
        .filter_map(runtime_class_snapshot)
        .collect::<Vec<_>>();
    runtime_classes.sort_by(|left, right| left.name.cmp(&right.name));

    let mut node_snapshots = items(&nodes)
        .iter()
        .filter_map(node_snapshot)
        .collect::<Vec<_>>();
    node_snapshots.sort_by(|left, right| left.name.cmp(&right.name));

    let mut workloads = items(&pods)
        .iter()
        .filter(|pod| !has_label(pod, request.validation_label_key))
        .filter_map(workload_snapshot)
        .collect::<Vec<_>>();
    workloads.sort_by(|left, right| {
        left.namespace
            .cmp(&right.namespace)
            .then_with(|| left.name.cmp(&right.name))
    });

    Ok(KubernetesRestoreContext {
        runtime_classes,
        nodes: node_snapshots,
        workloads,
    })
}

pub fn plan_restore(request: RestorePlanRequest) -> Result<RestorePlan, String> {
    let mut actions = Vec::new();
    let mut known_entry_ids = BTreeSet::new();

    for entry in &request.manifest.entries {
        known_entry_ids.insert(entry.id.clone());
        match entry.kind {
            BackupEntryKind::RegularFile => {
                let backup_relative_path =
                    entry.backup_relative_path.as_ref().ok_or_else(|| {
                        format!(
                            "regular file backup entry {} is missing backup path",
                            entry.id
                        )
                    })?;
                verify_backup_copy(&request.backup_root, entry, backup_relative_path)?;
                actions.push(RestoreAction::RestoreRegularFile {
                    id: entry.id.clone(),
                    from_backup: backup_relative_path.clone(),
                    to_path: entry.original_path.clone(),
                    uid: entry.uid,
                    gid: entry.gid,
                    mode: entry.mode,
                });
            }
            BackupEntryKind::Symlink => {
                let target = entry.symlink_target.clone().ok_or_else(|| {
                    format!("symlink backup entry {} is missing target", entry.id)
                })?;
                actions.push(RestoreAction::RestoreSymlink {
                    id: entry.id.clone(),
                    target,
                    link_path: entry.original_path.clone(),
                    uid: entry.uid,
                    gid: entry.gid,
                });
            }
            BackupEntryKind::Missing => {
                actions.push(RestoreAction::EnsureMissing {
                    id: entry.id.clone(),
                    path: entry.original_path.clone(),
                });
            }
        }
    }

    let mut validation_owned_paths = request.validation_owned_paths;
    validation_owned_paths.sort();
    validation_owned_paths.dedup();
    actions.extend(
        validation_owned_paths
            .into_iter()
            .map(|path| RestoreAction::RemoveValidationPath { path }),
    );

    let services = request
        .services
        .into_iter()
        .map(|service| (service.service_name.clone(), service))
        .collect::<BTreeMap<_, _>>();
    let mut managed_inputs = request.managed_service_inputs;
    managed_inputs.sort_by(|left, right| left.service_name.cmp(&right.service_name));
    for managed in managed_inputs {
        for entry_id in &managed.entry_ids {
            if !known_entry_ids.contains(entry_id) {
                return Err(format!(
                    "managed service {} references unknown backup entry {entry_id}",
                    managed.service_name
                ));
            }
        }
        let service = services.get(&managed.service_name).ok_or_else(|| {
            format!(
                "managed service {} is missing captured service state",
                managed.service_name
            )
        })?;
        actions.push(RestoreAction::RestoreServiceState {
            service_name: service.service_name.clone(),
            active_state: service.active_state.clone(),
            unit_file_state: service.unit_file_state.clone(),
        });
    }

    Ok(RestorePlan {
        schema_version: 1,
        actions,
    })
}

pub fn build_validation_report(
    request: ValidationReportRequest<'_>,
) -> Result<HostValidationReport, String> {
    std::fs::create_dir_all(&request.output_dir)
        .map_err(|error| format!("failed to create validation output directory: {error}"))?;
    let backup_manifest = capture_backup_manifest(BackupCaptureRequest {
        output_dir: request.output_dir.clone(),
        sources: request.backup_sources,
    })?;
    let services = request
        .service_requests
        .into_iter()
        .map(capture_service_state)
        .collect::<Result<Vec<_>, _>>()?;
    let kubernetes = capture_kubernetes_restore_context(request.kubernetes)?;
    let restore_plan = plan_restore(RestorePlanRequest {
        backup_root: request.output_dir.clone(),
        manifest: backup_manifest.clone(),
        services: services.clone(),
        managed_service_inputs: request.managed_service_inputs,
        validation_owned_paths: request.validation_owned_paths,
    })?;
    let report = HostValidationReport {
        schema_version: 1,
        backup_manifest,
        services,
        kubernetes,
        restore_plan,
    };
    write_json(
        &request.output_dir.join("backup-manifest.json"),
        &report.backup_manifest,
    )?;
    write_json(
        &request.output_dir.join("service-state.json"),
        &report.services,
    )?;
    write_json(
        &request.output_dir.join("kubernetes-context.json"),
        &report.kubernetes,
    )?;
    write_json(
        &request.output_dir.join("restore-plan.json"),
        &report.restore_plan,
    )?;
    Ok(report)
}

pub fn collect_host_validation_report(output_dir: PathBuf) -> Result<HostValidationReport, String> {
    let service_outputs = default_service_specs()
        .into_iter()
        .map(|spec| {
            let output = systemctl_show(&spec.service_name)?;
            Ok((spec, output))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let service_requests = service_outputs
        .iter()
        .map(|(spec, output)| ServiceCaptureRequest {
            service_name: spec.service_name.clone(),
            systemctl_show: output.as_str(),
            runtime_sockets: spec.runtime_sockets.clone(),
        })
        .collect::<Vec<_>>();
    let runtimeclasses_json = kubectl_json(&["get", "runtimeclasses", "-o", "json"])?;
    let nodes_json = kubectl_json(&["get", "nodes", "-o", "json"])?;
    let pods_json = kubectl_json(&["get", "pods", "-A", "-o", "json"])?;

    build_validation_report(ValidationReportRequest {
        output_dir,
        backup_sources: default_host_backup_sources(),
        service_requests,
        kubernetes: KubernetesCaptureRequest {
            runtimeclasses_json: &runtimeclasses_json,
            nodes_json: &nodes_json,
            pods_json: &pods_json,
            validation_label_key: "apolysis.dev/validation",
        },
        managed_service_inputs: default_managed_service_inputs(),
        validation_owned_paths: default_validation_owned_paths(),
    })
}

fn capture_source(
    output_dir: &std::path::Path,
    source: BackupSource,
) -> Result<BackupEntry, String> {
    let metadata = match std::fs::symlink_metadata(&source.path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(BackupEntry {
                id: source.id,
                original_path: source.path,
                kind: BackupEntryKind::Missing,
                backup_relative_path: None,
                sha256_hex: None,
                symlink_target: None,
                uid: None,
                gid: None,
                mode: None,
            })
        }
        Err(error) => {
            return Err(format!(
                "failed to inspect backup source {}: {error}",
                source.path.display()
            ))
        }
    };

    if metadata.file_type().is_symlink() {
        let target = std::fs::read_link(&source.path).map_err(|error| {
            format!("failed to read symlink {}: {error}", source.path.display())
        })?;
        return Ok(BackupEntry {
            id: source.id,
            original_path: source.path,
            kind: BackupEntryKind::Symlink,
            backup_relative_path: None,
            sha256_hex: None,
            symlink_target: Some(target),
            uid: Some(metadata.uid()),
            gid: Some(metadata.gid()),
            mode: Some(metadata.permissions().mode() & 0o7777),
        });
    }

    if !metadata.file_type().is_file() {
        return Err(format!(
            "backup source is not a regular file or symlink: {}",
            source.path.display()
        ));
    }

    let backup_relative_path = PathBuf::from("files").join(safe_backup_name(&source.id));
    let backup_path = output_dir.join(&backup_relative_path);
    let bytes = std::fs::read(&source.path).map_err(|error| {
        format!(
            "failed to read backup source {}: {error}",
            source.path.display()
        )
    })?;
    std::fs::write(&backup_path, &bytes).map_err(|error| {
        format!(
            "failed to write backup copy {}: {error}",
            backup_path.display()
        )
    })?;

    Ok(BackupEntry {
        id: source.id,
        original_path: source.path,
        kind: BackupEntryKind::RegularFile,
        backup_relative_path: Some(backup_relative_path),
        sha256_hex: Some(sha256_hex(&bytes)),
        symlink_target: None,
        uid: Some(metadata.uid()),
        gid: Some(metadata.gid()),
        mode: Some(metadata.permissions().mode() & 0o7777),
    })
}

fn safe_backup_name(id: &str) -> String {
    id.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

fn required_systemctl_value(input: &str, key: &str) -> Result<String, String> {
    systemctl_value(input, key)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("systemd service state is missing {key}"))
}

fn systemctl_value<'a>(input: &'a str, key: &str) -> Option<&'a str> {
    input
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
}

fn optional_path(value: Option<&str>) -> Option<PathBuf> {
    value.filter(|path| !path.is_empty()).map(PathBuf::from)
}

fn split_paths(value: &str) -> Vec<PathBuf> {
    value
        .split_whitespace()
        .filter(|path| !path.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn parse_json(input: &str, name: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(input).map_err(|error| format!("failed to parse {name} JSON: {error}"))
}

fn verify_backup_copy(
    backup_root: &std::path::Path,
    entry: &BackupEntry,
    backup_relative_path: &std::path::Path,
) -> Result<(), String> {
    let path = backup_root.join(backup_relative_path);
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("backup copy is missing for {}: {error}", entry.id))?;
    let checksum = sha256_hex(&bytes);
    if entry.sha256_hex.as_deref() != Some(checksum.as_str()) {
        return Err(format!("backup checksum mismatch for {}", entry.id));
    }
    Ok(())
}

fn write_json(path: &std::path::Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("failed to serialize {}: {error}", path.display()))?;
    std::fs::write(path, bytes)
        .map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn default_managed_service_inputs() -> Vec<ManagedServiceInputs> {
    vec![
        ManagedServiceInputs {
            service_name: "containerd.service".to_string(),
            entry_ids: vec!["containerd_config".to_string()],
        },
        ManagedServiceInputs {
            service_name: "docker.service".to_string(),
            entry_ids: vec![
                "docker_daemon".to_string(),
                "docker_http_proxy_dropin".to_string(),
            ],
        },
        ManagedServiceInputs {
            service_name: "k3s.service".to_string(),
            entry_ids: vec![
                "k3s_containerd_template".to_string(),
                "k3s_http_proxy_dropin".to_string(),
            ],
        },
    ]
}

fn default_validation_owned_paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/run/apolysis-validation"),
        PathBuf::from("/var/lib/apolysis-validation"),
    ]
}

fn systemctl_show(service_name: &str) -> Result<String, String> {
    command_output(
        "systemctl",
        &[
            "show",
            service_name,
            "--property=LoadState",
            "--property=ActiveState",
            "--property=UnitFileState",
            "--property=FragmentPath",
            "--property=DropInPaths",
            "--no-page",
        ],
    )
}

fn kubectl_json(args: &[&str]) -> Result<String, String> {
    command_output("k3s", &[&["kubectl"], args].concat())
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed with status {}: {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map_err(|error| format!("{program} output is not UTF-8: {error}"))
}

fn items(value: &serde_json::Value) -> &[serde_json::Value] {
    value
        .get("items")
        .and_then(serde_json::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn runtime_class_snapshot(value: &serde_json::Value) -> Option<RuntimeClassSnapshot> {
    Some(RuntimeClassSnapshot {
        name: metadata_string(value, "name")?,
        handler: value.get("handler")?.as_str()?.to_string(),
    })
}

fn node_snapshot(value: &serde_json::Value) -> Option<NodeSnapshot> {
    Some(NodeSnapshot {
        name: metadata_string(value, "name")?,
        ready: value
            .pointer("/status/conditions")
            .and_then(serde_json::Value::as_array)
            .map(|conditions| {
                conditions.iter().any(|condition| {
                    condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
                        && condition.get("status").and_then(serde_json::Value::as_str)
                            == Some("True")
                })
            })
            .unwrap_or(false),
    })
}

fn workload_snapshot(value: &serde_json::Value) -> Option<KubernetesWorkloadSnapshot> {
    Some(KubernetesWorkloadSnapshot {
        namespace: metadata_string(value, "namespace").unwrap_or_else(|| "default".to_string()),
        name: metadata_string(value, "name")?,
        service_account_name: spec_string(value, "serviceAccountName"),
        runtime_class_name: spec_string(value, "runtimeClassName"),
        node_name: spec_string(value, "nodeName"),
    })
}

fn metadata_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get("metadata")?
        .get(key)?
        .as_str()
        .map(ToOwned::to_owned)
}

fn spec_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get("spec")?.get(key)?.as_str().map(ToOwned::to_owned)
}

fn has_label(value: &serde_json::Value, key: &str) -> bool {
    value
        .pointer("/metadata/labels")
        .and_then(|labels| labels.get(key))
        .is_some()
}
