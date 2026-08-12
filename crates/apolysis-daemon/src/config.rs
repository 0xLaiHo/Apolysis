// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use apolysis_core::{kubernetes_reference_v1, KubernetesReferenceKind};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub state_dir: PathBuf,
    pub bpf_object: Option<PathBuf>,
    pub docker_socket: Option<PathBuf>,
    pub containerd_socket: Option<PathBuf>,
    pub k3s_containerd_socket: Option<PathBuf>,
    pub kubernetes_source_socket: Option<PathBuf>,
    pub kubernetes_cluster_id: Option<String>,
    pub kubernetes_namespace: Option<String>,
    pub kubernetes_node_name: Option<String>,
    pub proc_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub runtime_adapter_scan_interval: Duration,
    pub runtime_adapter_seen_capacity: usize,
    pub max_sessions: usize,
    pub max_pending: usize,
    pub max_connections: usize,
    pub queue_capacity: usize,
    pub scope_command_capacity: usize,
    pub metrics_listen: Option<SocketAddr>,
    pub request_timeout: Duration,
    pub shutdown_drain_timeout: Duration,
    pub collector_checkpoint_interval: Duration,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/apolysis/apolysisd.sock"),
            state_dir: PathBuf::from("/var/lib/apolysis"),
            bpf_object: None,
            docker_socket: None,
            containerd_socket: None,
            k3s_containerd_socket: None,
            kubernetes_source_socket: None,
            kubernetes_cluster_id: None,
            kubernetes_namespace: None,
            kubernetes_node_name: None,
            proc_root: PathBuf::from("/proc"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            runtime_adapter_scan_interval: Duration::from_secs(5),
            runtime_adapter_seen_capacity: 16_384,
            max_sessions: 4_096,
            max_pending: 4_096,
            max_connections: 128,
            queue_capacity: 16_384,
            scope_command_capacity: 1_024,
            metrics_listen: None,
            request_timeout: Duration::from_secs(5),
            shutdown_drain_timeout: Duration::from_secs(5),
            collector_checkpoint_interval: Duration::from_secs(30),
        }
    }
}

impl DaemonConfig {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut config = Self::default();
        let args: Vec<String> = args.into_iter().collect();
        let mut index = 0;
        while index < args.len() {
            let option = &args[index];
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| format!("missing value for {option}"))?;
            match option.as_str() {
                "--socket" => config.socket_path = value.into(),
                "--state-dir" => config.state_dir = value.into(),
                "--bpf-object" => config.bpf_object = Some(value.into()),
                "--docker-socket" => config.docker_socket = Some(value.into()),
                "--containerd-socket" => config.containerd_socket = Some(value.into()),
                "--k3s-containerd-socket" => config.k3s_containerd_socket = Some(value.into()),
                "--kubernetes-source-socket" => {
                    config.kubernetes_source_socket = Some(value.into())
                }
                "--kubernetes-cluster-id" => config.kubernetes_cluster_id = Some(value.clone()),
                "--kubernetes-namespace" => config.kubernetes_namespace = Some(value.clone()),
                "--kubernetes-node-name" => config.kubernetes_node_name = Some(value.clone()),
                "--proc-root" => config.proc_root = value.into(),
                "--cgroup-root" => config.cgroup_root = value.into(),
                "--runtime-adapter-scan-ms" => {
                    config.runtime_adapter_scan_interval =
                        Duration::from_millis(parse_u64(option, value)?)
                }
                "--runtime-adapter-seen-capacity" => {
                    config.runtime_adapter_seen_capacity = parse_usize(option, value)?
                }
                "--max-sessions" => config.max_sessions = parse_usize(option, value)?,
                "--max-pending" => config.max_pending = parse_usize(option, value)?,
                "--max-connections" => config.max_connections = parse_usize(option, value)?,
                "--queue-capacity" => config.queue_capacity = parse_usize(option, value)?,
                "--scope-command-capacity" => {
                    config.scope_command_capacity = parse_usize(option, value)?
                }
                "--metrics-listen" => {
                    config.metrics_listen = Some(
                        value
                            .parse()
                            .map_err(|error| format!("invalid value for {option}: {error}"))?,
                    )
                }
                "--request-timeout-ms" => {
                    config.request_timeout = Duration::from_millis(parse_u64(option, value)?)
                }
                "--shutdown-drain-ms" => {
                    config.shutdown_drain_timeout = Duration::from_millis(parse_u64(option, value)?)
                }
                "--collector-checkpoint-ms" => {
                    config.collector_checkpoint_interval =
                        Duration::from_millis(parse_u64(option, value)?)
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
            index += 1;
        }
        if config.max_connections == 0 {
            return Err("--max-connections must be greater than zero".to_string());
        }
        if config.queue_capacity == 0 {
            return Err("--queue-capacity must be greater than zero".to_string());
        }
        if config.scope_command_capacity == 0 {
            return Err("--scope-command-capacity must be greater than zero".to_string());
        }
        if config.runtime_adapter_scan_interval.is_zero() {
            return Err("--runtime-adapter-scan-ms must be greater than zero".to_string());
        }
        if config.runtime_adapter_seen_capacity == 0 {
            return Err("--runtime-adapter-seen-capacity must be greater than zero".to_string());
        }
        if config.request_timeout.is_zero() {
            return Err("--request-timeout-ms must be greater than zero".to_string());
        }
        if config.shutdown_drain_timeout.is_zero() {
            return Err("--shutdown-drain-ms must be greater than zero".to_string());
        }
        if config.collector_checkpoint_interval.is_zero() {
            return Err("--collector-checkpoint-ms must be greater than zero".to_string());
        }
        config.validate_kubernetes_node_profile()?;
        Ok(config)
    }

    fn validate_kubernetes_node_profile(&self) -> Result<(), String> {
        let configured = [
            self.kubernetes_source_socket.is_some(),
            self.kubernetes_cluster_id.is_some(),
            self.kubernetes_namespace.is_some(),
            self.kubernetes_node_name.is_some(),
        ];
        if configured.iter().all(|configured| !configured) {
            return Ok(());
        }
        if !configured.iter().all(|configured| *configured) {
            return Err(
                "Kubernetes node profile requires source socket, cluster ID, namespace, and node name"
                    .to_string(),
            );
        }
        let source_socket = self
            .kubernetes_source_socket
            .as_ref()
            .ok_or_else(|| "Kubernetes node profile is incomplete".to_string())?;
        if !source_socket.is_absolute() {
            return Err("Kubernetes node profile source socket must be absolute".to_string());
        }
        let cluster_id = self
            .kubernetes_cluster_id
            .as_deref()
            .ok_or_else(|| "Kubernetes node profile is incomplete".to_string())?;
        if apolysis_kubernetes_source::KubernetesClusterId::parse(cluster_id).is_err() {
            return Err(
                "Kubernetes node profile cluster ID must be a canonical lowercase non-zero UUID"
                    .to_string(),
            );
        }
        let namespace = self.kubernetes_namespace.as_deref().unwrap_or_default();
        kubernetes_reference_v1(KubernetesReferenceKind::Namespace, namespace).map_err(|_| {
            "Kubernetes node profile namespace must be a canonical Kubernetes identifier"
                .to_string()
        })?;
        let node_name = self.kubernetes_node_name.as_deref().unwrap_or_default();
        kubernetes_reference_v1(KubernetesReferenceKind::Node, node_name).map_err(|_| {
            "Kubernetes node profile node name must be a canonical Kubernetes identifier"
                .to_string()
        })?;
        if self.containerd_socket.is_some() == self.k3s_containerd_socket.is_some() {
            return Err(
                "Kubernetes node profile requires exactly one containerd runtime socket"
                    .to_string(),
            );
        }
        Ok(())
    }
}

fn parse_u64(option: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|error| format!("invalid value for {option}: {error}"))
}

fn parse_usize(option: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|error| format!("invalid value for {option}: {error}"))
}
