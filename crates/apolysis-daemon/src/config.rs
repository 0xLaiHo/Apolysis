// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub state_dir: PathBuf,
    pub bpf_object: Option<PathBuf>,
    pub feedback_dir: Option<PathBuf>,
    pub docker_socket: Option<PathBuf>,
    pub containerd_socket: Option<PathBuf>,
    pub k3s_containerd_socket: Option<PathBuf>,
    pub kubernetes_kubectl: Option<PathBuf>,
    pub kubernetes_cri_socket: Option<PathBuf>,
    pub proc_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub runtime_adapter_scan_interval: Duration,
    pub runtime_adapter_seen_capacity: usize,
    pub max_sessions: usize,
    pub max_pending: usize,
    pub max_connections: usize,
    pub queue_capacity: usize,
    pub scope_command_capacity: usize,
    pub request_timeout: Duration,
    pub shutdown_drain_timeout: Duration,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/apolysis/apolysisd.sock"),
            state_dir: PathBuf::from("/var/lib/apolysis"),
            bpf_object: None,
            feedback_dir: None,
            docker_socket: None,
            containerd_socket: None,
            k3s_containerd_socket: None,
            kubernetes_kubectl: None,
            kubernetes_cri_socket: None,
            proc_root: PathBuf::from("/proc"),
            cgroup_root: PathBuf::from("/sys/fs/cgroup"),
            runtime_adapter_scan_interval: Duration::from_secs(5),
            runtime_adapter_seen_capacity: 16_384,
            max_sessions: 4_096,
            max_pending: 4_096,
            max_connections: 128,
            queue_capacity: 16_384,
            scope_command_capacity: 1_024,
            request_timeout: Duration::from_secs(5),
            shutdown_drain_timeout: Duration::from_secs(5),
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
                "--feedback-dir" => config.feedback_dir = Some(value.into()),
                "--docker-socket" => config.docker_socket = Some(value.into()),
                "--containerd-socket" => config.containerd_socket = Some(value.into()),
                "--k3s-containerd-socket" => config.k3s_containerd_socket = Some(value.into()),
                "--kubernetes-kubectl" => config.kubernetes_kubectl = Some(value.into()),
                "--kubernetes-cri-socket" => config.kubernetes_cri_socket = Some(value.into()),
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
                "--request-timeout-ms" => {
                    config.request_timeout = Duration::from_millis(parse_u64(option, value)?)
                }
                "--shutdown-drain-ms" => {
                    config.shutdown_drain_timeout = Duration::from_millis(parse_u64(option, value)?)
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
        Ok(config)
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
