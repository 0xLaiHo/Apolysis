// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use apolysis_daemon::DaemonConfig;

#[test]
fn parses_bounded_runtime_configuration() {
    let config = DaemonConfig::from_args(
        [
            "--bpf-object",
            "/opt/apolysis/apolysis_observer.bpf.o",
            "--docker-socket",
            "/var/run/docker.sock",
            "--containerd-socket",
            "/run/containerd/containerd.sock",
            "--k3s-containerd-socket",
            "/run/k3s/containerd/containerd.sock",
            "--proc-root",
            "/host/proc",
            "--cgroup-root",
            "/host/sys/fs/cgroup",
            "--runtime-adapter-scan-ms",
            "750",
            "--runtime-adapter-seen-capacity",
            "2048",
            "--queue-capacity",
            "8192",
            "--scope-command-capacity",
            "256",
            "--metrics-listen",
            "127.0.0.1:9909",
            "--shutdown-drain-ms",
            "3000",
            "--collector-checkpoint-ms",
            "15000",
        ]
        .into_iter()
        .map(str::to_string),
    )
    .expect("valid runtime configuration");

    assert_eq!(
        config.bpf_object,
        Some(PathBuf::from("/opt/apolysis/apolysis_observer.bpf.o"))
    );
    assert_eq!(
        config.docker_socket,
        Some(PathBuf::from("/var/run/docker.sock"))
    );
    assert_eq!(
        config.containerd_socket,
        Some(PathBuf::from("/run/containerd/containerd.sock"))
    );
    assert_eq!(
        config.k3s_containerd_socket,
        Some(PathBuf::from("/run/k3s/containerd/containerd.sock"))
    );
    assert_eq!(config.proc_root, PathBuf::from("/host/proc"));
    assert_eq!(config.cgroup_root, PathBuf::from("/host/sys/fs/cgroup"));
    assert_eq!(
        config.runtime_adapter_scan_interval,
        Duration::from_millis(750)
    );
    assert_eq!(config.runtime_adapter_seen_capacity, 2048);
    assert_eq!(config.queue_capacity, 8192);
    assert_eq!(config.scope_command_capacity, 256);
    assert_eq!(
        config.metrics_listen,
        Some("127.0.0.1:9909".parse::<SocketAddr>().unwrap())
    );
    assert_eq!(config.shutdown_drain_timeout, Duration::from_secs(3));
    assert_eq!(
        config.collector_checkpoint_interval,
        Duration::from_secs(15)
    );
}

#[test]
fn parses_complete_kubernetes_node_profile() {
    let config = DaemonConfig::from_args(
        [
            "--containerd-socket",
            "/run/containerd/containerd.sock",
            "--kubernetes-source-socket",
            "/run/apolysis/kubernetes-source.sock",
            "--kubernetes-cluster-id",
            "11111111-1111-1111-1111-111111111111",
            "--kubernetes-namespace",
            "qualification",
            "--kubernetes-node-name",
            "worker-a.example.internal",
        ]
        .into_iter()
        .map(str::to_string),
    )
    .expect("complete Kubernetes node profile");

    assert_eq!(
        config.kubernetes_source_socket,
        Some(PathBuf::from("/run/apolysis/kubernetes-source.sock"))
    );
    assert_eq!(
        config.kubernetes_cluster_id.as_deref(),
        Some("11111111-1111-1111-1111-111111111111")
    );
    assert_eq!(
        config.kubernetes_namespace.as_deref(),
        Some("qualification")
    );
    assert_eq!(
        config.kubernetes_node_name.as_deref(),
        Some("worker-a.example.internal")
    );
}

#[test]
fn rejects_partial_or_ambiguous_kubernetes_node_profiles() {
    for arguments in [
        vec![
            "--kubernetes-source-socket",
            "/run/apolysis/kubernetes-source.sock",
        ],
        vec![
            "--containerd-socket",
            "/run/containerd/containerd.sock",
            "--k3s-containerd-socket",
            "/run/k3s/containerd/containerd.sock",
            "--kubernetes-source-socket",
            "/run/apolysis/kubernetes-source.sock",
            "--kubernetes-cluster-id",
            "11111111-1111-1111-1111-111111111111",
            "--kubernetes-namespace",
            "qualification",
            "--kubernetes-node-name",
            "worker-a.example.internal",
        ],
    ] {
        let error = DaemonConfig::from_args(arguments.into_iter().map(str::to_string))
            .expect_err("unsafe Kubernetes node profile must fail closed");
        assert!(error.contains("Kubernetes node profile"), "{error}");
    }
}

#[test]
fn rejects_the_legacy_kubectl_production_path() {
    let error = DaemonConfig::from_args(
        ["--kubernetes-kubectl", "/usr/local/bin/kubectl"]
            .into_iter()
            .map(str::to_string),
    )
    .expect_err("kubectl shelling must not remain a production option");
    assert!(error.contains("unknown argument"), "{error}");
}

#[test]
fn rejects_zero_runtime_bounds() {
    for arguments in [
        vec!["--queue-capacity", "0"],
        vec!["--scope-command-capacity", "0"],
        vec!["--runtime-adapter-scan-ms", "0"],
        vec!["--runtime-adapter-seen-capacity", "0"],
        vec!["--shutdown-drain-ms", "0"],
        vec!["--collector-checkpoint-ms", "0"],
    ] {
        let error = DaemonConfig::from_args(arguments.into_iter().map(str::to_string))
            .expect_err("zero runtime bound must fail");
        assert!(error.contains("greater than zero"), "{error}");
    }
}
