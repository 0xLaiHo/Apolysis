// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::Duration;

use apolysis_daemon::DaemonConfig;

#[test]
fn parses_bounded_runtime_configuration() {
    let config = DaemonConfig::from_args(
        [
            "--bpf-object",
            "/opt/apolysis/apolysis_observer.bpf.o",
            "--feedback-dir",
            "/run/apolysis/feedback",
            "--docker-socket",
            "/var/run/docker.sock",
            "--proc-root",
            "/host/proc",
            "--cgroup-root",
            "/host/sys/fs/cgroup",
            "--queue-capacity",
            "8192",
            "--scope-command-capacity",
            "256",
            "--shutdown-drain-ms",
            "3000",
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
        config.feedback_dir,
        Some(PathBuf::from("/run/apolysis/feedback"))
    );
    assert_eq!(
        config.docker_socket,
        Some(PathBuf::from("/var/run/docker.sock"))
    );
    assert_eq!(config.proc_root, PathBuf::from("/host/proc"));
    assert_eq!(config.cgroup_root, PathBuf::from("/host/sys/fs/cgroup"));
    assert_eq!(config.queue_capacity, 8192);
    assert_eq!(config.scope_command_capacity, 256);
    assert_eq!(config.shutdown_drain_timeout, Duration::from_secs(3));
}

#[test]
fn rejects_zero_runtime_bounds() {
    for arguments in [
        vec!["--queue-capacity", "0"],
        vec!["--scope-command-capacity", "0"],
        vec!["--shutdown-drain-ms", "0"],
    ] {
        let error = DaemonConfig::from_args(arguments.into_iter().map(str::to_string))
            .expect_err("zero runtime bound must fail");
        assert!(error.contains("greater than zero"), "{error}");
    }
}
