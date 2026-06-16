// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{default_host_backup_sources, default_service_specs};

#[test]
fn default_backup_sources_cover_runtime_configuration_without_duplicates() {
    let sources = default_host_backup_sources();
    let ids = sources
        .iter()
        .map(|source| source.id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        ids,
        vec![
            "docker_daemon",
            "containerd_config",
            "k3s_generated_containerd_config",
            "k3s_containerd_v3_template",
            "k3s_runtime_dropin",
            "docker_http_proxy_dropin",
            "k3s_http_proxy_dropin"
        ]
    );
    assert_eq!(
        sources[0].path,
        std::path::Path::new("/etc/docker/daemon.json")
    );
    assert_eq!(
        sources[1].path,
        std::path::Path::new("/etc/containerd/config.toml")
    );
    assert_eq!(
        sources[2].path,
        std::path::Path::new("/var/lib/rancher/k3s/agent/etc/containerd/config.toml")
    );
    assert_eq!(
        sources[3].path,
        std::path::Path::new("/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl")
    );
    assert_eq!(
        sources[4].path,
        std::path::Path::new(
            "/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/99-apolysis-runtimes.toml"
        )
    );
}

#[test]
fn default_service_specs_cover_runtime_sockets() {
    let specs = default_service_specs();

    assert_eq!(specs.len(), 3);
    assert_eq!(specs[0].service_name, "containerd.service");
    assert_eq!(
        specs[0].runtime_sockets,
        vec![std::path::PathBuf::from("/run/containerd/containerd.sock")]
    );
    assert_eq!(specs[1].service_name, "docker.service");
    assert_eq!(
        specs[1].runtime_sockets,
        vec![std::path::PathBuf::from("/run/docker.sock")]
    );
    assert_eq!(specs[2].service_name, "k3s.service");
    assert_eq!(
        specs[2].runtime_sockets,
        vec![std::path::PathBuf::from(
            "/run/k3s/containerd/containerd.sock"
        )]
    );
}
