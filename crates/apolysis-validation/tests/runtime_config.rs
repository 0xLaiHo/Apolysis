// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

use apolysis_validation::{
    render_containerd_runtime_config, render_docker_runtime_config,
    render_k3s_runtime_dropin_config,
};

#[test]
fn docker_runtime_config_adds_runsc_without_changing_default_or_existing_runtimes() {
    let input = r#"{
  "default-runtime": "runc",
  "runtimes": {
    "nvidia": {
      "args": [],
      "path": "nvidia-container-runtime"
    }
  }
}"#;

    let rendered = render_docker_runtime_config(input).expect("render docker config");
    let value: Value = serde_json::from_str(&rendered).expect("valid docker JSON");

    assert_eq!(value["default-runtime"], "runc");
    assert_eq!(
        value["runtimes"]["nvidia"]["path"],
        "nvidia-container-runtime"
    );
    assert_eq!(value["runtimes"]["runsc"]["path"], "/usr/local/bin/runsc");
    assert_eq!(
        render_docker_runtime_config(&rendered).expect("render docker config again"),
        rendered
    );
}

#[test]
fn containerd_runtime_config_adds_runc_runsc_and_kata_handlers_idempotently() {
    let input = r#"version = 3
imports = ["/etc/containerd/conf.d/*.toml"]

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]
  runtime_type = "io.containerd.runc.v2"

[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc.options]
  SystemdCgroup = true
"#;

    let rendered = render_containerd_runtime_config(input).expect("render containerd config");

    assert!(rendered.contains("version = 3"));
    assert!(rendered.contains("imports = [\"/etc/containerd/conf.d/*.toml\"]"));
    assert!(rendered.contains(".containerd.runtimes.runc]"));
    assert!(rendered.contains("runtime_type = \"io.containerd.runc.v2\""));
    assert!(rendered.contains("SystemdCgroup = false"));
    assert!(
        rendered.contains(".containerd.runtimes.runsc]"),
        "{rendered}"
    );
    assert!(rendered.contains("runtime_type = \"io.containerd.runsc.v1\""));
    assert!(rendered.contains(".containerd.runtimes.kata]"));
    assert!(rendered.contains("runtime_type = \"io.containerd.kata.v2\""));
    assert_eq!(
        render_containerd_runtime_config(&rendered).expect("render containerd config again"),
        rendered
    );
}

#[test]
fn k3s_runtime_dropin_contains_only_runtime_handler_tables() {
    let rendered = render_k3s_runtime_dropin_config();

    assert!(
        rendered.contains(".containerd.runtimes.runsc]"),
        "{rendered}"
    );
    assert!(rendered.contains("runtime_type = \"io.containerd.runsc.v1\""));
    assert!(rendered.contains(".containerd.runtimes.kata]"));
    assert!(rendered.contains("runtime_type = \"io.containerd.kata.v2\""));
    assert!(!rendered.contains("/run/k3s/containerd/containerd.sock"));
    assert!(!rendered.contains("root ="));
}
