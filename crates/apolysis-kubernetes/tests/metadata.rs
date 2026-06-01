// SPDX-License-Identifier: Apache-2.0

use apolysis_kubernetes::{KubernetesMetadata, RuntimeIsolationProfile};

#[test]
fn parses_agent_sandbox_gvisor_pod_metadata() {
    let input = std::fs::read_to_string(
        workspace_root().join("tests/fixtures/kubernetes/agent-sandbox-gvisor-pod.yaml"),
    )
    .expect("read fixture");

    let metadata = KubernetesMetadata::parse(&input).expect("parse metadata");

    assert_eq!(metadata.pod_name, "codex-session-7");
    assert_eq!(metadata.namespace, "agents");
    assert_eq!(metadata.pod_uid.as_deref(), Some("pod-uid-123"));
    assert_eq!(metadata.service_account.as_deref(), Some("agent-runner"));
    assert_eq!(metadata.runtime_class_name.as_deref(), Some("gvisor"));
    assert_eq!(
        metadata.runtime_isolation_profile(),
        RuntimeIsolationProfile::Gvisor
    );
    assert_eq!(metadata.node_name.as_deref(), Some("worker-a"));
    assert_eq!(metadata.sandbox_name.as_deref(), Some("codex-sandbox"));
    assert_eq!(metadata.automount_service_account_token, Some(false));
}

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn identifies_kata_runtime_class_metadata() {
    let metadata = KubernetesMetadata::parse(
        r#"
apiVersion: v1
kind: Pod
metadata:
  name: kata-session
  namespace: agents
spec:
  serviceAccountName: agent-runner
  automountServiceAccountToken: false
  runtimeClassName: kata-qemu
  nodeName: worker-b
"#,
    )
    .expect("parse metadata");

    assert_eq!(
        metadata.runtime_isolation_profile(),
        RuntimeIsolationProfile::Kata
    );
}
