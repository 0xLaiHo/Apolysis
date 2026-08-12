// SPDX-License-Identifier: Apache-2.0

use apolysis_kubernetes_source::{
    kubernetes_container_ref, kubernetes_namespace_ref, kubernetes_node_ref,
    kubernetes_pod_revision_ref, kubernetes_runtime_class_ref, ContainerKind, KubernetesClusterId,
    KubernetesContainerSnapshot, KubernetesPodSnapshot, KubernetesPodUid, KubernetesSnapshot,
    OpaqueRef, RuntimeContainerId, SourceEpoch, KUBERNETES_SOURCE_SCHEMA_V1,
};

#[test]
fn source_refs_are_stable_and_domain_separated() {
    assert_eq!(
        kubernetes_namespace_ref("agents").expect("valid namespace"),
        OpaqueRef::parse("db7fa66f488329603afb3d2b0765958996799e39abb31db19aae166cea16e12c")
            .expect("known namespace ref")
    );
    assert_eq!(
        kubernetes_node_ref("worker-a").expect("valid node"),
        OpaqueRef::parse("0d847197ff7550d6cdbaef96e1bf345784e7900776a477bb20eb14e9a88c419a")
            .expect("known node ref")
    );
    assert_eq!(
        kubernetes_container_ref("agent").expect("valid container name"),
        OpaqueRef::parse("9b0cd035c863d0a1cecd2ed425a4941a324a23f44c05dd9e423f173afb22b177")
            .expect("known container ref")
    );
    assert_eq!(
        kubernetes_runtime_class_ref("gvisor").expect("valid runtime class"),
        OpaqueRef::parse("31dd3b9bd06c0ce61d5d5d4eb8f17a0003240cf5c4fbd6f42c9b8caa878fc024")
            .expect("known runtime class ref")
    );
}

#[test]
fn source_identifiers_reject_noncanonical_or_ambiguous_values() {
    assert!(kubernetes_namespace_ref("").is_err());
    assert!(kubernetes_namespace_ref(" Agents").is_err());
    assert!(kubernetes_namespace_ref("agents/other").is_err());
    assert!(kubernetes_node_ref("Worker-1").is_err());
    assert!(kubernetes_node_ref("worker_1").is_err());
    assert!(kubernetes_container_ref("agent/container").is_err());
    assert!(kubernetes_runtime_class_ref("gVisor").is_err());
    assert!(kubernetes_pod_revision_ref("").is_err());
    assert!(kubernetes_pod_revision_ref("revision\nprivate").is_err());
    assert!(kubernetes_pod_revision_ref(&"r".repeat(257)).is_err());
    assert!(SourceEpoch::parse("00000000-0000-0000-0000-000000000000").is_err());
    assert!(SourceEpoch::parse("550E8400-E29B-41D4-A716-446655440000").is_err());
}

#[test]
fn snapshot_wire_is_exact_and_contains_no_raw_kubernetes_names() {
    let snapshot = KubernetesSnapshot {
        schema_version: KUBERNETES_SOURCE_SCHEMA_V1,
        source_epoch: SourceEpoch::parse("550e8400-e29b-41d4-a716-446655440000")
            .expect("source epoch"),
        snapshot_sequence: 7,
        cluster_id: KubernetesClusterId::parse("123e4567-e89b-42d3-a456-426614174000")
            .expect("cluster id"),
        namespace_ref: kubernetes_namespace_ref("agents").expect("namespace ref"),
        node_ref: kubernetes_node_ref("worker-a").expect("node ref"),
        pods: vec![KubernetesPodSnapshot {
            pod_uid: KubernetesPodUid::parse("9f4d08b8-5f06-4df0-84f7-a347900a1445")
                .expect("pod UID"),
            pod_revision_ref: OpaqueRef::parse(&"e".repeat(64)).expect("Pod revision ref"),
            deleting: false,
            runtime_class_ref: Some(
                kubernetes_runtime_class_ref("gvisor").expect("runtime class ref"),
            ),
            containers: vec![KubernetesContainerSnapshot {
                kind: ContainerKind::Application,
                container_ref: kubernetes_container_ref("agent").expect("container ref"),
                runtime_container_id: Some(
                    RuntimeContainerId::parse(&format!("containerd://{}", "a".repeat(64)))
                        .expect("runtime container ID"),
                ),
                running: true,
            }],
        }],
    };

    let json = serde_json::to_string(&snapshot).expect("serialize snapshot");
    assert!(!json.contains("agents"));
    assert!(!json.contains("worker-a"));
    assert!(!json.contains("gvisor"));
    assert!(!json.contains("\"agent\""));
    assert!(!json.contains("resource_version"));
    assert!(!json.contains("service_account"));
    assert!(!json.contains("annotations"));
    assert!(!json.contains("labels"));

    let decoded: KubernetesSnapshot = serde_json::from_str(&json).expect("decode exact snapshot");
    assert_eq!(decoded, snapshot);

    let with_unknown = json.replacen('{', "{\"unexpected\":true,", 1);
    assert!(serde_json::from_str::<KubernetesSnapshot>(&with_unknown).is_err());
}

#[test]
fn snapshot_wire_rejects_running_container_without_exact_runtime_identity() {
    let wire = serde_json::json!({
        "schema_version": 1,
        "source_epoch": "550e8400-e29b-41d4-a716-446655440000",
        "snapshot_sequence": 1,
        "cluster_id": "123e4567-e89b-42d3-a456-426614174000",
        "namespace_ref": "a".repeat(64),
        "node_ref": "b".repeat(64),
        "pods": [{
            "pod_uid": "9f4d08b8-5f06-4df0-84f7-a347900a1445",
            "pod_revision_ref": "e".repeat(64),
            "deleting": false,
            "runtime_class_ref": null,
            "containers": [{
                "kind": "application",
                "container_ref": "c".repeat(64),
                "runtime_container_id": null,
                "running": true
            }]
        }]
    });

    assert!(serde_json::from_value::<KubernetesSnapshot>(wire).is_err());
}
