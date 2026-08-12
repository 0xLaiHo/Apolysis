// SPDX-License-Identifier: Apache-2.0

use apolysis_core::{
    kubernetes_reference_v1, KubernetesAttributionOptionalRef, KubernetesAttributionRecordType,
    KubernetesAttributionWireV1, KubernetesContainerKind, KubernetesReferenceKind,
    KubernetesWorkloadClaimV1, RuntimeBindingRecordType, RuntimeBindingRuntimeHandler,
    RuntimeBindingWireV1, KUBERNETES_ATTRIBUTION_SCHEMA_VERSION, RUNTIME_BINDING_SCHEMA_VERSION,
};
use serde_json::json;

#[test]
fn kubernetes_reference_v1_has_stable_domain_separated_known_answers() {
    let cases = [
        (
            KubernetesReferenceKind::Namespace,
            "agents",
            "db7fa66f488329603afb3d2b0765958996799e39abb31db19aae166cea16e12c",
        ),
        (
            KubernetesReferenceKind::Node,
            "worker-a",
            "0d847197ff7550d6cdbaef96e1bf345784e7900776a477bb20eb14e9a88c419a",
        ),
        (
            KubernetesReferenceKind::Container,
            "agent",
            "9b0cd035c863d0a1cecd2ed425a4941a324a23f44c05dd9e423f173afb22b177",
        ),
        (
            KubernetesReferenceKind::RuntimeClass,
            "gvisor",
            "31dd3b9bd06c0ce61d5d5d4eb8f17a0003240cf5c4fbd6f42c9b8caa878fc024",
        ),
    ];

    for (kind, raw, expected) in cases {
        assert_eq!(
            kubernetes_reference_v1(kind, raw).expect("canonical Kubernetes identifier"),
            expected
        );
    }
}

#[test]
fn kubernetes_reference_v1_rejects_noncanonical_input_without_echoing_it() {
    let private = " Private.Namespace ";
    let error = kubernetes_reference_v1(KubernetesReferenceKind::Namespace, private)
        .expect_err("noncanonical input");

    assert_eq!(error.field(), "namespace");
    assert!(!error.to_string().contains(private));

    for kind in [
        KubernetesReferenceKind::Namespace,
        KubernetesReferenceKind::Container,
    ] {
        assert!(
            kubernetes_reference_v1(kind, "a.b").is_err(),
            "DNS labels must not accept subdomain separators"
        );
    }
}

#[test]
fn kubernetes_attribution_v1_wire_round_trips_the_exact_privacy_contract() {
    let wire = attribution_wire();
    let expected = json!({
        "record_type": "kubernetes_attribution_observed",
        "schema_version": 1,
        "agent_run_id": "agent-run-1",
        "cluster_id": "11111111-1111-1111-1111-111111111111",
        "namespace_ref": "a".repeat(64),
        "pod_uid": "22222222-2222-2222-2222-222222222222",
        "node_ref": "b".repeat(64),
        "runtime_class_ref": "c".repeat(64),
        "container_kind": "application",
        "container_ref": "d".repeat(64),
        "runtime_binding": {
            "record_type": "runtime_binding_observed",
            "schema_version": 1,
            "agent_run_id": "agent-run-1",
            "adapter": "containerd",
            "workload_id": format!("containerd/{}", "e".repeat(64)),
            "start_marker": "42",
            "host_boot_id": "44444444-4444-4444-4444-444444444444",
            "init_process_start_time_ticks": 103,
            "cgroup_device": 7,
            "cgroup_id": 107,
            "runtime_handler": "runc",
        },
    });

    assert_eq!(serde_json::to_value(&wire).expect("serialize"), expected);
    assert_eq!(
        serde_json::from_value::<KubernetesAttributionWireV1>(expected)
            .expect("deserialize exact wire"),
        wire
    );
    assert_eq!(wire.validate(), Ok(()));
}

#[test]
fn kubernetes_attribution_v1_requires_explicit_nullable_runtime_class_and_rejects_unknown_fields() {
    let mut value = serde_json::to_value(attribution_wire()).expect("serialize");
    value["runtime_class_ref"] = serde_json::Value::Null;
    let decoded = serde_json::from_value::<KubernetesAttributionWireV1>(value.clone())
        .expect("explicit null is valid wire shape");
    assert_eq!(decoded.runtime_class_ref.0, None);
    assert_eq!(decoded.validate(), Ok(()));

    value
        .as_object_mut()
        .expect("object")
        .remove("runtime_class_ref");
    assert!(serde_json::from_value::<KubernetesAttributionWireV1>(value).is_err());

    let mut private = serde_json::to_value(attribution_wire()).expect("serialize");
    private["pod_name"] = json!("private-workload-name");
    assert!(serde_json::from_value::<KubernetesAttributionWireV1>(private).is_err());
}

#[test]
fn kubernetes_workload_claim_v1_is_one_exact_revisioned_container_slot() {
    let claim = KubernetesWorkloadClaimV1 {
        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        claim_revision: 7,
        cluster_id: "11111111-1111-1111-1111-111111111111".to_string(),
        namespace_ref: "a".repeat(64),
        pod_uid: "22222222-2222-2222-2222-222222222222".to_string(),
        container_kind: KubernetesContainerKind::Application,
        container_ref: "d".repeat(64),
    };

    assert_eq!(claim.validate(), Ok(()));
    assert_eq!(
        serde_json::to_value(&claim).expect("serialize"),
        json!({
            "schema_version": 1,
            "claim_revision": 7,
            "cluster_id": "11111111-1111-1111-1111-111111111111",
            "namespace_ref": "a".repeat(64),
            "pod_uid": "22222222-2222-2222-2222-222222222222",
            "container_kind": "application",
            "container_ref": "d".repeat(64),
        })
    );
}

#[test]
fn kubernetes_attribution_validation_never_echoes_rejected_private_values() {
    let mut wire = attribution_wire();
    wire.node_ref = "private-node-name".to_string();

    let error = wire.validate().expect_err("raw node names are forbidden");

    assert_eq!(error.field(), "node_ref");
    assert!(!error.to_string().contains("private-node-name"));
}

#[test]
fn kubernetes_attribution_wire_only_links_qualified_cri_runtime_domains() {
    let mut wire = attribution_wire();
    wire.runtime_binding.adapter = "docker".to_string();
    wire.runtime_binding.workload_id = "e".repeat(64);
    wire.runtime_binding.start_marker = "2026-08-12T01:02:03.000000000Z".to_string();

    let error = wire
        .validate()
        .expect_err("K1 does not qualify Docker as a Kubernetes node runtime");

    assert_eq!(error.field(), "runtime_binding.adapter");
}

fn attribution_wire() -> KubernetesAttributionWireV1 {
    KubernetesAttributionWireV1 {
        record_type: KubernetesAttributionRecordType::Observed,
        schema_version: KUBERNETES_ATTRIBUTION_SCHEMA_VERSION,
        agent_run_id: "agent-run-1".to_string(),
        cluster_id: "11111111-1111-1111-1111-111111111111".to_string(),
        namespace_ref: "a".repeat(64),
        pod_uid: "22222222-2222-2222-2222-222222222222".to_string(),
        node_ref: "b".repeat(64),
        runtime_class_ref: KubernetesAttributionOptionalRef(Some("c".repeat(64))),
        container_kind: KubernetesContainerKind::Application,
        container_ref: "d".repeat(64),
        runtime_binding: RuntimeBindingWireV1 {
            record_type: RuntimeBindingRecordType::Observed,
            schema_version: RUNTIME_BINDING_SCHEMA_VERSION,
            agent_run_id: "agent-run-1".to_string(),
            adapter: "containerd".to_string(),
            workload_id: format!("containerd/{}", "e".repeat(64)),
            start_marker: "42".to_string(),
            host_boot_id: "44444444-4444-4444-4444-444444444444".to_string(),
            init_process_start_time_ticks: 103,
            cgroup_device: 7,
            cgroup_id: 107,
            runtime_handler: RuntimeBindingRuntimeHandler(Some("runc".to_string())),
        },
    }
}
