// SPDX-License-Identifier: Apache-2.0

use apolysis_validation::{capture_kubernetes_restore_context, KubernetesCaptureRequest};

#[test]
fn captures_runtimeclasses_nodes_and_redacted_non_test_workloads() {
    let context = capture_kubernetes_restore_context(KubernetesCaptureRequest {
        runtimeclasses_json: r#"{
          "items":[
            {"metadata":{"name":"runsc"},"handler":"runsc"},
            {"metadata":{"name":"kata"},"handler":"kata"}
          ]
        }"#,
        nodes_json: r#"{
          "items":[
            {"metadata":{"name":"worker-a"},"status":{"conditions":[{"type":"Ready","status":"True"}]}},
            {"metadata":{"name":"worker-b"},"status":{"conditions":[{"type":"Ready","status":"False"}]}}
          ]
        }"#,
        pods_json: r#"{
          "items":[
            {
              "metadata":{
                "namespace":"default",
                "name":"existing-agent",
                "annotations":{"secret.example/token":"do-not-store"},
                "labels":{"app":"agent"}
              },
              "spec":{
                "serviceAccountName":"agent-sa",
                "runtimeClassName":"runsc",
                "nodeName":"worker-a",
                "containers":[{"name":"main","env":[{"name":"TOKEN","value":"super-secret"}]}]
              }
            },
            {
              "metadata":{
                "namespace":"default",
                "name":"apolysis-validation-pod",
                "labels":{"apolysis.dev/validation":"true"}
              },
              "spec":{"serviceAccountName":"default","nodeName":"worker-a"}
            }
          ]
        }"#,
        validation_label_key: "apolysis.dev/validation",
    })
    .expect("capture kubernetes context");

    assert_eq!(context.runtime_classes.len(), 2);
    assert_eq!(context.runtime_classes[0].name, "kata");
    assert_eq!(context.runtime_classes[1].handler, "runsc");
    assert_eq!(context.nodes.len(), 2);
    assert_eq!(context.nodes[0].name, "worker-a");
    assert!(context.nodes[0].ready);
    assert!(!context.nodes[1].ready);
    assert_eq!(context.workloads.len(), 1);
    assert_eq!(context.workloads[0].namespace, "default");
    assert_eq!(context.workloads[0].name, "existing-agent");
    assert_eq!(
        context.workloads[0].service_account_name.as_deref(),
        Some("agent-sa")
    );
    assert_eq!(
        context.workloads[0].runtime_class_name.as_deref(),
        Some("runsc")
    );
    assert_eq!(context.workloads[0].node_name.as_deref(), Some("worker-a"));

    let serialized = serde_json::to_string(&context).unwrap();
    assert!(!serialized.contains("super-secret"));
    assert!(!serialized.contains("do-not-store"));
    assert!(!serialized.contains("apolysis-validation-pod"));
}

#[test]
fn invalid_kubernetes_json_fails_closed() {
    let error = capture_kubernetes_restore_context(KubernetesCaptureRequest {
        runtimeclasses_json: "{not-json",
        nodes_json: r#"{"items":[]}"#,
        pods_json: r#"{"items":[]}"#,
        validation_label_key: "apolysis.dev/validation",
    })
    .expect_err("invalid input must fail");

    assert!(error.contains("runtimeclasses"), "{error}");
}
