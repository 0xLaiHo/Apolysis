// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::sync::Mutex;

use apolysis_kubernetes_source::{
    kubernetes_container_ref, kubernetes_namespace_ref, kubernetes_node_ref,
    kubernetes_runtime_class_ref, AuthoritativeSnapshotSource, CaptureLimits, ContainerKind,
    KubernetesApiContainer, KubernetesApiPod, KubernetesClusterId, KubernetesListPort,
    KubernetesPodPage, KubernetesSourceErrorKind, ListPageRequest, RuntimeContainerId,
    SourceProfile,
};

#[tokio::test]
async fn authoritative_capture_closes_one_paginated_collection_and_emits_only_refs() {
    let api = ScriptedListPort::new([
        Ok(KubernetesPodPage {
            resource_version: "700".to_string(),
            continue_token: Some("next-page".to_string()),
            encoded_bytes: 2048,
            pods: vec![pod("9f4d08b8-5f06-4df0-84f7-a347900a1445", "sidecar", "b")],
        }),
        Ok(KubernetesPodPage {
            resource_version: "700".to_string(),
            continue_token: None,
            encoded_bytes: 1024,
            pods: vec![pod("15f59104-d1db-41f4-935d-3c4db7a5fe01", "agent", "a")],
        }),
    ]);
    let source = AuthoritativeSnapshotSource::new(
        SourceProfile::new(
            KubernetesClusterId::parse("123e4567-e89b-42d3-a456-426614174000").expect("cluster ID"),
            "agents",
            "worker-a",
            CaptureLimits {
                page_size: 1,
                max_pages: 2,
                max_pods: 2,
                max_containers_per_pod: 2,
                max_response_bytes: 4096,
                max_snapshot_bytes: 4096,
            },
        )
        .expect("source profile"),
        api,
    );

    let first = source.capture().await.expect("authoritative snapshot");
    let second = source.capture().await.expect_err("script is now exhausted");

    assert_eq!(first.snapshot_sequence, 1);
    assert_eq!(
        first.cluster_id.as_str(),
        "123e4567-e89b-42d3-a456-426614174000"
    );
    assert_eq!(
        first.namespace_ref,
        kubernetes_namespace_ref("agents").expect("namespace ref")
    );
    assert_eq!(
        first.node_ref,
        kubernetes_node_ref("worker-a").expect("node ref")
    );
    assert_eq!(first.pods.len(), 2);
    assert_eq!(
        first.pods[0].pod_uid.as_str(),
        "15f59104-d1db-41f4-935d-3c4db7a5fe01"
    );
    assert_eq!(
        first.pods[0].runtime_class_ref,
        Some(kubernetes_runtime_class_ref("gvisor").expect("runtime class ref"))
    );
    assert_eq!(
        first.pods[0].containers[0].container_ref,
        kubernetes_container_ref("agent").expect("container ref")
    );
    assert_eq!(
        first.pods[0].containers[0].runtime_container_id,
        Some(
            RuntimeContainerId::parse(&format!("containerd://{}", "a".repeat(64)))
                .expect("runtime container ID")
        )
    );
    assert_eq!(second.kind(), KubernetesSourceErrorKind::Unavailable);
}

#[tokio::test]
async fn running_container_without_a_full_runtime_id_fails_the_whole_capture() {
    let mut raw = pod("15f59104-d1db-41f4-935d-3c4db7a5fe01", "agent", "a");
    raw.containers[0].runtime_container_id = None;
    let source = source_with_pages([Ok(KubernetesPodPage {
        resource_version: "702".to_string(),
        continue_token: None,
        encoded_bytes: 1024,
        pods: vec![raw],
    })]);

    let error = source
        .capture()
        .await
        .expect_err("running container without runtime ID");
    assert_eq!(error.kind(), KubernetesSourceErrorKind::Malformed);
}

#[tokio::test]
async fn terminated_container_without_a_runtime_id_remains_an_explicit_slot() {
    let mut raw = pod("15f59104-d1db-41f4-935d-3c4db7a5fe01", "agent", "a");
    raw.deleting = true;
    raw.containers[0].running = false;
    raw.containers[0].runtime_container_id = None;
    let source = source_with_pages([Ok(KubernetesPodPage {
        resource_version: "703".to_string(),
        continue_token: None,
        encoded_bytes: 1024,
        pods: vec![raw],
    })]);

    let snapshot = source.capture().await.expect("terminated container slot");
    assert!(snapshot.pods[0].deleting);
    assert!(!snapshot.pods[0].containers[0].running);
    assert!(snapshot.pods[0].containers[0]
        .runtime_container_id
        .is_none());
}

#[tokio::test]
async fn pagination_resource_version_change_rejects_the_entire_capture() {
    let source = source_with_pages([
        Ok(KubernetesPodPage {
            resource_version: "704".to_string(),
            continue_token: Some("next".to_string()),
            encoded_bytes: 1024,
            pods: Vec::new(),
        }),
        Ok(KubernetesPodPage {
            resource_version: "705".to_string(),
            continue_token: None,
            encoded_bytes: 1024,
            pods: Vec::new(),
        }),
    ]);

    assert_eq!(
        source
            .capture()
            .await
            .expect_err("resourceVersion changed within one collection")
            .kind(),
        KubernetesSourceErrorKind::Inconsistent
    );
}

#[tokio::test]
async fn duplicate_pod_uid_across_pages_rejects_the_entire_capture() {
    let uid = "15f59104-d1db-41f4-935d-3c4db7a5fe01";
    let source = source_with_pages([
        Ok(KubernetesPodPage {
            resource_version: "706".to_string(),
            continue_token: Some("next".to_string()),
            encoded_bytes: 1024,
            pods: vec![pod(uid, "agent", "a")],
        }),
        Ok(KubernetesPodPage {
            resource_version: "706".to_string(),
            continue_token: None,
            encoded_bytes: 1024,
            pods: vec![pod(uid, "agent", "a")],
        }),
    ]);

    assert_eq!(
        source
            .capture()
            .await
            .expect_err("duplicate Pod UID")
            .kind(),
        KubernetesSourceErrorKind::Inconsistent
    );
}

#[tokio::test]
async fn source_error_never_echoes_a_private_kubernetes_identifier() {
    let private = "private-pod-name";
    let mut raw = pod("15f59104-d1db-41f4-935d-3c4db7a5fe01", "agent", "a");
    raw.node_name = private.to_string();
    let source = source_with_pages([Ok(KubernetesPodPage {
        resource_version: "707".to_string(),
        continue_token: None,
        encoded_bytes: 1024,
        pods: vec![raw],
    })]);

    let error = source.capture().await.expect_err("wrong node");
    assert_eq!(error.kind(), KubernetesSourceErrorKind::Inconsistent);
    assert!(!error.to_string().contains(private));
}

#[tokio::test]
async fn pod_revision_is_content_off_and_changes_across_authoritative_captures() {
    let mut first_pod = pod("15f59104-d1db-41f4-935d-3c4db7a5fe01", "agent", "a");
    first_pod.resource_version = "private-revision-700".to_string();
    let mut second_pod = pod("15f59104-d1db-41f4-935d-3c4db7a5fe01", "agent", "a");
    second_pod.resource_version = "private-revision-701".to_string();
    let source = source_with_pages([
        Ok(KubernetesPodPage {
            resource_version: "900".to_string(),
            continue_token: None,
            encoded_bytes: 1024,
            pods: vec![first_pod],
        }),
        Ok(KubernetesPodPage {
            resource_version: "901".to_string(),
            continue_token: None,
            encoded_bytes: 1024,
            pods: vec![second_pod],
        }),
    ]);

    let first = source.capture().await.expect("first complete snapshot");
    let second = source.capture().await.expect("second complete snapshot");

    assert_ne!(
        first.pods[0].pod_revision_ref,
        second.pods[0].pod_revision_ref
    );
    let encoded = serde_json::to_string(&second).expect("serialize snapshot");
    assert!(!encoded.contains("private-revision"));
}

struct ScriptedListPort {
    pages: Mutex<VecDeque<Result<KubernetesPodPage, KubernetesSourceErrorKind>>>,
}

impl ScriptedListPort {
    fn new(
        pages: impl IntoIterator<Item = Result<KubernetesPodPage, KubernetesSourceErrorKind>>,
    ) -> Self {
        Self {
            pages: Mutex::new(pages.into_iter().collect()),
        }
    }
}

impl KubernetesListPort for ScriptedListPort {
    async fn list_page(
        &self,
        _request: ListPageRequest,
    ) -> Result<KubernetesPodPage, KubernetesSourceErrorKind> {
        self.pages
            .lock()
            .expect("script lock")
            .pop_front()
            .unwrap_or(Err(KubernetesSourceErrorKind::Unavailable))
    }
}

fn pod(uid: &str, container: &str, identifier: &str) -> KubernetesApiPod {
    KubernetesApiPod {
        namespace: "agents".to_string(),
        node_name: "worker-a".to_string(),
        marked_for_observation: true,
        pod_uid: uid.to_string(),
        resource_version: "private-revision-1".to_string(),
        deleting: false,
        runtime_class_name: Some("gvisor".to_string()),
        containers: vec![KubernetesApiContainer {
            kind: ContainerKind::Application,
            name: container.to_string(),
            runtime_container_id: Some(format!("containerd://{}", identifier.repeat(64))),
            running: true,
        }],
    }
}

fn source_with_pages(
    pages: impl IntoIterator<Item = Result<KubernetesPodPage, KubernetesSourceErrorKind>>,
) -> AuthoritativeSnapshotSource<ScriptedListPort> {
    AuthoritativeSnapshotSource::new(
        SourceProfile::new(
            KubernetesClusterId::parse("123e4567-e89b-42d3-a456-426614174000").expect("cluster ID"),
            "agents",
            "worker-a",
            CaptureLimits {
                page_size: 4,
                max_pages: 2,
                max_pods: 4,
                max_containers_per_pod: 4,
                max_response_bytes: 4096,
                max_snapshot_bytes: 4096,
            },
        )
        .expect("source profile"),
        ScriptedListPort::new(pages),
    )
}
