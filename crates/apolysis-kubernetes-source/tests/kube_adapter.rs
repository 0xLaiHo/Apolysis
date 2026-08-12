// SPDX-License-Identifier: Apache-2.0

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use apolysis_kubernetes_source::{
    kubernetes_container_ref, AuthoritativeSnapshotSource, CaptureLimits, KubeListAdapter,
    KubernetesClusterId, SourceProfile, WatchPollOutcome,
};
use http::{Request, Response};
use kube::client::Body;
use tower::service_fn;

#[tokio::test]
async fn production_list_uses_node_and_marker_selectors_and_projects_only_needed_fields() {
    let observed_request = Arc::new(Mutex::new(None));
    let service = service_fn({
        let observed_request = Arc::clone(&observed_request);
        move |request: Request<Body>| {
            let observed_request = Arc::clone(&observed_request);
            async move {
                *observed_request.lock().expect("request lock") =
                    Some((request.uri().clone(), request.headers().clone()));
                Ok::<_, Infallible>(Response::new(Body::from(
                    br#"{
                      "apiVersion":"v1",
                      "kind":"PodList",
                      "metadata":{"resourceVersion":"701","continue":""},
                      "items":[{
                        "metadata":{
                          "namespace":"agents",
                          "resourceVersion":"private-pod-revision-701",
                          "uid":"15f59104-d1db-41f4-935d-3c4db7a5fe01",
                          "labels":{"apolysis.dev/observe":"true","private.example/payload":"do-not-retain"},
                          "name":"private-agent-name"
                        },
                        "spec":{
                          "nodeName":"worker-a",
                          "runtimeClassName":"gvisor",
                          "containers":[{"name":"agent","env":[{"name":"SECRET","value":"do-not-retain"}]}]
                        },
                        "status":{
                          "containerStatuses":[{
                            "name":"agent",
                            "containerID":"containerd://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "state":{"running":{"startedAt":"2026-08-12T00:00:00Z"}},
                            "image":"private.example/agent:latest"
                          }]
                        }
                      }]
                    }"#
                    .to_vec(),
                )))
            }
        }
    });
    let client = kube::Client::new(service, "agents");
    let adapter = KubeListAdapter::from_client(client, 4096, Duration::from_secs(1))
        .expect("bounded adapter");
    let source = AuthoritativeSnapshotSource::new(
        SourceProfile::new(
            KubernetesClusterId::parse("123e4567-e89b-42d3-a456-426614174000").expect("cluster ID"),
            "agents",
            "worker-a",
            CaptureLimits {
                page_size: 100,
                max_pages: 1,
                max_pods: 4,
                max_containers_per_pod: 4,
                max_response_bytes: 4096,
                max_snapshot_bytes: 4096,
            },
        )
        .expect("source profile"),
        adapter,
    );

    let snapshot = source.capture().await.expect("capture slim Pod projection");
    assert_eq!(snapshot.pods.len(), 1);
    assert_eq!(
        snapshot.pods[0].containers[0].container_ref,
        kubernetes_container_ref("agent").expect("container ref")
    );
    let encoded = serde_json::to_string(&snapshot).expect("serialize snapshot");
    for forbidden in [
        "private-agent-name",
        "private.example",
        "private-pod-revision-701",
        "SECRET",
        "do-not-retain",
        "resourceVersion",
        "startedAt",
    ] {
        assert!(!encoded.contains(forbidden), "snapshot leaked {forbidden}");
    }

    let request = observed_request
        .lock()
        .expect("request lock")
        .take()
        .expect("Kubernetes request");
    assert_eq!(request.0.path(), "/api/v1/namespaces/agents/pods");
    let query: std::collections::BTreeMap<_, _> =
        url::form_urlencoded::parse(request.0.query().expect("query").as_bytes())
            .into_owned()
            .collect();
    assert_eq!(
        query.get("fieldSelector").map(String::as_str),
        Some("spec.nodeName=worker-a")
    );
    assert_eq!(
        query.get("labelSelector").map(String::as_str),
        Some("apolysis.dev/observe=true")
    );
    assert_eq!(query.get("limit").map(String::as_str), Some("100"));
    assert_eq!(
        request
            .1
            .get(http::header::ACCEPT)
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
}

#[tokio::test]
async fn expired_watch_cursor_is_only_a_relist_dirty_hint() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_watch_uri = Arc::new(Mutex::new(None));
    let service = service_fn({
        let calls = Arc::clone(&calls);
        let observed_watch_uri = Arc::clone(&observed_watch_uri);
        move |request: Request<Body>| {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let observed_watch_uri = Arc::clone(&observed_watch_uri);
            async move {
                if call == 0 {
                    Ok::<_, Infallible>(Response::new(Body::from(
                        br#"{"metadata":{"resourceVersion":"811","continue":""},"items":[]}"#
                            .to_vec(),
                    )))
                } else {
                    *observed_watch_uri.lock().expect("watch URI lock") =
                        Some(request.uri().clone());
                    Ok(Response::builder()
                        .status(http::StatusCode::GONE)
                        .body(Body::from(
                            br#"{"kind":"Status","code":410,"message":"private detail"}"#.to_vec(),
                        ))
                        .expect("410 response"))
                }
            }
        }
    });
    let adapter = KubeListAdapter::from_client(
        kube::Client::new(service, "agents"),
        4096,
        Duration::from_secs(1),
    )
    .expect("bounded adapter");
    let source = AuthoritativeSnapshotSource::new(
        SourceProfile::new(
            KubernetesClusterId::parse("123e4567-e89b-42d3-a456-426614174000").expect("cluster ID"),
            "agents",
            "worker-a",
            CaptureLimits {
                page_size: 100,
                max_pages: 1,
                max_pods: 4,
                max_containers_per_pod: 4,
                max_response_bytes: 4096,
                max_snapshot_bytes: 4096,
            },
        )
        .expect("source profile"),
        adapter,
    );

    source.capture().await.expect("initial authoritative list");
    assert_eq!(
        source.poll_watch().await.expect("watch outcome"),
        WatchPollOutcome::RelistRequired
    );
    let uri = observed_watch_uri
        .lock()
        .expect("watch URI lock")
        .take()
        .expect("watch request");
    let query: std::collections::BTreeMap<_, _> =
        url::form_urlencoded::parse(uri.query().expect("watch query").as_bytes())
            .into_owned()
            .collect();
    assert_eq!(query.get("watch").map(String::as_str), Some("true"));
    assert_eq!(
        query.get("resourceVersion").map(String::as_str),
        Some("811")
    );
    assert_eq!(
        query.get("fieldSelector").map(String::as_str),
        Some("spec.nodeName=worker-a")
    );
}

#[tokio::test]
async fn watch_timeout_without_events_is_idle_not_authoritative_absence() {
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let service = service_fn({
        let calls = Arc::clone(&calls);
        move |_request: Request<Body>| {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                let body = if call == 0 {
                    br#"{"metadata":{"resourceVersion":"812","continue":""},"items":[]}"#.to_vec()
                } else {
                    Vec::new()
                };
                Ok::<_, Infallible>(Response::new(Body::from(body)))
            }
        }
    });
    let adapter = KubeListAdapter::from_client(
        kube::Client::new(service, "agents"),
        4096,
        Duration::from_secs(1),
    )
    .expect("bounded adapter");
    let source = AuthoritativeSnapshotSource::new(
        SourceProfile::new(
            KubernetesClusterId::parse("123e4567-e89b-42d3-a456-426614174000").expect("cluster ID"),
            "agents",
            "worker-a",
            CaptureLimits {
                page_size: 100,
                max_pages: 1,
                max_pods: 4,
                max_containers_per_pod: 4,
                max_response_bytes: 4096,
                max_snapshot_bytes: 4096,
            },
        )
        .expect("source profile"),
        adapter,
    );

    source.capture().await.expect("initial authoritative list");
    assert_eq!(
        source.poll_watch().await.expect("watch outcome"),
        WatchPollOutcome::Idle
    );
}
