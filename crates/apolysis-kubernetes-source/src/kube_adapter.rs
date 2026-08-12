// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::time::Duration;

use http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use kube::client::Body;
use kube::{Client, Config};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use crate::{
    ContainerKind, KubernetesApiContainer, KubernetesApiPod, KubernetesListPort, KubernetesPodPage,
    KubernetesSourceError, KubernetesSourceErrorKind, KubernetesWatchPort, ListPageRequest,
    WatchPollOutcome, WatchRequest,
};

const MAX_KUBE_RESPONSE_BYTES_HARD: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct KubeListAdapter {
    client: Client,
    max_response_bytes: usize,
    request_timeout: Duration,
}

impl KubeListAdapter {
    pub fn in_cluster(
        max_response_bytes: usize,
        request_timeout: Duration,
    ) -> Result<Self, KubernetesSourceError> {
        let mut config = Config::incluster_env()
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
        config.connect_timeout = Some(request_timeout);
        config.read_timeout = Some(request_timeout);
        config.write_timeout = Some(request_timeout);
        config.disable_compression = true;
        config.default_retry = false;
        let client = Client::try_from(config)
            .map_err(|_| KubernetesSourceError::new(KubernetesSourceErrorKind::Unavailable))?;
        Self::from_client(client, max_response_bytes, request_timeout)
    }

    pub fn from_client(
        client: Client,
        max_response_bytes: usize,
        request_timeout: Duration,
    ) -> Result<Self, KubernetesSourceError> {
        if max_response_bytes == 0
            || max_response_bytes > MAX_KUBE_RESPONSE_BYTES_HARD
            || request_timeout.is_zero()
        {
            return Err(KubernetesSourceError::new(
                KubernetesSourceErrorKind::Malformed,
            ));
        }
        Ok(Self {
            client,
            max_response_bytes,
            request_timeout,
        })
    }

    async fn request_page(
        &self,
        request: ListPageRequest,
    ) -> Result<KubernetesPodPage, KubernetesSourceErrorKind> {
        let uri = page_uri(&request)?;
        let request = Request::get(uri)
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .map_err(|_| KubernetesSourceErrorKind::Malformed)?;
        let response = tokio::time::timeout(self.request_timeout, self.client.send(request))
            .await
            .map_err(|_| KubernetesSourceErrorKind::Timeout)?
            .map_err(|_| KubernetesSourceErrorKind::Unavailable)?;
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        if response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|length| length > self.max_response_bytes)
        {
            return Err(KubernetesSourceErrorKind::Oversized);
        }

        let body = tokio::time::timeout(
            self.request_timeout,
            collect_bounded(response.into_body(), self.max_response_bytes, false),
        )
        .await
        .map_err(|_| KubernetesSourceErrorKind::Timeout)??;
        let document: PodListDocument =
            serde_json::from_slice(&body).map_err(|_| KubernetesSourceErrorKind::Malformed)?;
        let continue_token = match document.metadata.continue_token {
            Some(token) if token.is_empty() => None,
            token => token,
        };
        let pods = document
            .items
            .into_iter()
            .map(PodDocument::project)
            .collect();
        Ok(KubernetesPodPage {
            resource_version: document.metadata.resource_version,
            continue_token,
            encoded_bytes: body.len(),
            pods,
        })
    }
}

impl KubernetesListPort for KubeListAdapter {
    async fn list_page(
        &self,
        request: ListPageRequest,
    ) -> Result<KubernetesPodPage, KubernetesSourceErrorKind> {
        self.request_page(request).await
    }
}

impl KubernetesWatchPort for KubeListAdapter {
    async fn watch_once(
        &self,
        request: WatchRequest,
    ) -> Result<WatchPollOutcome, KubernetesSourceErrorKind> {
        let uri = watch_uri(&request, self.request_timeout)?;
        let request = Request::get(uri)
            .header(header::ACCEPT, "application/json")
            .body(Body::empty())
            .map_err(|_| KubernetesSourceErrorKind::Malformed)?;
        let response = tokio::time::timeout(self.request_timeout, self.client.send(request))
            .await
            .map_err(|_| KubernetesSourceErrorKind::Timeout)?
            .map_err(|_| KubernetesSourceErrorKind::Unavailable)?;
        if response.status() == StatusCode::GONE {
            return Ok(WatchPollOutcome::RelistRequired);
        }
        if !response.status().is_success() {
            return Err(status_error(response.status()));
        }
        let body = tokio::time::timeout(
            self.request_timeout,
            collect_bounded(response.into_body(), self.max_response_bytes, true),
        )
        .await
        .map_err(|_| KubernetesSourceErrorKind::Timeout)??;
        watch_outcome(&body)
    }
}

fn page_uri(request: &ListPageRequest) -> Result<http::Uri, KubernetesSourceErrorKind> {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair(
        "fieldSelector",
        &format!("spec.nodeName={}", request.node_name()),
    );
    query.append_pair("labelSelector", request.marker_selector());
    query.append_pair("limit", &request.page_size().to_string());
    if let Some(token) = request.continue_token() {
        query.append_pair("continue", token);
    }
    format!(
        "/api/v1/namespaces/{}/pods?{}",
        request.namespace(),
        query.finish()
    )
    .parse()
    .map_err(|_| KubernetesSourceErrorKind::Malformed)
}

fn watch_uri(
    request: &WatchRequest,
    request_timeout: Duration,
) -> Result<http::Uri, KubernetesSourceErrorKind> {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("watch", "true");
    query.append_pair("allowWatchBookmarks", "true");
    query.append_pair(
        "timeoutSeconds",
        &(request_timeout.as_secs() / 2).clamp(1, 30).to_string(),
    );
    query.append_pair(
        "fieldSelector",
        &format!("spec.nodeName={}", request.node_name()),
    );
    query.append_pair("labelSelector", request.marker_selector());
    query.append_pair("resourceVersion", request.resource_version());
    format!(
        "/api/v1/namespaces/{}/pods?{}",
        request.namespace(),
        query.finish()
    )
    .parse()
    .map_err(|_| KubernetesSourceErrorKind::Malformed)
}

async fn collect_bounded(
    mut body: Body,
    maximum: usize,
    allow_empty: bool,
) -> Result<Vec<u8>, KubernetesSourceErrorKind> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| KubernetesSourceErrorKind::Unavailable)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let next_length = bytes
            .len()
            .checked_add(data.len())
            .ok_or(KubernetesSourceErrorKind::Oversized)?;
        if next_length > maximum {
            return Err(KubernetesSourceErrorKind::Oversized);
        }
        bytes.extend_from_slice(&data);
    }
    if bytes.is_empty() && !allow_empty {
        return Err(KubernetesSourceErrorKind::Malformed);
    }
    Ok(bytes)
}

fn status_error(status: StatusCode) -> KubernetesSourceErrorKind {
    match status {
        StatusCode::UNAUTHORIZED => KubernetesSourceErrorKind::Unauthorized,
        StatusCode::FORBIDDEN => KubernetesSourceErrorKind::Forbidden,
        StatusCode::GONE => KubernetesSourceErrorKind::Inconsistent,
        StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => {
            KubernetesSourceErrorKind::Timeout
        }
        _ if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS => {
            KubernetesSourceErrorKind::Unavailable
        }
        _ => KubernetesSourceErrorKind::Malformed,
    }
}

fn watch_outcome(body: &[u8]) -> Result<WatchPollOutcome, KubernetesSourceErrorKind> {
    let mut outcome = WatchPollOutcome::Idle;
    for line in body.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let event: WatchEventDocument =
            serde_json::from_slice(line).map_err(|_| KubernetesSourceErrorKind::Malformed)?;
        match event.event_type.as_str() {
            "ADDED" | "MODIFIED" | "DELETED" => outcome = WatchPollOutcome::Dirty,
            "BOOKMARK" => {}
            "ERROR" if event.object.code == Some(410) => {
                return Ok(WatchPollOutcome::RelistRequired);
            }
            "ERROR" => return Err(KubernetesSourceErrorKind::Unavailable),
            _ => return Err(KubernetesSourceErrorKind::Malformed),
        }
    }
    Ok(outcome)
}

#[derive(Deserialize)]
struct WatchEventDocument {
    #[serde(rename = "type")]
    event_type: String,
    #[serde(default)]
    object: WatchObjectDocument,
}

#[derive(Default, Deserialize)]
struct WatchObjectDocument {
    #[serde(default)]
    code: Option<u16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodListDocument {
    metadata: PodListMetadata,
    items: Vec<PodDocument>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodListMetadata {
    resource_version: String,
    #[serde(rename = "continue", default)]
    continue_token: Option<String>,
}

#[derive(Deserialize)]
struct PodDocument {
    metadata: PodMetadataDocument,
    spec: PodSpecDocument,
    #[serde(default)]
    status: PodStatusDocument,
}

impl PodDocument {
    fn project(self) -> KubernetesApiPod {
        let mut containers = Vec::with_capacity(
            self.status.container_statuses.len()
                + self.status.init_container_statuses.len()
                + self.status.ephemeral_container_statuses.len(),
        );
        containers.extend(
            self.status
                .container_statuses
                .into_iter()
                .map(|status| status.project(ContainerKind::Application)),
        );
        containers.extend(
            self.status
                .init_container_statuses
                .into_iter()
                .map(|status| status.project(ContainerKind::Init)),
        );
        containers.extend(
            self.status
                .ephemeral_container_statuses
                .into_iter()
                .map(|status| status.project(ContainerKind::Ephemeral)),
        );
        KubernetesApiPod {
            namespace: self.metadata.namespace,
            node_name: self.spec.node_name,
            marked_for_observation: self.metadata.labels.observed,
            pod_uid: self.metadata.uid,
            resource_version: self.metadata.resource_version,
            deleting: self.metadata.deletion_timestamp,
            runtime_class_name: self.spec.runtime_class_name,
            containers,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodMetadataDocument {
    namespace: String,
    uid: String,
    resource_version: String,
    #[serde(default)]
    labels: ObservationMarkerLabels,
    #[serde(default, deserialize_with = "deserialize_presence")]
    deletion_timestamp: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodSpecDocument {
    node_name: String,
    #[serde(default)]
    runtime_class_name: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PodStatusDocument {
    #[serde(default)]
    container_statuses: Vec<ContainerStatusDocument>,
    #[serde(default)]
    init_container_statuses: Vec<ContainerStatusDocument>,
    #[serde(default)]
    ephemeral_container_statuses: Vec<ContainerStatusDocument>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ContainerStatusDocument {
    name: String,
    #[serde(rename = "containerID", default)]
    container_id: Option<String>,
    #[serde(default)]
    state: ContainerStateDocument,
}

impl ContainerStatusDocument {
    fn project(self, kind: ContainerKind) -> KubernetesApiContainer {
        KubernetesApiContainer {
            kind,
            name: self.name,
            runtime_container_id: self.container_id,
            running: self.state.running,
        }
    }
}

#[derive(Default, Deserialize)]
struct ContainerStateDocument {
    #[serde(default, deserialize_with = "deserialize_presence")]
    running: bool,
}

#[derive(Default)]
struct ObservationMarkerLabels {
    observed: bool,
}

impl<'de> Deserialize<'de> for ObservationMarkerLabels {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LabelsVisitor;

        impl<'de> Visitor<'de> for LabelsVisitor {
            type Value = ObservationMarkerLabels;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a Kubernetes labels map")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut observed = false;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "apolysis.dev/observe" {
                        observed = map.next_value::<String>()? == "true";
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(ObservationMarkerLabels { observed })
            }
        }

        deserializer.deserialize_map(LabelsVisitor)
    }
}

fn deserialize_presence<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<IgnoredAny>::deserialize(deserializer)?.is_some())
}
