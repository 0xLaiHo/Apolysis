// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use apolysis_contracts::{
    ContractErrorCode, GatewayErrorResponse, OpenRunRequest, OpenRunResponse,
};
use apolysis_gateway::{
    ExecutionEvidenceGateway, GatewayClock, GatewayFailure, OsRandomIdGenerator, SystemClock,
};
use apolysis_gateway_postgres::PostgresGatewayRepository;
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{
        header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use axum_server_mtls::PeerCertificates;

use crate::{error::GatewayServerErrorKind, AuthorityStore, GatewayServerError};

const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const AUTHORITY_HEADERS: [&str; 6] = [
    "x-organization-id",
    "x-tenant-id",
    "x-principal-id",
    "x-source-id",
    "x-source-registration-id",
    "x-policy-revision",
];

type GatewayApplication =
    ExecutionEvidenceGateway<PostgresGatewayRepository, SystemClock, OsRandomIdGenerator>;

#[derive(Clone)]
pub(crate) struct GatewayHttpState {
    gateway: Arc<GatewayApplication>,
    authority: Arc<AuthorityStore>,
}

impl GatewayHttpState {
    pub(crate) fn new(gateway: GatewayApplication, authority: AuthorityStore) -> Self {
        Self {
            gateway: Arc::new(gateway),
            authority: Arc::new(authority),
        }
    }
}

pub(crate) fn router(state: GatewayHttpState) -> Router {
    Router::new()
        .route("/gateway/v0.1/open-run", post(open_run))
        .with_state(state)
}

async fn open_run(State(state): State<GatewayHttpState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    if !accepts_json(&parts.headers)
        || !has_json_content_type(&parts.headers)
        || contains_authority_headers(&parts.headers)
    {
        return contract_error(
            StatusCode::BAD_REQUEST,
            ContractErrorCode::InvalidContract,
            "Request headers do not match the Gateway contract",
            false,
            None,
        );
    }

    let Some(peer_certificates) = parts.extensions.get::<PeerCertificates>() else {
        return unauthenticated_response();
    };
    let Some(leaf_certificate) = peer_certificates.leaf() else {
        return unauthenticated_response();
    };

    let now_unix_ms = SystemClock.now_unix_ms();
    let context = match state
        .authority
        .resolve_mtls(leaf_certificate.as_ref(), "open_run", now_unix_ms)
        .await
    {
        Ok(context) => context,
        Err(error) => return authority_error(error),
    };

    if content_length_exceeds_limit(&parts.headers) {
        return body_too_large_response();
    }
    let request_bytes = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return body_too_large_response(),
    };
    let request = match serde_json::from_slice::<OpenRunRequest>(&request_bytes) {
        Ok(request) => request,
        Err(_) => {
            return contract_error(
                StatusCode::BAD_REQUEST,
                ContractErrorCode::InvalidContract,
                "Request does not match the Gateway contract",
                false,
                None,
            )
        }
    };

    match state.gateway.open_run(&context, request).await {
        Ok(response) => success(response),
        Err(failure) => gateway_error(failure),
    }
}

fn success(response: OpenRunResponse) -> Response {
    let mut response = (StatusCode::OK, Json(response)).into_response();
    set_no_store(response.headers_mut());
    response
}

fn gateway_error(failure: GatewayFailure) -> Response {
    let status = status_for_contract_error(failure.code());
    match failure.response() {
        Ok(body) => wire_error(
            status,
            body,
            failure.code() == ContractErrorCode::Unauthenticated,
        ),
        Err(_) => internal_response(),
    }
}

fn authority_error(error: GatewayServerError) -> Response {
    match error.kind() {
        GatewayServerErrorKind::Unauthenticated => unauthenticated_response(),
        GatewayServerErrorKind::Forbidden => contract_error(
            StatusCode::FORBIDDEN,
            ContractErrorCode::Forbidden,
            "Operation is not authorized",
            false,
            None,
        ),
        GatewayServerErrorKind::Database => contract_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ContractErrorCode::Backpressure,
            "Gateway persistence is temporarily unavailable",
            true,
            Some(250),
        ),
        _ => internal_response(),
    }
}

fn unauthenticated_response() -> Response {
    contract_error(
        StatusCode::UNAUTHORIZED,
        ContractErrorCode::Unauthenticated,
        "Authentication is missing or expired",
        false,
        None,
    )
}

fn body_too_large_response() -> Response {
    contract_error(
        StatusCode::PAYLOAD_TOO_LARGE,
        ContractErrorCode::BatchTooLarge,
        "Request exceeds the bounded Gateway limit",
        false,
        None,
    )
}

fn contract_error(
    status: StatusCode,
    code: ContractErrorCode,
    message: &'static str,
    retryable: bool,
    retry_after_ms: Option<u64>,
) -> Response {
    match GatewayErrorResponse::new(code, message, retryable, retry_after_ms) {
        Ok(body) => wire_error(status, body, code == ContractErrorCode::Unauthenticated),
        Err(_) => internal_response(),
    }
}

fn wire_error(status: StatusCode, body: GatewayErrorResponse, authenticate: bool) -> Response {
    let mut response = (status, Json(body)).into_response();
    set_no_store(response.headers_mut());
    if authenticate {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Mutual realm=\"apolysis-gateway\""),
        );
    }
    response
}

fn internal_response() -> Response {
    let mut response = StatusCode::INTERNAL_SERVER_ERROR.into_response();
    set_no_store(response.headers_mut());
    response
}

fn status_for_contract_error(code: ContractErrorCode) -> StatusCode {
    match code {
        ContractErrorCode::Unauthenticated
        | ContractErrorCode::LeaseExpired
        | ContractErrorCode::LeaseRevoked => StatusCode::UNAUTHORIZED,
        ContractErrorCode::Forbidden
        | ContractErrorCode::LeaseScopeMismatch
        | ContractErrorCode::CapabilityMismatch
        | ContractErrorCode::RedactionRequired
        | ContractErrorCode::ContentNotAuthorized
        | ContractErrorCode::RetentionNotAuthorized => StatusCode::FORBIDDEN,
        ContractErrorCode::NotFound => StatusCode::NOT_FOUND,
        ContractErrorCode::UnsupportedContractVersion
        | ContractErrorCode::UnsupportedSourceVersion
        | ContractErrorCode::InvalidContract
        | ContractErrorCode::CursorInvalid => StatusCode::BAD_REQUEST,
        ContractErrorCode::InvalidLifecycleTransition
        | ContractErrorCode::IdempotencyConflict
        | ContractErrorCode::SourceEventConflict
        | ContractErrorCode::SequenceConflict => StatusCode::CONFLICT,
        ContractErrorCode::CursorExpired => StatusCode::GONE,
        ContractErrorCode::BatchTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        ContractErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        ContractErrorCode::Backpressure | ContractErrorCode::ProjectionUnavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

fn set_no_store(headers: &mut HeaderMap) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn has_json_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn accepts_json(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.split(',').any(|entry| {
                let media_type = entry.split(';').next().unwrap_or_default().trim();
                media_type.eq_ignore_ascii_case("application/json") || media_type == "*/*"
            })
        })
}

fn contains_authority_headers(headers: &HeaderMap) -> bool {
    AUTHORITY_HEADERS
        .iter()
        .any(|header_name| headers.contains_key(*header_name))
}

fn content_length_exceeds_limit(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|value| value > MAX_REQUEST_BODY_BYTES)
}
