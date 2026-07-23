// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use apolysis_contracts::{
    AuthenticatedSourceContext, BindRuntimeRequest, ContractErrorCode, FinishRunRequest,
    GatewayErrorResponse, IngestRequest, OpenRunRequest,
};
use apolysis_gateway::{
    ExecutionEvidenceGateway, GatewayClock, GatewayFailure, OsRandomIdGenerator, SystemClock,
};
use apolysis_gateway_postgres::PostgresGatewayRepository;
use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{
        header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, StatusCode,
    },
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use axum_server_mtls::PeerCertificates;
use serde::{de::DeserializeOwned, Serialize};

#[cfg(feature = "qualification")]
use crate::qualification::QualificationBarrier;
use crate::{error::GatewayServerErrorKind, AuthorityStore, GatewayServerError};

const MAX_REQUEST_BODY_BYTES: usize = 1024 * 1024;
const ALLOWED_REQUEST_HEADERS: [&str; 12] = [
    "accept",
    "accept-encoding",
    "connection",
    "content-length",
    "content-type",
    "expect",
    "host",
    "te",
    "traceparent",
    "tracestate",
    "transfer-encoding",
    "user-agent",
];

type GatewayApplication =
    ExecutionEvidenceGateway<PostgresGatewayRepository, GatewayServerClock, OsRandomIdGenerator>;

#[derive(Clone, Copy, Debug)]
pub(crate) enum GatewayServerClock {
    System,
    #[cfg(feature = "qualification")]
    Fixed(u64),
}

impl GatewayClock for GatewayServerClock {
    fn now_unix_ms(&self) -> u64 {
        match self {
            Self::System => SystemClock.now_unix_ms(),
            #[cfg(feature = "qualification")]
            Self::Fixed(now_unix_ms) => *now_unix_ms,
        }
    }
}

/// A frozen Gateway lifecycle route shared by authority and response handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayRouteOperation {
    OpenRun,
    BindRuntime,
    Ingest,
    FinishRun,
}

impl GatewayRouteOperation {
    fn authority_name(self) -> &'static str {
        match self {
            Self::OpenRun => "open_run",
            Self::BindRuntime => "bind_runtime",
            Self::Ingest => "ingest",
            Self::FinishRun => "finish_run",
        }
    }
}

#[derive(Clone)]
pub(crate) struct GatewayHttpState {
    gateway: Arc<GatewayApplication>,
    authority: Arc<AuthorityStore>,
    clock: GatewayServerClock,
    qualification_hook: GatewayQualificationHook,
}

impl GatewayHttpState {
    pub(crate) fn with_qualification_hook(
        repository: PostgresGatewayRepository,
        authority: AuthorityStore,
        clock: GatewayServerClock,
        qualification_hook: GatewayQualificationHook,
    ) -> Self {
        Self {
            gateway: Arc::new(ExecutionEvidenceGateway::new(
                repository,
                clock,
                OsRandomIdGenerator,
            )),
            authority: Arc::new(authority),
            clock,
            qualification_hook,
        }
    }
}

#[derive(Clone, Default)]
pub(crate) enum GatewayQualificationHook {
    #[default]
    Disabled,
    #[cfg(feature = "qualification")]
    Qualification(Arc<QualificationBarrier>),
}

impl GatewayQualificationHook {
    #[cfg(feature = "qualification")]
    pub(crate) fn qualification(barrier: QualificationBarrier) -> Self {
        Self::Qualification(Arc::new(barrier))
    }

    async fn before_operation(
        &self,
        operation: GatewayRouteOperation,
    ) -> Result<(), GatewayServerError> {
        #[cfg(not(feature = "qualification"))]
        let _ = operation;
        match self {
            Self::Disabled => Ok(()),
            #[cfg(feature = "qualification")]
            Self::Qualification(barrier) => barrier.before_operation(operation).await,
        }
    }

    async fn after_commit(
        &self,
        operation: GatewayRouteOperation,
    ) -> Result<(), GatewayServerError> {
        #[cfg(not(feature = "qualification"))]
        let _ = operation;
        match self {
            Self::Disabled => Ok(()),
            #[cfg(feature = "qualification")]
            Self::Qualification(barrier) => barrier.reach(operation).await,
        }
    }
}

pub(crate) fn router(state: GatewayHttpState) -> Router {
    Router::new()
        .route("/gateway/v0.1/open-run", post(open_run))
        .route("/gateway/v0.1/bind-runtime", post(bind_runtime))
        .route("/gateway/v0.1/ingest", post(ingest))
        .route("/gateway/v0.1/finish-run", post(finish_run))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(middleware::map_response(apply_no_store))
}

async fn finish_run(State(state): State<GatewayHttpState>, request: Request) -> Response {
    let operation = GatewayRouteOperation::FinishRun;
    let (context, request) =
        match authenticate_and_decode::<FinishRunRequest>(&state, request, operation).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };

    if let Err(response) = reach_pre_operation_qualification(&state, operation).await {
        return response;
    }

    match state.gateway.finish_run(&context, request).await {
        Ok(response) => committed_success(&state, operation, response).await,
        Err(failure) => gateway_error(failure),
    }
}

async fn ingest(State(state): State<GatewayHttpState>, request: Request) -> Response {
    let operation = GatewayRouteOperation::Ingest;
    let (context, request) =
        match authenticate_and_decode::<IngestRequest>(&state, request, operation).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };

    if let Err(response) = reach_pre_operation_qualification(&state, operation).await {
        return response;
    }

    match state.gateway.ingest(&context, request).await {
        Ok(response) => committed_success(&state, operation, response).await,
        Err(failure) => gateway_error(failure),
    }
}

async fn bind_runtime(State(state): State<GatewayHttpState>, request: Request) -> Response {
    let operation = GatewayRouteOperation::BindRuntime;
    let (context, request) =
        match authenticate_and_decode::<BindRuntimeRequest>(&state, request, operation).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };

    if let Err(response) = reach_pre_operation_qualification(&state, operation).await {
        return response;
    }

    match state.gateway.bind_runtime(&context, request).await {
        Ok(response) => committed_success(&state, operation, response).await,
        Err(failure) => gateway_error(failure),
    }
}

async fn open_run(State(state): State<GatewayHttpState>, request: Request) -> Response {
    let operation = GatewayRouteOperation::OpenRun;
    let (context, request) =
        match authenticate_and_decode::<OpenRunRequest>(&state, request, operation).await {
            Ok(authenticated) => authenticated,
            Err(response) => return response,
        };

    if let Err(response) = reach_pre_operation_qualification(&state, operation).await {
        return response;
    }

    match state.gateway.open_run(&context, request).await {
        Ok(response) => committed_success(&state, operation, response).await,
        Err(failure) => gateway_error(failure),
    }
}

async fn reach_pre_operation_qualification(
    state: &GatewayHttpState,
    operation: GatewayRouteOperation,
) -> Result<(), Response> {
    state
        .qualification_hook
        .before_operation(operation)
        .await
        .map_err(|error| {
            eprintln!("Gateway pre-operation qualification barrier failed: {error}");
            internal_response()
        })
}

async fn committed_success<T: Serialize>(
    state: &GatewayHttpState,
    operation: GatewayRouteOperation,
    value: T,
) -> Response {
    // Construct the complete response before the qualification barrier. A
    // reached marker therefore proves that commit completed and serialization
    // succeeded, while the handler still has not returned the response to Axum.
    let response = success(value);
    if let Err(error) = state.qualification_hook.after_commit(operation).await {
        // The error type retains closed labels only; no request or response
        // content is admitted to this diagnostic seam.
        eprintln!("Gateway post-commit response barrier failed: {error}");
        return internal_response();
    }
    response
}

async fn authenticate_and_decode<T>(
    state: &GatewayHttpState,
    request: Request,
    operation: GatewayRouteOperation,
) -> Result<(AuthenticatedSourceContext, T), Response>
where
    T: DeserializeOwned,
{
    let (parts, body) = request.into_parts();
    let Some(peer_certificates) = parts.extensions.get::<PeerCertificates>() else {
        return Err(unauthenticated_response());
    };
    let Some(leaf_certificate) = peer_certificates.leaf() else {
        return Err(unauthenticated_response());
    };

    let now_unix_ms = state.clock.now_unix_ms();
    let context = match state
        .authority
        .resolve_mtls(
            leaf_certificate.as_ref(),
            operation.authority_name(),
            now_unix_ms,
        )
        .await
    {
        Ok(context) => context,
        Err(error) => return Err(authority_error(error)),
    };

    if !accepts_json(&parts.headers)
        || !has_json_content_type(&parts.headers)
        || contains_disallowed_headers(&parts.headers)
    {
        return Err(contract_error(
            StatusCode::BAD_REQUEST,
            ContractErrorCode::InvalidContract,
            "Request headers do not match the Gateway contract",
            false,
            None,
        ));
    }

    if content_length_exceeds_limit(&parts.headers) {
        return Err(body_too_large_response());
    }
    let request_bytes = match to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => return Err(body_too_large_response()),
    };
    let request = match serde_json::from_slice::<T>(&request_bytes) {
        Ok(request) => request,
        Err(_) => {
            return Err(contract_error(
                StatusCode::BAD_REQUEST,
                ContractErrorCode::InvalidContract,
                "Request does not match the Gateway contract",
                false,
                None,
            ))
        }
    };
    Ok((context, request))
}

async fn not_found() -> Response {
    contract_error(
        StatusCode::NOT_FOUND,
        ContractErrorCode::NotFound,
        "Gateway route was not found",
        false,
        None,
    )
}

async fn method_not_allowed() -> Response {
    contract_error(
        StatusCode::METHOD_NOT_ALLOWED,
        ContractErrorCode::InvalidContract,
        "HTTP method is not supported by this Gateway route",
        false,
        None,
    )
}

async fn apply_no_store(mut response: Response) -> Response {
    set_no_store(response.headers_mut());
    response
}

fn success<T: Serialize>(response: T) -> Response {
    let mut response = (StatusCode::OK, Json(response)).into_response();
    set_no_store(response.headers_mut());
    response
}

fn gateway_error(failure: GatewayFailure) -> Response {
    let status = status_for_contract_error(failure.code());
    match failure.response() {
        Ok(body) => wire_error(status, body),
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
        GatewayServerErrorKind::Database => {
            report_authority_failure(&error);
            contract_error(
                StatusCode::SERVICE_UNAVAILABLE,
                ContractErrorCode::Backpressure,
                "Gateway persistence is temporarily unavailable",
                true,
                Some(250),
            )
        }
        _ => {
            report_authority_failure(&error);
            internal_response()
        }
    }
}

fn report_authority_failure(error: &GatewayServerError) {
    // GatewayServerError deliberately retains only closed diagnostic labels.
    // Never add request, certificate, URL, or source-error data at this seam.
    eprintln!("Gateway current-authority request failed: {error}");
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
        Ok(body) => wire_error(status, body),
        Err(_) => internal_response(),
    }
}

fn wire_error(status: StatusCode, body: GatewayErrorResponse) -> Response {
    let retry_after_ms = body.retry_after_ms();
    let mut response = (status, Json(body)).into_response();
    set_no_store(response.headers_mut());
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            WWW_AUTHENTICATE,
            HeaderValue::from_static("Mutual realm=\"apolysis-gateway\""),
        );
    }
    if let Some(retry_after_ms) = retry_after_ms {
        let retry_after_seconds = retry_after_seconds(retry_after_ms);
        if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
            response.headers_mut().insert(RETRY_AFTER, value);
        }
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

fn retry_after_seconds(retry_after_ms: u64) -> u64 {
    retry_after_ms / 1_000 + u64::from(!retry_after_ms.is_multiple_of(1_000))
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

fn contains_disallowed_headers(headers: &HeaderMap) -> bool {
    headers
        .keys()
        .any(|header_name| !ALLOWED_REQUEST_HEADERS.contains(&header_name.as_str()))
}

fn content_length_exceeds_limit(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|value| value > MAX_REQUEST_BODY_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "qualification")]
    #[test]
    fn fixed_qualification_clock_returns_one_process_time() {
        let clock = GatewayServerClock::Fixed(1_234_567_890);

        assert_eq!(clock.now_unix_ms(), 1_234_567_890);
        assert_eq!(clock.now_unix_ms(), 1_234_567_890);
    }

    #[test]
    fn rejects_authority_and_proxy_header_variants() {
        for header_name in [
            "authorization",
            "cookie",
            "forwarded",
            "proxy-authorization",
            "x-apolysis-organization-id",
            "x-auth-request-user",
            "x-auth-user",
            "x-forwarded-client-cert",
            "x-forwarded-organization-id",
            "x-original-principal-id",
            "x-organization-id",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                header_name.parse::<axum::http::HeaderName>().unwrap(),
                HeaderValue::from_static("untrusted"),
            );

            assert!(
                contains_disallowed_headers(&headers),
                "expected {header_name} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_remote_qualification_control_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-apolysis-qualification-now-unix-ms"
                .parse::<axum::http::HeaderName>()
                .unwrap(),
            HeaderValue::from_static("123456789"),
        );

        assert!(contains_disallowed_headers(&headers));
    }

    #[test]
    fn allows_only_bounded_transport_representation_and_trace_headers() {
        let mut headers = HeaderMap::new();
        for header_name in ALLOWED_REQUEST_HEADERS {
            let mut individual_headers = HeaderMap::new();
            individual_headers.insert(
                header_name.parse::<axum::http::HeaderName>().unwrap(),
                HeaderValue::from_static("bounded"),
            );

            assert!(
                !contains_disallowed_headers(&individual_headers),
                "expected {header_name} to be accepted"
            );
        }
        headers.insert(
            "traceparent".parse::<axum::http::HeaderName>().unwrap(),
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        headers.insert(
            "tracestate".parse::<axum::http::HeaderName>().unwrap(),
            HeaderValue::from_static("vendor=value"),
        );

        assert!(!contains_disallowed_headers(&headers));
    }

    #[test]
    fn retry_after_rounds_milliseconds_up_to_seconds() {
        assert_eq!(retry_after_seconds(0), 0);
        assert_eq!(retry_after_seconds(1), 1);
        assert_eq!(retry_after_seconds(999), 1);
        assert_eq!(retry_after_seconds(1_000), 1);
        assert_eq!(retry_after_seconds(1_001), 2);
        assert_eq!(retry_after_seconds(u64::MAX), u64::MAX / 1_000 + 1);
    }

    #[test]
    fn wire_error_sets_retry_after_and_no_store() {
        let body = GatewayErrorResponse::new(
            ContractErrorCode::Backpressure,
            "Gateway persistence is temporarily unavailable",
            true,
            Some(1_001),
        )
        .unwrap();

        let response = wire_error(StatusCode::SERVICE_UNAVAILABLE, body);

        assert_eq!(
            response.headers().get(RETRY_AFTER),
            Some(&HeaderValue::from_static("2"))
        );
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }

    #[test]
    fn every_unauthorized_contract_error_sets_the_mtls_challenge() {
        for code in [
            ContractErrorCode::Unauthenticated,
            ContractErrorCode::LeaseExpired,
            ContractErrorCode::LeaseRevoked,
        ] {
            let response = contract_error(
                status_for_contract_error(code),
                code,
                "Authentication or lease authority is unavailable",
                false,
                None,
            );

            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers().get(WWW_AUTHENTICATE),
                Some(&HeaderValue::from_static(
                    "Mutual realm=\"apolysis-gateway\""
                ))
            );
        }
    }

    #[test]
    fn status_mapping_covers_retryable_contract_failures() {
        assert_eq!(
            status_for_contract_error(ContractErrorCode::RateLimited),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status_for_contract_error(ContractErrorCode::Backpressure),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status_for_contract_error(ContractErrorCode::ProjectionUnavailable),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
