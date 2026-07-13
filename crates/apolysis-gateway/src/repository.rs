// SPDX-License-Identifier: Apache-2.0

use std::{future::Future, pin::Pin};

use apolysis_contracts::{
    AuthenticatedSourceContext, BindRuntimeRequest, BindRuntimeResponse, FinishRunRequest,
    FinishRunResponse, IngestAck, IngestRequest, OpenRunRequest, OpenRunResponse,
};

use crate::{GatewayFailure, GatewayIdGenerator};

pub type RepositoryFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Opaque server-owned command admitted only after application-service checks.
///
/// Its inner variants and constructors are crate-private. A repository adapter
/// can inspect the borrowed operation but cannot manufacture an authorized
/// command and bypass authentication, request validation, or digest checks.
pub struct LedgerCommand {
    inner: LedgerCommandInner,
}

enum LedgerCommandInner {
    OpenRun {
        context: AuthenticatedSourceContext,
        request: OpenRunRequest,
        now_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
    },
    Ingest {
        context: AuthenticatedSourceContext,
        request: IngestRequest,
        now_unix_ms: u64,
    },
    BindRuntime {
        context: AuthenticatedSourceContext,
        request: BindRuntimeRequest,
        now_unix_ms: u64,
    },
    FinishRun {
        context: AuthenticatedSourceContext,
        request: FinishRunRequest,
        now_unix_ms: u64,
        finalization_deadline_unix_ms: u64,
    },
}

/// Borrowed view available to trusted persistence adapters.
pub enum LedgerOperation<'a> {
    OpenRun {
        context: &'a AuthenticatedSourceContext,
        request: &'a OpenRunRequest,
        now_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
    },
    Ingest {
        context: &'a AuthenticatedSourceContext,
        request: &'a IngestRequest,
        now_unix_ms: u64,
    },
    BindRuntime {
        context: &'a AuthenticatedSourceContext,
        request: &'a BindRuntimeRequest,
        now_unix_ms: u64,
    },
    FinishRun {
        context: &'a AuthenticatedSourceContext,
        request: &'a FinishRunRequest,
        now_unix_ms: u64,
        finalization_deadline_unix_ms: u64,
    },
}

impl LedgerCommand {
    pub(crate) fn open_run(
        context: AuthenticatedSourceContext,
        request: OpenRunRequest,
        now_unix_ms: u64,
        lease_expires_at_unix_ms: u64,
    ) -> Self {
        Self {
            inner: LedgerCommandInner::OpenRun {
                context,
                request,
                now_unix_ms,
                lease_expires_at_unix_ms,
            },
        }
    }

    pub(crate) fn ingest(
        context: AuthenticatedSourceContext,
        request: IngestRequest,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            inner: LedgerCommandInner::Ingest {
                context,
                request,
                now_unix_ms,
            },
        }
    }

    pub(crate) fn bind_runtime(
        context: AuthenticatedSourceContext,
        request: BindRuntimeRequest,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            inner: LedgerCommandInner::BindRuntime {
                context,
                request,
                now_unix_ms,
            },
        }
    }

    pub(crate) fn finish_run(
        context: AuthenticatedSourceContext,
        request: FinishRunRequest,
        now_unix_ms: u64,
        finalization_deadline_unix_ms: u64,
    ) -> Self {
        Self {
            inner: LedgerCommandInner::FinishRun {
                context,
                request,
                now_unix_ms,
                finalization_deadline_unix_ms,
            },
        }
    }

    pub fn operation(&self) -> LedgerOperation<'_> {
        match &self.inner {
            LedgerCommandInner::OpenRun {
                context,
                request,
                now_unix_ms,
                lease_expires_at_unix_ms,
            } => LedgerOperation::OpenRun {
                context,
                request,
                now_unix_ms: *now_unix_ms,
                lease_expires_at_unix_ms: *lease_expires_at_unix_ms,
            },
            LedgerCommandInner::Ingest {
                context,
                request,
                now_unix_ms,
            } => LedgerOperation::Ingest {
                context,
                request,
                now_unix_ms: *now_unix_ms,
            },
            LedgerCommandInner::BindRuntime {
                context,
                request,
                now_unix_ms,
            } => LedgerOperation::BindRuntime {
                context,
                request,
                now_unix_ms: *now_unix_ms,
            },
            LedgerCommandInner::FinishRun {
                context,
                request,
                now_unix_ms,
                finalization_deadline_unix_ms,
            } => LedgerOperation::FinishRun {
                context,
                request,
                now_unix_ms: *now_unix_ms,
                finalization_deadline_unix_ms: *finalization_deadline_unix_ms,
            },
        }
    }
}

/// Typed outcome of one atomic ledger command.
#[derive(Clone, Debug)]
pub enum LedgerOutcome {
    OpenRun(OpenRunResponse),
    BindRuntime(BindRuntimeResponse),
    Ingest(IngestAck),
    FinishRun(FinishRunResponse),
}

/// High-level atomic persistence seam. It intentionally exposes no CRUD API.
pub trait GatewayRepository: Send + Sync {
    fn execute<'a>(
        &'a self,
        command: LedgerCommand,
        ids: &'a dyn GatewayIdGenerator,
    ) -> RepositoryFuture<'a, Result<LedgerOutcome, GatewayFailure>>;
}
