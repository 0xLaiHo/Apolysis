// SPDX-License-Identifier: Apache-2.0

//! Authenticated Execution Evidence Gateway application core.

mod digest;
mod error;
mod identity;
mod memory;
mod repository;
mod service;

pub use digest::{
    canonical_inline_payload_digest, canonical_request_digest, canonical_runtime_binding_digest,
    canonical_source_envelope_digest, canonical_source_manifest_digest, lease_id_digest,
    DigestError,
};
pub use error::{AuditReason, GatewayFailure, GatewayResult};
pub use identity::{GatewayClock, GatewayIdGenerator, OsRandomIdGenerator, SystemClock};
pub use memory::{MemoryGatewayRepository, MemoryGatewaySnapshot};
pub use repository::{
    GatewayRepository, LedgerCommand, LedgerOperation, LedgerOutcome, RepositoryFuture,
};
pub use service::ExecutionEvidenceGateway;
