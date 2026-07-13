// SPDX-License-Identifier: Apache-2.0

use apolysis_contracts::ContractErrorCode;
use apolysis_gateway::{
    canonical_runtime_binding_digest, canonical_source_envelope_digest,
    canonical_source_manifest_digest, lease_id_digest, AuditReason, GatewayFailure,
    GatewayIdGenerator, GatewayRepository, LedgerCommand, LedgerOperation, LedgerOutcome,
    RepositoryFuture,
};

struct ExternalAdapter;

impl GatewayRepository for ExternalAdapter {
    fn execute<'a>(
        &'a self,
        command: LedgerCommand,
        _ids: &'a dyn GatewayIdGenerator,
    ) -> RepositoryFuture<'a, Result<LedgerOutcome, GatewayFailure>> {
        let operation_name = match command.operation() {
            LedgerOperation::OpenRun { request, .. } => {
                let _ = canonical_source_manifest_digest(request.source_manifest());
                "open_run"
            }
            LedgerOperation::Ingest { request, .. } => {
                let _ = canonical_source_envelope_digest(&request.envelopes()[0]);
                let _ = lease_id_digest(request.lease_id());
                "ingest"
            }
            LedgerOperation::BindRuntime { request, .. } => {
                let _ = canonical_runtime_binding_digest(request.binding());
                let _ = lease_id_digest(request.lease_id());
                "bind_runtime"
            }
            LedgerOperation::FinishRun { request, .. } => {
                let _ = lease_id_digest(request.lease_id());
                "finish_run"
            }
        };
        Box::pin(async move {
            let _ = operation_name;
            Err(GatewayFailure::repository_backpressure(
                750,
                AuditReason::RepositoryInvariant,
            ))
        })
    }
}

#[test]
fn an_external_crate_can_implement_the_atomic_repository_seam() {
    fn assert_repository<T: GatewayRepository>() {}
    assert_repository::<ExternalAdapter>();

    let error = GatewayFailure::classified(
        ContractErrorCode::NotFound,
        AuditReason::RepositoryInvariant,
    );
    assert_eq!(error.code(), ContractErrorCode::NotFound);
}
