// SPDX-License-Identifier: Apache-2.0

//! Reusable repository conformance tests for Execution Evidence Gateway adapters.
//!
//! This crate is test infrastructure, not a production persistence API. Adapter
//! crates implement [`GatewayConformanceHarness`] with isolated repository state,
//! trusted join-authorization setup, and content-free inspection metrics. The
//! lifecycle scenarios continue to exercise behavior through
//! `ExecutionEvidenceGateway` and `GatewayRepository::execute`.

use std::{error::Error, future::Future, pin::Pin};

use apolysis_contracts::{AuthenticatedSourceContext, RunId, SourceKind, TrustProfile};
use apolysis_gateway::{GatewayFailure, GatewayRepository, MemoryGatewayRepository};

pub mod scenarios;

/// Boxed future returned by test-only harness capabilities.
pub type HarnessFuture<'a, T> = Pin<Box<dyn Future<Output = HarnessResult<T>> + Send + 'a>>;

/// Boxed future for trusted setup operations whose rejection is contractual.
pub type HarnessAdminFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), GatewayFailure>> + Send + 'a>>;

/// Adapter-neutral failure type used while preparing or inspecting test state.
pub type HarnessResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

/// Content-free durable-state metrics asserted by the conformance scenarios.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConformanceSnapshot {
    record_item_count: usize,
    projection_outbox_count: usize,
    incomplete_record_item_count: usize,
    incomplete_projection_outbox_count: usize,
    evidence_event_count: usize,
    operation_count: usize,
    replay_count: usize,
    finalization_declaration_count: usize,
    source_stream_count: usize,
    lease_count: usize,
    runtime_binding_count: usize,
    active_runtime_identity_count: usize,
    pending_join_authorization_count: usize,
    consumed_join_authorization_count: usize,
    accepted_effective_trust_profiles: Vec<TrustProfile>,
}

/// Named content-free counts used to construct an adapter-neutral snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayConformanceCounts {
    pub record_item_count: usize,
    pub projection_outbox_count: usize,
    pub incomplete_record_item_count: usize,
    pub incomplete_projection_outbox_count: usize,
    pub evidence_event_count: usize,
    pub operation_count: usize,
    pub replay_count: usize,
    pub finalization_declaration_count: usize,
    pub source_stream_count: usize,
    pub lease_count: usize,
    pub runtime_binding_count: usize,
    pub active_runtime_identity_count: usize,
    pub pending_join_authorization_count: usize,
    pub consumed_join_authorization_count: usize,
}

impl GatewayConformanceSnapshot {
    pub fn new(
        counts: GatewayConformanceCounts,
        accepted_effective_trust_profiles: Vec<TrustProfile>,
    ) -> Self {
        Self {
            record_item_count: counts.record_item_count,
            projection_outbox_count: counts.projection_outbox_count,
            incomplete_record_item_count: counts.incomplete_record_item_count,
            incomplete_projection_outbox_count: counts.incomplete_projection_outbox_count,
            evidence_event_count: counts.evidence_event_count,
            operation_count: counts.operation_count,
            replay_count: counts.replay_count,
            finalization_declaration_count: counts.finalization_declaration_count,
            source_stream_count: counts.source_stream_count,
            lease_count: counts.lease_count,
            runtime_binding_count: counts.runtime_binding_count,
            active_runtime_identity_count: counts.active_runtime_identity_count,
            pending_join_authorization_count: counts.pending_join_authorization_count,
            consumed_join_authorization_count: counts.consumed_join_authorization_count,
            accepted_effective_trust_profiles,
        }
    }

    pub fn record_item_count(&self) -> usize {
        self.record_item_count
    }

    pub fn projection_outbox_count(&self) -> usize {
        self.projection_outbox_count
    }

    pub fn incomplete_record_item_count(&self) -> usize {
        self.incomplete_record_item_count
    }

    pub fn incomplete_projection_outbox_count(&self) -> usize {
        self.incomplete_projection_outbox_count
    }

    pub fn evidence_event_count(&self) -> usize {
        self.evidence_event_count
    }

    pub fn operation_count(&self) -> usize {
        self.operation_count
    }

    pub fn replay_count(&self) -> usize {
        self.replay_count
    }

    pub fn finalization_declaration_count(&self) -> usize {
        self.finalization_declaration_count
    }

    pub fn source_stream_count(&self) -> usize {
        self.source_stream_count
    }

    pub fn lease_count(&self) -> usize {
        self.lease_count
    }

    pub fn runtime_binding_count(&self) -> usize {
        self.runtime_binding_count
    }

    pub fn active_runtime_identity_count(&self) -> usize {
        self.active_runtime_identity_count
    }

    pub fn pending_join_authorization_count(&self) -> usize {
        self.pending_join_authorization_count
    }

    pub fn consumed_join_authorization_count(&self) -> usize {
        self.consumed_join_authorization_count
    }

    pub fn accepted_effective_trust_profiles(&self) -> &[TrustProfile] {
        &self.accepted_effective_trust_profiles
    }
}

/// Test-only capabilities required to run the shared Gateway repository suite.
///
/// The repository itself remains constrained to the production atomic command
/// seam. Administrative setup and inspection live here so production adapters
/// do not need to expose broad CRUD solely for tests.
pub trait GatewayConformanceHarness: Sized + Send + Sync + 'static {
    type Repository: GatewayRepository + Clone + Send + Sync + 'static;

    /// Start one isolated repository instance for a single scenario.
    fn start() -> HarnessFuture<'static, Self>;

    /// Clone the production repository handle exercised by the Gateway service.
    fn repository(&self) -> Self::Repository;

    /// Inspect content-free counts and trust classifications atomically.
    fn snapshot(&self) -> HarnessFuture<'_, GatewayConformanceSnapshot>;

    /// Seed one current source authority through the adapter's test control plane.
    fn seed_current_authority<'a>(
        &'a self,
        current: &'a AuthenticatedSourceContext,
    ) -> HarnessAdminFuture<'a>;

    /// Atomically replace one current source authority.
    fn rotate_current_authority<'a>(
        &'a self,
        expected_current: &'a AuthenticatedSourceContext,
        replacement: &'a AuthenticatedSourceContext,
    ) -> HarnessAdminFuture<'a>;

    /// Revoke one current source authority without allowing it to be resurrected.
    fn revoke_current_authority<'a>(
        &'a self,
        expected_current: &'a AuthenticatedSourceContext,
    ) -> HarnessAdminFuture<'a>;

    /// Register a trusted, one-use join grant outside the request path.
    fn register_join_grant<'a>(
        &'a self,
        issuer: &'a AuthenticatedSourceContext,
        joining_source: &'a AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &'a str,
        expires_at_unix_ms: u64,
    ) -> HarnessAdminFuture<'a>;

    /// Register a trusted reusable join policy outside the request path.
    fn register_join_policy<'a>(
        &'a self,
        issuer: &'a AuthenticatedSourceContext,
        joining_source: &'a AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &'a str,
        expires_at_unix_ms: u64,
    ) -> HarnessAdminFuture<'a>;
}

/// Reference harness used to prove the shared scenarios against the memory adapter.
pub struct MemoryGatewayHarness {
    repository: MemoryGatewayRepository,
}

impl GatewayConformanceHarness for MemoryGatewayHarness {
    type Repository = MemoryGatewayRepository;

    fn start() -> HarnessFuture<'static, Self> {
        Box::pin(async {
            Ok(Self {
                repository: MemoryGatewayRepository::new(),
            })
        })
    }

    fn repository(&self) -> Self::Repository {
        self.repository.clone()
    }

    fn snapshot(&self) -> HarnessFuture<'_, GatewayConformanceSnapshot> {
        Box::pin(async {
            let snapshot = self
                .repository
                .snapshot()
                .map_err(|error| Box::new(error) as Box<dyn Error + Send + Sync>)?;
            Ok(GatewayConformanceSnapshot::new(
                GatewayConformanceCounts {
                    record_item_count: snapshot.record_item_count(),
                    projection_outbox_count: snapshot.projection_outbox_count(),
                    incomplete_record_item_count: snapshot.incomplete_record_item_count(),
                    incomplete_projection_outbox_count: snapshot
                        .incomplete_projection_outbox_count(),
                    evidence_event_count: snapshot.evidence_event_count(),
                    operation_count: snapshot.operation_count(),
                    replay_count: snapshot.replay_count(),
                    finalization_declaration_count: snapshot.finalization_declaration_count(),
                    source_stream_count: snapshot.source_stream_count(),
                    lease_count: snapshot.lease_count(),
                    runtime_binding_count: snapshot.runtime_binding_count(),
                    active_runtime_identity_count: snapshot.active_runtime_identity_count(),
                    pending_join_authorization_count: snapshot.pending_join_authorization_count(),
                    consumed_join_authorization_count: snapshot.consumed_join_authorization_count(),
                },
                snapshot.accepted_effective_trust_profiles().to_vec(),
            ))
        })
    }

    fn seed_current_authority<'a>(
        &'a self,
        current: &'a AuthenticatedSourceContext,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move { self.repository.seed_current_authority(current) })
    }

    fn rotate_current_authority<'a>(
        &'a self,
        expected_current: &'a AuthenticatedSourceContext,
        replacement: &'a AuthenticatedSourceContext,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move {
            self.repository
                .rotate_current_authority(expected_current, replacement)
        })
    }

    fn revoke_current_authority<'a>(
        &'a self,
        expected_current: &'a AuthenticatedSourceContext,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move { self.repository.revoke_current_authority(expected_current) })
    }

    fn register_join_grant<'a>(
        &'a self,
        issuer: &'a AuthenticatedSourceContext,
        joining_source: &'a AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &'a str,
        expires_at_unix_ms: u64,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move {
            self.repository.register_join_grant(
                issuer,
                joining_source,
                run_id,
                source_kind,
                proof_ref,
                expires_at_unix_ms,
            )
        })
    }

    fn register_join_policy<'a>(
        &'a self,
        issuer: &'a AuthenticatedSourceContext,
        joining_source: &'a AuthenticatedSourceContext,
        run_id: RunId,
        source_kind: SourceKind,
        proof_ref: &'a str,
        expires_at_unix_ms: u64,
    ) -> HarnessAdminFuture<'a> {
        Box::pin(async move {
            self.repository.register_join_policy(
                issuer,
                joining_source,
                run_id,
                source_kind,
                proof_ref,
                expires_at_unix_ms,
            )
        })
    }
}

/// Generate all Gateway repository conformance tests for a harness type.
#[macro_export]
macro_rules! gateway_repository_conformance_tests {
    ($(#[$test_attr:meta])* $harness:ty) => {
        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_returns_a_scoped_lease_and_exact_retry() {
            $crate::scenarios::open_run_returns_a_scoped_lease_and_exact_retry::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn source_stream_freezes_trust_and_policy_revision() {
            $crate::scenarios::source_stream_freezes_trust_and_policy_revision::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn current_authority_rotation_rejects_stale_replay_and_preserves_operation_identity() {
            $crate::scenarios::current_authority_rotation_rejects_stale_replay_and_preserves_operation_identity::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn novel_lifecycle_operations_recheck_authentication_expiry_at_final_transaction_time() {
            $crate::scenarios::novel_lifecycle_operations_recheck_authentication_expiry_at_final_transaction_time::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn credential_rotation_requires_new_join_authority_and_a_new_source_stream() {
            $crate::scenarios::credential_rotation_requires_new_join_authority_and_a_new_source_stream::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn revoked_current_authority_rejects_novel_work_and_replay_without_effects() {
            $crate::scenarios::revoked_current_authority_rejects_novel_work_and_replay_without_effects::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn every_lifecycle_replay_is_bound_to_its_credential_epoch_and_policy() {
            $crate::scenarios::every_lifecycle_replay_is_bound_to_its_credential_epoch_and_policy::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_join_requires_a_server_registered_grant() {
            $crate::scenarios::open_run_join_requires_a_server_registered_grant::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_join_rechecks_grant_expiry_after_admission() {
            $crate::scenarios::open_run_join_rechecks_grant_expiry_after_admission::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_join_rechecks_finalization_deadline_after_admission() {
            $crate::scenarios::open_run_join_rechecks_finalization_deadline_after_admission::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_join_rechecks_last_lease_expiry_after_admission() {
            $crate::scenarios::open_run_join_rechecks_last_lease_expiry_after_admission::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_join_rejects_invalid_transaction_time_without_partial_state() {
            $crate::scenarios::open_run_join_rejects_invalid_transaction_time_without_partial_state::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_join_is_enumeration_safe_across_organizations() {
            $crate::scenarios::open_run_join_is_enumeration_safe_across_organizations::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_registration_policy_is_server_registered_and_reusable() {
            $crate::scenarios::open_run_registration_policy_is_server_registered_and_reusable::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_enforces_the_256_source_stream_limit_without_partial_state() {
            $crate::scenarios::open_run_enforces_the_256_source_stream_limit_without_partial_state::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_rejects_an_expired_authentication_snapshot() {
            $crate::scenarios::open_run_rejects_an_expired_authentication_snapshot::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_rejects_source_capability_escalation() {
            $crate::scenarios::open_run_rejects_source_capability_escalation::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_rejects_a_client_selected_authority() {
            $crate::scenarios::open_run_rejects_a_client_selected_authority::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_rejects_stale_request_digest_without_consuming_identity() {
            $crate::scenarios::open_run_rejects_stale_request_digest_without_consuming_identity::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn ingest_commits_an_atomic_batch_and_reports_source_gaps() {
            $crate::scenarios::ingest_commits_an_atomic_batch_and_reports_source_gaps::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn ingest_accepts_a_mixed_duplicate_and_gap_fill_retry() {
            $crate::scenarios::ingest_accepts_a_mixed_duplicate_and_gap_fill_retry::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn ingest_coalesces_same_batch_exact_duplicates_without_partial_state() {
            $crate::scenarios::ingest_coalesces_same_batch_exact_duplicates_without_partial_state::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn ingest_rejects_payload_tampering_without_a_partial_commit() {
            $crate::scenarios::ingest_rejects_payload_tampering_without_a_partial_commit::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn ingest_rejects_reused_operation_identity_with_changed_content() {
            $crate::scenarios::ingest_rejects_reused_operation_identity_with_changed_content::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn ingest_conflicts_roll_back_the_entire_batch_and_operation_identity() {
            $crate::scenarios::ingest_conflicts_roll_back_the_entire_batch_and_operation_identity::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn lease_failures_are_explicit_and_cross_organization_safe() {
            $crate::scenarios::lease_failures_are_explicit_and_cross_organization_safe::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn active_run_seals_only_after_its_last_lease_expires_and_cannot_be_revived() {
            $crate::scenarios::active_run_seals_only_after_its_last_lease_expires_and_cannot_be_revived::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn open_run_does_not_leave_partial_state_when_identity_generation_fails() {
            $crate::scenarios::open_run_does_not_leave_partial_state_when_identity_generation_fails::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn bind_runtime_is_source_scoped_and_idempotent() {
            $crate::scenarios::bind_runtime_is_source_scoped_and_idempotent::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn bind_runtime_prevents_cross_run_identity_confusion_until_seal() {
            $crate::scenarios::bind_runtime_prevents_cross_run_identity_confusion_until_seal::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn bind_runtime_rechecks_last_lease_expiry_after_admission() {
            $crate::scenarios::bind_runtime_rechecks_last_lease_expiry_after_admission::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn bind_runtime_rejects_an_expired_lease_without_sealing_while_another_lease_is_live() {
            $crate::scenarios::bind_runtime_rejects_an_expired_lease_without_sealing_while_another_lease_is_live::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn bind_runtime_rejects_invalid_transaction_time_without_partial_state() {
            $crate::scenarios::bind_runtime_rejects_invalid_transaction_time_without_partial_state::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn finish_run_remains_bounded_until_declared_gaps_are_filled() {
            $crate::scenarios::finish_run_remains_bounded_until_declared_gaps_are_filled::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn first_finish_seals_an_already_reconciled_run_atomically() {
            $crate::scenarios::first_finish_seals_an_already_reconciled_run_atomically::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn finish_run_rejects_a_terminal_position_below_the_durable_watermark() {
            $crate::scenarios::finish_run_rejects_a_terminal_position_below_the_durable_watermark::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn finish_run_deadline_is_frozen_and_expires_to_incomplete() {
            $crate::scenarios::finish_run_deadline_is_frozen_and_expires_to_incomplete::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn ingest_rechecks_finalization_deadline_after_admission() {
            $crate::scenarios::ingest_rechecks_finalization_deadline_after_admission::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn ingest_rechecks_last_lease_expiry_after_admission() {
            $crate::scenarios::ingest_rechecks_last_lease_expiry_after_admission::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn ingest_rejects_invalid_transaction_time_without_partial_state() {
            $crate::scenarios::ingest_rejects_invalid_transaction_time_without_partial_state::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn finish_run_rejects_an_elapsed_requested_deadline_without_extending_it() {
            $crate::scenarios::finish_run_rejects_an_elapsed_requested_deadline_without_extending_it::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn finishing_run_bounds_joined_leases_and_rejects_novel_work_at_deadline() {
            $crate::scenarios::finishing_run_bounds_joined_leases_and_rejects_novel_work_at_deadline::<$harness>().await;
        }

        $(#[$test_attr])*
        #[tokio::test]
        async fn finish_run_requires_every_server_required_source_stream() {
            $crate::scenarios::finish_run_requires_every_server_required_source_stream::<$harness>().await;
        }
    };
}
