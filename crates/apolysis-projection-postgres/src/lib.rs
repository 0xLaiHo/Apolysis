// SPDX-License-Identifier: Apache-2.0

//! Durable PostgreSQL projection foundation for Agent Run lifecycle facts.

mod error;
mod migration;
mod model;
mod repository;
mod validation;

pub use error::{ProjectionError, ProjectionErrorCode, ProjectionResult};
pub use migration::migrate_projection_schema;
pub use model::{
    ComputationVersion, Cutover, GenerationId, GenerationKey, GenerationState, InputFailureCode,
    LifecycleCursor, LifecyclePage, ProjectionBatchOutcome, ProjectionCheckpoint, ProjectionCommit,
    ProjectionConfig, ProjectionGeneration, ProjectionStatus, RunLifecycleRead,
    MAX_LIFECYCLE_PAGE_SIZE, MAX_PROJECTION_BATCH_SIZE,
};
pub use repository::PostgresRunProjection;
