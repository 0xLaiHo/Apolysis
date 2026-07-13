// SPDX-License-Identifier: Apache-2.0

//! PostgreSQL persistence for the Execution Evidence Gateway.
//!
//! The adapter owns transaction ordering, uniqueness constraints, encrypted
//! operation replay, and the one-to-one ledger/outbox boundary. It deliberately
//! implements the high-level [`apolysis_gateway::GatewayRepository`] seam rather
//! than exposing database CRUD to the application service.

mod error;
mod model;
mod operations;
mod replay;
mod repository;

pub use replay::Aes256GcmReplayProtector;
pub use repository::{PostgresGatewayConfig, PostgresGatewayRepository};

/// Embedded, ordered migrations for the dedicated Gateway schema.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");
