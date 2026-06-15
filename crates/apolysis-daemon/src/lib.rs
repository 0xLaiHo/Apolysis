// SPDX-License-Identifier: Apache-2.0

mod config;
mod pipeline;
mod runtime;
mod scope;
mod server;
mod state;

pub use config::DaemonConfig;
pub use pipeline::{DaemonRecord, EventPipeline, SubmitError, WriterSummary};
pub use runtime::{
    ingest_observer_batch, run_observer_runtime, ObserverIngestSummary, ObserverRuntimeBackend,
    ObserverRuntimeSummary,
};
pub use scope::{scope_channel, ScopeController, ScopeOperation, ScopeRequest};
pub use server::{serve, DaemonResponse, DAEMON_SCHEMA_V1};
pub use state::DaemonState;
