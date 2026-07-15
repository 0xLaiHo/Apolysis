// SPDX-License-Identifier: Apache-2.0

//! Production transport and current-authority admission for the Execution
//! Evidence Gateway.

mod authority;
mod config;
mod error;
mod file_input;
mod http;
#[cfg(feature = "qualification")]
mod qualification;
mod server;

pub use authority::{run_authority_command, AuthorityStore};
pub use config::GatewayServerConfig;
pub use error::GatewayServerError;
#[cfg(feature = "qualification")]
pub use http::GatewayRouteOperation as QualificationOperation;
#[cfg(feature = "qualification")]
pub use qualification::register_qualification_join_grant;
pub use server::serve;
#[cfg(feature = "qualification")]
pub use server::serve_with_post_commit_response_barrier;
#[cfg(feature = "qualification")]
pub use server::serve_with_pre_operation_barrier;
