// SPDX-License-Identifier: Apache-2.0

//! Production transport and current-authority admission for the Execution
//! Evidence Gateway.

mod authority;
mod config;
mod error;
mod file_input;
mod http;
mod server;

pub use authority::{run_authority_command, AuthorityStore};
pub use config::GatewayServerConfig;
pub use error::GatewayServerError;
pub use server::serve;
