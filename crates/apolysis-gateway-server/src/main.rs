// SPDX-License-Identifier: Apache-2.0

use apolysis_gateway_server::{serve, GatewayServerConfig, GatewayServerError};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), GatewayServerError> {
    let config = GatewayServerConfig::from_args(std::env::args_os())?;
    serve(config).await
}
