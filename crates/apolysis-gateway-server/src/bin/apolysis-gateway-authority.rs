// SPDX-License-Identifier: Apache-2.0

#[tokio::main]
async fn main() {
    if let Err(error) = apolysis_gateway_server::run_authority_command().await {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}
