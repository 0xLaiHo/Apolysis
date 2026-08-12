// SPDX-License-Identifier: Apache-2.0

use apolysis_kubernetes_source::{run_production_source, ProductionSourceConfig};

#[tokio::main]
async fn main() {
    let config = match ProductionSourceConfig::from_environment() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("apolysis-kubernetes-source: {error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = run_production_source(config, shutdown_signal()).await {
        eprintln!("apolysis-kubernetes-source: {error}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() {
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
    let mut terminate = match terminate {
        Ok(signal) => signal,
        Err(_) => return,
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}
