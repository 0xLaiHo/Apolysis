// SPDX-License-Identifier: Apache-2.0

use apolysis_daemon::{serve, DaemonConfig};
use tokio::sync::oneshot;

#[tokio::main]
async fn main() {
    let config = match DaemonConfig::from_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("apolysisd: {error}");
            std::process::exit(2);
        }
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _ = shutdown_signal().await;
        let _ = shutdown_tx.send(());
    });
    if let Err(error) = serve(config, shutdown_rx).await {
        eprintln!("apolysisd: {error}");
        std::process::exit(1);
    }
}

async fn shutdown_signal() -> Result<(), String> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| format!("failed to install SIGTERM handler: {error}"))?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            result.map_err(|error| format!("failed to install SIGINT handler: {error}"))
        }
        _ = terminate.recv() => Ok(()),
    }
}
