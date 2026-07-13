// SPDX-License-Identifier: Apache-2.0

use std::{
    fs::OpenOptions,
    io::{BufReader, Write},
    net::SocketAddr,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::Arc,
    time::Duration,
};

use apolysis_gateway::{ExecutionEvidenceGateway, OsRandomIdGenerator, SystemClock};
use apolysis_gateway_postgres::{
    Aes256GcmReplayProtector, PostgresGatewayConfig, PostgresGatewayRepository,
};
use axum_server::{
    tls_rustls::{RustlsAcceptor, RustlsConfig},
    Handle,
};
use axum_server_mtls::MtlsAcceptor;
use rustls::{crypto::aws_lc_rs, server::WebPkiClientVerifier, RootCertStore, ServerConfig};
use zeroize::Zeroizing;

use crate::{
    file_input::read_bounded_file,
    http::{router, GatewayHttpState},
    AuthorityStore, GatewayServerConfig, GatewayServerError,
};

const MAX_DATABASE_URL_BYTES: u64 = 4096;
const MAX_REPLAY_KEY_BYTES: u64 = 256;
const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;
const ACTIVE_REPLAY_KEY_ID: &str = "gateway-live-v1";

/// Run the direct-mTLS production Gateway until it receives a shutdown signal.
pub async fn serve(config: GatewayServerConfig) -> Result<(), GatewayServerError> {
    let database_url = read_secret_text(config.database_url_file(), MAX_DATABASE_URL_BYTES)?;
    if !(database_url.starts_with("postgres://") || database_url.starts_with("postgresql://")) {
        return Err(GatewayServerError::configuration(
            "Gateway database URL uses an unsupported scheme",
        ));
    }
    let replay_key_text = read_secret_text(config.replay_key(), MAX_REPLAY_KEY_BYTES)?;
    let replay_key = decode_replay_key(&replay_key_text)?;

    let replay_protector = Arc::new(
        Aes256GcmReplayProtector::new(
            ACTIVE_REPLAY_KEY_ID,
            [(ACTIVE_REPLAY_KEY_ID.to_string(), replay_key)],
        )
        .map_err(GatewayServerError::gateway)?,
    );
    let repository = PostgresGatewayRepository::connect_and_migrate(
        &database_url,
        replay_protector,
        PostgresGatewayConfig::default(),
    )
    .await
    .map_err(GatewayServerError::gateway)?;
    let authority = AuthorityStore::connect_and_migrate(&database_url).await?;
    let gateway = ExecutionEvidenceGateway::new(repository, SystemClock, OsRandomIdGenerator);
    let application = router(GatewayHttpState::new(gateway, authority));

    let tls_config = build_tls_config(
        config.tls_certificate(),
        config.tls_private_key(),
        config.client_ca(),
    )?;
    let acceptor = MtlsAcceptor::new(RustlsAcceptor::new(tls_config));
    let handle = Handle::<SocketAddr>::new();
    let server = axum_server::bind(config.listen())
        .handle(handle.clone())
        .acceptor(acceptor)
        .serve(application.into_make_service());
    tokio::pin!(server);

    let bound_address = tokio::select! {
        address = handle.listening() => {
            address.ok_or_else(|| GatewayServerError::configuration("Gateway listener failed to bind"))?
        }
        result = &mut server => {
            result.map_err(|error| GatewayServerError::io_at("listener-serve", error))?;
            return Err(GatewayServerError::configuration("Gateway stopped before becoming ready"));
        }
    };
    write_ready_file(config.ready_file(), bound_address)?;

    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        wait_for_shutdown().await;
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
    });

    server
        .await
        .map_err(|error| GatewayServerError::io_at("listener-serve", error))
}

fn build_tls_config(
    server_certificate_path: &Path,
    server_key_path: &Path,
    client_ca_path: &Path,
) -> Result<RustlsConfig, GatewayServerError> {
    let server_certificate = read_bounded_file(server_certificate_path, MAX_TLS_FILE_BYTES, false)?;
    let server_private_key = Zeroizing::new(read_bounded_file(
        server_key_path,
        MAX_TLS_FILE_BYTES,
        true,
    )?);
    let client_ca = read_bounded_file(client_ca_path, MAX_TLS_FILE_BYTES, false)?;

    let mut certificate_reader = BufReader::new(server_certificate.as_slice());
    let certificate_chain = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayServerError::tls_at("server-certificate"))?;
    if certificate_chain.is_empty() {
        return Err(GatewayServerError::tls_at("server-certificate"));
    }

    let mut private_key_reader = BufReader::new(server_private_key.as_slice());
    let private_key = rustls_pemfile::private_key(&mut private_key_reader)
        .map_err(|_| GatewayServerError::tls_at("server-private-key"))?
        .ok_or_else(|| GatewayServerError::tls_at("server-private-key"))?;

    let mut client_ca_reader = BufReader::new(client_ca.as_slice());
    let client_ca_certificates = rustls_pemfile::certs(&mut client_ca_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayServerError::tls_at("client-ca"))?;
    if client_ca_certificates.is_empty() {
        return Err(GatewayServerError::tls_at("client-ca"));
    }
    let mut roots = RootCertStore::empty();
    for certificate in client_ca_certificates {
        roots
            .add(certificate)
            .map_err(|_| GatewayServerError::tls_at("client-ca"))?;
    }

    // SQLx also enables rustls' ring provider. Selecting AWS-LC explicitly
    // avoids process-global provider ambiguity and an otherwise possible panic.
    let provider = Arc::new(aws_lc_rs::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .map_err(|_| GatewayServerError::tls_at("client-verifier"))?;
    let mut server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| GatewayServerError::tls_at("protocol-versions"))?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(certificate_chain, private_key)
        .map_err(|_| GatewayServerError::tls_at("server-identity"))?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

fn read_secret_text(
    path: &Path,
    maximum_bytes: u64,
) -> Result<Zeroizing<String>, GatewayServerError> {
    let bytes = Zeroizing::new(read_bounded_file(path, maximum_bytes, true)?);
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| GatewayServerError::configuration("Gateway secret file is not UTF-8"))?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(GatewayServerError::configuration(
            "Gateway secret file must not be empty",
        ));
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

fn decode_replay_key(value: &str) -> Result<[u8; 32], GatewayServerError> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err(GatewayServerError::configuration(
            "Gateway replay key must be 32-byte lowercase hexadecimal",
        ));
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        decoded[index] = decode_hex_nibble(pair[0])?
            .checked_mul(16)
            .and_then(|high| high.checked_add(decode_hex_nibble(pair[1]).ok()?))
            .ok_or_else(|| {
                GatewayServerError::configuration(
                    "Gateway replay key must be 32-byte lowercase hexadecimal",
                )
            })?;
    }
    Ok(decoded)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, GatewayServerError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(GatewayServerError::configuration(
            "Gateway replay key must be 32-byte lowercase hexadecimal",
        )),
    }
}

fn write_ready_file(path: &Path, bound_address: SocketAddr) -> Result<(), GatewayServerError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| GatewayServerError::io_at("ready-open", error))?;
    writeln!(file, "https://{bound_address}")
        .map_err(|error| GatewayServerError::io_at("ready-write", error))?;
    file.sync_all()
        .map_err(|error| GatewayServerError::io_at("ready-sync", error))
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        match terminate {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::decode_replay_key;

    #[test]
    fn replay_key_requires_lowercase_hex() {
        assert!(decode_replay_key(&"ab".repeat(32)).is_ok());
        assert!(decode_replay_key(&"AB".repeat(32)).is_err());
        assert!(decode_replay_key("00").is_err());
    }
}
