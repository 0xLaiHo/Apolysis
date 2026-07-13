// SPDX-License-Identifier: Apache-2.0

use std::{io::Cursor, path::Path};

use sha2::{Digest, Sha256};
use x509_parser::prelude::parse_x509_certificate;

use super::input::{require_absolute_path, MAX_CERTIFICATE_PEM_BYTES, MAX_IJSON_INTEGER};
use crate::{file_input::read_bounded_file, GatewayServerError};

const MTLS_FINGERPRINT_DOMAIN: &[u8] = b"apolysis.gateway.mtls-leaf/v1\0";

pub(super) struct ClientCertificate {
    pub(super) fingerprint: [u8; 32],
    pub(super) not_before_unix_ms: u64,
    pub(super) not_after_unix_ms: u64,
}

pub(super) fn mtls_leaf_fingerprint(leaf_der: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(MTLS_FINGERPRINT_DOMAIN);
    digest.update(leaf_der);
    digest.finalize().into()
}

pub(super) fn credential_id(fingerprint: &[u8; 32]) -> String {
    let mut value = String::with_capacity(5 + fingerprint.len() * 2);
    value.push_str("mtls_");
    for byte in fingerprint {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

pub(super) fn read_client_certificate(
    path: &Path,
) -> Result<ClientCertificate, GatewayServerError> {
    require_absolute_path(path)?;
    let pem = read_bounded_file(path, MAX_CERTIFICATE_PEM_BYTES as u64, false)?;
    if pem.is_empty() || pem.len() > MAX_CERTIFICATE_PEM_BYTES {
        return Err(GatewayServerError::configuration(
            "Client certificate file is invalid",
        ));
    }
    let mut cursor = Cursor::new(pem.as_slice());
    let certificates = rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GatewayServerError::configuration("Client certificate PEM is invalid"))?;
    let leaf = certificates.first().ok_or_else(|| {
        GatewayServerError::configuration("Client certificate PEM contains no certificate")
    })?;
    let leaf_der = leaf.as_ref();
    let (remaining, certificate) = parse_x509_certificate(leaf_der)
        .map_err(|_| GatewayServerError::configuration("Client certificate DER is invalid"))?;
    if !remaining.is_empty() || certificate.is_ca() {
        return Err(GatewayServerError::configuration(
            "Client certificate must be a leaf certificate",
        ));
    }
    let extended_key_usage = certificate
        .extended_key_usage()
        .map_err(|_| GatewayServerError::configuration("Client certificate usage is invalid"))?
        .ok_or_else(|| {
            GatewayServerError::configuration("Client certificate must declare clientAuth")
        })?;
    if !extended_key_usage.value.client_auth && !extended_key_usage.value.any {
        return Err(GatewayServerError::configuration(
            "Client certificate must declare clientAuth",
        ));
    }
    let not_before_unix_ms =
        certificate_time_millis(certificate.validity().not_before.timestamp())?;
    let not_after_unix_ms = certificate_time_millis(certificate.validity().not_after.timestamp())?;
    Ok(ClientCertificate {
        fingerprint: mtls_leaf_fingerprint(leaf_der),
        not_before_unix_ms,
        not_after_unix_ms,
    })
}

fn certificate_time_millis(timestamp_seconds: i64) -> Result<u64, GatewayServerError> {
    let timestamp_seconds = u64::try_from(timestamp_seconds)
        .map_err(|_| GatewayServerError::configuration("Client certificate validity is invalid"))?;
    timestamp_seconds
        .checked_mul(1_000)
        .filter(|value| *value <= MAX_IJSON_INTEGER)
        .ok_or_else(|| GatewayServerError::configuration("Client certificate validity is invalid"))
}
