// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, fmt, sync::Arc};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use zeroize::{Zeroize, Zeroizing};

use crate::error::repository_failure;

const AES_GCM_NONCE_BYTES: usize = 12;

/// Encrypted operation response retained for an exact retry after restart.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SealedReplay {
    key_id: String,
    cipher_version: u16,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl SealedReplay {
    pub(crate) fn new(
        key_id: impl Into<String>,
        cipher_version: u16,
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> Result<Self, apolysis_gateway::GatewayFailure> {
        let key_id = key_id.into();
        if key_id.is_empty()
            || key_id.len() > 128
            || key_id.chars().any(char::is_control)
            || cipher_version == 0
            || nonce.len() != AES_GCM_NONCE_BYTES
            || ciphertext.is_empty()
        {
            return Err(repository_failure());
        }
        Ok(Self {
            key_id,
            cipher_version,
            nonce,
            ciphertext,
        })
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn cipher_version(&self) -> u16 {
        self.cipher_version
    }

    pub(crate) fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for SealedReplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedReplay")
            .field("key_id", &self.key_id)
            .field("cipher_version", &self.cipher_version)
            .field("nonce", &"[REDACTED]")
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

/// Mandatory authenticated-encryption boundary for durable idempotency responses.
pub(crate) trait ReplayProtector: Send + Sync {
    fn seal(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedReplay, apolysis_gateway::GatewayFailure>;

    fn open(
        &self,
        associated_data: &[u8],
        sealed: &SealedReplay,
    ) -> Result<Zeroizing<Vec<u8>>, apolysis_gateway::GatewayFailure>;
}

struct KeyMaterial(Zeroizing<[u8; 32]>);

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// In-process AES-256-GCM keyring implementation.
///
/// Production deployments should load these bytes through their KMS or secret
/// manager and rotate key identifiers without logging key material.
#[derive(Clone)]
pub struct Aes256GcmReplayProtector {
    active_key_id: Arc<str>,
    keys: Arc<BTreeMap<String, KeyMaterial>>,
}

impl Aes256GcmReplayProtector {
    pub fn new(
        active_key_id: impl Into<String>,
        keys: impl IntoIterator<Item = (String, [u8; 32])>,
    ) -> Result<Self, apolysis_gateway::GatewayFailure> {
        let active_key_id = active_key_id.into();
        if active_key_id.is_empty()
            || active_key_id.len() > 128
            || active_key_id.chars().any(char::is_control)
        {
            return Err(repository_failure());
        }
        let mut keyring = BTreeMap::new();
        for (key_id, key) in keys {
            let key = KeyMaterial(Zeroizing::new(key));
            if key_id.is_empty()
                || key_id.len() > 128
                || key_id.chars().any(char::is_control)
                || keyring.insert(key_id, key).is_some()
            {
                return Err(repository_failure());
            }
        }
        if !keyring.contains_key(&active_key_id) {
            return Err(repository_failure());
        }
        Ok(Self {
            active_key_id: Arc::from(active_key_id),
            keys: Arc::new(keyring),
        })
    }
}

impl fmt::Debug for Aes256GcmReplayProtector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Aes256GcmReplayProtector")
            .field("active_key_id", &self.active_key_id)
            .field("keys", &"[REDACTED]")
            .finish()
    }
}

impl ReplayProtector for Aes256GcmReplayProtector {
    fn seal(
        &self,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<SealedReplay, apolysis_gateway::GatewayFailure> {
        let key = self
            .keys
            .get(self.active_key_id.as_ref())
            .ok_or_else(repository_failure)?;
        let cipher = Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| repository_failure())?;
        let mut nonce_bytes = [0_u8; AES_GCM_NONCE_BYTES];
        getrandom::fill(&mut nonce_bytes).map_err(|_| repository_failure())?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| repository_failure())?;
        SealedReplay::new(
            self.active_key_id.to_string(),
            1,
            nonce_bytes.to_vec(),
            ciphertext,
        )
    }

    fn open(
        &self,
        associated_data: &[u8],
        sealed: &SealedReplay,
    ) -> Result<Zeroizing<Vec<u8>>, apolysis_gateway::GatewayFailure> {
        if sealed.cipher_version() != 1 || sealed.nonce().len() != AES_GCM_NONCE_BYTES {
            return Err(repository_failure());
        }
        let key = self
            .keys
            .get(sealed.key_id())
            .ok_or_else(repository_failure)?;
        let cipher = Aes256Gcm::new_from_slice(key.0.as_ref()).map_err(|_| repository_failure())?;
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(sealed.nonce()),
                Payload {
                    msg: sealed.ciphertext(),
                    aad: associated_data,
                },
            )
            .map_err(|_| repository_failure())?;
        Ok(Zeroizing::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_cipher_round_trips_and_debug_is_redacted() {
        let protector = Aes256GcmReplayProtector::new("test-key", [("test-key".into(), [7; 32])])
            .expect("valid keyring");
        let sealed = protector
            .seal(b"org/op/digest", b"lease-secret")
            .expect("seal replay");
        assert_ne!(sealed.ciphertext(), b"lease-secret");
        assert!(!format!("{sealed:?}").contains("lease-secret"));
        assert_eq!(
            protector
                .open(b"org/op/digest", &sealed)
                .expect("open replay")
                .as_slice(),
            b"lease-secret"
        );
        assert!(protector.open(b"different-aad", &sealed).is_err());
    }
}
