// SPDX-License-Identifier: Apache-2.0

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    error::{FailureCause, FailureStage},
    model::{AES_GCM_TAG_BYTES, MAX_IN_MEMORY_OBJECT_BYTES},
    EvidenceObjectError,
};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = AES_GCM_TAG_BYTES as usize;

#[derive(Clone)]
pub(crate) struct ObjectBinding<'a> {
    pub organization_id: &'a str,
    pub object_id: &'a str,
    pub run_id: &'a str,
    pub source_registration_id: &'a str,
    pub source_stream_id: &'a str,
    pub source_id: &'a str,
    pub lease_digest: &'a [u8; 32],
    pub required_source_capability: &'a str,
    pub payload_type: &'a str,
    pub payload_version: &'a str,
    pub content_digest: &'a str,
    pub content_size_bytes: u64,
    pub storage_backend_binding: &'a [u8; 32],
    pub encryption_key_ref: &'a str,
}

pub(crate) struct NewCryptoMaterial {
    pub encrypted_data_key: Vec<u8>,
    pub key_wrap_nonce: [u8; NONCE_BYTES],
    pub content_nonce: [u8; NONCE_BYTES],
    pub aad_digest: [u8; 32],
}

fn object_aad(binding: &ObjectBinding<'_>) -> Vec<u8> {
    let lease_digest = hex_digest(binding.lease_digest);
    let storage_backend_binding = hex_digest(binding.storage_backend_binding);
    [
        "apolysis.evidence-object/v1",
        binding.organization_id,
        binding.object_id,
        binding.run_id,
        binding.source_registration_id,
        binding.source_stream_id,
        binding.source_id,
        &lease_digest,
        binding.required_source_capability,
        binding.payload_type,
        binding.payload_version,
        binding.content_digest,
        &binding.content_size_bytes.to_string(),
        &storage_backend_binding,
        binding.encryption_key_ref,
    ]
    .join("\0")
    .into_bytes()
}

fn key_wrap_aad(aad_digest: &[u8; 32], encryption_key_ref: &str) -> Vec<u8> {
    let mut aad = b"apolysis.evidence-object-key-wrap/v1\0".to_vec();
    aad.extend_from_slice(encryption_key_ref.as_bytes());
    aad.push(0);
    aad.extend_from_slice(aad_digest);
    aad
}

fn cipher(key: &[u8]) -> Result<Aes256Gcm, EvidenceObjectError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| EvidenceObjectError::invalid())
}

fn allocation_failure(stage: FailureStage) -> EvidenceObjectError {
    EvidenceObjectError::storage_failure(stage, FailureCause::ResourceLimit)
}

fn checked_postfix_tag_len(
    plaintext_len: usize,
    stage: FailureStage,
) -> Result<usize, EvidenceObjectError> {
    plaintext_len
        .checked_add(TAG_BYTES)
        .ok_or_else(|| allocation_failure(stage))
}

fn checked_content_encrypt_len(plaintext_len: usize) -> Result<usize, EvidenceObjectError> {
    let plaintext_len_u64 =
        u64::try_from(plaintext_len).map_err(|_| allocation_failure(FailureStage::StorageWrite))?;
    if plaintext_len_u64 > MAX_IN_MEMORY_OBJECT_BYTES {
        return Err(allocation_failure(FailureStage::StorageWrite));
    }
    checked_postfix_tag_len(plaintext_len, FailureStage::StorageWrite)
}

fn checked_content_decrypt_len(ciphertext_len: usize) -> Result<usize, EvidenceObjectError> {
    let ciphertext_len_u64 =
        u64::try_from(ciphertext_len).map_err(|_| allocation_failure(FailureStage::StorageRead))?;
    let maximum_ciphertext_size = MAX_IN_MEMORY_OBJECT_BYTES
        .checked_add(AES_GCM_TAG_BYTES)
        .ok_or_else(|| allocation_failure(FailureStage::StorageRead))?;
    if ciphertext_len_u64 > maximum_ciphertext_size {
        return Err(allocation_failure(FailureStage::StorageRead));
    }
    ciphertext_len
        .checked_sub(TAG_BYTES)
        .ok_or_else(EvidenceObjectError::integrity)
}

fn encrypt_with_postfix_tag(
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    plaintext: &[u8],
    allocation_stage: FailureStage,
    operation_failure: impl FnOnce() -> EvidenceObjectError,
) -> Result<Vec<u8>, EvidenceObjectError> {
    let output_len = checked_postfix_tag_len(plaintext.len(), allocation_stage)?;
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve_exact(output_len)
        .map_err(|_| allocation_failure(allocation_stage))?;
    output.extend_from_slice(plaintext);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, output.as_mut())
        .map_err(|_| operation_failure())?;
    output.extend_from_slice(tag.as_slice());
    debug_assert_eq!(output.len(), output_len);
    Ok(std::mem::take(output.as_mut()))
}

fn decrypt_with_postfix_tag(
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    ciphertext: &[u8],
    plaintext_len: usize,
    allocation_stage: FailureStage,
    operation_failure: impl FnOnce() -> EvidenceObjectError,
) -> Result<Zeroizing<Vec<u8>>, EvidenceObjectError> {
    let (ciphertext, tag) = ciphertext
        .split_at_checked(plaintext_len)
        .filter(|(_, tag)| tag.len() == TAG_BYTES)
        .ok_or_else(EvidenceObjectError::integrity)?;
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext
        .try_reserve_exact(plaintext_len)
        .map_err(|_| allocation_failure(allocation_stage))?;
    plaintext.extend_from_slice(ciphertext);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            aad,
            plaintext.as_mut(),
            Tag::from_slice(tag),
        )
        .map_err(|_| operation_failure())?;
    Ok(plaintext)
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn decode_digest(value: &str) -> Result<[u8; 32], EvidenceObjectError> {
    if value.len() != 64 {
        return Err(EvidenceObjectError::invalid());
    }
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_nibble(pair[0]).ok_or_else(EvidenceObjectError::invalid)?;
        let low = decode_nibble(pair[1]).ok_or_else(EvidenceObjectError::invalid)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

pub(crate) fn random_identifier(prefix: &str) -> Result<String, EvidenceObjectError> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|error| {
        EvidenceObjectError::entropy_failure(FailureStage::EntropyIdentifier, &error)
    })?;
    Ok(format!("{prefix}{}", hex_digest(&random)))
}

pub(crate) fn new_crypto_material(
    wrapping_key: &[u8; 32],
    binding: &ObjectBinding<'_>,
) -> Result<NewCryptoMaterial, EvidenceObjectError> {
    let mut data_key = Zeroizing::new([0_u8; KEY_BYTES]);
    let mut key_wrap_nonce = [0_u8; NONCE_BYTES];
    let mut content_nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(data_key.as_mut()).map_err(|error| {
        EvidenceObjectError::entropy_failure(FailureStage::EntropyDataKey, &error)
    })?;
    getrandom::fill(&mut key_wrap_nonce).map_err(|error| {
        EvidenceObjectError::entropy_failure(FailureStage::EntropyKeyWrapNonce, &error)
    })?;
    getrandom::fill(&mut content_nonce).map_err(|error| {
        EvidenceObjectError::entropy_failure(FailureStage::EntropyContentNonce, &error)
    })?;

    let aad = object_aad(binding);
    let aad_digest = sha256_bytes(&aad);
    let key_aad = key_wrap_aad(&aad_digest, binding.encryption_key_ref);
    let wrapped = encrypt_with_postfix_tag(
        &cipher(wrapping_key)?,
        &key_wrap_nonce,
        &key_aad,
        data_key.as_ref(),
        FailureStage::CryptographicKeyWrap,
        || EvidenceObjectError::cryptographic_failure(FailureStage::CryptographicKeyWrap),
    )?;
    Ok(NewCryptoMaterial {
        encrypted_data_key: wrapped,
        key_wrap_nonce,
        content_nonce,
        aad_digest,
    })
}

pub(crate) fn seal_content(
    wrapping_key: &[u8; 32],
    binding: &ObjectBinding<'_>,
    encrypted_data_key: &[u8],
    key_wrap_nonce: &[u8; NONCE_BYTES],
    content_nonce: &[u8; NONCE_BYTES],
    expected_aad_digest: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, EvidenceObjectError> {
    let aad = object_aad(binding);
    if &sha256_bytes(&aad) != expected_aad_digest {
        return Err(EvidenceObjectError::integrity());
    }
    let wrapped_plaintext_len = encrypted_data_key
        .len()
        .checked_sub(TAG_BYTES)
        .filter(|length| *length == KEY_BYTES)
        .ok_or_else(EvidenceObjectError::integrity)?;
    let key_aad = key_wrap_aad(expected_aad_digest, binding.encryption_key_ref);
    let data_key = decrypt_with_postfix_tag(
        &cipher(wrapping_key)?,
        key_wrap_nonce,
        &key_aad,
        encrypted_data_key,
        wrapped_plaintext_len,
        FailureStage::CryptographicKeyWrap,
        EvidenceObjectError::integrity,
    )?;
    if data_key.len() != KEY_BYTES {
        return Err(EvidenceObjectError::integrity());
    }
    checked_content_encrypt_len(plaintext.len())?;
    encrypt_with_postfix_tag(
        &cipher(data_key.as_ref())?,
        content_nonce,
        &aad,
        plaintext,
        FailureStage::StorageWrite,
        EvidenceObjectError::integrity,
    )
}

pub(crate) fn open_content(
    wrapping_key: &[u8; 32],
    binding: &ObjectBinding<'_>,
    encrypted_data_key: &[u8],
    key_wrap_nonce: &[u8; NONCE_BYTES],
    content_nonce: &[u8; NONCE_BYTES],
    expected_aad_digest: &[u8; 32],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, EvidenceObjectError> {
    let aad = object_aad(binding);
    if &sha256_bytes(&aad) != expected_aad_digest {
        return Err(EvidenceObjectError::integrity());
    }
    let wrapped_plaintext_len = encrypted_data_key
        .len()
        .checked_sub(TAG_BYTES)
        .filter(|length| *length == KEY_BYTES)
        .ok_or_else(EvidenceObjectError::integrity)?;
    let key_aad = key_wrap_aad(expected_aad_digest, binding.encryption_key_ref);
    let data_key = decrypt_with_postfix_tag(
        &cipher(wrapping_key)?,
        key_wrap_nonce,
        &key_aad,
        encrypted_data_key,
        wrapped_plaintext_len,
        FailureStage::CryptographicKeyWrap,
        EvidenceObjectError::integrity,
    )?;
    if data_key.len() != KEY_BYTES {
        return Err(EvidenceObjectError::integrity());
    }
    let plaintext_len = checked_content_decrypt_len(ciphertext.len())?;
    decrypt_with_postfix_tag(
        &cipher(data_key.as_ref())?,
        content_nonce,
        &aad,
        ciphertext,
        plaintext_len,
        FailureStage::StorageRead,
        EvidenceObjectError::integrity,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEASE_DIGEST: [u8; 32] = [0x11; 32];
    const STORAGE_BACKEND_BINDING: [u8; 32] = [0x22; 32];

    fn binding<'a>() -> ObjectBinding<'a> {
        ObjectBinding {
            organization_id: "org_test",
            object_id: "object_test",
            run_id: "run_test",
            source_registration_id: "registration_test",
            source_stream_id: "stream_test",
            source_id: "source_test",
            lease_digest: &LEASE_DIGEST,
            required_source_capability: "verified_outcome",
            payload_type: "binary_artifact",
            payload_version: "1.0",
            content_digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            content_size_bytes: 3,
            storage_backend_binding: &STORAGE_BACKEND_BINDING,
            encryption_key_ref: "key_test",
        }
    }

    #[test]
    fn envelope_crypto_round_trips_and_binds_metadata() {
        let key = [7_u8; 32];
        let object_binding = binding();
        let material = new_crypto_material(&key, &object_binding).expect("crypto material");
        let ciphertext = seal_content(
            &key,
            &object_binding,
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            b"abc",
        )
        .expect("encrypt");
        assert_ne!(ciphertext, b"abc");
        let plaintext = open_content(
            &key,
            &object_binding,
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            &ciphertext,
        )
        .expect("decrypt");
        assert_eq!(plaintext.as_slice(), b"abc");

        let mut wrong_binding = binding();
        wrong_binding.object_id = "object_other";
        assert!(open_content(
            &key,
            &wrong_binding,
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            &ciphertext,
        )
        .is_err());

        let wrong_lease_digest = [0x33; 32];
        let mut wrong_binding = binding();
        wrong_binding.lease_digest = &wrong_lease_digest;
        assert!(open_content(
            &key,
            &wrong_binding,
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            &ciphertext,
        )
        .is_err());

        let wrong_storage_backend = [0x44; 32];
        let mut wrong_binding = binding();
        wrong_binding.storage_backend_binding = &wrong_storage_backend;
        assert!(open_content(
            &key,
            &wrong_binding,
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            &ciphertext,
        )
        .is_err());
    }

    #[test]
    fn envelope_crypto_preserves_postfix_tag_wire_format_and_rejects_tampering() {
        let key = [7_u8; 32];
        let object_binding = binding();
        let material = new_crypto_material(&key, &object_binding).expect("crypto material");
        assert_eq!(material.encrypted_data_key.len(), KEY_BYTES + TAG_BYTES);

        let ciphertext = seal_content(
            &key,
            &object_binding,
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            b"abc",
        )
        .expect("encrypt");
        assert_eq!(ciphertext.len(), 3 + TAG_BYTES);

        let mut changed_ciphertext = ciphertext.clone();
        changed_ciphertext[0] ^= 1;
        assert_eq!(
            open_content(
                &key,
                &object_binding,
                &material.encrypted_data_key,
                &material.key_wrap_nonce,
                &material.content_nonce,
                &material.aad_digest,
                &changed_ciphertext,
            )
            .expect_err("changed ciphertext must be rejected")
            .code(),
            crate::EvidenceObjectErrorCode::IntegrityMismatch
        );

        let mut changed_tag = ciphertext;
        *changed_tag.last_mut().expect("postfix tag") ^= 1;
        assert_eq!(
            open_content(
                &key,
                &object_binding,
                &material.encrypted_data_key,
                &material.key_wrap_nonce,
                &material.content_nonce,
                &material.aad_digest,
                &changed_tag,
            )
            .expect_err("changed postfix tag must be rejected")
            .code(),
            crate::EvidenceObjectErrorCode::IntegrityMismatch
        );
    }

    #[test]
    fn detached_encryption_matches_the_aes_gcm_postfix_tag_vector() {
        // NIST AES-256-GCM, 128-bit plaintext, empty AAD. Keeping the expected
        // bytes literal makes tag placement independent of this implementation.
        let key = [0_u8; 32];
        let nonce = [0_u8; NONCE_BYTES];
        let plaintext = [0_u8; 16];
        let expected = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18, 0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5,
            0xd4, 0x8a, 0xb9, 0x19,
        ];
        let ciphertext = encrypt_with_postfix_tag(
            &cipher(&key).expect("valid key"),
            &nonce,
            &[],
            &plaintext,
            FailureStage::StorageWrite,
            EvidenceObjectError::integrity,
        )
        .expect("encrypt vector");
        assert_eq!(ciphertext, expected);

        let decrypted = decrypt_with_postfix_tag(
            &cipher(&key).expect("valid key"),
            &nonce,
            &[],
            &ciphertext,
            plaintext.len(),
            FailureStage::StorageRead,
            EvidenceObjectError::integrity,
        )
        .expect("decrypt vector");
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn crypto_allocation_lengths_are_checked_at_the_memory_boundary() {
        let maximum_plaintext =
            usize::try_from(MAX_IN_MEMORY_OBJECT_BYTES).expect("64 MiB fits usize");
        assert_eq!(
            checked_content_encrypt_len(maximum_plaintext).expect("bounded plaintext"),
            maximum_plaintext + TAG_BYTES
        );
        assert_eq!(
            checked_content_decrypt_len(maximum_plaintext + TAG_BYTES).expect("bounded ciphertext"),
            maximum_plaintext
        );

        let oversized = checked_content_encrypt_len(maximum_plaintext + 1)
            .expect_err("oversized plaintext must be rejected before allocation");
        assert_eq!(
            oversized.code(),
            crate::EvidenceObjectErrorCode::StorageUnavailable
        );
        assert!(oversized.retryable());

        let oversized = checked_content_decrypt_len(maximum_plaintext + TAG_BYTES + 1)
            .expect_err("oversized ciphertext must be rejected before allocation");
        assert_eq!(
            oversized.code(),
            crate::EvidenceObjectErrorCode::StorageUnavailable
        );

        let missing_tag = checked_content_decrypt_len(TAG_BYTES - 1)
            .expect_err("ciphertext shorter than one tag must be rejected");
        assert_eq!(
            missing_tag.code(),
            crate::EvidenceObjectErrorCode::IntegrityMismatch
        );

        let overflow = checked_postfix_tag_len(usize::MAX, FailureStage::StorageWrite)
            .expect_err("tag length overflow must be rejected before allocation");
        assert_eq!(
            overflow.code(),
            crate::EvidenceObjectErrorCode::StorageUnavailable
        );
    }

    #[test]
    fn empty_plaintext_round_trips_as_one_postfix_tag() {
        let key = [7_u8; 32];
        let mut object_binding = binding();
        object_binding.content_size_bytes = 0;
        let material = new_crypto_material(&key, &object_binding).expect("crypto material");
        let ciphertext = seal_content(
            &key,
            &object_binding,
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            &[],
        )
        .expect("encrypt empty plaintext");
        assert_eq!(ciphertext.len(), TAG_BYTES);
        let plaintext = open_content(
            &key,
            &object_binding,
            &material.encrypted_data_key,
            &material.key_wrap_nonce,
            &material.content_nonce,
            &material.aad_digest,
            &ciphertext,
        )
        .expect("decrypt empty plaintext");
        assert!(plaintext.is_empty());
    }
}
