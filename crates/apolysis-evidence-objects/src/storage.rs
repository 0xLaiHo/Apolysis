// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use aws_credential_types::Credentials;
use aws_sdk_s3::{
    config::{retry::RetryConfig, timeout::TimeoutConfig, BehaviorVersion, Region},
    primitives::ByteStream,
    types::BucketVersioningStatus,
    Client,
};
use bytes::Bytes;
use tokio::{io::AsyncReadExt, time::timeout};

use crate::{
    error::{FailureCause, FailureStage},
    model::{ObjectLifecycleConfig, AES_GCM_TAG_BYTES, MAX_IN_MEMORY_OBJECT_BYTES},
    EvidenceObjectError,
};

const MAX_VERSIONS_PER_OBJECT: usize = 4_096;
const MAX_LIST_PAGES_PER_PASS: usize = 4_096;
const PURGE_BARRIER_METADATA_KEY: &str = "apolysis-purge-barrier";
const PURGE_BARRIER_METADATA_VALUE: &str = "1";

async fn read_up_to_capacity(
    reader: &mut (impl tokio::io::AsyncRead + Unpin),
    buffer: &mut [u8],
) -> Result<usize, std::io::Error> {
    let mut bytes_read = 0_usize;
    while bytes_read < buffer.len() {
        let read = reader.read(&mut buffer[bytes_read..]).await?;
        if read == 0 {
            break;
        }
        bytes_read += read;
    }
    Ok(bytes_read)
}

fn checked_download_capacity(expected_size: u64) -> Result<usize, EvidenceObjectError> {
    let maximum_ciphertext_size = MAX_IN_MEMORY_OBJECT_BYTES + AES_GCM_TAG_BYTES;
    if expected_size > maximum_ciphertext_size {
        return Err(EvidenceObjectError::storage_failure(
            FailureStage::StorageRead,
            FailureCause::ResourceLimit,
        ));
    }
    let read_capacity = expected_size.checked_add(1).ok_or_else(|| {
        EvidenceObjectError::storage_failure(FailureStage::StorageRead, FailureCause::ResourceLimit)
    })?;
    usize::try_from(read_capacity).map_err(|_| {
        EvidenceObjectError::storage_failure(FailureStage::StorageRead, FailureCause::ResourceLimit)
    })
}

fn version_contains_ciphertext(size: Option<i64>) -> Result<bool, EvidenceObjectError> {
    match size {
        Some(0) => Ok(false),
        Some(value) if value > 0 => Ok(true),
        _ => Err(EvidenceObjectError::storage_failure(
            FailureStage::StoragePurge,
            FailureCause::InvalidProviderResponse,
        )),
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RetrievedObject {
    pub bytes: Bytes,
    pub etag: Option<String>,
    pub version_id: Option<String>,
}

#[derive(Clone)]
pub(crate) struct S3Storage {
    client: Client,
    bucket: String,
    operation_timeout: Duration,
}

impl S3Storage {
    pub fn new(config: &ObjectLifecycleConfig) -> Self {
        let credentials = Credentials::new(
            config.access_key_id.to_string(),
            config.secret_access_key.to_string(),
            None,
            None,
            "apolysis-evidence-object-static-provider",
        );
        let timeout_config = TimeoutConfig::builder()
            .connect_timeout(config.operation_timeout)
            .read_timeout(config.operation_timeout)
            .operation_attempt_timeout(config.operation_timeout)
            .operation_timeout(config.operation_timeout)
            .build();
        let sdk_config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .endpoint_url(&config.endpoint_url)
            .region(Region::new(config.region.clone()))
            .credentials_provider(credentials)
            .force_path_style(true)
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .timeout_config(timeout_config)
            .build();
        Self {
            client: Client::from_conf(sdk_config),
            bucket: config.bucket.clone(),
            operation_timeout: config.operation_timeout,
        }
    }

    pub async fn probe_bucket(&self) -> Result<(), EvidenceObjectError> {
        timeout(
            self.operation_timeout,
            self.client.head_bucket().bucket(&self.bucket).send(),
        )
        .await
        .map_err(|_| {
            EvidenceObjectError::storage_failure(
                FailureStage::StorageProbe,
                FailureCause::OperationDeadline,
            )
        })?
        .map_err(|error| {
            EvidenceObjectError::provider_failure(FailureStage::StorageProbe, &error)
        })?;
        let versioning = timeout(
            self.operation_timeout,
            self.client
                .get_bucket_versioning()
                .bucket(&self.bucket)
                .send(),
        )
        .await
        .map_err(|_| {
            EvidenceObjectError::storage_failure(
                FailureStage::StorageProbe,
                FailureCause::OperationDeadline,
            )
        })?
        .map_err(|error| {
            EvidenceObjectError::provider_failure(FailureStage::StorageProbe, &error)
        })?;
        if versioning.status() != Some(&BucketVersioningStatus::Enabled) {
            return Err(EvidenceObjectError::storage_failure(
                FailureStage::StorageProbe,
                FailureCause::InvalidProviderResponse,
            ));
        }
        Ok(())
    }

    pub async fn put_if_absent(
        &self,
        key: &str,
        ciphertext: Vec<u8>,
    ) -> Result<(), EvidenceObjectError> {
        timeout(
            self.operation_timeout,
            self.client
                .put_object()
                .bucket(&self.bucket)
                .key(key)
                .if_none_match("*")
                .content_type("application/octet-stream")
                .metadata("apolysis-cipher-version", "1")
                .body(ByteStream::from(ciphertext))
                .send(),
        )
        .await
        .map_err(|_| {
            EvidenceObjectError::storage_failure(
                FailureStage::StorageWrite,
                FailureCause::OperationDeadline,
            )
        })?
        .map_err(|error| {
            EvidenceObjectError::provider_failure(FailureStage::StorageWrite, &error)
        })?;
        Ok(())
    }

    pub async fn get_exact(
        &self,
        key: &str,
        expected_size: u64,
    ) -> Result<RetrievedObject, EvidenceObjectError> {
        let read_capacity = checked_download_capacity(expected_size)?;
        let output = timeout(
            self.operation_timeout,
            self.client
                .get_object()
                .bucket(&self.bucket)
                .key(key)
                .send(),
        )
        .await
        .map_err(|_| {
            EvidenceObjectError::storage_failure(
                FailureStage::StorageRead,
                FailureCause::OperationDeadline,
            )
        })?
        .map_err(|error| {
            EvidenceObjectError::provider_failure(FailureStage::StorageRead, &error)
        })?;
        let content_length = output
            .content_length()
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(EvidenceObjectError::integrity)?;
        if content_length != expected_size {
            return Err(EvidenceObjectError::integrity());
        }
        let etag = output.e_tag().map(str::to_string);
        let version_id = output.version_id().map(str::to_string);
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(read_capacity).map_err(|_| {
            EvidenceObjectError::storage_failure(
                FailureStage::StorageRead,
                FailureCause::ResourceLimit,
            )
        })?;
        bytes.resize(read_capacity, 0);
        let read = async move {
            let mut reader = output.body.into_async_read();
            let bytes_read = read_up_to_capacity(&mut reader, &mut bytes).await?;
            bytes.truncate(bytes_read);
            Ok::<_, std::io::Error>(bytes)
        };
        let bytes = timeout(self.operation_timeout, read)
            .await
            .map_err(|_| {
                EvidenceObjectError::storage_failure(
                    FailureStage::StorageRead,
                    FailureCause::OperationDeadline,
                )
            })?
            .map_err(|_| {
                EvidenceObjectError::storage_failure(
                    FailureStage::StorageRead,
                    FailureCause::BodyIo,
                )
            })?;
        if bytes.len() as u64 != expected_size {
            return Err(EvidenceObjectError::integrity());
        }
        Ok(RetrievedObject {
            bytes: Bytes::from(bytes),
            etag,
            version_id,
        })
    }

    pub async fn purge_all_versions(&self, key: &str) -> Result<(), EvidenceObjectError> {
        // Install a durable, zero-byte barrier before deleting any data. Data
        // uploads use `If-None-Match: *`, so an outcome-unknown PUT either
        // linearizes before this barrier (and is deleted below) or is rejected
        // after it. Keeping the barrier is what makes a late PUT unable to
        // resurrect evidence after PostgreSQL records physical data purge.
        let current = timeout(
            self.operation_timeout,
            self.client
                .head_object()
                .bucket(&self.bucket)
                .key(key)
                .send(),
        )
        .await
        .map_err(|_| {
            EvidenceObjectError::storage_failure(
                FailureStage::StoragePurge,
                FailureCause::OperationDeadline,
            )
        })?;
        let reusable_barrier_version = match current {
            Ok(head)
                if head.content_length() == Some(0)
                    && head
                        .metadata()
                        .and_then(|metadata| metadata.get(PURGE_BARRIER_METADATA_KEY))
                        .is_some_and(|value| value == PURGE_BARRIER_METADATA_VALUE) =>
            {
                head.version_id()
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            }
            Ok(_) => None,
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.is_not_found()) =>
            {
                None
            }
            Err(error) => {
                return Err(EvidenceObjectError::provider_failure(
                    FailureStage::StoragePurge,
                    &error,
                ));
            }
        };
        let barrier_version_id = if let Some(version_id) = reusable_barrier_version {
            version_id
        } else {
            let barrier = timeout(
                self.operation_timeout,
                self.client
                    .put_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .content_type("application/octet-stream")
                    .metadata(PURGE_BARRIER_METADATA_KEY, PURGE_BARRIER_METADATA_VALUE)
                    .body(ByteStream::from_static(&[]))
                    .send(),
            )
            .await
            .map_err(|_| {
                EvidenceObjectError::storage_failure(
                    FailureStage::StoragePurge,
                    FailureCause::OperationDeadline,
                )
            })?
            .map_err(|error| {
                EvidenceObjectError::provider_failure(FailureStage::StoragePurge, &error)
            })?;
            barrier
                .version_id()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    EvidenceObjectError::storage_failure(
                        FailureStage::StoragePurge,
                        FailureCause::InvalidProviderResponse,
                    )
                })?
                .to_string()
        };

        let invalid_provider_response = || {
            EvidenceObjectError::storage_failure(
                FailureStage::StoragePurge,
                FailureCause::InvalidProviderResponse,
            )
        };
        let mut deleted_versions = 0_usize;
        loop {
            let mut key_marker = None;
            let mut version_marker = None;
            let mut found = false;
            let mut saw_barrier = false;
            let mut scanned_entries = 0_usize;
            let mut listed_pages = 0_usize;
            loop {
                listed_pages += 1;
                if listed_pages > MAX_LIST_PAGES_PER_PASS {
                    return Err(EvidenceObjectError::storage_failure(
                        FailureStage::StoragePurge,
                        FailureCause::ResourceLimit,
                    ));
                }
                let output = timeout(
                    self.operation_timeout,
                    self.client
                        .list_object_versions()
                        .bucket(&self.bucket)
                        .prefix(key)
                        .set_key_marker(key_marker.clone())
                        .set_version_id_marker(version_marker.clone())
                        .send(),
                )
                .await
                .map_err(|_| {
                    EvidenceObjectError::storage_failure(
                        FailureStage::StoragePurge,
                        FailureCause::OperationDeadline,
                    )
                })?
                .map_err(|error| {
                    EvidenceObjectError::provider_failure(FailureStage::StoragePurge, &error)
                })?;

                let mut versions = Vec::new();
                for version in output.versions() {
                    let listed_key = version.key().ok_or_else(&invalid_provider_response)?;
                    if listed_key != key {
                        continue;
                    }
                    scanned_entries += 1;
                    if scanned_entries > MAX_VERSIONS_PER_OBJECT {
                        return Err(EvidenceObjectError::storage_failure(
                            FailureStage::StoragePurge,
                            FailureCause::ResourceLimit,
                        ));
                    }
                    let version_id = version
                        .version_id()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(&invalid_provider_response)?;
                    if version_id == barrier_version_id {
                        saw_barrier = true;
                        continue;
                    }
                    // Concurrent expired claims may each install a purge
                    // barrier before the exact database attempt token is
                    // rechecked. Retain every known zero-byte barrier
                    // candidate: encrypted evidence is always at least one
                    // GCM tag, and deleting another worker's barrier after it
                    // commits would reopen the late-PUT race. Missing or
                    // invalid provider size metadata fails closed.
                    if version_contains_ciphertext(version.size())? {
                        versions.push(version_id.to_string());
                    }
                }
                for marker in output.delete_markers() {
                    let listed_key = marker.key().ok_or_else(&invalid_provider_response)?;
                    if listed_key != key {
                        continue;
                    }
                    scanned_entries += 1;
                    if scanned_entries > MAX_VERSIONS_PER_OBJECT {
                        return Err(EvidenceObjectError::storage_failure(
                            FailureStage::StoragePurge,
                            FailureCause::ResourceLimit,
                        ));
                    }
                    let version_id = marker
                        .version_id()
                        .filter(|value| !value.is_empty())
                        .ok_or_else(&invalid_provider_response)?;
                    versions.push(version_id.to_string());
                }
                for version_id in versions {
                    found = true;
                    deleted_versions += 1;
                    if deleted_versions > MAX_VERSIONS_PER_OBJECT {
                        return Err(EvidenceObjectError::storage_failure(
                            FailureStage::StoragePurge,
                            FailureCause::ResourceLimit,
                        ));
                    }
                    timeout(
                        self.operation_timeout,
                        self.client
                            .delete_object()
                            .bucket(&self.bucket)
                            .key(key)
                            .version_id(version_id)
                            .send(),
                    )
                    .await
                    .map_err(|_| {
                        EvidenceObjectError::storage_failure(
                            FailureStage::StoragePurge,
                            FailureCause::OperationDeadline,
                        )
                    })?
                    .map_err(|error| {
                        EvidenceObjectError::provider_failure(FailureStage::StoragePurge, &error)
                    })?;
                }
                match output.is_truncated() {
                    Some(false) => break,
                    Some(true) => {
                        let next_key = output
                            .next_key_marker()
                            .filter(|value| !value.is_empty())
                            .ok_or_else(&invalid_provider_response)?
                            .to_string();
                        let next_version = output
                            .next_version_id_marker()
                            .filter(|value| !value.is_empty())
                            .ok_or_else(&invalid_provider_response)?
                            .to_string();
                        if key_marker.as_deref() == Some(next_key.as_str())
                            && version_marker.as_deref() == Some(next_version.as_str())
                        {
                            return Err(invalid_provider_response());
                        }
                        key_marker = Some(next_key);
                        version_marker = Some(next_version);
                    }
                    None => return Err(invalid_provider_response()),
                }
            }
            if !saw_barrier {
                return Err(invalid_provider_response());
            }
            if !found {
                break;
            }
        }

        let head = timeout(
            self.operation_timeout,
            self.client
                .head_object()
                .bucket(&self.bucket)
                .key(key)
                .version_id(&barrier_version_id)
                .send(),
        )
        .await
        .map_err(|_| {
            EvidenceObjectError::storage_failure(
                FailureStage::StoragePurge,
                FailureCause::OperationDeadline,
            )
        })?
        .map_err(|error| {
            EvidenceObjectError::provider_failure(FailureStage::StoragePurge, &error)
        })?;
        let barrier_is_exact = head.content_length() == Some(0)
            && head.version_id() == Some(barrier_version_id.as_str())
            && head
                .metadata()
                .and_then(|metadata| metadata.get(PURGE_BARRIER_METADATA_KEY))
                .is_some_and(|value| value == PURGE_BARRIER_METADATA_VALUE);
        if !barrier_is_exact {
            return Err(EvidenceObjectError::storage_failure(
                FailureStage::StoragePurge,
                FailureCause::InvalidProviderResponse,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_capacity_is_bounded_and_checked_before_allocation() {
        let maximum_ciphertext_size = MAX_IN_MEMORY_OBJECT_BYTES + AES_GCM_TAG_BYTES;
        let capacity =
            checked_download_capacity(maximum_ciphertext_size).expect("bounded ciphertext");
        assert_eq!(capacity as u64, maximum_ciphertext_size + 1);

        let error = checked_download_capacity(maximum_ciphertext_size + 1)
            .expect_err("oversized ciphertext must be rejected");
        assert_eq!(
            error.code(),
            crate::EvidenceObjectErrorCode::StorageUnavailable
        );
        assert!(error.retryable());
    }

    #[test]
    fn purge_version_size_classification_fails_closed() {
        assert!(!version_contains_ciphertext(Some(0)).expect("zero-byte barrier"));
        assert!(version_contains_ciphertext(Some(16)).expect("GCM ciphertext"));
        for invalid in [None, Some(-1)] {
            let error = version_contains_ciphertext(invalid)
                .expect_err("missing or negative provider size must fail closed");
            assert_eq!(
                error.code(),
                crate::EvidenceObjectErrorCode::StorageUnavailable
            );
            assert!(error.retryable());
        }
    }

    #[tokio::test]
    async fn bounded_reader_stops_at_the_preallocated_sentinel_capacity() {
        let input = b"abcde";
        let mut reader = &input[..];
        let mut bounded = [0_u8; 4];

        let bytes_read = read_up_to_capacity(&mut reader, &mut bounded)
            .await
            .expect("bounded read");
        assert_eq!(bytes_read, bounded.len());
        assert_eq!(&bounded, b"abcd");

        let mut remainder = [0_u8; 1];
        reader
            .read_exact(&mut remainder)
            .await
            .expect("reader must retain bytes beyond capacity");
        assert_eq!(&remainder, b"e");
    }
}
