// SPDX-License-Identifier: Apache-2.0

//! Durable write-side lifecycle for explicitly privacy-authorized evidence
//! objects.
//!
//! This crate deliberately exposes no source-credential object-read API.
//! Capture finalization performs an internal integrity read-back, while future
//! operator reads must enter through the independently authenticated Query
//! plane.

mod crypto;
mod error;
mod model;
mod service;
mod storage;

pub use error::{EvidenceObjectError, EvidenceObjectErrorCode};
pub use model::{
    AuthenticatedDeletionComponent, CaptureRequest, EvidenceObjectPolicy, EvidenceObjectRunLease,
    EvidenceObjectState, ObjectLifecycleConfig, OperatorActor, PendingObjectUpload, ReapReport,
    UploadedEvidenceObject, MAX_IN_MEMORY_OBJECT_BYTES,
};
pub use service::EvidenceObjectLifecycle;
