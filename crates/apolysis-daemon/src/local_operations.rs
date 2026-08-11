// SPDX-License-Identifier: Apache-2.0

//! Bounded local installation lifecycle for the Linux daemon bundle.
//!
//! The public surface is intentionally limited to inspect, plan, and apply.
//! Bundle paths never become destinations: a closed artifact set maps to fixed
//! host-relative paths, and a receipt is the only ownership authority used by
//! replacement or uninstall.

use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
#[cfg(test)]
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MANIFEST_NAME: &str = "apolysis-release-manifest.json";
const RECEIPT_PATH: &str = "usr/local/lib/apolysis/install-receipt-v1.json";
const JOURNAL_PATH: &str = "usr/local/lib/apolysis/.local-operation-transaction-v1.json";
const JOURNAL_STAGING_PREFIX: &str = ".apolysis-journal-";
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 512 * 1024 * 1024;
const RECEIPT_SCHEMA_V1: u32 = 1;
const RELEASE_MANIFEST_SCHEMA_V2: u32 = 2;

static NEXT_OPERATION_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TestHookPoint {
    JournalCreateWriteStarted,
    JournalRewriteWriteStarted,
    PrecommitJournalPrepared,
    CommittedJournalPrepared,
    CommittedJournalPublished,
    ReceiptJournalPublished,
    JournalCreated,
    TargetValidated,
    StagedFileValidated,
    EntryMutated,
    Committed,
}

#[cfg(test)]
type TestHook = (TestHookPoint, Box<dyn FnOnce(&Path) + Send>);

#[cfg(test)]
fn test_hook_slot() -> &'static Mutex<Option<TestHook>> {
    static SLOT: OnceLock<Mutex<Option<TestHook>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn install_test_hook(point: TestHookPoint, hook: impl FnOnce(&Path) + Send + 'static) {
    let mut slot = test_hook_slot().lock().expect("lock local operation hook");
    assert!(
        slot.is_none(),
        "local operation test hook already installed"
    );
    *slot = Some((point, Box::new(hook)));
}

#[cfg(test)]
fn run_test_hook(point: TestHookPoint, path: &Path) {
    let hook = {
        let mut slot = test_hook_slot().lock().expect("lock local operation hook");
        match slot.as_ref() {
            Some((installed, _)) if *installed == point => slot.take().map(|(_, hook)| hook),
            _ => None,
        }
    };
    if let Some(hook) = hook {
        hook(path);
    }
}

#[derive(Clone, Copy)]
struct ArtifactSpec {
    bundle_path: &'static str,
    kind: &'static str,
    target_path: &'static str,
    mode: u32,
    maximum_bytes: u64,
}

const ARTIFACT_SPECS: [ArtifactSpec; 5] = [
    ArtifactSpec {
        bundle_path: "bin/apolysis",
        kind: "cli_binary",
        target_path: "usr/local/bin/apolysis",
        mode: 0o755,
        maximum_bytes: 128 * 1024 * 1024,
    },
    ArtifactSpec {
        bundle_path: "bin/apolysisd",
        kind: "daemon_binary",
        target_path: "usr/local/bin/apolysisd",
        mode: 0o755,
        maximum_bytes: 256 * 1024 * 1024,
    },
    ArtifactSpec {
        bundle_path: "bin/apolysisd-health",
        kind: "health_binary",
        target_path: "usr/local/bin/apolysisd-health",
        mode: 0o755,
        maximum_bytes: 64 * 1024 * 1024,
    },
    ArtifactSpec {
        bundle_path: "ebpf/apolysis_observer.bpf.o",
        kind: "core_bpf_object",
        target_path: "usr/local/lib/apolysis/apolysis_observer.bpf.o",
        mode: 0o644,
        maximum_bytes: 32 * 1024 * 1024,
    },
    ArtifactSpec {
        bundle_path: "systemd/apolysisd.service",
        kind: "systemd_unit",
        target_path: "etc/systemd/system/apolysisd.service",
        mode: 0o644,
        maximum_bytes: 1024 * 1024,
    },
];

/// One bounded local daemon change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LocalDaemonChange {
    /// Install or replace the closed artifact set from an unpacked bundle.
    Install { bundle_root: PathBuf },
    /// Remove only receipt-owned runtime artifacts while retaining Agent Runs.
    UninstallPreserveState,
}

/// Stable operation category returned to callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalDaemonOperationKind {
    Install,
    Uninstall,
}

/// Stable, payload-free failure category.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalDaemonErrorCode {
    InvalidBundle,
    InvalidReceipt,
    UnsafeRoot,
    UnsafeTarget,
    UnmanagedTarget,
    ManagedTargetChanged,
    StalePlan,
    UnsafeTransaction,
    Io,
}

/// A bounded local-operation error.
#[derive(Debug)]
pub struct LocalDaemonError {
    code: LocalDaemonErrorCode,
    context: String,
}

impl LocalDaemonError {
    pub fn code(&self) -> LocalDaemonErrorCode {
        self.code
    }
}

impl fmt::Display for LocalDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}",
            error_code_name(self.code),
            self.context
        )
    }
}

impl std::error::Error for LocalDaemonError {}

/// Opaque plan bound to the staged root and exact filesystem snapshot.
pub struct LocalDaemonPlan {
    change: LocalDaemonChange,
    fingerprint: [u8; 32],
    operation: LocalDaemonOperationKind,
}

impl fmt::Debug for LocalDaemonPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LocalDaemonPlan")
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

/// Read-only state of the fixed local daemon installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDaemonInspection {
    installed: bool,
    release_version: Option<String>,
    target: Option<String>,
    recovered_interrupted_operation: bool,
}

impl LocalDaemonInspection {
    pub fn installed(&self) -> bool {
        self.installed
    }

    pub fn release_version(&self) -> Option<&str> {
        self.release_version.as_deref()
    }

    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// Whether opening this operations handle recovered one durable transaction.
    pub fn recovered_interrupted_operation(&self) -> bool {
        self.recovered_interrupted_operation
    }
}

/// Result of one applied local daemon plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalDaemonOperationReport {
    operation: LocalDaemonOperationKind,
    changed_files: usize,
    preserved_agent_run_state: bool,
}

impl LocalDaemonOperationReport {
    pub fn operation(&self) -> LocalDaemonOperationKind {
        self.operation
    }

    pub fn changed_files(&self) -> usize {
        self.changed_files
    }

    pub fn preserved_agent_run_state(&self) -> bool {
        self.preserved_agent_run_state
    }
}

/// Deep module for deterministic alternate-root qualification and installation.
pub struct LocalDaemonOperations {
    root: PathBuf,
    root_directory: File,
    root_identity: FileIdentity,
    recovered_interrupted_operation: bool,
}

impl LocalDaemonOperations {
    /// Open an existing non-symlink directory as an alternate installation root.
    /// This mode performs filesystem operations only and never invokes systemd.
    pub fn open_staged(root: impl AsRef<Path>) -> Result<Self, LocalDaemonError> {
        let supplied = root.as_ref();
        let OpenedDirectoryPath {
            directory: root_directory,
            lexical_absolute_path: root,
            anchors: root_path_anchors,
        } = open_directory_path_no_symlinks(
            supplied,
            LocalDaemonErrorCode::UnsafeRoot,
            "staged root",
        )?;
        let opened_metadata = root_directory
            .metadata()
            .map_err(|error| io_error("inspect opened staged root", error))?;
        if !opened_metadata.file_type().is_dir() {
            return Err(error(
                LocalDaemonErrorCode::UnsafeRoot,
                "staged root is not a plain directory",
            ));
        }
        lock_root_directory(&root_directory)?;
        let root_identity = FileIdentity::from_metadata(&opened_metadata);
        verify_directory_path_anchors(
            &root_path_anchors,
            LocalDaemonErrorCode::UnsafeRoot,
            "staged root",
        )?;
        let mut operations = Self {
            root,
            root_directory,
            root_identity,
            recovered_interrupted_operation: false,
        };
        operations.recovered_interrupted_operation =
            operations.recover_interrupted_transaction()?;
        operations.reject_orphan_transaction_paths()?;
        Ok(operations)
    }

    /// Inspect the receipt and every receipt-owned artifact without mutation.
    pub fn inspect(&self) -> Result<LocalDaemonInspection, LocalDaemonError> {
        self.verify_root_identity()?;
        let loaded = self.load_receipt()?;
        match loaded {
            Some(loaded) => {
                self.validate_installed_artifacts(Some(&loaded.receipt), None)?;
                Ok(LocalDaemonInspection {
                    installed: true,
                    release_version: Some(loaded.receipt.release_version),
                    target: Some(loaded.receipt.target),
                    recovered_interrupted_operation: self.recovered_interrupted_operation,
                })
            }
            None => {
                self.validate_installed_artifacts(None, None)?;
                Ok(LocalDaemonInspection {
                    installed: false,
                    release_version: None,
                    target: None,
                    recovered_interrupted_operation: self.recovered_interrupted_operation,
                })
            }
        }
    }

    /// Produce an opaque plan after validating the complete mutation set.
    pub fn plan(&self, change: LocalDaemonChange) -> Result<LocalDaemonPlan, LocalDaemonError> {
        let prepared = self.prepare(change.clone())?;
        Ok(LocalDaemonPlan {
            change,
            fingerprint: prepared.fingerprint,
            operation: prepared.operation(),
        })
    }

    /// Revalidate and durably apply a plan with bounded crash recovery.
    pub fn apply(
        &mut self,
        plan: LocalDaemonPlan,
    ) -> Result<LocalDaemonOperationReport, LocalDaemonError> {
        let prepared = self.prepare(plan.change)?;
        if prepared.fingerprint != plan.fingerprint {
            return Err(error(
                LocalDaemonErrorCode::StalePlan,
                "filesystem state changed after planning",
            ));
        }
        match prepared.mutation {
            PreparedMutation::Install { writes } => {
                let changed_files = writes.len();
                self.apply_writes(writes)?;
                Ok(LocalDaemonOperationReport {
                    operation: LocalDaemonOperationKind::Install,
                    changed_files,
                    preserved_agent_run_state: true,
                })
            }
            PreparedMutation::Uninstall { removes } => {
                let changed_files = removes.len();
                self.apply_removes(removes)?;
                Ok(LocalDaemonOperationReport {
                    operation: LocalDaemonOperationKind::Uninstall,
                    changed_files,
                    preserved_agent_run_state: true,
                })
            }
        }
    }

    fn prepare(&self, change: LocalDaemonChange) -> Result<PreparedPlan, LocalDaemonError> {
        self.verify_root_identity()?;
        match change {
            LocalDaemonChange::Install { bundle_root } => self.prepare_install(&bundle_root),
            LocalDaemonChange::UninstallPreserveState => self.prepare_uninstall(),
        }
    }

    fn prepare_install(&self, bundle_root: &Path) -> Result<PreparedPlan, LocalDaemonError> {
        let bundle = load_bundle(bundle_root)?;
        let loaded_receipt = self.load_receipt()?;
        let mut snapshot = Snapshot::new("install");
        snapshot.identity("root", &self.root_identity);
        snapshot.identity("bundle-root", &bundle.root_identity);
        snapshot.bytes("manifest", &bundle.manifest_bytes);

        if let Some(loaded) = loaded_receipt.as_ref() {
            validate_receipt_shape(&loaded.receipt)?;
            snapshot.file("receipt", &loaded.state);
        } else {
            snapshot.missing("receipt");
        }

        let target_states = self.validate_installed_artifacts(
            loaded_receipt.as_ref().map(|loaded| &loaded.receipt),
            Some(&mut snapshot),
        )?;
        let mut writes = Vec::new();
        let mut receipt_artifacts = Vec::with_capacity(ARTIFACT_SPECS.len());
        for (artifact, existing) in bundle.artifacts.into_iter().zip(target_states) {
            snapshot.file(artifact.spec.kind, &artifact.source_state);
            let changed = existing.as_ref().is_none_or(|state| {
                state.sha256 != artifact.manifest.sha256 || state.mode != artifact.spec.mode
            });
            let identity = existing
                .as_ref()
                .filter(|_| !changed)
                .map(|state| state.identity)
                .unwrap_or(FileIdentity {
                    device: 0,
                    inode: 0,
                });
            receipt_artifacts.push(ReceiptArtifact {
                kind: artifact.spec.kind.to_string(),
                target_path: artifact.spec.target_path.to_string(),
                sha256: artifact.manifest.sha256.clone(),
                size_bytes: artifact.manifest.size_bytes,
                mode: artifact.manifest.mode.clone(),
                uid: effective_uid(),
                gid: effective_gid(),
                device: identity.device,
                inode: identity.inode,
            });
            if changed {
                writes.push(PlannedWrite {
                    logical_name: artifact.spec.kind,
                    target_path: artifact.spec.target_path,
                    bytes: artifact.source_state.bytes,
                    mode: artifact.spec.mode,
                    existing,
                    receipt_template: None,
                });
            }
        }

        let receipt = InstallReceipt {
            schema_version: RECEIPT_SCHEMA_V1,
            release_version: bundle.manifest.release_version,
            target: bundle.manifest.target,
            installer_uid: effective_uid(),
            installer_gid: effective_gid(),
            artifacts: receipt_artifacts,
        };
        let placeholder_receipt_bytes = receipt_bytes(&receipt)?;
        let receipt_existing = loaded_receipt.as_ref().map(|loaded| loaded.state.clone());
        let receipt_changed = !writes.is_empty()
            || receipt_existing
                .as_ref()
                .is_none_or(|state| state.sha256 != sha256_hex(&placeholder_receipt_bytes));
        if receipt_changed {
            writes.push(PlannedWrite {
                logical_name: "install_receipt",
                target_path: RECEIPT_PATH,
                bytes: placeholder_receipt_bytes,
                mode: 0o644,
                existing: receipt_existing,
                receipt_template: Some(receipt),
            });
        }

        Ok(PreparedPlan {
            fingerprint: snapshot.finish(),
            mutation: PreparedMutation::Install { writes },
        })
    }

    fn prepare_uninstall(&self) -> Result<PreparedPlan, LocalDaemonError> {
        let loaded_receipt = self.load_receipt()?;
        let mut snapshot = Snapshot::new("uninstall");
        snapshot.identity("root", &self.root_identity);
        let target_states = self.validate_installed_artifacts(
            loaded_receipt.as_ref().map(|loaded| &loaded.receipt),
            Some(&mut snapshot),
        )?;
        let mut removes = Vec::new();
        if let Some(loaded) = loaded_receipt {
            for (spec, state) in ARTIFACT_SPECS.iter().zip(target_states) {
                let state = state.ok_or_else(|| {
                    error(
                        LocalDaemonErrorCode::ManagedTargetChanged,
                        format!("managed artifact {} is missing", spec.kind),
                    )
                })?;
                removes.push(PlannedRemove {
                    logical_name: spec.kind,
                    target_path: spec.target_path,
                    existing: state,
                });
            }
            snapshot.file("receipt", &loaded.state);
            removes.push(PlannedRemove {
                logical_name: "install_receipt",
                target_path: RECEIPT_PATH,
                existing: loaded.state,
            });
        } else {
            snapshot.missing("receipt");
        }
        Ok(PreparedPlan {
            fingerprint: snapshot.finish(),
            mutation: PreparedMutation::Uninstall { removes },
        })
    }

    fn validate_installed_artifacts(
        &self,
        receipt: Option<&InstallReceipt>,
        mut snapshot: Option<&mut Snapshot>,
    ) -> Result<Vec<Option<FileState>>, LocalDaemonError> {
        if let Some(receipt) = receipt {
            validate_receipt_shape(receipt)?;
        }
        let mut states = Vec::with_capacity(ARTIFACT_SPECS.len());
        for spec in ARTIFACT_SPECS {
            let expected = receipt.and_then(|receipt| {
                receipt
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.target_path == spec.target_path)
            });
            let state = self.inspect_target(spec, expected)?;
            if let Some(snapshot) = snapshot.as_deref_mut() {
                match state.as_ref() {
                    Some(state) => snapshot.file(spec.kind, state),
                    None => snapshot.missing(spec.kind),
                }
            }
            states.push(state);
        }
        Ok(states)
    }

    fn inspect_target(
        &self,
        spec: ArtifactSpec,
        expected: Option<&ReceiptArtifact>,
    ) -> Result<Option<FileState>, LocalDaemonError> {
        let Some(parent) = self.open_parent(spec.target_path, false)? else {
            if expected.is_some() {
                return Err(error(
                    LocalDaemonErrorCode::ManagedTargetChanged,
                    format!("managed artifact {} is missing", spec.kind),
                ));
            }
            return Ok(None);
        };
        let target_name = target_file_name(spec.target_path)?;
        let state = read_optional_regular_file_at(
            &parent.directory,
            target_name,
            spec.kind,
            spec.maximum_bytes,
            LocalDaemonErrorCode::UnsafeTarget,
        )?;
        let Some(mut state) = state else {
            if expected.is_some() {
                return Err(error(
                    LocalDaemonErrorCode::ManagedTargetChanged,
                    format!("managed artifact {} is missing", spec.kind),
                ));
            }
            return Ok(None);
        };
        let Some(expected) = expected else {
            return Err(error(
                LocalDaemonErrorCode::UnmanagedTarget,
                format!("target {} has no installation receipt", spec.kind),
            ));
        };
        if state.sha256 != expected.sha256
            || state.len != expected.size_bytes
            || state.mode != parse_mode(&expected.mode).unwrap_or(u32::MAX)
            || state.uid != expected.uid
            || state.gid != expected.gid
            || state.identity.device != expected.device
            || state.identity.inode != expected.inode
            || state.uid != effective_uid()
            || state.gid != effective_gid()
        {
            return Err(error(
                LocalDaemonErrorCode::ManagedTargetChanged,
                format!(
                    "managed artifact {} no longer matches its receipt",
                    spec.kind
                ),
            ));
        }
        state.bytes.clear();
        Ok(Some(state))
    }

    fn load_receipt(&self) -> Result<Option<LoadedReceipt>, LocalDaemonError> {
        let Some(parent) = self.open_parent(RECEIPT_PATH, false)? else {
            return Ok(None);
        };
        let state = read_optional_regular_file_at(
            &parent.directory,
            target_file_name(RECEIPT_PATH)?,
            "install_receipt",
            MAX_RECEIPT_BYTES,
            LocalDaemonErrorCode::InvalidReceipt,
        )?;
        let Some(mut state) = state else {
            return Ok(None);
        };
        if state.mode != 0o644 {
            return Err(error(
                LocalDaemonErrorCode::InvalidReceipt,
                "installation receipt permissions are unsafe",
            ));
        }
        if state.uid != effective_uid() || state.gid != effective_gid() {
            return Err(error(
                LocalDaemonErrorCode::InvalidReceipt,
                "installation receipt owner is unsafe",
            ));
        }
        let receipt: InstallReceipt = serde_json::from_slice(&state.bytes).map_err(|_| {
            error(
                LocalDaemonErrorCode::InvalidReceipt,
                "installation receipt is not valid schema v1 JSON",
            )
        })?;
        validate_receipt_shape(&receipt)?;
        state.bytes.clear();
        Ok(Some(LoadedReceipt { receipt, state }))
    }

    fn apply_writes(&self, writes: Vec<PlannedWrite>) -> Result<(), LocalDaemonError> {
        if writes.is_empty() {
            return Ok(());
        }
        self.execute_transaction(TransactionInput::Install(writes))
    }

    fn apply_removes(&self, removes: Vec<PlannedRemove>) -> Result<(), LocalDaemonError> {
        if removes.is_empty() {
            return Ok(());
        }
        self.execute_transaction(TransactionInput::Uninstall(removes))
    }

    fn stage_anonymous_install_entries(
        &self,
        runtime: &mut [TransactionRuntimeEntry],
        journal: &mut TransactionJournal,
    ) -> Result<(), LocalDaemonError> {
        if runtime.len() != journal.entries.len() {
            return Err(unsafe_transaction("install transaction shape changed"));
        }
        let receipt_index = derived_receipt_index(runtime)?;
        for (index, entry) in runtime.iter_mut().enumerate().take(receipt_index) {
            self.verify_parent_live(&entry.parent)?;
            let bytes = entry
                .bytes
                .take()
                .ok_or_else(|| unsafe_transaction("install artifact bytes are missing"))?;
            let mode = entry
                .mode
                .ok_or_else(|| unsafe_transaction("install artifact mode is missing"))?;
            let (file, state) = write_anonymous_staged_file(
                &entry.parent.directory,
                bytes,
                mode,
                entry.logical_name,
            )?;
            journal.entries[index].new = Some(JournalFileProof::from_state(&state));
            entry.new = Some(state);
            entry.staged_file = Some(file);
        }

        let receipt = bind_receipt_identities(
            runtime[receipt_index]
                .receipt_template
                .clone()
                .ok_or_else(|| unsafe_transaction("derived receipt template is missing"))?,
            runtime,
        )?;
        let bytes = receipt_bytes(&receipt)?;
        let entry = &mut runtime[receipt_index];
        self.verify_parent_live(&entry.parent)?;
        let mode = entry
            .mode
            .ok_or_else(|| unsafe_transaction("derived receipt mode is missing"))?;
        let (file, state) = write_anonymous_staged_file(
            &entry.parent.directory,
            bytes,
            mode,
            "derived installation receipt",
        )?;
        entry.bytes = None;
        journal.entries[receipt_index].new = Some(JournalFileProof::from_state(&state));
        entry.new = Some(state);
        entry.staged_file = Some(file);
        validate_transaction_journal(journal)
    }

    fn link_anonymous_install_entries(
        &self,
        runtime: &mut [TransactionRuntimeEntry],
        journal: &TransactionJournal,
    ) -> Result<(), LocalDaemonError> {
        if runtime.len() != journal.entries.len() {
            return Err(unsafe_transaction("install transaction shape changed"));
        }
        for (index, entry) in runtime.iter_mut().enumerate() {
            self.verify_parent_live(&entry.parent)?;
            let file = entry
                .staged_file
                .as_ref()
                .ok_or_else(|| unsafe_transaction("anonymous staged file is missing"))?;
            link_anonymous_file_at(file, &entry.parent.directory, &entry.temporary_name).map_err(
                |source| {
                    error(
                        LocalDaemonErrorCode::UnsafeTransaction,
                        format!(
                            "failed to link anonymous staged {}: {}",
                            entry.logical_name,
                            source.kind()
                        ),
                    )
                },
            )?;
            let mut linked = read_required_regular_file_at(
                &entry.parent.directory,
                &entry.temporary_name,
                entry.logical_name,
                managed_maximum_bytes(entry.target_path)?,
                LocalDaemonErrorCode::UnsafeTransaction,
            )?;
            let proof = journal.entries[index]
                .new
                .as_ref()
                .ok_or_else(|| unsafe_transaction("anonymous staged proof is missing"))?;
            if !matches_proof(&linked, proof) {
                return Err(unsafe_transaction(
                    "linked anonymous staged identity changed",
                ));
            }
            linked.bytes.clear();
            entry.new = Some(linked);
        }
        Ok(())
    }

    fn execute_transaction(&self, input: TransactionInput) -> Result<(), LocalDaemonError> {
        self.verify_root_identity()?;
        let operation_id = operation_id();
        let (operation, mut runtime, mut journal) =
            self.prepare_transaction(input, &operation_id)?;
        if operation == TransactionOperation::Install {
            self.stage_anonymous_install_entries(&mut runtime, &mut journal)?;
        }
        let mut journal_handle = self.create_journal(&journal)?;
        #[cfg(test)]
        run_test_hook(TestHookPoint::JournalCreated, &self.root);

        let precommit_result = (|| {
            if operation == TransactionOperation::Install {
                #[cfg(test)]
                run_test_hook(TestHookPoint::ReceiptJournalPublished, &self.root);
                self.link_anonymous_install_entries(&mut runtime, &journal)?;
                self.sync_runtime_parents(&runtime)?;
            }

            for (index, entry) in runtime.iter().enumerate() {
                self.verify_parent_live(&entry.parent)?;
                ensure_target_snapshot_at(
                    &entry.parent.directory,
                    &entry.target_name,
                    entry.logical_name,
                    entry.old.as_ref(),
                    managed_maximum_bytes(entry.target_path)?,
                )?;
                #[cfg(test)]
                run_test_hook(
                    TestHookPoint::TargetValidated,
                    &self.root.join(entry.target_path),
                );
                match operation {
                    TransactionOperation::Install => self.publish_install_entry(entry)?,
                    TransactionOperation::Uninstall => self.retire_uninstall_entry(entry)?,
                }
                #[cfg(test)]
                run_test_hook(
                    TestHookPoint::EntryMutated,
                    &self.root.join(entry.target_path),
                );
                if index + 1 == runtime.len() {
                    self.sync_runtime_parents(&runtime)?;
                }
            }
            Ok(())
        })();

        if let Err(failure) = precommit_result {
            let rollback = self.recover_precommit_runtime(&journal, &runtime);
            if rollback.is_ok() {
                let _ = self.remove_journal(&journal_handle);
                return Err(failure);
            }
            return Err(error(
                LocalDaemonErrorCode::UnsafeTransaction,
                "transaction failed and exact rollback could not be completed",
            ));
        }

        journal.phase = TransactionPhase::Committed;
        if let Err(failure) = self.rewrite_journal(&mut journal_handle, &journal) {
            match failure {
                JournalRewriteFailure::AfterPublish(failure) => return Err(failure),
                JournalRewriteFailure::BeforePublish(failure) => {
                    if self
                        .recover_precommit_runtime(
                            &TransactionJournal {
                                phase: TransactionPhase::Precommit,
                                ..journal.clone()
                            },
                            &runtime,
                        )
                        .is_ok()
                    {
                        let _ = self.remove_journal(&journal_handle);
                        return Err(failure);
                    }
                    return Err(error(
                        LocalDaemonErrorCode::UnsafeTransaction,
                        "transaction commit failed and exact rollback could not be completed",
                    ));
                }
            }
        }

        #[cfg(test)]
        run_test_hook(TestHookPoint::Committed, &self.root);

        self.recover_committed(&journal)?;
        self.remove_journal(&journal_handle)
    }

    fn prepare_transaction(
        &self,
        input: TransactionInput,
        operation_id: &str,
    ) -> Result<
        (
            TransactionOperation,
            Vec<TransactionRuntimeEntry>,
            TransactionJournal,
        ),
        LocalDaemonError,
    > {
        let (operation, items): (TransactionOperation, Vec<TransactionSource>) = match input {
            TransactionInput::Install(writes) => (
                TransactionOperation::Install,
                writes.into_iter().map(TransactionSource::Install).collect(),
            ),
            TransactionInput::Uninstall(removes) => (
                TransactionOperation::Uninstall,
                removes
                    .into_iter()
                    .map(TransactionSource::Uninstall)
                    .collect(),
            ),
        };
        let mut runtime = Vec::with_capacity(items.len());
        let mut entries = Vec::with_capacity(items.len());
        for item in items {
            let (logical_name, target_path, old, bytes, mode, receipt_template) = match item {
                TransactionSource::Install(write) => (
                    write.logical_name,
                    write.target_path,
                    write.existing,
                    Some(write.bytes),
                    Some(write.mode),
                    write.receipt_template,
                ),
                TransactionSource::Uninstall(remove) => (
                    remove.logical_name,
                    remove.target_path,
                    Some(remove.existing),
                    None,
                    None,
                    None,
                ),
            };
            let parent = self
                .open_parent(target_path, operation == TransactionOperation::Install)?
                .ok_or_else(|| {
                    error(
                        LocalDaemonErrorCode::StalePlan,
                        format!("parent for {logical_name} disappeared after planning"),
                    )
                })?;
            let target_name = target_file_name(target_path)?.to_os_string();
            ensure_target_snapshot_at(
                &parent.directory,
                &target_name,
                logical_name,
                old.as_ref(),
                managed_maximum_bytes(target_path)?,
            )?;
            let phase = match operation {
                TransactionOperation::Install => "install",
                TransactionOperation::Uninstall => "uninstall",
            };
            let temporary_name = transaction_sibling_name(&target_name, phase, operation_id)?;
            ensure_missing_at(&parent.directory, &temporary_name)?;
            entries.push(TransactionJournalEntry {
                logical_name: logical_name.to_string(),
                target_path: target_path.to_string(),
                temporary_name: os_string_to_string(&temporary_name)?,
                old: old.as_ref().map(JournalFileProof::from_state),
                new: bytes
                    .as_ref()
                    .zip(mode)
                    .map(|(bytes, mode)| JournalFileProof {
                        identity: None,
                        len: bytes.len() as u64,
                        mode,
                        uid: effective_uid(),
                        gid: effective_gid(),
                        sha256: sha256_hex(bytes),
                    }),
            });
            runtime.push(TransactionRuntimeEntry {
                logical_name,
                target_path,
                target_name,
                temporary_name,
                parent,
                old,
                new: None,
                bytes,
                mode,
                receipt_template,
                staged_file: None,
            });
        }
        let journal = TransactionJournal {
            schema_version: 1,
            phase: TransactionPhase::Precommit,
            operation,
            operation_id: operation_id.to_string(),
            root_identity: self.root_identity,
            installer_uid: effective_uid(),
            installer_gid: effective_gid(),
            entries,
        };
        validate_transaction_draft(&journal)?;
        Ok((operation, runtime, journal))
    }

    fn publish_install_entry(
        &self,
        entry: &TransactionRuntimeEntry,
    ) -> Result<(), LocalDaemonError> {
        let new = entry.new.as_ref().ok_or_else(|| {
            error(
                LocalDaemonErrorCode::UnsafeTransaction,
                "install transaction has no staged identity",
            )
        })?;
        ensure_target_snapshot_at(
            &entry.parent.directory,
            &entry.temporary_name,
            entry.logical_name,
            Some(new),
            managed_maximum_bytes(entry.target_path)?,
        )?;
        #[cfg(test)]
        run_test_hook(
            TestHookPoint::StagedFileValidated,
            &self.root.join(entry.target_path),
        );
        if let Some(old) = entry.old.as_ref() {
            rename_exchange_at(
                &entry.parent.directory,
                &entry.temporary_name,
                &entry.target_name,
            )?;
            let target = read_optional_regular_file_at(
                &entry.parent.directory,
                &entry.target_name,
                entry.logical_name,
                managed_maximum_bytes(entry.target_path)?,
                LocalDaemonErrorCode::UnsafeTransaction,
            );
            let retired = read_optional_regular_file_at(
                &entry.parent.directory,
                &entry.temporary_name,
                entry.logical_name,
                managed_maximum_bytes(entry.target_path)?,
                LocalDaemonErrorCode::UnsafeTransaction,
            );
            let (target, retired) = match (target, retired) {
                (Ok(target), Ok(retired)) => (target, retired),
                (Err(failure), _) | (_, Err(failure)) => {
                    rename_exchange_at(
                        &entry.parent.directory,
                        &entry.temporary_name,
                        &entry.target_name,
                    )?;
                    return Err(failure);
                }
            };
            if target
                .as_ref()
                .is_none_or(|state| !matches_proof(state, &JournalFileProof::from_state(new)))
                || retired
                    .as_ref()
                    .is_none_or(|state| !matches_proof(state, &JournalFileProof::from_state(old)))
            {
                restore_exchange_if_unchanged(entry, target.as_ref(), retired.as_ref())?;
                return Err(error(
                    LocalDaemonErrorCode::StalePlan,
                    format!("target {} raced during replacement", entry.logical_name),
                ));
            }
        } else {
            rename_noreplace_at(
                &entry.parent.directory,
                &entry.temporary_name,
                &entry.target_name,
            )
            .map_err(|source| {
                error(
                    LocalDaemonErrorCode::StalePlan,
                    format!(
                        "target {} appeared during publish: {}",
                        entry.logical_name,
                        source.kind()
                    ),
                )
            })?;
            let target = read_required_regular_file_at(
                &entry.parent.directory,
                &entry.target_name,
                entry.logical_name,
                managed_maximum_bytes(entry.target_path)?,
                LocalDaemonErrorCode::UnsafeTransaction,
            );
            let target = match target {
                Ok(target) => target,
                Err(failure) => {
                    restore_noreplace_at(
                        &entry.parent.directory,
                        &entry.target_name,
                        &entry.temporary_name,
                    )?;
                    return Err(failure);
                }
            };
            if !matches_proof(&target, &JournalFileProof::from_state(new)) {
                restore_noreplace_at(
                    &entry.parent.directory,
                    &entry.target_name,
                    &entry.temporary_name,
                )?;
                return Err(error(
                    LocalDaemonErrorCode::UnsafeTransaction,
                    "published artifact identity changed",
                ));
            }
        }
        entry
            .parent
            .directory
            .sync_all()
            .map_err(|source| io_error("sync published artifact directory", source))
    }

    fn retire_uninstall_entry(
        &self,
        entry: &TransactionRuntimeEntry,
    ) -> Result<(), LocalDaemonError> {
        let old = entry.old.as_ref().ok_or_else(|| {
            error(
                LocalDaemonErrorCode::UnsafeTransaction,
                "uninstall transaction has no managed identity",
            )
        })?;
        rename_noreplace_at(
            &entry.parent.directory,
            &entry.target_name,
            &entry.temporary_name,
        )
        .map_err(|source| {
            error(
                LocalDaemonErrorCode::StalePlan,
                format!(
                    "target {} raced during retirement: {}",
                    entry.logical_name,
                    source.kind()
                ),
            )
        })?;
        let retired = match read_required_regular_file_at(
            &entry.parent.directory,
            &entry.temporary_name,
            entry.logical_name,
            managed_maximum_bytes(entry.target_path)?,
            LocalDaemonErrorCode::UnsafeTransaction,
        ) {
            Ok(retired) => retired,
            Err(failure) => {
                restore_noreplace_at(
                    &entry.parent.directory,
                    &entry.temporary_name,
                    &entry.target_name,
                )?;
                return Err(failure);
            }
        };
        if !matches_proof(&retired, &JournalFileProof::from_state(old)) {
            restore_noreplace_at(
                &entry.parent.directory,
                &entry.temporary_name,
                &entry.target_name,
            )?;
            return Err(error(
                LocalDaemonErrorCode::StalePlan,
                format!("target {} raced during retirement", entry.logical_name),
            ));
        }
        entry
            .parent
            .directory
            .sync_all()
            .map_err(|source| io_error("sync retired artifact directory", source))
    }

    fn sync_runtime_parents(
        &self,
        entries: &[TransactionRuntimeEntry],
    ) -> Result<(), LocalDaemonError> {
        let mut synced = Vec::new();
        for entry in entries {
            self.verify_parent_live(&entry.parent)?;
            if synced.contains(&entry.parent.identity) {
                continue;
            }
            entry
                .parent
                .directory
                .sync_all()
                .map_err(|source| io_error("sync transaction directory", source))?;
            synced.push(entry.parent.identity);
        }
        Ok(())
    }

    fn open_parent(
        &self,
        target_path: &str,
        create: bool,
    ) -> Result<Option<AnchoredParent>, LocalDaemonError> {
        open_parent_at_root(&self.root_directory, Path::new(target_path), create)
    }

    fn verify_parent_live(&self, parent: &AnchoredParent) -> Result<(), LocalDaemonError> {
        self.verify_root_identity()?;
        let probe_path = parent.relative_path.join("probe");
        let reopened =
            open_parent_at_root(&self.root_directory, &probe_path, false)?.ok_or_else(|| {
                error(
                    LocalDaemonErrorCode::StalePlan,
                    "managed target parent disappeared",
                )
            })?;
        if reopened.identity != parent.identity {
            return Err(error(
                LocalDaemonErrorCode::StalePlan,
                "managed target parent identity changed",
            ));
        }
        Ok(())
    }

    fn create_journal(
        &self,
        journal: &TransactionJournal,
    ) -> Result<JournalHandle, LocalDaemonError> {
        let parent = self.open_parent(JOURNAL_PATH, true)?.ok_or_else(|| {
            error(
                LocalDaemonErrorCode::UnsafeTransaction,
                "transaction journal parent is missing",
            )
        })?;
        self.verify_parent_live(&parent)?;
        let name = target_file_name(JOURNAL_PATH)?.to_os_string();
        ensure_missing_at(&parent.directory, &name)?;
        if !journal_staging_names_at(&parent.directory)?.is_empty() {
            return Err(unsafe_transaction(
                "transaction journal directory contains an unknown staging file",
            ));
        }
        let bytes = transaction_journal_bytes(journal)?;
        let mut file =
            create_anonymous_private_file_at(&parent.directory, 0o600).map_err(|source| {
                error(
                    LocalDaemonErrorCode::UnsafeTransaction,
                    format!(
                        "failed to create anonymous transaction journal: {}",
                        source.kind()
                    ),
                )
            })?;
        #[cfg(test)]
        {
            let split = bytes.len() / 2;
            file.write_all(&bytes[..split])
                .map_err(|source| io_error("write transaction journal", source))?;
            run_test_hook(
                TestHookPoint::JournalCreateWriteStarted,
                &self.root.join(JOURNAL_PATH),
            );
            file.write_all(&bytes[split..])
                .map_err(|source| io_error("write transaction journal", source))?;
        }
        #[cfg(not(test))]
        file.write_all(&bytes)
            .map_err(|source| io_error("write transaction journal", source))?;
        file.sync_all()
            .map_err(|source| io_error("sync transaction journal", source))?;
        let staged_metadata = validate_anonymous_journal_file(&file, &bytes)?;
        let staged_identity = FileIdentity::from_metadata(&staged_metadata);
        link_anonymous_file_at(&file, &parent.directory, &name).map_err(|source| {
            error(
                LocalDaemonErrorCode::UnsafeTransaction,
                format!("failed to publish transaction journal: {}", source.kind()),
            )
        })?;
        parent
            .directory
            .sync_all()
            .map_err(|source| io_error("sync transaction journal directory", source))?;
        let state = read_journal_state_at(&parent.directory, &name)?;
        if state.identity != staged_identity || state.bytes != bytes {
            return Err(unsafe_transaction(
                "published transaction journal identity changed",
            ));
        }
        ensure_open_file_at_identity(&parent.directory, &name, &file, state.identity, 0o600)?;
        Ok(JournalHandle {
            parent,
            name,
            file,
            state,
            operation_id: journal.operation_id.clone(),
        })
    }

    fn rewrite_journal(
        &self,
        handle: &mut JournalHandle,
        journal: &TransactionJournal,
    ) -> Result<(), JournalRewriteFailure> {
        self.verify_parent_live(&handle.parent)
            .map_err(JournalRewriteFailure::BeforePublish)?;
        ensure_journal_state_at(&handle.parent.directory, &handle.name, &handle.state)
            .map_err(JournalRewriteFailure::BeforePublish)?;
        ensure_open_file_at_identity(
            &handle.parent.directory,
            &handle.name,
            &handle.file,
            handle.state.identity,
            0o600,
        )
        .map_err(JournalRewriteFailure::BeforePublish)?;
        if journal.operation_id != handle.operation_id {
            return Err(JournalRewriteFailure::BeforePublish(unsafe_transaction(
                "transaction journal operation changed",
            )));
        }
        let bytes =
            transaction_journal_bytes(journal).map_err(JournalRewriteFailure::BeforePublish)?;
        let staging_name = journal_staging_name(&journal.operation_id)
            .map_err(JournalRewriteFailure::BeforePublish)?;
        ensure_missing_at(&handle.parent.directory, &staging_name).map_err(|_| {
            JournalRewriteFailure::BeforePublish(unsafe_transaction(
                "replacement journal staging name is occupied",
            ))
        })?;
        let mut staged_file = create_anonymous_private_file_at(&handle.parent.directory, 0o600)
            .map_err(|source| {
                JournalRewriteFailure::BeforePublish(error(
                    LocalDaemonErrorCode::UnsafeTransaction,
                    format!(
                        "failed to create anonymous replacement journal: {}",
                        source.kind()
                    ),
                ))
            })?;
        #[cfg(test)]
        {
            let split = bytes.len() / 2;
            staged_file.write_all(&bytes[..split]).map_err(|source| {
                JournalRewriteFailure::BeforePublish(io_error(
                    "write replacement transaction journal",
                    source,
                ))
            })?;
            run_test_hook(
                TestHookPoint::JournalRewriteWriteStarted,
                &self.root.join(JOURNAL_PATH),
            );
            staged_file.write_all(&bytes[split..]).map_err(|source| {
                JournalRewriteFailure::BeforePublish(io_error(
                    "write replacement transaction journal",
                    source,
                ))
            })?;
        }
        #[cfg(not(test))]
        staged_file.write_all(&bytes).map_err(|source| {
            JournalRewriteFailure::BeforePublish(io_error(
                "write replacement transaction journal",
                source,
            ))
        })?;
        staged_file.sync_all().map_err(|source| {
            JournalRewriteFailure::BeforePublish(io_error(
                "sync replacement transaction journal",
                source,
            ))
        })?;
        let staged_metadata = validate_anonymous_journal_file(&staged_file, &bytes)
            .map_err(JournalRewriteFailure::BeforePublish)?;
        let staged_identity = FileIdentity::from_metadata(&staged_metadata);
        link_anonymous_file_at(&staged_file, &handle.parent.directory, &staging_name).map_err(
            |source| {
                JournalRewriteFailure::BeforePublish(error(
                    LocalDaemonErrorCode::UnsafeTransaction,
                    format!(
                        "failed to publish replacement journal staging file: {}",
                        source.kind()
                    ),
                ))
            },
        )?;
        handle.parent.directory.sync_all().map_err(|source| {
            JournalRewriteFailure::AfterPublish(io_error(
                "sync replacement journal staging directory",
                source,
            ))
        })?;
        let staged_state = read_journal_state_at(&handle.parent.directory, &staging_name)
            .map_err(JournalRewriteFailure::AfterPublish)?;
        if staged_state.identity != staged_identity || staged_state.bytes != bytes {
            return Err(JournalRewriteFailure::AfterPublish(unsafe_transaction(
                "replacement transaction journal identity changed",
            )));
        }
        ensure_open_file_at_identity(
            &handle.parent.directory,
            &staging_name,
            &staged_file,
            staged_identity,
            0o600,
        )
        .map_err(JournalRewriteFailure::AfterPublish)?;
        #[cfg(test)]
        {
            let hook = match journal.phase {
                TransactionPhase::Precommit => TestHookPoint::PrecommitJournalPrepared,
                TransactionPhase::Committed => TestHookPoint::CommittedJournalPrepared,
            };
            run_test_hook(hook, &self.root.join(JOURNAL_PATH));
        }
        if let Err(failure) =
            ensure_journal_state_at(&handle.parent.directory, &handle.name, &handle.state)
        {
            return Err(JournalRewriteFailure::AfterPublish(failure));
        }
        if let Err(failure) =
            rename_exchange_at(&handle.parent.directory, &staging_name, &handle.name)
        {
            return Err(JournalRewriteFailure::AfterPublish(failure));
        }
        handle.parent.directory.sync_all().map_err(|source| {
            JournalRewriteFailure::AfterPublish(io_error(
                "sync published transaction journal directory",
                source,
            ))
        })?;
        let published_state = read_journal_state_at(&handle.parent.directory, &handle.name)
            .map_err(JournalRewriteFailure::AfterPublish)?;
        if published_state.identity != staged_state.identity || published_state.bytes != bytes {
            return Err(JournalRewriteFailure::AfterPublish(unsafe_transaction(
                "published replacement journal identity changed",
            )));
        }
        ensure_open_file_at_identity(
            &handle.parent.directory,
            &handle.name,
            &staged_file,
            published_state.identity,
            0o600,
        )
        .map_err(JournalRewriteFailure::AfterPublish)?;
        let retired_state = read_journal_state_at(&handle.parent.directory, &staging_name)
            .map_err(JournalRewriteFailure::AfterPublish)?;
        if !matches_proof(&retired_state, &JournalFileProof::from_state(&handle.state)) {
            return Err(JournalRewriteFailure::AfterPublish(unsafe_transaction(
                "retired transaction journal changed after exchange",
            )));
        }
        handle.file = staged_file;
        handle.state = published_state;
        #[cfg(test)]
        if journal.phase == TransactionPhase::Committed {
            run_test_hook(
                TestHookPoint::CommittedJournalPublished,
                &self.root.join(JOURNAL_PATH),
            );
        }
        unlink_exact_journal_state_at(&handle.parent.directory, &staging_name, &retired_state)
            .map_err(JournalRewriteFailure::AfterPublish)?;
        handle.parent.directory.sync_all().map_err(|source| {
            JournalRewriteFailure::AfterPublish(io_error(
                "sync retired transaction journal directory",
                source,
            ))
        })
    }

    fn remove_journal(&self, handle: &JournalHandle) -> Result<(), LocalDaemonError> {
        let parent_metadata = handle
            .parent
            .directory
            .metadata()
            .map_err(|source| io_error("inspect transaction journal parent", source))?;
        if !parent_metadata.file_type().is_dir()
            || FileIdentity::from_metadata(&parent_metadata) != handle.parent.identity
        {
            return Err(unsafe_transaction(
                "transaction journal parent identity changed",
            ));
        }
        ensure_open_file_at_identity(
            &handle.parent.directory,
            &handle.name,
            &handle.file,
            handle.state.identity,
            0o600,
        )?;
        ensure_journal_state_at(&handle.parent.directory, &handle.name, &handle.state)?;
        let staging_name = journal_staging_name(&handle.operation_id)?;
        if entry_exists_at(&handle.parent.directory, &staging_name)? {
            return Err(unsafe_transaction(
                "transaction journal staging file remains present",
            ));
        }
        unlink_at(&handle.parent.directory, &handle.name)
            .map_err(|source| io_error("remove transaction journal", source))?;
        handle
            .parent
            .directory
            .sync_all()
            .map_err(|source| io_error("sync removed transaction journal", source))
    }

    fn recover_interrupted_transaction(&mut self) -> Result<bool, LocalDaemonError> {
        self.verify_root_identity()?;
        let Some(parent) = self.open_parent(JOURNAL_PATH, false)? else {
            return Ok(false);
        };
        let name = target_file_name(JOURNAL_PATH)?.to_os_string();
        let staging_names = journal_staging_names_at(&parent.directory)?;
        let Some(state) = read_optional_regular_file_at(
            &parent.directory,
            &name,
            "transaction_journal",
            MAX_JOURNAL_BYTES,
            LocalDaemonErrorCode::UnsafeTransaction,
        )?
        else {
            return self.recover_unpublished_journal(&parent, staging_names);
        };
        validate_journal_state_metadata(&state)?;
        let journal = decode_transaction_journal(&state, self.root_identity)?;
        let expected_staging_name = journal_staging_name(&journal.operation_id)?;
        match staging_names.as_slice() {
            [] => {}
            [staging_name] if *staging_name == expected_staging_name => {
                let companion_state = read_journal_state_at(&parent.directory, staging_name)?;
                let companion_journal =
                    decode_transaction_journal(&companion_state, self.root_identity)?;
                if !journals_are_rewrite_pair(&journal, &companion_journal) {
                    return Err(unsafe_transaction(
                        "transaction journal staging file is unrelated",
                    ));
                }
                unlink_exact_journal_state_at(&parent.directory, staging_name, &companion_state)?;
                parent
                    .directory
                    .sync_all()
                    .map_err(|source| io_error("sync recovered journal staging file", source))?;
            }
            _ => {
                return Err(unsafe_transaction(
                    "unknown transaction journal staging file is present",
                ))
            }
        }
        match journal.phase {
            TransactionPhase::Precommit => self.recover_precommit(&journal)?,
            TransactionPhase::Committed => self.recover_committed(&journal)?,
        }
        let file = open_file_at(&parent.directory, &name, libc::O_RDWR).map_err(|source| {
            error(
                LocalDaemonErrorCode::UnsafeTransaction,
                format!("failed to reopen transaction journal: {}", source.kind()),
            )
        })?;
        let handle = JournalHandle {
            parent,
            name,
            file,
            state,
            operation_id: journal.operation_id,
        };
        self.remove_journal(&handle)?;
        Ok(true)
    }

    fn recover_unpublished_journal(
        &self,
        _parent: &AnchoredParent,
        staging_names: Vec<OsString>,
    ) -> Result<bool, LocalDaemonError> {
        if staging_names.is_empty() {
            Ok(false)
        } else {
            Err(unsafe_transaction(
                "named transaction journal exists without an official journal",
            ))
        }
    }

    fn recover_precommit(&self, journal: &TransactionJournal) -> Result<(), LocalDaemonError> {
        for entry in journal.entries.iter().rev() {
            let parent = self.transaction_entry_parent(entry, false)?;
            let target_name = target_file_name(&entry.target_path)?.to_os_string();
            let temporary_name = OsString::from(&entry.temporary_name);
            let maximum = managed_maximum_bytes(&entry.target_path)?;
            let target = read_recovery_entry_at(
                &parent.directory,
                &target_name,
                &entry.logical_name,
                maximum,
            )?;
            let temporary = read_recovery_entry_at(
                &parent.directory,
                &temporary_name,
                &entry.logical_name,
                maximum,
            )?;
            match journal.operation {
                TransactionOperation::Install => recover_precommit_install_entry(
                    &parent.directory,
                    &target_name,
                    &temporary_name,
                    entry,
                    &target,
                    &temporary,
                )?,
                TransactionOperation::Uninstall => recover_precommit_uninstall_entry(
                    &parent.directory,
                    &target_name,
                    &temporary_name,
                    entry,
                    &target,
                    &temporary,
                )?,
            }
            parent
                .directory
                .sync_all()
                .map_err(|source| io_error("sync recovered transaction directory", source))?;
        }
        Ok(())
    }

    fn recover_precommit_runtime(
        &self,
        journal: &TransactionJournal,
        runtime: &[TransactionRuntimeEntry],
    ) -> Result<(), LocalDaemonError> {
        if journal.entries.len() != runtime.len() {
            return Err(unsafe_transaction("runtime transaction shape changed"));
        }
        for index in (0..runtime.len()).rev() {
            let runtime_entry = &runtime[index];
            let journal_entry = &journal.entries[index];
            if runtime_entry.target_path != journal_entry.target_path
                || runtime_entry.temporary_name != OsStr::new(&journal_entry.temporary_name)
            {
                return Err(unsafe_transaction("runtime transaction entry changed"));
            }
            let maximum = managed_maximum_bytes(runtime_entry.target_path)?;
            let target = read_recovery_entry_at(
                &runtime_entry.parent.directory,
                &runtime_entry.target_name,
                runtime_entry.logical_name,
                maximum,
            )?;
            let temporary = read_recovery_entry_at(
                &runtime_entry.parent.directory,
                &runtime_entry.temporary_name,
                runtime_entry.logical_name,
                maximum,
            )?;
            match journal.operation {
                TransactionOperation::Install => recover_precommit_install_entry(
                    &runtime_entry.parent.directory,
                    &runtime_entry.target_name,
                    &runtime_entry.temporary_name,
                    journal_entry,
                    &target,
                    &temporary,
                )?,
                TransactionOperation::Uninstall => recover_precommit_uninstall_entry(
                    &runtime_entry.parent.directory,
                    &runtime_entry.target_name,
                    &runtime_entry.temporary_name,
                    journal_entry,
                    &target,
                    &temporary,
                )?,
            }
            runtime_entry
                .parent
                .directory
                .sync_all()
                .map_err(|source| io_error("sync runtime transaction rollback", source))?;
        }
        Ok(())
    }

    fn recover_committed(&self, journal: &TransactionJournal) -> Result<(), LocalDaemonError> {
        for entry in &journal.entries {
            let parent = self.transaction_entry_parent(entry, false)?;
            let target_name = target_file_name(&entry.target_path)?.to_os_string();
            let temporary_name = OsString::from(&entry.temporary_name);
            let maximum = managed_maximum_bytes(&entry.target_path)?;
            let target = read_optional_regular_file_at(
                &parent.directory,
                &target_name,
                &entry.logical_name,
                maximum,
                LocalDaemonErrorCode::UnsafeTransaction,
            )?;
            let temporary = read_optional_regular_file_at(
                &parent.directory,
                &temporary_name,
                &entry.logical_name,
                maximum,
                LocalDaemonErrorCode::UnsafeTransaction,
            )?;
            match journal.operation {
                TransactionOperation::Install => {
                    let new = entry
                        .new
                        .as_ref()
                        .ok_or_else(|| unsafe_transaction("missing new proof"))?;
                    if target
                        .as_ref()
                        .is_none_or(|state| !matches_proof(state, new))
                    {
                        return Err(unsafe_transaction("committed install target changed"));
                    }
                    match (entry.old.as_ref(), temporary.as_ref()) {
                        (Some(old), Some(state)) if matches_proof(state, old) => {
                            unlink_verified_at(&parent.directory, &temporary_name, old, maximum)?;
                        }
                        (Some(_), None) | (None, None) => {}
                        _ => return Err(unsafe_transaction("committed install backup changed")),
                    }
                }
                TransactionOperation::Uninstall => {
                    if target.is_some() {
                        return Err(unsafe_transaction("committed uninstall target reappeared"));
                    }
                    match (entry.old.as_ref(), temporary.as_ref()) {
                        (Some(old), Some(state)) if matches_proof(state, old) => {
                            unlink_verified_at(&parent.directory, &temporary_name, old, maximum)?;
                        }
                        (Some(_), None) => {}
                        _ => return Err(unsafe_transaction("committed uninstall retiree changed")),
                    }
                }
            }
            parent
                .directory
                .sync_all()
                .map_err(|source| io_error("sync committed transaction cleanup", source))?;
        }
        Ok(())
    }

    fn transaction_entry_parent(
        &self,
        entry: &TransactionJournalEntry,
        create: bool,
    ) -> Result<AnchoredParent, LocalDaemonError> {
        self.verify_root_identity()?;
        self.open_parent(&entry.target_path, create)?
            .ok_or_else(|| unsafe_transaction("transaction target parent is missing"))
    }

    fn reject_orphan_transaction_paths(&self) -> Result<(), LocalDaemonError> {
        for target in managed_paths().chain(std::iter::once(JOURNAL_PATH)) {
            let Some(parent) = self.open_parent(target, false)? else {
                continue;
            };
            for name in directory_names(&parent.directory)? {
                let Some(name) = name.to_str() else {
                    return Err(unsafe_transaction(
                        "managed directory contains a non-UTF-8 entry",
                    ));
                };
                if name.starts_with(".apolysis-install-")
                    || name.starts_with(".apolysis-backup-")
                    || name.starts_with(".apolysis-uninstall-")
                    || name.starts_with(JOURNAL_STAGING_PREFIX)
                {
                    return Err(unsafe_transaction("orphan transaction sibling is present"));
                }
            }
        }
        Ok(())
    }

    fn verify_root_identity(&self) -> Result<(), LocalDaemonError> {
        let opened = self
            .root_directory
            .metadata()
            .map_err(|error| io_error("inspect opened staged root", error))?;
        let reopened = open_directory_path_no_symlinks(
            &self.root,
            LocalDaemonErrorCode::UnsafeRoot,
            "staged root",
        )?;
        verify_directory_path_anchors(
            &reopened.anchors,
            LocalDaemonErrorCode::UnsafeRoot,
            "staged root",
        )?;
        let reopened_metadata = reopened
            .directory
            .metadata()
            .map_err(|error| io_error("inspect reopened staged root", error))?;
        if !opened.file_type().is_dir()
            || FileIdentity::from_metadata(&opened) != self.root_identity
            || !reopened_metadata.file_type().is_dir()
            || FileIdentity::from_metadata(&reopened_metadata) != self.root_identity
        {
            return Err(error(
                LocalDaemonErrorCode::UnsafeRoot,
                "staged root identity changed",
            ));
        }
        Ok(())
    }
}

struct PreparedPlan {
    fingerprint: [u8; 32],
    mutation: PreparedMutation,
}

impl PreparedPlan {
    fn operation(&self) -> LocalDaemonOperationKind {
        match self.mutation {
            PreparedMutation::Install { .. } => LocalDaemonOperationKind::Install,
            PreparedMutation::Uninstall { .. } => LocalDaemonOperationKind::Uninstall,
        }
    }
}

enum PreparedMutation {
    Install { writes: Vec<PlannedWrite> },
    Uninstall { removes: Vec<PlannedRemove> },
}

struct PlannedWrite {
    logical_name: &'static str,
    target_path: &'static str,
    bytes: Vec<u8>,
    mode: u32,
    existing: Option<FileState>,
    receipt_template: Option<InstallReceipt>,
}

struct PlannedRemove {
    logical_name: &'static str,
    target_path: &'static str,
    existing: FileState,
}

enum TransactionInput {
    Install(Vec<PlannedWrite>),
    Uninstall(Vec<PlannedRemove>),
}

enum TransactionSource {
    Install(PlannedWrite),
    Uninstall(PlannedRemove),
}

struct AnchoredParent {
    directory: File,
    relative_path: PathBuf,
    identity: FileIdentity,
}

struct OpenedDirectoryPath {
    directory: File,
    lexical_absolute_path: PathBuf,
    anchors: Vec<DirectoryPathAnchor>,
}

struct DirectoryPathAnchor {
    parent: File,
    name: OsString,
    identity: FileIdentity,
}

struct TransactionRuntimeEntry {
    logical_name: &'static str,
    target_path: &'static str,
    target_name: OsString,
    temporary_name: OsString,
    parent: AnchoredParent,
    old: Option<FileState>,
    new: Option<FileState>,
    bytes: Option<Vec<u8>>,
    mode: Option<u32>,
    receipt_template: Option<InstallReceipt>,
    staged_file: Option<File>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TransactionJournal {
    schema_version: u32,
    phase: TransactionPhase,
    operation: TransactionOperation,
    operation_id: String,
    root_identity: FileIdentity,
    installer_uid: u32,
    installer_gid: u32,
    entries: Vec<TransactionJournalEntry>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransactionPhase {
    Precommit,
    Committed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum TransactionOperation {
    Install,
    Uninstall,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct TransactionJournalEntry {
    logical_name: String,
    target_path: String,
    temporary_name: String,
    old: Option<JournalFileProof>,
    new: Option<JournalFileProof>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct JournalFileProof {
    identity: Option<FileIdentity>,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    sha256: String,
}

impl JournalFileProof {
    fn from_state(state: &FileState) -> Self {
        Self {
            identity: Some(state.identity),
            len: state.len,
            mode: state.mode,
            uid: state.uid,
            gid: state.gid,
            sha256: state.sha256.clone(),
        }
    }
}

struct JournalHandle {
    parent: AnchoredParent,
    name: OsString,
    file: File,
    state: FileState,
    operation_id: String,
}

enum JournalRewriteFailure {
    BeforePublish(LocalDaemonError),
    AfterPublish(LocalDaemonError),
}

#[derive(Deserialize)]
struct ReleaseManifest {
    schema_version: u32,
    release_version: String,
    target: String,
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Clone, Deserialize)]
struct ManifestArtifact {
    path: String,
    kind: String,
    sha256: String,
    size_bytes: u64,
    mode: String,
}

struct LoadedBundle {
    root_identity: FileIdentity,
    manifest: ReleaseManifest,
    manifest_bytes: Vec<u8>,
    artifacts: Vec<BundleArtifact>,
}

struct BundleArtifact {
    spec: ArtifactSpec,
    manifest: ManifestArtifact,
    source_state: FileState,
}

#[derive(Clone, Deserialize, Serialize)]
struct InstallReceipt {
    schema_version: u32,
    release_version: String,
    target: String,
    installer_uid: u32,
    installer_gid: u32,
    artifacts: Vec<ReceiptArtifact>,
}

#[derive(Clone, Deserialize, Serialize)]
struct ReceiptArtifact {
    kind: String,
    target_path: String,
    sha256: String,
    size_bytes: u64,
    mode: String,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
}

struct LoadedReceipt {
    receipt: InstallReceipt,
    state: FileState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone)]
struct FileState {
    identity: FileIdentity,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    mode: u32,
    uid: u32,
    gid: u32,
    sha256: String,
    bytes: Vec<u8>,
}

enum RecoveryEntryState {
    Missing,
    Regular(FileState),
    Other,
}

fn open_parent_at_root(
    root: &File,
    relative: &Path,
    create: bool,
) -> Result<Option<AnchoredParent>, LocalDaemonError> {
    validate_relative_path(relative, LocalDaemonErrorCode::UnsafeTarget)?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let mut directory = root
        .try_clone()
        .map_err(|source| io_error("clone staged root descriptor", source))?;
    validate_managed_directory(&directory, "staged root")?;
    let mut relative_path = PathBuf::new();
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return Err(error(
                LocalDaemonErrorCode::UnsafeTarget,
                "managed target escapes the staged root",
            ));
        };
        relative_path.push(name);
        let next = match open_directory_at(&directory, name) {
            Ok(next) => next,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound && create => {
                match mkdir_at(&directory, name, 0o755) {
                    Ok(()) => directory
                        .sync_all()
                        .map_err(|source| io_error("sync managed target directory", source))?,
                    Err(create_error)
                        if create_error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(create_error) => {
                        return Err(io_error("create managed target directory", create_error))
                    }
                }
                open_directory_at(&directory, name).map_err(|open_error| {
                    error(
                        LocalDaemonErrorCode::UnsafeTarget,
                        format!(
                            "managed parent changed during creation: {}",
                            open_error.kind()
                        ),
                    )
                })?
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(error(
                    LocalDaemonErrorCode::UnsafeTarget,
                    format!(
                        "failed to open managed parent without links: {}",
                        source.kind()
                    ),
                ))
            }
        };
        validate_managed_directory(&next, "managed target parent")?;
        directory = next;
    }
    let metadata = directory
        .metadata()
        .map_err(|source| io_error("inspect managed target parent", source))?;
    Ok(Some(AnchoredParent {
        directory,
        relative_path,
        identity: FileIdentity::from_metadata(&metadata),
    }))
}

fn lock_root_directory(root: &File) -> Result<(), LocalDaemonError> {
    // SAFETY: root is a valid, open directory descriptor. LOCK_NB guarantees
    // opening a second handle never waits or attempts recovery concurrently.
    let status = unsafe { libc::flock(root.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if status == 0 {
        Ok(())
    } else {
        let source = std::io::Error::last_os_error();
        Err(error(
            LocalDaemonErrorCode::UnsafeTransaction,
            format!("staged root is busy: {}", source.kind()),
        ))
    }
}

fn validate_managed_directory(directory: &File, name: &str) -> Result<(), LocalDaemonError> {
    let metadata = directory
        .metadata()
        .map_err(|source| io_error("inspect managed directory descriptor", source))?;
    let mode = metadata.mode() & 0o7777;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid()
        || metadata.gid() != effective_gid()
        || mode & 0o7022 != 0
    {
        return Err(error(
            LocalDaemonErrorCode::UnsafeTarget,
            format!("{name} has unsafe type, owner, or permissions"),
        ));
    }
    Ok(())
}

fn open_directory_path_no_symlinks(
    path: &Path,
    failure_code: LocalDaemonErrorCode,
    logical_name: &str,
) -> Result<OpenedDirectoryPath, LocalDaemonError> {
    if path.as_os_str().is_empty() {
        return Err(error(failure_code, format!("{logical_name} path is empty")));
    }

    let absolute = path.is_absolute();
    let anchor_path = if absolute {
        Path::new("/")
    } else {
        Path::new(".")
    };
    let mut directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(anchor_path)
        .map_err(|source| {
            error(
                failure_code,
                format!(
                    "failed to open {logical_name} anchor without links: {}",
                    source.kind()
                ),
            )
        })?;
    let mut lexical_absolute_path = if absolute {
        PathBuf::from("/")
    } else {
        std::env::current_dir().map_err(|source| {
            error(
                failure_code,
                format!("failed to resolve {logical_name} anchor: {}", source.kind()),
            )
        })?
    };
    let mut anchors = Vec::new();

    for component in path.components() {
        let name = match component {
            Component::RootDir if absolute => continue,
            Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(error(
                    failure_code,
                    format!("{logical_name} path escapes its trusted anchor"),
                ))
            }
        };
        let child = open_directory_at(&directory, name).map_err(|source| {
            error(
                failure_code,
                format!(
                    "failed to open {logical_name} component without links: {}",
                    source.kind()
                ),
            )
        })?;
        let child_metadata = child.metadata().map_err(|source| {
            error(
                failure_code,
                format!(
                    "failed to inspect {logical_name} component: {}",
                    source.kind()
                ),
            )
        })?;
        let identity = FileIdentity::from_metadata(&child_metadata);
        let confirmation = open_directory_at(&directory, name).map_err(|source| {
            error(
                failure_code,
                format!(
                    "{logical_name} component changed while opening: {}",
                    source.kind()
                ),
            )
        })?;
        let confirmation_metadata = confirmation.metadata().map_err(|source| {
            error(
                failure_code,
                format!(
                    "failed to reinspect {logical_name} component: {}",
                    source.kind()
                ),
            )
        })?;
        if !child_metadata.file_type().is_dir()
            || FileIdentity::from_metadata(&confirmation_metadata) != identity
        {
            return Err(error(
                failure_code,
                format!("{logical_name} component changed while opening"),
            ));
        }

        lexical_absolute_path.push(name);
        anchors.push(DirectoryPathAnchor {
            parent: directory,
            name: name.to_os_string(),
            identity,
        });
        directory = child;
    }

    Ok(OpenedDirectoryPath {
        directory,
        lexical_absolute_path,
        anchors,
    })
}

fn verify_directory_path_anchors(
    anchors: &[DirectoryPathAnchor],
    failure_code: LocalDaemonErrorCode,
    logical_name: &str,
) -> Result<(), LocalDaemonError> {
    for anchor in anchors {
        let reopened = open_directory_at(&anchor.parent, &anchor.name).map_err(|source| {
            error(
                failure_code,
                format!(
                    "{logical_name} component changed after opening: {}",
                    source.kind()
                ),
            )
        })?;
        let metadata = reopened.metadata().map_err(|source| {
            error(
                failure_code,
                format!(
                    "failed to verify {logical_name} component: {}",
                    source.kind()
                ),
            )
        })?;
        if FileIdentity::from_metadata(&metadata) != anchor.identity {
            return Err(error(
                failure_code,
                format!("{logical_name} component identity changed"),
            ));
        }
    }
    Ok(())
}

fn open_directory_at(parent: &File, name: &OsStr) -> std::io::Result<File> {
    let name = c_string(name)?;
    // SAFETY: parent is an open directory and name is a NUL-terminated,
    // single path component. O_NOFOLLOW and O_DIRECTORY prevent link traversal.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    file_from_descriptor(descriptor)
}

fn open_file_at(parent: &File, name: &OsStr, access: libc::c_int) -> std::io::Result<File> {
    let name = c_string(name)?;
    // SAFETY: parent is an open directory and name is a NUL-terminated,
    // single path component. O_NOFOLLOW prevents final-component traversal.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            access | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    file_from_descriptor(descriptor)
}

fn create_anonymous_private_file_at(parent: &File, mode: u32) -> std::io::Result<File> {
    let current_directory = c".";
    // SAFETY: parent is an open directory and `.` is a fixed relative path.
    // O_TMPFILE keeps all partial bytes unreachable until linkat publishes the
    // fully written and fsynced inode.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            current_directory.as_ptr(),
            libc::O_RDWR | libc::O_TMPFILE | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::mode_t,
        )
    };
    let file = file_from_descriptor(descriptor)?;
    // SAFETY: file owns a valid descriptor. fchmod makes the private mode
    // exact even under an unusually restrictive process umask.
    let status = unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) };
    syscall_result(status)?;
    Ok(file)
}

fn link_anonymous_file_at(file: &File, parent: &File, name: &OsStr) -> std::io::Result<()> {
    let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let name = c_string(name)?;
    // SAFETY: source names this process's held O_TMPFILE descriptor;
    // AT_SYMLINK_FOLLOW resolves that procfs descriptor link. Destination is
    // a single component anchored to the already verified parent directory.
    // linkat never replaces an existing destination.
    let status = unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    };
    syscall_result(status)
}

fn file_from_descriptor(descriptor: libc::c_int) -> std::io::Result<File> {
    if descriptor < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: a non-negative descriptor returned by openat is uniquely
        // transferred into this File.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn mkdir_at(parent: &File, name: &OsStr, mode: u32) -> std::io::Result<()> {
    let name = c_string(name)?;
    // SAFETY: parent is an open directory and name is a NUL-terminated
    // component. mkdirat creates only beneath that descriptor.
    let status = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode as libc::mode_t) };
    syscall_result(status)
}

fn unlink_at(parent: &File, name: &OsStr) -> std::io::Result<()> {
    let name = c_string(name)?;
    // SAFETY: parent is an open directory and name is a NUL-terminated
    // component. Flags zero unlink only a non-directory entry.
    let status = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
    syscall_result(status)
}

fn rename_noreplace_at(parent: &File, source: &OsStr, destination: &OsStr) -> std::io::Result<()> {
    rename_at2(parent, source, destination, libc::RENAME_NOREPLACE)
}

fn rename_exchange_at(
    parent: &File,
    source: &OsStr,
    destination: &OsStr,
) -> Result<(), LocalDaemonError> {
    rename_at2(parent, source, destination, libc::RENAME_EXCHANGE)
        .map_err(|source| io_error("exchange managed transaction entries", source))
}

fn rename_at2(
    parent: &File,
    source: &OsStr,
    destination: &OsStr,
    flags: libc::c_uint,
) -> std::io::Result<()> {
    let source = c_string(source)?;
    let destination = c_string(destination)?;
    // SAFETY: both names are NUL-terminated components anchored to the same
    // open directory; the kernel performs the requested atomic rename.
    let status = unsafe {
        libc::renameat2(
            parent.as_raw_fd(),
            source.as_ptr(),
            parent.as_raw_fd(),
            destination.as_ptr(),
            flags,
        )
    };
    syscall_result(status)
}

fn syscall_result(status: libc::c_int) -> std::io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn c_string(value: &OsStr) -> std::io::Result<CString> {
    CString::new(value.as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

fn target_file_name(target_path: &str) -> Result<&OsStr, LocalDaemonError> {
    Path::new(target_path).file_name().ok_or_else(|| {
        error(
            LocalDaemonErrorCode::UnsafeTarget,
            "managed target has no name",
        )
    })
}

fn transaction_sibling_name(
    target_name: &OsStr,
    phase: &str,
    operation_id: &str,
) -> Result<OsString, LocalDaemonError> {
    let target_name = target_name.to_str().ok_or_else(|| {
        error(
            LocalDaemonErrorCode::UnsafeTarget,
            "managed target name is not UTF-8",
        )
    })?;
    Ok(OsString::from(format!(
        ".apolysis-{phase}-{operation_id}-{target_name}"
    )))
}

fn os_string_to_string(value: &OsStr) -> Result<String, LocalDaemonError> {
    value
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| unsafe_transaction("transaction name is not UTF-8"))
}

fn ensure_missing_at(parent: &File, name: &OsStr) -> Result<(), LocalDaemonError> {
    match open_file_at(parent, name, libc::O_RDONLY) {
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(error(
            LocalDaemonErrorCode::UnsafeTarget,
            "managed transaction path is already occupied",
        )),
    }
}

fn read_optional_regular_file_at(
    parent: &File,
    name: &OsStr,
    logical_name: &str,
    maximum_bytes: u64,
    failure_code: LocalDaemonErrorCode,
) -> Result<Option<FileState>, LocalDaemonError> {
    let file = match open_file_at(parent, name, libc::O_RDONLY) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(error(
                failure_code,
                format!(
                    "failed to open {logical_name} without links: {}",
                    source.kind()
                ),
            ))
        }
    };
    read_regular_open_file(file, logical_name, maximum_bytes, failure_code).map(Some)
}

fn read_bundle_file(
    root: &File,
    relative: &Path,
    logical_name: &str,
    maximum_bytes: u64,
) -> Result<FileState, LocalDaemonError> {
    validate_relative_path(relative, LocalDaemonErrorCode::InvalidBundle)?;
    let parent_path = relative.parent().unwrap_or_else(|| Path::new(""));
    let mut parent = root.try_clone().map_err(|source| {
        error(
            LocalDaemonErrorCode::InvalidBundle,
            format!("failed to clone release bundle root: {}", source.kind()),
        )
    })?;
    for component in parent_path.components() {
        let Component::Normal(name) = component else {
            return Err(error(
                LocalDaemonErrorCode::InvalidBundle,
                "release bundle path escapes its root",
            ));
        };
        parent = open_directory_at(&parent, name).map_err(|source| {
            error(
                LocalDaemonErrorCode::InvalidBundle,
                format!(
                    "failed to open release bundle parent without links: {}",
                    source.kind()
                ),
            )
        })?;
    }
    read_required_regular_file_at(
        &parent,
        relative.file_name().ok_or_else(|| {
            error(
                LocalDaemonErrorCode::InvalidBundle,
                "bundle file has no name",
            )
        })?,
        logical_name,
        maximum_bytes,
        LocalDaemonErrorCode::InvalidBundle,
    )
}

fn read_required_regular_file_at(
    parent: &File,
    name: &OsStr,
    logical_name: &str,
    maximum_bytes: u64,
    failure_code: LocalDaemonErrorCode,
) -> Result<FileState, LocalDaemonError> {
    read_optional_regular_file_at(parent, name, logical_name, maximum_bytes, failure_code)?
        .ok_or_else(|| error(failure_code, format!("{logical_name} is missing")))
}

fn read_recovery_entry_at(
    parent: &File,
    name: &OsStr,
    logical_name: &str,
    maximum_bytes: u64,
) -> Result<RecoveryEntryState, LocalDaemonError> {
    match read_optional_regular_file_at(
        parent,
        name,
        logical_name,
        maximum_bytes,
        LocalDaemonErrorCode::UnsafeTransaction,
    ) {
        Ok(Some(state)) => Ok(RecoveryEntryState::Regular(state)),
        Ok(None) => Ok(RecoveryEntryState::Missing),
        Err(_) => match entry_exists_at(parent, name)? {
            true => Ok(RecoveryEntryState::Other),
            false => Ok(RecoveryEntryState::Missing),
        },
    }
}

fn entry_exists_at(parent: &File, name: &OsStr) -> Result<bool, LocalDaemonError> {
    let name =
        c_string(name).map_err(|source| io_error("encode transaction entry name", source))?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: metadata points to writable storage, parent is an open directory,
    // and name is NUL-terminated. AT_SYMLINK_NOFOLLOW inspects the entry itself.
    let status = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if status == 0 {
        Ok(true)
    } else {
        let source = std::io::Error::last_os_error();
        if source.kind() == std::io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(io_error("inspect transaction entry", source))
        }
    }
}

fn read_regular_open_file(
    mut file: File,
    logical_name: &str,
    maximum_bytes: u64,
    failure_code: LocalDaemonErrorCode,
) -> Result<FileState, LocalDaemonError> {
    let before = file.metadata().map_err(|source| {
        error(
            failure_code,
            format!("failed to inspect opened {logical_name}: {}", source.kind()),
        )
    })?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > maximum_bytes {
        return Err(error(
            failure_code,
            format!("{logical_name} is linked, non-regular, or too large"),
        ));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(before.len()).unwrap_or(0));
    std::io::Read::by_ref(&mut file)
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| {
            error(
                failure_code,
                format!("failed to read {logical_name}: {}", source.kind()),
            )
        })?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(error(
            failure_code,
            format!("{logical_name} exceeds its size bound"),
        ));
    }
    let after = file.metadata().map_err(|source| {
        error(
            failure_code,
            format!("failed to re-inspect {logical_name}: {}", source.kind()),
        )
    })?;
    if !same_file_metadata(&before, &after) || after.len() != bytes.len() as u64 {
        return Err(error(
            failure_code,
            format!("{logical_name} changed while reading"),
        ));
    }
    Ok(file_state_from_metadata(&after, bytes))
}

fn file_state_from_metadata(metadata: &std::fs::Metadata, bytes: Vec<u8>) -> FileState {
    FileState {
        identity: FileIdentity::from_metadata(metadata),
        len: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        sha256: sha256_hex(&bytes),
        bytes,
    }
}

fn ensure_target_snapshot_at(
    parent: &File,
    target_name: &OsStr,
    logical_name: &str,
    expected: Option<&FileState>,
    maximum_bytes: u64,
) -> Result<(), LocalDaemonError> {
    let current = read_optional_regular_file_at(
        parent,
        target_name,
        logical_name,
        maximum_bytes,
        LocalDaemonErrorCode::StalePlan,
    )?;
    match (expected, current.as_ref()) {
        (None, None) => Ok(()),
        (Some(expected), Some(current)) if same_file_state(expected, current) => Ok(()),
        (None, Some(_)) => Err(error(
            LocalDaemonErrorCode::StalePlan,
            format!("target {logical_name} appeared after planning"),
        )),
        (Some(_), None) => Err(error(
            LocalDaemonErrorCode::StalePlan,
            format!("target {logical_name} disappeared after planning"),
        )),
        (Some(_), Some(_)) => Err(error(
            LocalDaemonErrorCode::StalePlan,
            format!("target {logical_name} changed after planning"),
        )),
    }
}

fn ensure_open_file_at_identity(
    parent: &File,
    name: &OsStr,
    opened: &File,
    identity: FileIdentity,
    mode: u32,
) -> Result<(), LocalDaemonError> {
    let path_file = open_file_at(parent, name, libc::O_RDONLY)
        .map_err(|source| io_error("reopen managed transaction file", source))?;
    let path_metadata = path_file
        .metadata()
        .map_err(|source| io_error("inspect managed transaction path", source))?;
    let opened_metadata = opened
        .metadata()
        .map_err(|source| io_error("inspect managed transaction descriptor", source))?;
    if FileIdentity::from_metadata(&path_metadata) != identity
        || FileIdentity::from_metadata(&opened_metadata) != identity
        || !path_metadata.file_type().is_file()
        || path_metadata.nlink() != 1
        || path_metadata.mode() & 0o7777 != mode
        || path_metadata.uid() != effective_uid()
        || path_metadata.gid() != effective_gid()
    {
        return Err(unsafe_transaction(
            "managed transaction file identity changed",
        ));
    }
    Ok(())
}

fn matches_proof(state: &FileState, proof: &JournalFileProof) -> bool {
    proof
        .identity
        .is_none_or(|identity| identity == state.identity)
        && state.len == proof.len
        && state.mode == proof.mode
        && state.uid == proof.uid
        && state.gid == proof.gid
        && state.sha256 == proof.sha256
}

fn restore_exchange_if_unchanged(
    entry: &TransactionRuntimeEntry,
    target: Option<&FileState>,
    temporary: Option<&FileState>,
) -> Result<(), LocalDaemonError> {
    let (Some(target), Some(temporary)) = (target, temporary) else {
        return Err(unsafe_transaction("cannot safely restore raced exchange"));
    };
    let maximum = managed_maximum_bytes(entry.target_path)?;
    let current_target = read_required_regular_file_at(
        &entry.parent.directory,
        &entry.target_name,
        entry.logical_name,
        maximum,
        LocalDaemonErrorCode::UnsafeTransaction,
    )?;
    let current_temporary = read_required_regular_file_at(
        &entry.parent.directory,
        &entry.temporary_name,
        entry.logical_name,
        maximum,
        LocalDaemonErrorCode::UnsafeTransaction,
    )?;
    if !same_file_state(target, &current_target) || !same_file_state(temporary, &current_temporary)
    {
        return Err(unsafe_transaction(
            "cannot safely restore changed exchange entries",
        ));
    }
    rename_exchange_at(
        &entry.parent.directory,
        &entry.temporary_name,
        &entry.target_name,
    )?;
    Ok(())
}

fn restore_noreplace_at(
    parent: &File,
    source: &OsStr,
    target: &OsStr,
) -> Result<(), LocalDaemonError> {
    rename_noreplace_at(parent, source, target)
        .map_err(|_| unsafe_transaction("cannot safely restore raced managed target"))
}

fn recover_precommit_install_entry(
    parent: &File,
    target_name: &OsStr,
    temporary_name: &OsStr,
    entry: &TransactionJournalEntry,
    target: &RecoveryEntryState,
    temporary: &RecoveryEntryState,
) -> Result<(), LocalDaemonError> {
    let new = entry
        .new
        .as_ref()
        .ok_or_else(|| unsafe_transaction("install journal lacks new proof"))?;
    let maximum = managed_maximum_bytes(&entry.target_path)?;
    match entry.old.as_ref() {
        // A replacement may only be before publication, fully staged, or at
        // the exact post-exchange point. Any other sibling is evidence that a
        // concurrent actor changed the transaction set and must be preserved.
        Some(old) => match (target, temporary) {
            (RecoveryEntryState::Regular(target), RecoveryEntryState::Missing)
                if matches_proof(target, old) =>
            {
                Ok(())
            }
            (RecoveryEntryState::Regular(target), RecoveryEntryState::Regular(temporary))
                if matches_proof(target, old) && matches_proof(temporary, new) =>
            {
                unlink_verified_at(parent, temporary_name, new, maximum)
            }
            (RecoveryEntryState::Regular(target), RecoveryEntryState::Regular(temporary))
                if matches_proof(target, new) && matches_proof(temporary, old) =>
            {
                rename_exchange_at(parent, temporary_name, target_name)?;
                let restored = read_required_regular_file_at(
                    parent,
                    target_name,
                    &entry.logical_name,
                    maximum,
                    LocalDaemonErrorCode::UnsafeTransaction,
                )?;
                if !matches_proof(&restored, old) {
                    return Err(unsafe_transaction("restored install target changed"));
                }
                unlink_verified_at(parent, temporary_name, new, maximum)
            }
            _ => Err(unsafe_transaction(
                "precommit replacement state is ambiguous",
            )),
        },
        // A fresh install has exactly three legitimate precommit points:
        // before staging, after staging, or after the no-replace publish.
        None => match (target, temporary) {
            (RecoveryEntryState::Missing, RecoveryEntryState::Missing) => Ok(()),
            (RecoveryEntryState::Missing, RecoveryEntryState::Regular(temporary))
                if matches_proof(temporary, new) =>
            {
                unlink_verified_at(parent, temporary_name, new, maximum)
            }
            (RecoveryEntryState::Regular(target), RecoveryEntryState::Missing)
                if matches_proof(target, new) =>
            {
                rename_noreplace_at(parent, target_name, temporary_name)
                    .map_err(|_| unsafe_transaction("cannot retire precommit new target"))?;
                unlink_verified_at(parent, temporary_name, new, maximum)
            }
            _ => Err(unsafe_transaction(
                "precommit fresh install state is ambiguous",
            )),
        },
    }
}

fn recover_precommit_uninstall_entry(
    parent: &File,
    target_name: &OsStr,
    temporary_name: &OsStr,
    entry: &TransactionJournalEntry,
    target: &RecoveryEntryState,
    temporary: &RecoveryEntryState,
) -> Result<(), LocalDaemonError> {
    let old = entry
        .old
        .as_ref()
        .ok_or_else(|| unsafe_transaction("uninstall journal lacks old proof"))?;
    match (target, temporary) {
        (RecoveryEntryState::Regular(target), RecoveryEntryState::Missing)
            if matches_proof(target, old) =>
        {
            Ok(())
        }
        (RecoveryEntryState::Missing, RecoveryEntryState::Regular(temporary))
            if matches_proof(temporary, old) =>
        {
            rename_noreplace_at(parent, temporary_name, target_name)
                .map_err(|_| unsafe_transaction("cannot restore precommit uninstall target"))?;
            let restored = read_required_regular_file_at(
                parent,
                target_name,
                &entry.logical_name,
                managed_maximum_bytes(&entry.target_path)?,
                LocalDaemonErrorCode::UnsafeTransaction,
            )?;
            if matches_proof(&restored, old) {
                Ok(())
            } else {
                Err(unsafe_transaction("restored uninstall target changed"))
            }
        }
        _ => Err(unsafe_transaction("precommit uninstall state is ambiguous")),
    }
}

fn unlink_verified_at(
    parent: &File,
    name: &OsStr,
    proof: &JournalFileProof,
    maximum_bytes: u64,
) -> Result<(), LocalDaemonError> {
    let state = read_required_regular_file_at(
        parent,
        name,
        "transaction_retiree",
        maximum_bytes,
        LocalDaemonErrorCode::UnsafeTransaction,
    )?;
    if !matches_proof(&state, proof) {
        return Err(unsafe_transaction(
            "transaction retiree changed before deletion",
        ));
    }
    unlink_at(parent, name).map_err(|source| io_error("unlink verified transaction file", source))
}

fn validate_transaction_journal(journal: &TransactionJournal) -> Result<(), LocalDaemonError> {
    validate_transaction_journal_shape(journal, true)
}

fn validate_transaction_draft(journal: &TransactionJournal) -> Result<(), LocalDaemonError> {
    if journal.phase != TransactionPhase::Precommit {
        return Err(unsafe_transaction(
            "transaction draft phase is not precommit",
        ));
    }
    validate_transaction_journal_shape(journal, false)
}

fn validate_transaction_journal_shape(
    journal: &TransactionJournal,
    require_new_identity: bool,
) -> Result<(), LocalDaemonError> {
    if journal.schema_version != 1
        || journal.root_identity.device == 0
        || journal.installer_uid != effective_uid()
        || journal.installer_gid != effective_gid()
        || journal.operation_id.is_empty()
        || journal.operation_id.len() > 64
        || !journal
            .operation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-')
        || journal.entries.is_empty()
        || journal.entries.len() > ARTIFACT_SPECS.len() + 1
    {
        return Err(unsafe_transaction("transaction journal header is invalid"));
    }
    let mut seen = Vec::new();
    for entry in &journal.entries {
        let (logical_name, expected_mode, maximum) = managed_path_contract(&entry.target_path)?;
        if entry.logical_name != logical_name || seen.contains(&entry.target_path) {
            return Err(unsafe_transaction("transaction target set is invalid"));
        }
        seen.push(entry.target_path.clone());
        let phase = match journal.operation {
            TransactionOperation::Install => "install",
            TransactionOperation::Uninstall => "uninstall",
        };
        let expected_temporary = transaction_sibling_name(
            target_file_name(&entry.target_path)?,
            phase,
            &journal.operation_id,
        )?;
        if entry.temporary_name != os_string_to_string(&expected_temporary)? {
            return Err(unsafe_transaction("transaction sibling name is invalid"));
        }
        if let Some(old) = entry.old.as_ref() {
            validate_journal_proof(old, expected_mode, maximum, true)?;
        }
        match journal.operation {
            TransactionOperation::Install => {
                let new = entry
                    .new
                    .as_ref()
                    .ok_or_else(|| unsafe_transaction("install journal lacks new proof"))?;
                validate_journal_proof(new, expected_mode, maximum, require_new_identity)?;
            }
            TransactionOperation::Uninstall if entry.old.is_some() && entry.new.is_none() => {}
            TransactionOperation::Uninstall => {
                return Err(unsafe_transaction("uninstall journal proof is invalid"))
            }
        }
    }
    Ok(())
}

fn validate_journal_proof(
    proof: &JournalFileProof,
    expected_mode: u32,
    maximum: u64,
    identity_required: bool,
) -> Result<(), LocalDaemonError> {
    if (identity_required && proof.identity.is_none())
        || proof.len > maximum
        || proof.mode != expected_mode
        || proof.uid != effective_uid()
        || proof.gid != effective_gid()
        || !valid_sha256(&proof.sha256)
    {
        return Err(unsafe_transaction("transaction file proof is invalid"));
    }
    Ok(())
}

fn transaction_journal_bytes(journal: &TransactionJournal) -> Result<Vec<u8>, LocalDaemonError> {
    validate_transaction_journal(journal)?;
    let mut bytes = serde_json::to_vec_pretty(journal)
        .map_err(|_| unsafe_transaction("failed to encode transaction journal"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(unsafe_transaction(
            "transaction journal exceeds its size bound",
        ));
    }
    Ok(bytes)
}

fn journal_staging_name(operation_id: &str) -> Result<OsString, LocalDaemonError> {
    if operation_id.is_empty()
        || operation_id.len() > 64
        || !operation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-')
    {
        return Err(unsafe_transaction(
            "transaction journal operation identifier is invalid",
        ));
    }
    Ok(OsString::from(format!(
        "{JOURNAL_STAGING_PREFIX}{operation_id}"
    )))
}

fn read_journal_state_at(parent: &File, name: &OsStr) -> Result<FileState, LocalDaemonError> {
    let state = read_required_regular_file_at(
        parent,
        name,
        "transaction_journal",
        MAX_JOURNAL_BYTES,
        LocalDaemonErrorCode::UnsafeTransaction,
    )?;
    validate_journal_state_metadata(&state)?;
    Ok(state)
}

fn validate_anonymous_journal_file(
    file: &File,
    bytes: &[u8],
) -> Result<std::fs::Metadata, LocalDaemonError> {
    validate_anonymous_staged_file(file, bytes, 0o600, "anonymous transaction journal")
}

fn validate_anonymous_staged_file(
    file: &File,
    bytes: &[u8],
    mode: u32,
    logical_name: &str,
) -> Result<std::fs::Metadata, LocalDaemonError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect anonymous staged file", source))?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 0
        || metadata.len() != bytes.len() as u64
        || metadata.mode() & 0o7777 != mode
        || metadata.uid() != effective_uid()
        || metadata.gid() != effective_gid()
    {
        return Err(unsafe_transaction(format!(
            "{logical_name} metadata is unsafe"
        )));
    }
    Ok(metadata)
}

fn validate_journal_state_metadata(state: &FileState) -> Result<(), LocalDaemonError> {
    if state.mode == 0o600 && state.uid == effective_uid() && state.gid == effective_gid() {
        Ok(())
    } else {
        Err(unsafe_transaction("transaction journal metadata is unsafe"))
    }
}

fn decode_transaction_journal(
    state: &FileState,
    root_identity: FileIdentity,
) -> Result<TransactionJournal, LocalDaemonError> {
    let journal: TransactionJournal = serde_json::from_slice(&state.bytes)
        .map_err(|_| unsafe_transaction("transaction journal is invalid"))?;
    validate_transaction_journal(&journal)?;
    if journal.root_identity != root_identity {
        return Err(unsafe_transaction(
            "transaction journal belongs to another staged root",
        ));
    }
    Ok(journal)
}

fn journal_staging_names_at(parent: &File) -> Result<Vec<OsString>, LocalDaemonError> {
    Ok(directory_names(parent)?
        .into_iter()
        .filter(|name| {
            name.as_bytes()
                .starts_with(JOURNAL_STAGING_PREFIX.as_bytes())
        })
        .collect())
}

fn journals_are_rewrite_pair(
    official: &TransactionJournal,
    companion: &TransactionJournal,
) -> bool {
    if official.schema_version != companion.schema_version
        || official.operation != companion.operation
        || official.operation_id != companion.operation_id
        || official.root_identity != companion.root_identity
        || official.installer_uid != companion.installer_uid
        || official.installer_gid != companion.installer_gid
        || official.entries.len() != companion.entries.len()
        || (official.phase == TransactionPhase::Committed
            && companion.phase == TransactionPhase::Committed)
    {
        return false;
    }
    official
        .entries
        .iter()
        .zip(&companion.entries)
        .all(|(left, right)| {
            left.logical_name == right.logical_name
                && left.target_path == right.target_path
                && left.temporary_name == right.temporary_name
                && left.old == right.old
                && journal_new_proofs_are_compatible(left.new.as_ref(), right.new.as_ref())
        })
}

fn journal_new_proofs_are_compatible(
    left: Option<&JournalFileProof>,
    right: Option<&JournalFileProof>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.len == right.len
                && left.mode == right.mode
                && left.uid == right.uid
                && left.gid == right.gid
                && left.sha256 == right.sha256
                && (left.identity == right.identity
                    || left.identity.is_none()
                    || right.identity.is_none())
        }
        _ => false,
    }
}

fn ensure_journal_state_at(
    parent: &File,
    name: &OsStr,
    expected: &FileState,
) -> Result<(), LocalDaemonError> {
    let current = read_journal_state_at(parent, name)?;
    if same_file_state(expected, &current) {
        Ok(())
    } else {
        Err(unsafe_transaction(
            "transaction journal changed after validation",
        ))
    }
}

fn unlink_exact_journal_state_at(
    parent: &File,
    name: &OsStr,
    expected: &FileState,
) -> Result<(), LocalDaemonError> {
    ensure_journal_state_at(parent, name, expected)?;
    unlink_at(parent, name).map_err(|source| io_error("remove exact transaction journal", source))
}

fn managed_paths() -> impl Iterator<Item = &'static str> {
    ARTIFACT_SPECS
        .iter()
        .map(|spec| spec.target_path)
        .chain(std::iter::once(RECEIPT_PATH))
}

fn managed_path_contract(path: &str) -> Result<(&'static str, u32, u64), LocalDaemonError> {
    if path == RECEIPT_PATH {
        return Ok(("install_receipt", 0o644, MAX_RECEIPT_BYTES));
    }
    ARTIFACT_SPECS
        .iter()
        .find(|spec| spec.target_path == path)
        .map(|spec| (spec.kind, spec.mode, spec.maximum_bytes))
        .ok_or_else(|| unsafe_transaction("transaction contains an unmanaged path"))
}

fn managed_maximum_bytes(path: &str) -> Result<u64, LocalDaemonError> {
    managed_path_contract(path).map(|(_, _, maximum)| maximum)
}

fn directory_names(directory: &File) -> Result<Vec<OsString>, LocalDaemonError> {
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    std::fs::read_dir(descriptor_path)
        .map_err(|source| io_error("scan managed transaction directory", source))?
        .map(|entry| {
            entry
                .map(|entry| entry.file_name())
                .map_err(|source| io_error("read managed transaction directory entry", source))
        })
        .collect()
}

fn unsafe_transaction(context: impl Into<String>) -> LocalDaemonError {
    error(LocalDaemonErrorCode::UnsafeTransaction, context)
}

fn load_bundle(bundle_root: &Path) -> Result<LoadedBundle, LocalDaemonError> {
    let opened = open_directory_path_no_symlinks(
        bundle_root,
        LocalDaemonErrorCode::InvalidBundle,
        "release bundle root",
    )?;
    let root = opened.directory;
    let root_metadata = root.metadata().map_err(|source| {
        error(
            LocalDaemonErrorCode::InvalidBundle,
            format!("failed to inspect release bundle root: {}", source.kind()),
        )
    })?;
    if !root_metadata.file_type().is_dir() {
        return Err(error(
            LocalDaemonErrorCode::InvalidBundle,
            "release bundle root is not a plain directory",
        ));
    }
    let root_identity = FileIdentity::from_metadata(&root_metadata);
    let manifest_state = read_bundle_file(
        &root,
        Path::new(MANIFEST_NAME),
        "release_manifest",
        MAX_MANIFEST_BYTES,
    )?;
    let manifest: ReleaseManifest =
        serde_json::from_slice(&manifest_state.bytes).map_err(|_| {
            error(
                LocalDaemonErrorCode::InvalidBundle,
                "release manifest is not valid schema v2 JSON",
            )
        })?;
    validate_manifest_shape(&manifest)?;
    let mut artifacts = Vec::with_capacity(ARTIFACT_SPECS.len());
    for spec in ARTIFACT_SPECS {
        let manifest_artifact = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == spec.kind)
            .ok_or_else(|| {
                error(
                    LocalDaemonErrorCode::InvalidBundle,
                    format!("release bundle is missing {}", spec.kind),
                )
            })?
            .clone();
        let source_relative = Path::new(spec.bundle_path);
        let source_state = read_bundle_file(&root, source_relative, spec.kind, spec.maximum_bytes)?;
        if source_state.sha256 != manifest_artifact.sha256
            || source_state.len != manifest_artifact.size_bytes
            || source_state.mode != spec.mode
        {
            return Err(error(
                LocalDaemonErrorCode::InvalidBundle,
                format!("release artifact {} does not match its manifest", spec.kind),
            ));
        }
        artifacts.push(BundleArtifact {
            spec,
            manifest: manifest_artifact,
            source_state,
        });
    }
    verify_directory_path_anchors(
        &opened.anchors,
        LocalDaemonErrorCode::InvalidBundle,
        "release bundle root",
    )?;
    let verified_root_metadata = root.metadata().map_err(|source| {
        error(
            LocalDaemonErrorCode::InvalidBundle,
            format!("failed to verify release bundle root: {}", source.kind()),
        )
    })?;
    if FileIdentity::from_metadata(&verified_root_metadata) != root_identity {
        return Err(error(
            LocalDaemonErrorCode::InvalidBundle,
            "release bundle root changed while loading",
        ));
    }
    Ok(LoadedBundle {
        root_identity,
        manifest,
        manifest_bytes: manifest_state.bytes,
        artifacts,
    })
}

fn validate_manifest_shape(manifest: &ReleaseManifest) -> Result<(), LocalDaemonError> {
    if manifest.schema_version != RELEASE_MANIFEST_SCHEMA_V2
        || !valid_component(&manifest.release_version)
        || manifest.target != supported_release_target()
        || manifest.artifacts.len() != ARTIFACT_SPECS.len()
    {
        return Err(error(
            LocalDaemonErrorCode::InvalidBundle,
            "release manifest has an invalid schema or artifact set",
        ));
    }
    let total_bytes = manifest
        .artifacts
        .iter()
        .try_fold(0_u64, |total, artifact| {
            total.checked_add(artifact.size_bytes)
        });
    if total_bytes.is_none_or(|total| total > MAX_BUNDLE_BYTES) {
        return Err(error(
            LocalDaemonErrorCode::InvalidBundle,
            "release manifest exceeds the total artifact bound",
        ));
    }
    for spec in ARTIFACT_SPECS {
        let matching: Vec<_> = manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == spec.kind)
            .collect();
        if matching.len() != 1 {
            return Err(error(
                LocalDaemonErrorCode::InvalidBundle,
                format!(
                    "release manifest kind {} is missing or duplicated",
                    spec.kind
                ),
            ));
        }
        let artifact = matching[0];
        if artifact.path != spec.bundle_path
            || artifact.mode != format!("{:04o}", spec.mode)
            || !valid_sha256(&artifact.sha256)
            || artifact.size_bytes > spec.maximum_bytes
        {
            return Err(error(
                LocalDaemonErrorCode::InvalidBundle,
                format!("release manifest entry {} is invalid", spec.kind),
            ));
        }
    }
    Ok(())
}

fn validate_receipt_shape(receipt: &InstallReceipt) -> Result<(), LocalDaemonError> {
    if receipt.schema_version != RECEIPT_SCHEMA_V1
        || !valid_component(&receipt.release_version)
        || receipt.target != supported_release_target()
        || receipt.installer_uid != effective_uid()
        || receipt.installer_gid != effective_gid()
        || receipt.artifacts.len() != ARTIFACT_SPECS.len()
    {
        return Err(error(
            LocalDaemonErrorCode::InvalidReceipt,
            "installation receipt has an invalid schema or artifact set",
        ));
    }
    for spec in ARTIFACT_SPECS {
        let matching: Vec<_> = receipt
            .artifacts
            .iter()
            .filter(|artifact| artifact.target_path == spec.target_path)
            .collect();
        if matching.len() != 1 {
            return Err(error(
                LocalDaemonErrorCode::InvalidReceipt,
                format!(
                    "installation receipt entry {} is missing or duplicated",
                    spec.kind
                ),
            ));
        }
        let artifact = matching[0];
        if artifact.kind != spec.kind
            || artifact.mode != format!("{:04o}", spec.mode)
            || !valid_sha256(&artifact.sha256)
            || artifact.size_bytes > spec.maximum_bytes
            || artifact.uid != receipt.installer_uid
            || artifact.gid != receipt.installer_gid
            || artifact.device == 0
            || artifact.inode == 0
        {
            return Err(error(
                LocalDaemonErrorCode::InvalidReceipt,
                format!("installation receipt entry {} is invalid", spec.kind),
            ));
        }
    }
    Ok(())
}

fn bind_receipt_identities(
    mut receipt: InstallReceipt,
    runtime: &[TransactionRuntimeEntry],
) -> Result<InstallReceipt, LocalDaemonError> {
    for artifact in &mut receipt.artifacts {
        if let Some(entry) = runtime
            .iter()
            .find(|entry| entry.target_path == artifact.target_path)
        {
            let state = entry
                .new
                .as_ref()
                .ok_or_else(|| unsafe_transaction("staged artifact identity is missing"))?;
            if state.sha256 != artifact.sha256
                || state.len != artifact.size_bytes
                || state.mode != parse_mode(&artifact.mode).unwrap_or(u32::MAX)
                || state.uid != artifact.uid
                || state.gid != artifact.gid
            {
                return Err(unsafe_transaction(
                    "staged artifact does not match the derived receipt",
                ));
            }
            artifact.device = state.identity.device;
            artifact.inode = state.identity.inode;
        }
    }
    validate_receipt_shape(&receipt)?;
    Ok(receipt)
}

fn derived_receipt_index(runtime: &[TransactionRuntimeEntry]) -> Result<usize, LocalDaemonError> {
    let mut indices = runtime
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| entry.receipt_template.as_ref().map(|_| index));
    let index = indices
        .next()
        .ok_or_else(|| unsafe_transaction("install transaction lacks a derived receipt"))?;
    if indices.next().is_some() || index + 1 != runtime.len() {
        return Err(unsafe_transaction(
            "derived receipt is not the final install transaction entry",
        ));
    }
    Ok(index)
}

fn write_anonymous_staged_file(
    parent: &File,
    bytes: Vec<u8>,
    mode: u32,
    logical_name: &str,
) -> Result<(File, FileState), LocalDaemonError> {
    let mut file = create_anonymous_private_file_at(parent, mode).map_err(|source| {
        error(
            LocalDaemonErrorCode::UnsafeTransaction,
            format!(
                "failed to create anonymous staged {logical_name}: {}",
                source.kind()
            ),
        )
    })?;
    file.write_all(&bytes)
        .map_err(|source| io_error(&format!("write anonymous staged {logical_name}"), source))?;
    file.sync_all()
        .map_err(|source| io_error(&format!("sync anonymous staged {logical_name}"), source))?;
    let metadata = validate_anonymous_staged_file(&file, &bytes, mode, logical_name)?;
    let mut state = file_state_from_metadata(&metadata, bytes);
    state.bytes.clear();
    Ok((file, state))
}

fn receipt_bytes(receipt: &InstallReceipt) -> Result<Vec<u8>, LocalDaemonError> {
    let mut bytes = serde_json::to_vec_pretty(receipt).map_err(|_| {
        error(
            LocalDaemonErrorCode::Io,
            "failed to encode installation receipt",
        )
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn same_file_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.nlink() == right.nlink()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mode() == right.mode()
}

fn validate_relative_path(
    relative: &Path,
    failure_code: LocalDaemonErrorCode,
) -> Result<(), LocalDaemonError> {
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(error(failure_code, "path escapes its fixed root"));
    }
    Ok(())
}

fn same_file_state(left: &FileState, right: &FileState) -> bool {
    left.identity == right.identity
        && left.len == right.len
        && left.modified_seconds == right.modified_seconds
        && left.modified_nanoseconds == right.modified_nanoseconds
        && left.changed_seconds == right.changed_seconds
        && left.changed_nanoseconds == right.changed_nanoseconds
        && left.mode == right.mode
        && left.uid == right.uid
        && left.gid == right.gid
        && left.sha256 == right.sha256
}

struct Snapshot(Sha256);

impl Snapshot {
    fn new(operation: &str) -> Self {
        let mut digest = Sha256::new();
        digest.update(operation.as_bytes());
        digest.update([0]);
        Self(digest)
    }

    fn identity(&mut self, name: &str, identity: &FileIdentity) {
        self.field(name, &identity.device.to_be_bytes());
        self.field(name, &identity.inode.to_be_bytes());
    }

    fn bytes(&mut self, name: &str, bytes: &[u8]) {
        self.field(name, bytes);
    }

    fn file(&mut self, name: &str, state: &FileState) {
        self.identity(name, &state.identity);
        self.field(name, &state.len.to_be_bytes());
        self.field(name, &state.modified_seconds.to_be_bytes());
        self.field(name, &state.modified_nanoseconds.to_be_bytes());
        self.field(name, &state.changed_seconds.to_be_bytes());
        self.field(name, &state.changed_nanoseconds.to_be_bytes());
        self.field(name, &state.mode.to_be_bytes());
        self.field(name, &state.uid.to_be_bytes());
        self.field(name, &state.gid.to_be_bytes());
        self.field(name, state.sha256.as_bytes());
    }

    fn missing(&mut self, name: &str) {
        self.field(name, b"missing");
    }

    fn field(&mut self, name: &str, value: &[u8]) {
        self.0.update((name.len() as u64).to_be_bytes());
        self.0.update(name.as_bytes());
        self.0.update((value.len() as u64).to_be_bytes());
        self.0.update(value);
    }

    fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

fn parse_mode(mode: &str) -> Option<u32> {
    if mode.len() != 4 {
        return None;
    }
    u32::from_str_radix(mode, 8).ok()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_component(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(byte) if byte.is_ascii_alphanumeric())
        && value.len() <= 128
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn supported_release_target() -> String {
    format!("{}-unknown-linux-gnu", std::env::consts::ARCH)
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }
}

fn effective_gid() -> u32 {
    // SAFETY: getegid has no preconditions and does not dereference pointers.
    unsafe { libc::getegid() }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn operation_id() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        NEXT_OPERATION_ID.fetch_add(1, Ordering::Relaxed)
    )
}

fn error(code: LocalDaemonErrorCode, context: impl Into<String>) -> LocalDaemonError {
    LocalDaemonError {
        code,
        context: context.into(),
    }
}

fn io_error(context: &str, source: std::io::Error) -> LocalDaemonError {
    error(
        LocalDaemonErrorCode::Io,
        format!("{context}: {}", source.kind()),
    )
}

fn error_code_name(code: LocalDaemonErrorCode) -> &'static str {
    match code {
        LocalDaemonErrorCode::InvalidBundle => "invalid_bundle",
        LocalDaemonErrorCode::InvalidReceipt => "invalid_receipt",
        LocalDaemonErrorCode::UnsafeRoot => "unsafe_root",
        LocalDaemonErrorCode::UnsafeTarget => "unsafe_target",
        LocalDaemonErrorCode::UnmanagedTarget => "unmanaged_target",
        LocalDaemonErrorCode::ManagedTargetChanged => "managed_target_changed",
        LocalDaemonErrorCode::StalePlan => "stale_plan",
        LocalDaemonErrorCode::UnsafeTransaction => "unsafe_transaction",
        LocalDaemonErrorCode::Io => "io_error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Arc;

    fn serial_hook_guard() -> std::sync::MutexGuard<'static, ()> {
        static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
        SERIAL
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("lock serialized local operation tests")
    }

    #[test]
    fn install_does_not_replace_a_target_that_appears_during_publish() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("publish-create-race");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let target = root.join("usr/local/bin/apolysis");
        let canary = Arc::new(target.clone());

        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        install_test_hook(TestHookPoint::TargetValidated, {
            let canary = Arc::clone(&canary);
            move |validated_target| {
                assert_eq!(validated_target, canary.as_path());
                write_test_file(validated_target, b"operator-race\n", 0o755);
            }
        });

        let result = operations.apply(plan);
        assert!(result.is_err(), "a raced target must fail closed");
        assert_eq!(
            std::fs::read(&target).expect("read raced target"),
            b"operator-race\n"
        );
        assert!(
            root.join(JOURNAL_PATH).is_file(),
            "an unprovable target state must retain its journal"
        );
        let reopen_error = match LocalDaemonOperations::open_staged(&root) {
            Err(error) => error,
            Ok(_) => panic!("unprovable precommit target must fail closed on reopen"),
        };
        assert_eq!(reopen_error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        for spec in ARTIFACT_SPECS {
            if spec.target_path != "usr/local/bin/apolysis" {
                assert!(!root.join(spec.target_path).exists());
            }
        }
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn interrupted_journal_creation_never_exposes_partial_official_json() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("journal-create-interruption");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        install_test_hook(TestHookPoint::JournalCreateWriteStarted, |_| {
            panic!("simulated interruption while creating the journal");
        });

        let interrupted = catch_unwind(AssertUnwindSafe(|| operations.apply(plan)));
        assert!(
            interrupted.is_err(),
            "fault hook must interrupt journal creation"
        );
        drop(operations);
        let official_exists = root.join(JOURNAL_PATH).exists();
        assert!(
            !official_exists,
            "partial bytes must never reach the official journal name"
        );
        assert!(
            journal_staging_entries(&root).is_empty(),
            "anonymous journal writes must not expose a staging sibling"
        );
        let reopened = LocalDaemonOperations::open_staged(&root)
            .expect("an anonymous interrupted create leaves no recovery work");
        let inspection = reopened.inspect().expect("inspect recovered empty root");
        assert!(!inspection.installed());
        assert!(!inspection.recovered_interrupted_operation());
        assert_no_transaction_entries(&root);
        drop(reopened);
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[test]
    fn interrupted_journal_rewrite_keeps_complete_official_json_recoverable() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("journal-rewrite-interruption");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        install_test_hook(TestHookPoint::JournalRewriteWriteStarted, |_| {
            panic!("simulated interruption while replacing the journal");
        });

        let interrupted = catch_unwind(AssertUnwindSafe(|| operations.apply(plan)));
        assert!(
            interrupted.is_err(),
            "fault hook must interrupt journal replacement"
        );
        drop(operations);
        assert!(
            journal_staging_entries(&root).is_empty(),
            "anonymous replacement write must not expose partial bytes"
        );
        let official: TransactionJournal = serde_json::from_slice(
            &std::fs::read(root.join(JOURNAL_PATH)).expect("read complete official journal"),
        )
        .expect("official journal must remain complete JSON");
        assert_eq!(official.phase, TransactionPhase::Precommit);
        let reopened = LocalDaemonOperations::open_staged(&root)
            .expect("complete official journal must recover past partial staging");
        let inspection = reopened.inspect().expect("inspect recovered empty root");
        assert!(!inspection.installed());
        assert!(inspection.recovered_interrupted_operation());
        assert_no_transaction_entries(&root);
        drop(reopened);
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[test]
    fn interrupted_after_j1_before_receipt_link_rolls_back_without_publication() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("j1-before-receipt-link");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        install_test_hook(TestHookPoint::ReceiptJournalPublished, |_| {
            panic!("simulated interruption after J1 before receipt link");
        });

        let interrupted = catch_unwind(AssertUnwindSafe(|| operations.apply(plan)));
        assert!(
            interrupted.is_err(),
            "fault hook must interrupt before receipt staging becomes visible"
        );
        drop(operations);
        let journal: TransactionJournal = serde_json::from_slice(
            &std::fs::read(root.join(JOURNAL_PATH)).expect("read J1 journal"),
        )
        .expect("J1 journal must be complete");
        assert_eq!(journal.phase, TransactionPhase::Precommit);
        let receipt_entry = journal
            .entries
            .iter()
            .find(|entry| entry.target_path == RECEIPT_PATH)
            .expect("receipt journal entry");
        assert!(receipt_entry
            .new
            .as_ref()
            .and_then(|proof| proof.identity)
            .is_some());
        assert!(!root
            .join("usr/local/lib/apolysis")
            .join(&receipt_entry.temporary_name)
            .exists());
        for entry in &journal.entries {
            let target = root.join(&entry.target_path);
            assert!(
                !target
                    .parent()
                    .expect("transaction target parent")
                    .join(&entry.temporary_name)
                    .exists(),
                "no anonymous artifact may be linked before the durable journal"
            );
        }
        for spec in ARTIFACT_SPECS {
            assert!(
                !root.join(spec.target_path).exists(),
                "J1 publication must precede every target publication"
            );
        }

        let reopened = LocalDaemonOperations::open_staged(&root)
            .expect("J1 with an unlinked receipt must recover");
        let inspection = reopened.inspect().expect("inspect recovered empty root");
        assert!(!inspection.installed());
        assert!(inspection.recovered_interrupted_operation());
        assert_no_transaction_entries(&root);
        drop(reopened);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn unpublished_journal_with_an_unknown_name_fails_closed() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("unknown-unpublished-journal");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let staging = root
            .join("usr/local/lib/apolysis")
            .join(".apolysis-journal-not-an-operation-id");
        write_test_file(&staging, b"operator-canary\n", 0o600);

        let error = match LocalDaemonOperations::open_staged(&root) {
            Err(error) => error,
            Ok(_) => panic!("unknown unpublished journal must fail closed"),
        };
        assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        assert_eq!(
            std::fs::read(&staging).expect("read preserved unknown staging file"),
            b"operator-canary\n"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn unpublished_journal_with_unsafe_metadata_fails_closed() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("unsafe-unpublished-journal");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let staging = root
            .join("usr/local/lib/apolysis")
            .join(".apolysis-journal-1-999");
        write_test_file(&staging, b"partial journal\n", 0o644);

        let error = match LocalDaemonOperations::open_staged(&root) {
            Err(error) => error,
            Ok(_) => panic!("unsafe unpublished journal must fail closed"),
        };
        assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        assert_eq!(
            std::fs::read(&staging).expect("read preserved unsafe staging file"),
            b"partial journal\n"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn unpublished_private_journal_canary_is_preserved() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("private-unpublished-journal-canary");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let staging = root
            .join("usr/local/lib/apolysis")
            .join(".apolysis-journal-1-999");
        write_test_file(&staging, b"operator-private-canary\n", 0o600);
        let before = std::fs::metadata(&staging).expect("private canary metadata");

        let error = match LocalDaemonOperations::open_staged(&root) {
            Err(error) => error,
            Ok(_) => panic!("unpublished named journal must fail closed"),
        };
        assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        let after = std::fs::metadata(&staging).expect("preserved private canary metadata");
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(
            std::fs::read(&staging).expect("read preserved private staging file"),
            b"operator-private-canary\n"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn invalid_companion_for_an_official_journal_is_preserved() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("invalid-official-journal-companion");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        let canary = Arc::new(Mutex::new(None));
        install_test_hook(TestHookPoint::JournalCreated, {
            let canary = Arc::clone(&canary);
            move |staged_root| {
                let journal: TransactionJournal = serde_json::from_slice(
                    &std::fs::read(staged_root.join(JOURNAL_PATH))
                        .expect("read official transaction journal"),
                )
                .expect("decode official transaction journal");
                let companion = staged_root
                    .join("usr/local/lib/apolysis")
                    .join(journal_staging_name(&journal.operation_id).expect("companion name"));
                write_test_file(&companion, b"operator-private-companion\n", 0o600);
                let metadata = std::fs::metadata(&companion).expect("companion metadata");
                *canary.lock().expect("record companion canary") =
                    Some((companion, metadata.dev(), metadata.ino()));
            }
        });

        let error = operations
            .apply(plan)
            .expect_err("occupied journal companion must fail closed");
        assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        drop(operations);
        let (companion, device, inode) = canary
            .lock()
            .expect("read companion canary")
            .take()
            .expect("companion canary path");
        let reopen_error = match LocalDaemonOperations::open_staged(&root) {
            Err(error) => error,
            Ok(_) => panic!("invalid official journal companion must fail closed"),
        };
        assert_eq!(reopen_error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        let after = std::fs::metadata(&companion).expect("preserved companion metadata");
        assert_eq!((device, inode), (after.dev(), after.ino()));
        assert_eq!(
            std::fs::read(&companion).expect("read preserved companion"),
            b"operator-private-companion\n"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn second_handle_cannot_open_or_recover_while_first_handle_is_alive() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("exclusive-root-handle");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let first = LocalDaemonOperations::open_staged(&root).expect("open first handle");

        let second_error = match LocalDaemonOperations::open_staged(&root) {
            Err(error) => error,
            Ok(_) => panic!("second handle must not inspect or recover the same root"),
        };
        assert_eq!(second_error.code(), LocalDaemonErrorCode::UnsafeTransaction);

        drop(first);
        let third = LocalDaemonOperations::open_staged(&root)
            .expect("root lock must release with the first handle");
        assert!(!third.inspect().expect("inspect third handle").installed());
        drop(third);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn second_handle_cannot_recover_an_active_apply_journal() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("exclusive-active-journal");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut first = LocalDaemonOperations::open_staged(&root).expect("open first handle");
        let plan = first
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        let second_result = Arc::new(Mutex::new(None));
        install_test_hook(TestHookPoint::JournalCreated, {
            let root = root.clone();
            let second_result = Arc::clone(&second_result);
            move |_| {
                let code = match LocalDaemonOperations::open_staged(&root) {
                    Err(error) => Some(error.code()),
                    Ok(_) => None,
                };
                *second_result.lock().expect("record second open") = Some(code);
            }
        });

        first.apply(plan).expect("first handle completes install");
        assert_eq!(
            second_result.lock().expect("read second open").take(),
            Some(Some(LocalDaemonErrorCode::UnsafeTransaction))
        );
        drop(first);

        let second = LocalDaemonOperations::open_staged(&root)
            .expect("second handle opens after first drops");
        assert!(second
            .inspect()
            .expect("inspect installed root")
            .installed());
        drop(second);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn interrupted_commit_journal_publish_reopens_from_complete_precommit_state() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("journal-commit-transition");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        install_test_hook(TestHookPoint::CommittedJournalPrepared, |_| {
            panic!("simulated interruption before committed journal publish");
        });

        let interrupted = catch_unwind(AssertUnwindSafe(|| operations.apply(plan)));
        assert!(
            interrupted.is_err(),
            "fault hook must interrupt phase transition"
        );
        drop(operations);
        let reopened = LocalDaemonOperations::open_staged(&root)
            .expect("complete precommit journal must remain recoverable");
        let inspection = reopened.inspect().expect("inspect recovered staged root");
        assert!(!inspection.installed());
        assert!(inspection.recovered_interrupted_operation());
        assert_no_transaction_entries(&root);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn interrupted_after_commit_journal_exchange_rolls_forward() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("journal-commit-exchanged");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        install_test_hook(TestHookPoint::CommittedJournalPublished, |_| {
            panic!("simulated interruption after committed journal exchange");
        });

        let interrupted = catch_unwind(AssertUnwindSafe(|| operations.apply(plan)));
        assert!(
            interrupted.is_err(),
            "fault hook must interrupt after committed journal exchange"
        );
        drop(operations);
        let official: TransactionJournal = serde_json::from_slice(
            &std::fs::read(root.join(JOURNAL_PATH)).expect("read committed official journal"),
        )
        .expect("committed official journal must be complete JSON");
        assert_eq!(official.phase, TransactionPhase::Committed);
        let reopened = LocalDaemonOperations::open_staged(&root)
            .expect("committed official journal must roll forward");
        let inspection = reopened.inspect().expect("inspect recovered installation");
        assert!(inspection.installed());
        assert!(inspection.recovered_interrupted_operation());
        assert_no_transaction_entries(&root);
        drop(reopened);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn install_never_overwrites_or_deletes_a_raced_transaction_sibling() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("transaction-sibling-race");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        let raced = Arc::new(Mutex::new(None));
        install_test_hook(TestHookPoint::JournalCreated, {
            let raced = Arc::clone(&raced);
            move |staged_root| {
                let journal: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(staged_root.join(JOURNAL_PATH))
                        .expect("read transaction journal"),
                )
                .expect("decode transaction journal");
                let entry = &journal["entries"][0];
                let target = staged_root.join(entry["target_path"].as_str().expect("target path"));
                let sibling = target
                    .parent()
                    .expect("target parent")
                    .join(entry["temporary_name"].as_str().expect("temporary name"));
                write_test_file(&sibling, b"operator-hidden-canary\n", 0o600);
                let metadata = std::fs::metadata(&sibling).expect("hidden canary metadata");
                *raced.lock().expect("record raced sibling") =
                    Some((sibling, metadata.dev(), metadata.ino()));
            }
        });

        let error = operations
            .apply(plan)
            .expect_err("raced transaction sibling must fail closed");
        assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        let (sibling, device, inode) = raced
            .lock()
            .expect("read raced sibling")
            .take()
            .expect("raced sibling path");
        let after = std::fs::metadata(&sibling).expect("hidden canary after refusal");
        assert_eq!((device, inode), (after.dev(), after.ino()));
        assert_eq!(
            std::fs::read(&sibling).expect("read hidden canary"),
            b"operator-hidden-canary\n"
        );
        let reopen_error = match LocalDaemonOperations::open_staged(&root) {
            Err(error) => error,
            Ok(_) => panic!("unknown journal sibling must continue to fail closed"),
        };
        assert_eq!(reopen_error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        assert_eq!(
            std::fs::read(&sibling).expect("read preserved hidden canary"),
            b"operator-hidden-canary\n"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn install_restores_a_staged_name_replaced_after_validation() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("staged-name-replacement");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let canary_source = workspace.join("operator-hidden-canary");
        write_test_file(&canary_source, b"operator-hidden-canary\n", 0o600);
        let raced = Arc::new(Mutex::new(None));
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        install_test_hook(TestHookPoint::StagedFileValidated, {
            let raced = Arc::clone(&raced);
            let canary_source = canary_source.clone();
            let root = root.clone();
            move |target| {
                let journal: serde_json::Value = serde_json::from_slice(
                    &std::fs::read(root.join(JOURNAL_PATH)).expect("read transaction journal"),
                )
                .expect("decode transaction journal");
                let temporary_name = journal["entries"][0]["temporary_name"]
                    .as_str()
                    .expect("temporary name");
                let temporary = target.parent().expect("target parent").join(temporary_name);
                let held_staged = target
                    .parent()
                    .expect("target parent")
                    .join(".operator-held-staged");
                std::fs::rename(&temporary, &held_staged).expect("hold validated staged file");
                std::fs::rename(&canary_source, &temporary).expect("replace validated staged name");
                let metadata = std::fs::metadata(&temporary).expect("raced staged metadata");
                *raced.lock().expect("record staged race") =
                    Some((temporary, metadata.dev(), metadata.ino()));
            }
        });

        let error = operations
            .apply(plan)
            .expect_err("replaced staged name must fail closed");
        assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        let (temporary, device, inode) = raced
            .lock()
            .expect("read staged race")
            .take()
            .expect("staged race path");
        let after = std::fs::metadata(&temporary).expect("restored staged canary metadata");
        assert_eq!((device, inode), (after.dev(), after.ino()));
        assert_eq!(
            std::fs::read(&temporary).expect("read restored staged canary"),
            b"operator-hidden-canary\n"
        );
        assert!(!root.join("usr/local/bin/apolysis").exists());
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn reopening_rolls_back_a_precommit_install_interruption() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("precommit-recovery");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        install_test_hook(TestHookPoint::EntryMutated, |_| {
            panic!("simulated process interruption before commit");
        });

        let interrupted = catch_unwind(AssertUnwindSafe(|| operations.apply(plan)));
        assert!(interrupted.is_err(), "fault hook must interrupt apply");
        drop(operations);

        let recovered =
            LocalDaemonOperations::open_staged(&root).expect("recover precommit journal");
        let inspection = recovered.inspect().expect("inspect recovered root");
        assert!(!inspection.installed());
        assert!(inspection.recovered_interrupted_operation());
        for target in managed_paths() {
            assert!(!root.join(target).exists(), "rollback must remove {target}");
        }
        assert_no_transaction_entries(&root);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn reopening_finishes_committed_install_cleanup() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("committed-install-recovery");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let first_bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let first_plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: first_bundle,
            })
            .expect("plan initial install");
        operations.apply(first_plan).expect("apply initial install");

        let replacement_bundle = create_test_bundle(&workspace, "v0.5.0");
        let replacement_plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: replacement_bundle,
            })
            .expect("plan replacement install");
        install_test_hook(TestHookPoint::Committed, |_| {
            panic!("simulated process interruption after commit");
        });
        let interrupted = catch_unwind(AssertUnwindSafe(|| operations.apply(replacement_plan)));
        assert!(
            interrupted.is_err(),
            "fault hook must interrupt committed cleanup"
        );
        drop(operations);

        let recovered =
            LocalDaemonOperations::open_staged(&root).expect("recover committed journal");
        let inspection = recovered.inspect().expect("inspect recovered replacement");
        assert!(inspection.installed());
        assert_eq!(inspection.release_version(), Some("v0.5.0"));
        assert!(inspection.recovered_interrupted_operation());
        assert_no_transaction_entries(&root);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn reopening_finishes_committed_uninstall_cleanup() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("committed-uninstall-recovery");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let install = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        operations.apply(install).expect("apply install");
        let uninstall = operations
            .plan(LocalDaemonChange::UninstallPreserveState)
            .expect("plan uninstall");
        install_test_hook(TestHookPoint::Committed, |_| {
            panic!("simulated process interruption after uninstall commit");
        });

        let interrupted = catch_unwind(AssertUnwindSafe(|| operations.apply(uninstall)));
        assert!(
            interrupted.is_err(),
            "fault hook must interrupt committed cleanup"
        );
        drop(operations);

        let recovered =
            LocalDaemonOperations::open_staged(&root).expect("recover committed uninstall journal");
        let inspection = recovered.inspect().expect("inspect recovered uninstall");
        assert!(!inspection.installed());
        assert!(inspection.recovered_interrupted_operation());
        for target in managed_paths() {
            assert!(
                !root.join(target).exists(),
                "uninstall must remove {target}"
            );
        }
        assert_no_transaction_entries(&root);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn parent_replacement_during_publish_never_reaches_an_external_directory() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("parent-replacement");
        let root = workspace.join("root");
        let external = workspace.join("external");
        std::fs::create_dir(&root).expect("create staged root");
        std::fs::create_dir(&external).expect("create external directory");
        let external_canary = external.join("apolysis");
        write_test_file(&external_canary, b"external-canary\n", 0o755);
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        let detached = root.join("usr/local/bin-detached");
        install_test_hook(TestHookPoint::TargetValidated, {
            let external = external.clone();
            let detached = detached.clone();
            move |target| {
                let parent = target.parent().expect("managed target parent");
                std::fs::rename(parent, &detached).expect("detach managed parent");
                std::os::unix::fs::symlink(&external, parent)
                    .expect("replace managed parent with symlink");
            }
        });

        let error = operations
            .apply(plan)
            .expect_err("replaced parent must fail closed");
        assert!(matches!(
            error.code(),
            LocalDaemonErrorCode::StalePlan | LocalDaemonErrorCode::UnsafeTarget
        ));
        assert_eq!(
            std::fs::read(&external_canary).expect("read external canary"),
            b"external-canary\n"
        );
        assert_eq!(
            std::fs::read_dir(&detached)
                .expect("read detached managed parent")
                .count(),
            0,
            "fd-anchored rollback must clean only its detached transaction objects"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn root_replacement_during_publish_never_reaches_an_external_root() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("root-replacement");
        let root = workspace.join("root");
        let detached_root = workspace.join("root-detached");
        let external_root = workspace.join("external-root");
        std::fs::create_dir(&root).expect("create staged root");
        std::fs::create_dir(&external_root).expect("create external root");
        let canary = external_root.join("canary");
        write_test_file(&canary, b"external-root-canary\n", 0o600);
        let before = std::fs::metadata(&canary).expect("external canary metadata");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let plan = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        install_test_hook(TestHookPoint::TargetValidated, {
            let root = root.clone();
            let detached_root = detached_root.clone();
            let external_root = external_root.clone();
            move |_| {
                std::fs::rename(&root, &detached_root).expect("detach staged root");
                std::os::unix::fs::symlink(&external_root, &root)
                    .expect("replace staged root with symlink");
            }
        });

        let error = operations
            .apply(plan)
            .expect_err("replaced staged root must fail closed");
        assert_eq!(error.code(), LocalDaemonErrorCode::UnsafeRoot);
        let after = std::fs::metadata(&canary).expect("external canary metadata after refusal");
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert_eq!(
            std::fs::read(&canary).expect("read external canary"),
            b"external-root-canary\n"
        );
        for target in managed_paths() {
            assert!(!external_root.join(target).exists());
            assert!(!detached_root.join(target).exists());
        }
        assert_no_transaction_entries(&detached_root);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn uninstall_restores_a_symlink_replacement_without_touching_its_canary() {
        let _serial = serial_hook_guard();
        let workspace = test_workspace("uninstall-target-replacement");
        let root = workspace.join("root");
        std::fs::create_dir(&root).expect("create staged root");
        let bundle = create_test_bundle(&workspace, "v0.4.0");
        let mut operations = LocalDaemonOperations::open_staged(&root).expect("open staged root");
        let install = operations
            .plan(LocalDaemonChange::Install {
                bundle_root: bundle,
            })
            .expect("plan install");
        operations.apply(install).expect("apply install");
        let uninstall = operations
            .plan(LocalDaemonChange::UninstallPreserveState)
            .expect("plan uninstall");
        let target = root.join("usr/local/bin/apolysis");
        let moved_managed = root.join("usr/local/bin/apolysis.operator-moved");
        let external = workspace.join("external-canary");
        write_test_file(&external, b"external-canary\n", 0o600);
        let external_before = std::fs::metadata(&external).expect("external metadata");
        install_test_hook(TestHookPoint::TargetValidated, {
            let moved_managed = moved_managed.clone();
            let external = external.clone();
            move |validated_target| {
                std::fs::rename(validated_target, &moved_managed)
                    .expect("move managed target out of the way");
                std::os::unix::fs::symlink(&external, validated_target)
                    .expect("replace target with external symlink");
            }
        });

        let error = operations
            .apply(uninstall)
            .expect_err("raced uninstall must fail closed");
        assert!(matches!(
            error.code(),
            LocalDaemonErrorCode::UnsafeTransaction | LocalDaemonErrorCode::StalePlan
        ));
        let external_after = std::fs::metadata(&external).expect("external metadata after refusal");
        assert_eq!(
            (external_before.dev(), external_before.ino()),
            (external_after.dev(), external_after.ino())
        );
        assert_eq!(
            std::fs::read(&external).expect("read canary"),
            b"external-canary\n"
        );
        assert!(std::fs::symlink_metadata(&target)
            .expect("restored raced target")
            .file_type()
            .is_symlink());
        assert!(moved_managed.is_file());
        assert!(
            root.join(JOURNAL_PATH).is_file(),
            "unprovable uninstall state must retain its journal"
        );
        let reopen_error = match LocalDaemonOperations::open_staged(&root) {
            Err(error) => error,
            Ok(_) => panic!("unprovable uninstall state must fail closed on reopen"),
        };
        assert_eq!(reopen_error.code(), LocalDaemonErrorCode::UnsafeTransaction);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn manifest_rejects_a_kind_specific_oversized_artifact() {
        let manifest = ReleaseManifest {
            schema_version: RELEASE_MANIFEST_SCHEMA_V2,
            release_version: "v0.4.0".to_string(),
            target: supported_release_target(),
            artifacts: ARTIFACT_SPECS
                .iter()
                .map(|spec| ManifestArtifact {
                    path: spec.bundle_path.to_string(),
                    kind: spec.kind.to_string(),
                    sha256: "0".repeat(64),
                    size_bytes: if spec.kind == "health_binary" {
                        spec.maximum_bytes + 1
                    } else {
                        1
                    },
                    mode: format!("{:04o}", spec.mode),
                })
                .collect(),
        };

        let error = validate_manifest_shape(&manifest)
            .expect_err("kind-specific artifact bound must fail closed");
        assert_eq!(error.code(), LocalDaemonErrorCode::InvalidBundle);
    }

    fn test_workspace(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "apolysis-local-operation-unit-{name}-{}-{}",
            std::process::id(),
            NEXT_OPERATION_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).expect("create test workspace");
        path
    }

    fn create_test_bundle(workspace: &Path, release_version: &str) -> PathBuf {
        let bundle = workspace.join("bundle");
        let mut artifacts = Vec::new();
        for spec in ARTIFACT_SPECS {
            let bytes = format!("fixture:{}:{release_version}\n", spec.kind).into_bytes();
            write_test_file(&bundle.join(spec.bundle_path), &bytes, spec.mode);
            artifacts.push(serde_json::json!({
                "path": spec.bundle_path,
                "kind": spec.kind,
                "sha256": sha256_hex(&bytes),
                "size_bytes": bytes.len(),
                "mode": format!("{:04o}", spec.mode),
            }));
        }
        let manifest = serde_json::json!({
            "schema_version": RELEASE_MANIFEST_SCHEMA_V2,
            "release_version": release_version,
            "target": format!("{}-unknown-linux-gnu", std::env::consts::ARCH),
            "artifacts": artifacts,
        });
        write_test_file(
            &bundle.join(MANIFEST_NAME),
            format!(
                "{}\n",
                serde_json::to_string_pretty(&manifest).expect("serialize test manifest")
            )
            .as_bytes(),
            0o644,
        );
        bundle
    }

    fn write_test_file(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::create_dir_all(path.parent().expect("test file parent"))
            .expect("create test file parent");
        std::fs::write(path, bytes).expect("write test file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .expect("set test file mode");
    }

    fn assert_no_transaction_entries(root: &Path) {
        for relative in [
            "usr/local/bin",
            "usr/local/lib/apolysis",
            "etc/systemd/system",
        ] {
            let directory = root.join(relative);
            let Ok(entries) = std::fs::read_dir(directory) else {
                continue;
            };
            for entry in entries {
                let name = entry
                    .expect("read managed directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned();
                assert!(
                    !name.starts_with(".apolysis-")
                        && name != ".local-operation-transaction-v1.json",
                    "unexpected transaction entry {name}"
                );
            }
        }
    }

    fn journal_staging_entries(root: &Path) -> Vec<OsString> {
        let directory = root.join("usr/local/lib/apolysis");
        let Ok(entries) = std::fs::read_dir(directory) else {
            return Vec::new();
        };
        entries
            .map(|entry| entry.expect("read journal directory entry").file_name())
            .filter(|name| {
                name.as_bytes()
                    .starts_with(JOURNAL_STAGING_PREFIX.as_bytes())
            })
            .collect()
    }
}
