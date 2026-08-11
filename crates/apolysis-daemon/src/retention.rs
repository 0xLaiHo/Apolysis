// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::ffi::CString;
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

static NEXT_RETENTION_TRANSACTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionError {
    UnsafeTarget,
    UnsafeTrash,
    StageFailed,
    StageRollbackFailed,
    CleanupIncomplete,
    ClockUnavailable,
}

impl RetentionError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsafeTarget => "retention_target_unsafe",
            Self::UnsafeTrash => "retention_trash_unsafe",
            Self::StageFailed => "retention_stage_failed",
            Self::StageRollbackFailed => "retention_stage_rollback_failed",
            Self::CleanupIncomplete => "retention_cleanup_incomplete",
            Self::ClockUnavailable => "retention_clock_unavailable",
        }
    }
}

impl std::fmt::Display for RetentionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for RetentionError {}

pub(super) struct AgentRunRetentionTarget {
    agent_run_id: String,
    agent_run_path: PathBuf,
    device: u64,
    inode: u64,
    timeline_device: u64,
    timeline_inode: u64,
}

impl AgentRunRetentionTarget {
    pub(super) fn agent_run_path(&self) -> &Path {
        &self.agent_run_path
    }

    pub(super) const fn directory_device(&self) -> u64 {
        self.device
    }

    pub(super) const fn directory_inode(&self) -> u64 {
        self.inode
    }

    pub(super) const fn timeline_device(&self) -> u64 {
        self.timeline_device
    }

    pub(super) const fn timeline_inode(&self) -> u64 {
        self.timeline_inode
    }
}

const RETENTION_JOURNAL_SCHEMA_VERSION: u32 = 1;
const RETENTION_JOURNAL_FILE: &str = "transaction-v1.json";
const RETENTION_JOURNAL_TEMP_FILE: &str = "transaction-v1.json.tmp";
const RETENTION_JOURNAL_MAX_BYTES: u64 = 64 * 1024;
// The on-disk directory name predates the Agent Run domain terminology.
const LEGACY_AGENT_RUN_STORAGE_DIR: &str = "sessions";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RetentionTransactionStatus {
    Staging,
    Committed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RetentionJournalAgentRun {
    agent_run_id: String,
    device: u64,
    inode: u64,
    timeline_device: u64,
    timeline_inode: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RetentionJournal {
    schema_version: u32,
    status: RetentionTransactionStatus,
    targets: Vec<RetentionJournalAgentRun>,
}

pub(super) struct RetentionTransaction {
    transaction_dir: PathBuf,
    trash_root: PathBuf,
    journal: RetentionJournal,
}

impl RetentionTransaction {
    pub(super) fn commit(&mut self) -> Result<(), RetentionError> {
        self.journal.status = RetentionTransactionStatus::Committed;
        write_retention_journal(&self.transaction_dir, &self.journal)
            .map_err(|_| RetentionError::StageFailed)
    }

    pub(super) fn rollback(self) -> Result<(), RetentionError> {
        rollback_retention_transaction(&self.transaction_dir, &self.trash_root, &self.journal)
    }

    pub(super) fn cleanup(self) -> Result<(), RetentionError> {
        cleanup_retention_transaction(&self.transaction_dir, &self.trash_root, &self.journal)
    }
}

pub(super) fn validate_agent_run_retention_target(
    agent_runs_dir: &Path,
    agent_run_id: &str,
) -> Result<AgentRunRetentionTarget, RetentionError> {
    let agent_run_path = Path::new(agent_run_id);
    let mut components = agent_run_path.components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(RetentionError::UnsafeTarget);
    }

    let agent_runs_metadata =
        std::fs::symlink_metadata(agent_runs_dir).map_err(|_| RetentionError::UnsafeTarget)?;
    if !agent_runs_metadata.file_type().is_dir() {
        return Err(RetentionError::UnsafeTarget);
    }
    let agent_run_dir = agent_runs_dir.join(agent_run_path);
    let metadata =
        std::fs::symlink_metadata(&agent_run_dir).map_err(|_| RetentionError::UnsafeTarget)?;
    if !metadata.file_type().is_dir()
        || metadata.dev() != agent_runs_metadata.dev()
        || metadata.uid() != agent_runs_metadata.uid()
    {
        return Err(RetentionError::UnsafeTarget);
    }

    let mut timeline_identity = None;
    for entry in std::fs::read_dir(&agent_run_dir).map_err(|_| RetentionError::UnsafeTarget)? {
        let entry = entry.map_err(|_| RetentionError::UnsafeTarget)?;
        let file_type = entry
            .file_type()
            .map_err(|_| RetentionError::UnsafeTarget)?;
        if !file_type.is_file() {
            return Err(RetentionError::UnsafeTarget);
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(RetentionError::UnsafeTarget);
        };
        let file_metadata =
            std::fs::symlink_metadata(entry.path()).map_err(|_| RetentionError::UnsafeTarget)?;
        if !file_metadata.file_type().is_file()
            || file_metadata.dev() != metadata.dev()
            || file_metadata.uid() != metadata.uid()
            || file_metadata.nlink() != 1
        {
            return Err(RetentionError::UnsafeTarget);
        }
        if name == "timeline.jsonl" {
            timeline_identity = Some((file_metadata.dev(), file_metadata.ino()));
        } else if !valid_quarantine_name(name) {
            return Err(RetentionError::UnsafeTarget);
        }
    }
    let Some((timeline_device, timeline_inode)) = timeline_identity else {
        return Err(RetentionError::UnsafeTarget);
    };
    Ok(AgentRunRetentionTarget {
        agent_run_id: agent_run_id.to_string(),
        agent_run_path: agent_run_dir,
        device: metadata.dev(),
        inode: metadata.ino(),
        timeline_device,
        timeline_inode,
    })
}

pub(super) fn stage_agent_run_retention_targets(
    agent_runs_dir: &Path,
    targets: &[AgentRunRetentionTarget],
) -> Result<RetentionTransaction, RetentionError> {
    let trash_root = ensure_retention_trash_root(agent_runs_dir)?;
    let transaction_dir = create_retention_transaction_dir(&trash_root)?;
    let journal = RetentionJournal {
        schema_version: RETENTION_JOURNAL_SCHEMA_VERSION,
        status: RetentionTransactionStatus::Staging,
        targets: targets
            .iter()
            .map(|target| RetentionJournalAgentRun {
                agent_run_id: target.agent_run_id.clone(),
                device: target.device,
                inode: target.inode,
                timeline_device: target.timeline_device,
                timeline_inode: target.timeline_inode,
            })
            .collect(),
    };
    if write_retention_journal(&transaction_dir, &journal).is_err()
        || sync_directory(&trash_root).is_err()
    {
        return Err(fail_retention_stage(&transaction_dir, &trash_root, &[]));
    }
    let mut moved = Vec::with_capacity(targets.len());

    for target in targets {
        let Some(file_name) = target.agent_run_path.file_name() else {
            return Err(fail_retention_stage(&transaction_dir, &trash_root, &moved));
        };
        let staged_path = transaction_dir.join(file_name);
        if std::fs::rename(&target.agent_run_path, &staged_path).is_err() {
            return Err(fail_retention_stage(&transaction_dir, &trash_root, &moved));
        }
        moved.push((target.agent_run_path.clone(), staged_path.clone()));
        let staged_metadata = match std::fs::symlink_metadata(&staged_path) {
            Ok(metadata) => metadata,
            Err(_) => {
                return Err(fail_retention_stage(&transaction_dir, &trash_root, &moved));
            }
        };
        if !staged_metadata.file_type().is_dir()
            || staged_metadata.dev() != target.device
            || staged_metadata.ino() != target.inode
        {
            return Err(fail_retention_stage(&transaction_dir, &trash_root, &moved));
        }
        let staged_target =
            match validate_agent_run_retention_target(&transaction_dir, &target.agent_run_id) {
                Ok(staged_target) => staged_target,
                Err(_) => {
                    return Err(fail_retention_stage(&transaction_dir, &trash_root, &moved));
                }
            };
        if staged_target.device != target.device
            || staged_target.inode != target.inode
            || staged_target.timeline_device != target.timeline_device
            || staged_target.timeline_inode != target.timeline_inode
        {
            return Err(fail_retention_stage(&transaction_dir, &trash_root, &moved));
        }
    }

    if sync_directory(agent_runs_dir).is_err()
        || sync_directory(&transaction_dir).is_err()
        || sync_directory(&trash_root).is_err()
    {
        return Err(fail_retention_stage(&transaction_dir, &trash_root, &moved));
    }
    Ok(RetentionTransaction {
        transaction_dir,
        trash_root,
        journal,
    })
}

fn ensure_retention_trash_root(agent_runs_dir: &Path) -> Result<PathBuf, RetentionError> {
    let agent_runs_metadata =
        std::fs::symlink_metadata(agent_runs_dir).map_err(|_| RetentionError::UnsafeTrash)?;
    if !agent_runs_metadata.file_type().is_dir() {
        return Err(RetentionError::UnsafeTrash);
    }
    let state_dir = agent_runs_dir.parent().ok_or(RetentionError::UnsafeTrash)?;
    let trash_root = state_dir.join(".retention-trash");
    match std::fs::symlink_metadata(&trash_root) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {
            DirBuilder::new()
                .mode(0o700)
                .create(&trash_root)
                .map_err(|_| RetentionError::UnsafeTrash)?;
            sync_directory(state_dir).map_err(|_| RetentionError::UnsafeTrash)?;
        }
        Err(_) => return Err(RetentionError::UnsafeTrash),
    }
    let metadata =
        std::fs::symlink_metadata(&trash_root).map_err(|_| RetentionError::UnsafeTrash)?;
    if !metadata.file_type().is_dir()
        || metadata.dev() != agent_runs_metadata.dev()
        || metadata.uid() != agent_runs_metadata.uid()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(RetentionError::UnsafeTrash);
    }
    Ok(trash_root)
}

fn create_retention_transaction_dir(trash_root: &Path) -> Result<PathBuf, RetentionError> {
    for _ in 0..32 {
        let id = NEXT_RETENTION_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
        let transaction_dir = trash_root.join(format!("purge-{}-{id}", std::process::id()));
        match DirBuilder::new().mode(0o700).create(&transaction_dir) {
            Ok(()) => return Ok(transaction_dir),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(RetentionError::StageFailed),
        }
    }
    Err(RetentionError::StageFailed)
}

fn write_retention_journal(
    transaction_dir: &Path,
    journal: &RetentionJournal,
) -> Result<(), RetentionError> {
    let bytes = serde_json::to_vec(journal).map_err(|_| RetentionError::StageFailed)?;
    let temporary = transaction_dir.join(RETENTION_JOURNAL_TEMP_FILE);
    match std::fs::remove_file(&temporary) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(_) => return Err(RetentionError::StageFailed),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temporary)
        .map_err(|_| RetentionError::StageFailed)?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| RetentionError::StageFailed)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| RetentionError::StageFailed)?;
    let metadata = file.metadata().map_err(|_| RetentionError::StageFailed)?;
    if !private_retention_journal_metadata(&metadata) || metadata.len() != bytes.len() as u64 {
        return Err(RetentionError::StageFailed);
    }
    std::fs::rename(&temporary, transaction_dir.join(RETENTION_JOURNAL_FILE))
        .map_err(|_| RetentionError::StageFailed)?;
    sync_directory(transaction_dir).map_err(|_| RetentionError::StageFailed)
}

fn read_retention_journal(transaction_dir: &Path) -> Result<RetentionJournal, RetentionError> {
    let transaction = open_retention_transaction_directory(transaction_dir)?;
    validate_optional_private_retention_journal_at(&transaction, RETENTION_JOURNAL_TEMP_FILE)?;
    let mut file = open_retention_journal_file_at(&transaction, RETENTION_JOURNAL_FILE)
        .map_err(|_| RetentionError::UnsafeTrash)?;
    let metadata = file.metadata().map_err(|_| RetentionError::UnsafeTrash)?;
    if !private_retention_journal_metadata(&metadata) {
        return Err(RetentionError::UnsafeTrash);
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(RETENTION_JOURNAL_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RetentionError::UnsafeTrash)?;
    if bytes.len() as u64 > RETENTION_JOURNAL_MAX_BYTES {
        return Err(RetentionError::UnsafeTrash);
    }
    let current = open_retention_journal_file_at(&transaction, RETENTION_JOURNAL_FILE)
        .map_err(|_| RetentionError::UnsafeTrash)?;
    let current_metadata = current
        .metadata()
        .map_err(|_| RetentionError::UnsafeTrash)?;
    if !private_retention_journal_metadata(&current_metadata)
        || current_metadata.dev() != metadata.dev()
        || current_metadata.ino() != metadata.ino()
    {
        return Err(RetentionError::UnsafeTrash);
    }
    let journal: RetentionJournal =
        serde_json::from_slice(&bytes).map_err(|_| RetentionError::UnsafeTrash)?;
    validate_retention_journal(&journal)?;
    Ok(journal)
}

fn open_retention_transaction_directory(path: &Path) -> Result<File, RetentionError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| RetentionError::UnsafeTrash)?;
    let opened = directory
        .metadata()
        .map_err(|_| RetentionError::UnsafeTrash)?;
    let current = std::fs::symlink_metadata(path).map_err(|_| RetentionError::UnsafeTrash)?;
    if !opened.file_type().is_dir()
        || !current.file_type().is_dir()
        || opened.dev() != current.dev()
        || opened.ino() != current.ino()
        || opened.uid() != effective_uid()
        || opened.gid() != effective_gid()
        || opened.mode() & 0o7777 != 0o700
    {
        return Err(RetentionError::UnsafeTrash);
    }
    Ok(directory)
}

fn open_retention_journal_file_at(transaction: &File, file_name: &str) -> std::io::Result<File> {
    let name = CString::new(file_name)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `transaction` is a verified open directory and `name` is one
    // fixed, NUL-terminated component. O_NOFOLLOW rejects a linked journal.
    let descriptor = unsafe {
        libc::openat(
            transaction.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the non-negative descriptor returned by openat is transferred
    // into exactly one File.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_optional_private_retention_journal_at(
    transaction: &File,
    file_name: &str,
) -> Result<(), RetentionError> {
    let file = match open_retention_journal_file_at(transaction, file_name) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(RetentionError::UnsafeTrash),
    };
    let metadata = file.metadata().map_err(|_| RetentionError::UnsafeTrash)?;
    if !private_retention_journal_metadata(&metadata) {
        return Err(RetentionError::UnsafeTrash);
    }
    let current = open_retention_journal_file_at(transaction, file_name)
        .map_err(|_| RetentionError::UnsafeTrash)?;
    let current_metadata = current
        .metadata()
        .map_err(|_| RetentionError::UnsafeTrash)?;
    if !private_retention_journal_metadata(&current_metadata)
        || current_metadata.dev() != metadata.dev()
        || current_metadata.ino() != metadata.ino()
    {
        return Err(RetentionError::UnsafeTrash);
    }
    Ok(())
}

fn private_retention_journal_metadata(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_file()
        && metadata.nlink() == 1
        && metadata.len() <= RETENTION_JOURNAL_MAX_BYTES
        && metadata.mode() & 0o7777 == 0o600
        && metadata.uid() == effective_uid()
        && metadata.gid() == effective_gid()
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }
}

fn effective_gid() -> u32 {
    // SAFETY: getegid has no preconditions and does not dereference pointers.
    unsafe { libc::getegid() }
}

fn validate_retention_journal(journal: &RetentionJournal) -> Result<(), RetentionError> {
    if journal.schema_version != RETENTION_JOURNAL_SCHEMA_VERSION || journal.targets.is_empty() {
        return Err(RetentionError::UnsafeTrash);
    }
    let mut agent_run_ids = BTreeSet::new();
    for target in &journal.targets {
        if !valid_agent_run_component(&target.agent_run_id)
            || !agent_run_ids.insert(target.agent_run_id.as_str())
        {
            return Err(RetentionError::UnsafeTrash);
        }
    }
    Ok(())
}

fn rollback_retention_transaction(
    transaction_dir: &Path,
    trash_root: &Path,
    journal: &RetentionJournal,
) -> Result<(), RetentionError> {
    let agent_runs_dir = trash_root
        .parent()
        .ok_or(RetentionError::StageRollbackFailed)?
        .join(LEGACY_AGENT_RUN_STORAGE_DIR);
    for target in journal.targets.iter().rev() {
        let staged = transaction_dir.join(&target.agent_run_id);
        let live_agent_run = agent_runs_dir.join(&target.agent_run_id);
        match std::fs::symlink_metadata(&staged) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir()
                    || metadata.dev() != target.device
                    || metadata.ino() != target.inode
                    || std::fs::symlink_metadata(&live_agent_run).is_ok()
                {
                    return Err(RetentionError::StageRollbackFailed);
                }
                let validated =
                    validate_agent_run_retention_target(transaction_dir, &target.agent_run_id)
                        .map_err(|_| RetentionError::StageRollbackFailed)?;
                if !journal_target_matches(target, &validated) {
                    return Err(RetentionError::StageRollbackFailed);
                }
                std::fs::rename(&staged, &live_agent_run)
                    .map_err(|_| RetentionError::StageRollbackFailed)?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                let metadata = std::fs::symlink_metadata(&live_agent_run)
                    .map_err(|_| RetentionError::StageRollbackFailed)?;
                if !metadata.file_type().is_dir()
                    || metadata.dev() != target.device
                    || metadata.ino() != target.inode
                {
                    return Err(RetentionError::StageRollbackFailed);
                }
                let validated =
                    validate_agent_run_retention_target(&agent_runs_dir, &target.agent_run_id)
                        .map_err(|_| RetentionError::StageRollbackFailed)?;
                if !journal_target_matches(target, &validated) {
                    return Err(RetentionError::StageRollbackFailed);
                }
            }
            Err(_) => return Err(RetentionError::StageRollbackFailed),
        }
    }
    remove_retention_journal_files(transaction_dir)
        .map_err(|_| RetentionError::StageRollbackFailed)?;
    std::fs::remove_dir(transaction_dir).map_err(|_| RetentionError::StageRollbackFailed)?;
    sync_directory(&agent_runs_dir).map_err(|_| RetentionError::StageRollbackFailed)?;
    sync_directory(trash_root).map_err(|_| RetentionError::StageRollbackFailed)
}

fn journal_target_matches(
    journal: &RetentionJournalAgentRun,
    target: &AgentRunRetentionTarget,
) -> bool {
    journal.device == target.device
        && journal.inode == target.inode
        && journal.timeline_device == target.timeline_device
        && journal.timeline_inode == target.timeline_inode
}

fn cleanup_retention_transaction(
    transaction_dir: &Path,
    trash_root: &Path,
    journal: &RetentionJournal,
) -> Result<(), RetentionError> {
    if journal.status != RetentionTransactionStatus::Committed {
        return Err(RetentionError::CleanupIncomplete);
    }
    let agent_runs_dir = trash_root
        .parent()
        .ok_or(RetentionError::CleanupIncomplete)?
        .join(LEGACY_AGENT_RUN_STORAGE_DIR);
    for entry in
        std::fs::read_dir(transaction_dir).map_err(|_| RetentionError::CleanupIncomplete)?
    {
        let entry = entry.map_err(|_| RetentionError::CleanupIncomplete)?;
        let name = entry.file_name();
        let is_journal = [RETENTION_JOURNAL_FILE, RETENTION_JOURNAL_TEMP_FILE]
            .iter()
            .any(|allowed| name == *allowed);
        let is_agent_run = journal
            .targets
            .iter()
            .any(|target| name == target.agent_run_id.as_str());
        if !is_journal && !is_agent_run {
            return Err(RetentionError::CleanupIncomplete);
        }
    }
    let mut cleanup_plans = Vec::with_capacity(journal.targets.len());
    for target in &journal.targets {
        match std::fs::symlink_metadata(agent_runs_dir.join(&target.agent_run_id)) {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            _ => return Err(RetentionError::CleanupIncomplete),
        }
        if let Some(plan) = plan_staged_agent_run_cleanup(transaction_dir, target)? {
            cleanup_plans.push(plan);
        }
    }
    for plan in cleanup_plans {
        execute_staged_agent_run_cleanup(plan)?;
    }
    remove_retention_journal_files(transaction_dir)
        .map_err(|_| RetentionError::CleanupIncomplete)?;
    std::fs::remove_dir(transaction_dir).map_err(|_| RetentionError::CleanupIncomplete)?;
    sync_directory(trash_root).map_err(|_| RetentionError::CleanupIncomplete)
}

struct StagedAgentRunCleanup {
    staged: PathBuf,
    ordinary_files: Vec<PathBuf>,
    timeline: Option<PathBuf>,
}

fn plan_staged_agent_run_cleanup(
    transaction_dir: &Path,
    target: &RetentionJournalAgentRun,
) -> Result<Option<StagedAgentRunCleanup>, RetentionError> {
    let staged = transaction_dir.join(&target.agent_run_id);
    let directory_metadata = match std::fs::symlink_metadata(&staged) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(RetentionError::CleanupIncomplete),
    };
    if !directory_metadata.file_type().is_dir()
        || directory_metadata.dev() != target.device
        || directory_metadata.ino() != target.inode
    {
        return Err(RetentionError::CleanupIncomplete);
    }

    let mut ordinary_files = Vec::new();
    let mut timeline = None;
    for entry in std::fs::read_dir(&staged).map_err(|_| RetentionError::CleanupIncomplete)? {
        let entry = entry.map_err(|_| RetentionError::CleanupIncomplete)?;
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|_| RetentionError::CleanupIncomplete)?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(RetentionError::CleanupIncomplete);
        };
        if !metadata.file_type().is_file()
            || metadata.dev() != directory_metadata.dev()
            || metadata.uid() != directory_metadata.uid()
            || metadata.nlink() != 1
        {
            return Err(RetentionError::CleanupIncomplete);
        }
        if name == "timeline.jsonl" {
            if metadata.dev() != target.timeline_device || metadata.ino() != target.timeline_inode {
                return Err(RetentionError::CleanupIncomplete);
            }
            timeline = Some(entry.path());
        } else if valid_quarantine_name(name) {
            ordinary_files.push(entry.path());
        } else {
            return Err(RetentionError::CleanupIncomplete);
        }
    }

    if timeline.is_none() && !ordinary_files.is_empty() {
        return Err(RetentionError::CleanupIncomplete);
    }
    Ok(Some(StagedAgentRunCleanup {
        staged,
        ordinary_files,
        timeline,
    }))
}

fn execute_staged_agent_run_cleanup(cleanup: StagedAgentRunCleanup) -> Result<(), RetentionError> {
    for path in cleanup.ordinary_files {
        std::fs::remove_file(path).map_err(|_| RetentionError::CleanupIncomplete)?;
    }
    if let Some(timeline) = cleanup.timeline {
        std::fs::remove_file(timeline).map_err(|_| RetentionError::CleanupIncomplete)?;
    } else if std::fs::read_dir(&cleanup.staged)
        .map_err(|_| RetentionError::CleanupIncomplete)?
        .next()
        .is_some()
    {
        return Err(RetentionError::CleanupIncomplete);
    }
    std::fs::remove_dir(&cleanup.staged).map_err(|_| RetentionError::CleanupIncomplete)
}

fn remove_retention_journal_files(transaction_dir: &Path) -> std::io::Result<()> {
    for file_name in [RETENTION_JOURNAL_TEMP_FILE, RETENTION_JOURNAL_FILE] {
        match std::fs::remove_file(transaction_dir.join(file_name)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn recover_retention_transactions(agent_runs_dir: &Path) -> Result<(), RetentionError> {
    let trash_root = ensure_retention_trash_root(agent_runs_dir)?;
    let entries = std::fs::read_dir(&trash_root).map_err(|_| RetentionError::UnsafeTrash)?;
    for entry in entries {
        let entry = entry.map_err(|_| RetentionError::UnsafeTrash)?;
        let file_type = entry.file_type().map_err(|_| RetentionError::UnsafeTrash)?;
        let name = entry.file_name();
        if !file_type.is_dir() || !name.to_str().is_some_and(|name| name.starts_with("purge-")) {
            return Err(RetentionError::UnsafeTrash);
        }
        let transaction_dir = entry.path();
        let journal = match read_retention_journal(&transaction_dir) {
            Ok(journal) => journal,
            Err(_) if retention_transaction_is_unstarted(&transaction_dir)? => {
                remove_retention_journal_files(&transaction_dir)
                    .map_err(|_| RetentionError::UnsafeTrash)?;
                std::fs::remove_dir(&transaction_dir).map_err(|_| RetentionError::UnsafeTrash)?;
                continue;
            }
            Err(error) => return Err(error),
        };
        match journal.status {
            RetentionTransactionStatus::Staging => {
                rollback_retention_transaction(&transaction_dir, &trash_root, &journal)
                    .map_err(|_| RetentionError::StageRollbackFailed)?;
            }
            RetentionTransactionStatus::Committed => {
                cleanup_retention_transaction(&transaction_dir, &trash_root, &journal)?;
            }
        }
    }
    sync_directory(&trash_root).map_err(|_| RetentionError::UnsafeTrash)
}

fn retention_transaction_is_unstarted(transaction_dir: &Path) -> Result<bool, RetentionError> {
    let transaction = open_retention_transaction_directory(transaction_dir)?;
    let mut has_temporary_journal = false;
    for entry in std::fs::read_dir(transaction_dir).map_err(|_| RetentionError::UnsafeTrash)? {
        let entry = entry.map_err(|_| RetentionError::UnsafeTrash)?;
        if entry.file_name() != RETENTION_JOURNAL_TEMP_FILE {
            return Ok(false);
        }
        has_temporary_journal = true;
    }
    if has_temporary_journal {
        validate_optional_private_retention_journal_at(&transaction, RETENTION_JOURNAL_TEMP_FILE)?;
    }
    Ok(true)
}

fn valid_agent_run_component(agent_run_id: &str) -> bool {
    let mut components = Path::new(agent_run_id).components();
    matches!(components.next(), Some(std::path::Component::Normal(_)))
        && components.next().is_none()
}

fn valid_quarantine_name(name: &str) -> bool {
    let Some(suffix) = name.strip_prefix("timeline.jsonl.quarantine-") else {
        return false;
    };
    let parts: Vec<_> = suffix.split('-').collect();
    matches!(parts.len(), 1 | 3)
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn fail_retention_stage(
    transaction_dir: &Path,
    trash_root: &Path,
    moved: &[(PathBuf, PathBuf)],
) -> RetentionError {
    let mut rollback_failed = false;
    for (agent_run_path, staged_path) in moved.iter().rev() {
        if std::fs::rename(staged_path, agent_run_path).is_err() {
            rollback_failed = true;
        }
    }
    if rollback_failed {
        let _ = sync_directory(trash_root);
        return RetentionError::StageRollbackFailed;
    }
    if moved
        .first()
        .and_then(|(agent_run_path, _)| agent_run_path.parent())
        .is_some_and(|agent_runs_dir| sync_directory(agent_runs_dir).is_err())
    {
        let _ = sync_directory(trash_root);
        return RetentionError::StageRollbackFailed;
    }
    for file_name in [RETENTION_JOURNAL_TEMP_FILE, RETENTION_JOURNAL_FILE] {
        match std::fs::remove_file(transaction_dir.join(file_name)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(_) => rollback_failed = true,
        }
    }
    if std::fs::remove_dir(transaction_dir).is_err() {
        rollback_failed = true;
    }
    if sync_directory(trash_root).is_err() {
        rollback_failed = true;
    }
    if rollback_failed {
        RetentionError::StageRollbackFailed
    } else {
        RetentionError::StageFailed
    }
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}
