// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
mod chat;
mod cli;
mod intent;
#[cfg(target_os = "linux")]
mod native;

use std::fs::{File, OpenOptions};
use std::io::{Read as IoRead, Write as IoWrite};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use apolysis_accountability::{
    project_agent_run, AccountabilityFinding, AgentRunRecordBatch, EvidenceBoundary,
    FindingDecision, FindingKind, RuntimeIdentity, FINDING_SCHEMA_V1,
    MAX_AGENT_RUN_PROJECTION_BATCHES, MAX_AGENT_RUN_PROJECTION_RECORDS,
};
use apolysis_core::{now_unix_ms, JsonLine};
use apolysis_daemon::{LocalDaemonChange, LocalDaemonOperations};
use apolysis_observer::{
    observe_fixture, observe_live, AgentDiscoveryRequest, AgentRunRequest, FixtureObserveRequest,
    LiveObserveRequest, LiveScope,
};
use apolysis_store::{
    read_agent_run_records, HashChainStore, JsonlRotationPolicy, LocalRecordFormat,
    MAX_SAVED_RUN_BYTES,
};
use apolysis_visibility::{assess_visibility, RuntimeVisibilityProfile, VisibilityInput};
use cli::{commands, options, values};

static NEXT_PRIVATE_OUTPUT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

#[tokio::main]
async fn main() {
    let exit_code = match run(std::env::args().skip(1).collect()).await {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("apolysis: {error}");
            2
        }
    };
    std::process::exit(exit_code);
}

async fn run(args: Vec<String>) -> Result<i32, String> {
    #[cfg(target_os = "linux")]
    if native::handles(&args) {
        return native::run(&args).await;
    }
    match args.first().map(String::as_str) {
        #[cfg(target_os = "linux")]
        Some("chat") => chat::run(&args[1..]).await,
        Some(commands::OBSERVE) => observe_command(args).await,
        Some(commands::RUN) => run_command(args),
        Some(commands::DAEMON) => daemon_command(args),
        Some(commands::INTENT) => intent_command(args).await,
        Some(commands::VISIBILITY) => visibility_command(args).await,
        Some(commands::VERIFY) => verify_command(args).await,
        _ => Err(usage()),
    }
}

fn daemon_command(args: Vec<String>) -> Result<i32, String> {
    match args.get(1).map(String::as_str) {
        Some(commands::INSTALL) => daemon_install_command(args),
        Some(commands::INSPECT) => daemon_inspect_command(args),
        Some(commands::UNINSTALL) => daemon_uninstall_command(args),
        _ => Err(usage()),
    }
}

fn daemon_install_command(args: Vec<String>) -> Result<i32, String> {
    let request = LocalDaemonRequest::parse(args, true)?;
    let bundle_root = request
        .bundle_root
        .ok_or_else(|| "daemon install requires --bundle <dir>".to_string())?;
    let mut operations = LocalDaemonOperations::open_staged(&request.root)
        .map_err(|error| format!("daemon install failed: {error}"))?;
    let plan = operations
        .plan(LocalDaemonChange::Install { bundle_root })
        .map_err(|error| format!("daemon install failed: {error}"))?;
    let report = operations
        .apply(plan)
        .map_err(|error| format!("daemon install failed: {error}"))?;
    let inspection = operations
        .inspect()
        .map_err(|error| format!("daemon install verification failed: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "operation": "install",
            "changed_files": report.changed_files(),
            "installed": inspection.installed(),
            "release_version": inspection.release_version(),
            "target": inspection.target(),
            "agent_run_state_preserved": report.preserved_agent_run_state(),
            "recovered_interrupted_operation": inspection.recovered_interrupted_operation(),
            "systemd_activated": false,
        })
    );
    Ok(0)
}

fn daemon_inspect_command(args: Vec<String>) -> Result<i32, String> {
    let request = LocalDaemonRequest::parse(args, false)?;
    let operations = LocalDaemonOperations::open_staged(&request.root)
        .map_err(|error| format!("daemon inspect failed: {error}"))?;
    let inspection = operations
        .inspect()
        .map_err(|error| format!("daemon inspect failed: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "operation": "inspect",
            "installed": inspection.installed(),
            "release_version": inspection.release_version(),
            "target": inspection.target(),
            "recovered_interrupted_operation": inspection.recovered_interrupted_operation(),
            "systemd_activated": false,
        })
    );
    Ok(0)
}

fn daemon_uninstall_command(args: Vec<String>) -> Result<i32, String> {
    let request = LocalDaemonRequest::parse(args, false)?;
    let mut operations = LocalDaemonOperations::open_staged(&request.root)
        .map_err(|error| format!("daemon uninstall failed: {error}"))?;
    let recovered_interrupted_operation = operations
        .inspect()
        .map_err(|error| format!("daemon uninstall failed: {error}"))?
        .recovered_interrupted_operation();
    let plan = operations
        .plan(LocalDaemonChange::UninstallPreserveState)
        .map_err(|error| format!("daemon uninstall failed: {error}"))?;
    let report = operations
        .apply(plan)
        .map_err(|error| format!("daemon uninstall failed: {error}"))?;
    println!(
        "{}",
        serde_json::json!({
            "schema_version": 1,
            "operation": "uninstall",
            "changed_files": report.changed_files(),
            "installed": false,
            "agent_run_state_preserved": report.preserved_agent_run_state(),
            "recovered_interrupted_operation": recovered_interrupted_operation,
            "systemd_activated": false,
        })
    );
    Ok(0)
}

struct LocalDaemonRequest {
    root: PathBuf,
    bundle_root: Option<PathBuf>,
}

impl LocalDaemonRequest {
    fn parse(args: Vec<String>, allow_bundle: bool) -> Result<Self, String> {
        let mut root = None;
        let mut bundle_root = None;
        let mut index = 2;
        while index < args.len() {
            let option = args[index].as_str();
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{option} requires a value"))?;
            match option {
                options::ROOT if root.is_none() => root = Some(PathBuf::from(value)),
                options::BUNDLE if allow_bundle && bundle_root.is_none() => {
                    bundle_root = Some(PathBuf::from(value));
                }
                _ => return Err(usage()),
            }
            index += 2;
        }
        let root = root.ok_or_else(|| {
            "daemon filesystem operations require an explicit --root <dir>".to_string()
        })?;
        if allow_bundle && bundle_root.is_none() {
            return Err("daemon install requires --bundle <dir>".to_string());
        }
        Ok(Self { root, bundle_root })
    }
}

fn run_command(args: Vec<String>) -> Result<i32, String> {
    match args.get(1).map(String::as_str) {
        Some(commands::PROJECT) => run_project_command(args),
        Some(commands::VIEW) => run_view_command(args),
        _ => Err(usage()),
    }
}

fn run_view_command(args: Vec<String>) -> Result<i32, String> {
    let request = ViewRunRequest::parse(args)?;
    let input = read_stable_bounded_regular_file(&request.input_path, MAX_SAVED_RUN_BYTES)
        .map_err(|error| format!("failed to read Agent Observation Record for viewing: {error}"))?;
    ensure_distinct_view_output(&input, &request.output_path)?;
    let html = apolysis_viewer::render_agent_observation_record_v1(&input.bytes)
        .map_err(|error| format!("failed to render saved Agent Run: {error}"))?;
    write_private_atomic(&request.output_path, html.as_ref())
        .map_err(|error| format!("failed to write saved Agent Run view: {error}"))?;
    Ok(0)
}

fn run_project_command(args: Vec<String>) -> Result<i32, String> {
    let request = ProjectRunRequest::parse(args)?;
    let mut batches = Vec::with_capacity(request.input_paths.len());
    let mut source_paths = Vec::new();
    let mut total_input_bytes = 0_u64;
    let mut total_input_records = 0_u64;
    for input_path in &request.input_paths {
        let batch = read_agent_run_records(input_path)
            .map_err(|error| format!("failed to read Agent Run input: {error}"))?;
        let batch_records = u64::try_from(batch.records.len())
            .map_err(|_| "Agent Run input exceeded the total record limit".to_string())?;
        accumulate_projection_input_budget(
            &mut total_input_bytes,
            &mut total_input_records,
            batch.source_bytes,
            batch_records,
        )?;
        source_paths.extend(batch.source_paths().iter().cloned());
        batches.push(match batch.format {
            LocalRecordFormat::PlainJsonl => AgentRunRecordBatch::plain(batch.records),
            LocalRecordFormat::VerifiedHashChain => {
                AgentRunRecordBatch::verified_hash_chain(batch.records)
            }
        });
    }
    ensure_distinct_projection_output(&source_paths, &request.output_path)?;
    let record = project_agent_run(batches)
        .map_err(|error| format!("failed to project Agent Run: {error}"))?;
    let mut output = serde_json::to_vec_pretty(&record)
        .map_err(|_| "failed to serialize Agent Observation Record".to_string())?;
    output.push(b'\n');
    write_private_atomic(&request.output_path, &output)
        .map_err(|error| format!("failed to write Agent Observation Record: {error}"))?;
    Ok(0)
}

fn accumulate_projection_input_budget(
    total_bytes: &mut u64,
    total_records: &mut u64,
    batch_bytes: u64,
    batch_records: u64,
) -> Result<(), String> {
    let next_bytes = total_bytes
        .checked_add(batch_bytes)
        .ok_or_else(|| "Agent Run input exceeded the total byte limit".to_string())?;
    if next_bytes > MAX_SAVED_RUN_BYTES {
        return Err("Agent Run input exceeded the total byte limit".to_string());
    }
    let next_records = total_records
        .checked_add(batch_records)
        .ok_or_else(|| "Agent Run input exceeded the total record limit".to_string())?;
    if next_records > MAX_AGENT_RUN_PROJECTION_RECORDS {
        return Err("Agent Run input exceeded the total record limit".to_string());
    }
    *total_bytes = next_bytes;
    *total_records = next_records;
    Ok(())
}

async fn intent_command(args: Vec<String>) -> Result<i32, String> {
    match args.get(1).map(String::as_str) {
        Some(commands::INGEST) => intent_ingest_command(args).await,
        Some(commands::HOOK) => intent_hook_command(args).await,
        Some("reason") => intent_reason_command(args).await,
        Some(commands::CORRELATE) => intent_correlate_command(args).await,
        _ => Err(usage()),
    }
}

async fn intent_ingest_command(args: Vec<String>) -> Result<i32, String> {
    let request = IntentIngestRequest::parse(args)?;
    let input = tokio::fs::read_to_string(&request.input_path)
        .await
        .map_err(|error| format!("failed to read intent input: {error}"))?;
    let records = intent::ingest(
        &request.adapter,
        &input,
        &request.session_id,
        request.workspace_root.as_deref(),
    )?;
    let mut store = apolysis_store::AsyncJsonlStore::create(&request.output_path)
        .await
        .map_err(|error| format!("failed to create intent output: {error}"))?;
    for record in records {
        store
            .append(&record)
            .await
            .map_err(|error| format!("failed to write intent record: {error}"))?;
    }
    store
        .flush()
        .await
        .map_err(|error| format!("failed to flush intent output: {error}"))?;
    Ok(0)
}

async fn intent_hook_command(args: Vec<String>) -> Result<i32, String> {
    let request = IntentHookRequest::parse(args)?;
    let mut input = Vec::new();
    std::io::Read::read_to_end(&mut std::io::stdin(), &mut input)
        .map_err(|error| format!("failed to read hook input: {error}"))?;
    let value = serde_json::from_slice::<serde_json::Value>(&input)
        .map_err(|_| "failed to parse hook input".to_string())?;
    let output = intent::hook_with_shell_bridge(
        &request.harness,
        &value,
        &request.workspace_root,
        request.session_id.as_deref(),
        request.shell_bridge.as_deref(),
    )?;
    if let Some(diagnostic) = output.diagnostic {
        eprintln!("apolysis: {diagnostic}");
    }
    if request.allow_reason_summary
        && matches!(
            value
                .get("hook_event_name")
                .and_then(serde_json::Value::as_str),
            Some("UserPromptSubmit" | "beforeSubmitPrompt")
        )
    {
        if let Some(prompt) = value.get("prompt").and_then(serde_json::Value::as_str) {
            intent::reason::save_user_prompt(&request.reason_output_path, prompt);
        }
    }
    if let Some(record) = output.record {
        let saved_prompt = if request.allow_reason_summary {
            intent::reason::load_user_prompt(&request.reason_output_path)
        } else {
            None
        };
        let reason = intent::reason::collect_with_user_prompt(
            &value,
            &record,
            request.allow_reason_summary,
            saved_prompt.as_deref(),
        )?;
        if reason.is_some() {
            distinct_output_paths(&request.output_path, &request.reason_output_path)?;
        }
        tokio::task::spawn_blocking(move || {
            apolysis_store::append_intent(&request.output_path, &record)?;
            if let Some(reason) = reason {
                distinct_output_paths(&request.output_path, &request.reason_output_path)
                    .map_err(std::io::Error::other)?;
                apolysis_store::append_intent_reason(&request.reason_output_path, &reason)?;
            }
            Ok::<(), std::io::Error>(())
        })
        .await
        .map_err(|_| "intent writer task failed".to_string())?
        .map_err(|error| format!("failed to append intent record: {error}"))?;
    }
    let response = serde_json::to_string(&output.response)
        .map_err(|error| format!("failed to serialize hook response: {error}"))?;
    println!("{response}");
    Ok(0)
}

// Explicit late annotations use the same native identity calculation as hooks.
// They never rewrite a command or create a new execution declaration.
async fn intent_reason_command(mut args: Vec<String>) -> Result<i32, String> {
    args[1] = commands::HOOK.to_string();
    if !args.iter().any(|arg| arg == options::WORKSPACE_ROOT) {
        args.extend([options::WORKSPACE_ROOT.to_string(), ".".to_string()]);
    }
    let request = IntentHookRequest::parse(args)?;
    let mut input = Vec::new();
    std::io::Read::read_to_end(&mut std::io::stdin(), &mut input)
        .map_err(|_| "failed to read reason input".to_string())?;
    let value: serde_json::Value =
        serde_json::from_slice(&input).map_err(|_| "failed to parse reason input".to_string())?;
    if value.get("apolysis_reason").is_none() {
        return Err("late annotation requires apolysis_reason".to_string());
    }
    let output = if let Some(shell) = request.shell_bridge.as_deref() {
        intent::hook_with_shell_bridge(
            &request.harness,
            &value,
            &request.workspace_root,
            request.session_id.as_deref(),
            Some(shell),
        )?
    } else {
        intent::hook(
            &request.harness,
            &value,
            &request.workspace_root,
            request.session_id.as_deref(),
        )?
    };
    let record = output
        .record
        .ok_or("reason requires a native tool-call identity")?;
    let reason = intent::reason::collect(&value, &record, request.allow_reason_summary)?
        .ok_or("reason input has no declared reason")?;
    tokio::task::spawn_blocking(move || {
        apolysis_store::append_intent_reason(&request.output_path, &reason)
    })
    .await
    .map_err(|_| "reason writer task failed".to_string())?
    .map_err(|error| format!("failed to append reason record: {error}"))?;
    Ok(0)
}

fn distinct_output_paths(left: &str, right: &str) -> Result<(), String> {
    fn resolved(path: &str) -> Option<PathBuf> {
        let path = std::path::Path::new(path);
        std::fs::canonicalize(path).ok().or_else(|| {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(std::path::Path::new("."));
            Some(std::fs::canonicalize(parent).ok()?.join(path.file_name()?))
        })
    }
    let same_name = left == right
        || resolved(left)
            .zip(resolved(right))
            .is_some_and(|(a, b)| a == b);
    #[cfg(unix)]
    let same_file = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(left)
            .ok()
            .zip(std::fs::metadata(right).ok())
            .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino())
    };
    #[cfg(not(unix))]
    let same_file = false;
    if same_name || same_file {
        return Err("input/output paths must refer to separate files".to_string());
    }
    Ok(())
}

async fn intent_correlate_command(args: Vec<String>) -> Result<i32, String> {
    let request = IntentCorrelateRequest::parse(args)?;
    for input in [&request.intent_input_path, &request.timeline_input_path]
        .into_iter()
        .chain(request.reason_input_path.iter())
    {
        distinct_output_paths(input, &request.output_path)?;
    }
    let intent_input = tokio::fs::read_to_string(&request.intent_input_path)
        .await
        .map_err(|error| format!("failed to read intent input: {error}"))?;
    let timeline_input = tokio::fs::read_to_string(&request.timeline_input_path)
        .await
        .map_err(|error| format!("failed to read timeline input: {error}"))?;
    let mut records = correlate_intents(&intent_input, &timeline_input)?;
    if let Some(path) = &request.reason_input_path {
        let reasons = tokio::fs::read_to_string(path)
            .await
            .map_err(|error| format!("failed to read reason input: {error}"))?;
        intent::reason_binding::enrich(&intent_input, &reasons, &mut records)?;
    }
    let (dropped, truncated, observation_gaps) = observer_evidence_loss(&timeline_input);
    if let Some(warning) = evidence_loss_warning(dropped, truncated, observation_gaps) {
        eprintln!("{warning}");
    }
    let mut store = apolysis_store::AsyncJsonlStore::create(&request.output_path)
        .await
        .map_err(|error| format!("failed to create intent correlation output: {error}"))?;
    for record in &records {
        store
            .append(&JsonValueLine(record.clone()))
            .await
            .map_err(|error| format!("failed to write intent correlation record: {error}"))?;
    }
    store
        .flush()
        .await
        .map_err(|error| format!("failed to flush intent correlation output: {error}"))?;
    if request.summary {
        let events = parse_observed_events(&timeline_input)?;
        print!("{}", render_correlation_summary(&records, &events));
    }
    Ok(0)
}

async fn visibility_command(args: Vec<String>) -> Result<i32, String> {
    let request = VisibilityRequest::parse(args)?;
    let host_events = tokio::fs::read_to_string(&request.input_path)
        .await
        .map_err(|error| format!("failed to read visibility input: {error}"))?;
    let kubernetes_metadata = if let Some(path) = request.kubernetes_metadata_path {
        let input = tokio::fs::read_to_string(&path)
            .await
            .map_err(|error| format!("failed to read kubernetes metadata: {error}"))?;
        Some(apolysis_kubernetes::KubernetesMetadata::parse(&input)?)
    } else {
        None
    };
    let assessment = assess_visibility(
        VisibilityInput::new(request.session_id, request.runtime_profile, host_events)
            .with_kubernetes_metadata(kubernetes_metadata),
    )?;
    let mut store = apolysis_store::AsyncJsonlStore::create(&request.output_path)
        .await
        .map_err(|error| format!("failed to create visibility output: {error}"))?;
    store
        .append(&assessment)
        .await
        .map_err(|error| format!("failed to write visibility assessment: {error}"))?;
    store
        .flush()
        .await
        .map_err(|error| format!("failed to flush visibility output: {error}"))?;
    Ok(0)
}

async fn verify_command(args: Vec<String>) -> Result<i32, String> {
    match args.get(1).map(String::as_str) {
        Some(commands::HASH_CHAIN) => verify_hash_chain_command(args).await,
        _ => Err(usage()),
    }
}

async fn verify_hash_chain_command(args: Vec<String>) -> Result<i32, String> {
    let request = VerifyHashChainRequest::parse(args)?;
    let report = HashChainStore::verify(&request.input_path)
        .map_err(|error| format!("failed to verify hash-chain timeline: {error}"))?;
    if let Some(parent) = request.output_path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|error| format!("failed to create verification report parent: {error}"))?;
        }
    }
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize verification report: {error}"))?;
    tokio::fs::write(&request.output_path, format!("{output}\n"))
        .await
        .map_err(|error| format!("failed to write verification report: {error}"))?;
    Ok(if report.passed { 0 } else { 1 })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LocalFileIdentity {
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

struct StableLocalFile {
    bytes: Vec<u8>,
    identity: LocalFileIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StableLocalFileReadError {
    Metadata,
    Symlink,
    NonRegular,
    Open,
    ByteLimit,
    Read,
    Changed,
}

impl std::fmt::Display for StableLocalFileReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Metadata => write!(formatter, "input metadata inspection failed"),
            Self::Symlink => write!(formatter, "input is a symlink"),
            Self::NonRegular => write!(formatter, "input is not a regular file"),
            Self::Open => write!(formatter, "input open failed"),
            Self::ByteLimit => write!(formatter, "input exceeded the byte limit"),
            Self::Read => write!(formatter, "input read failed"),
            Self::Changed => write!(formatter, "input changed while reading"),
        }
    }
}

fn read_stable_bounded_regular_file(
    path: &Path,
    max_bytes: u64,
) -> Result<StableLocalFile, StableLocalFileReadError> {
    let path_metadata =
        std::fs::symlink_metadata(path).map_err(|_| StableLocalFileReadError::Metadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(StableLocalFileReadError::Symlink);
    }
    if !path_metadata.is_file() {
        return Err(StableLocalFileReadError::NonRegular);
    }

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                StableLocalFileReadError::Symlink
            } else {
                StableLocalFileReadError::Open
            }
        })?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| StableLocalFileReadError::Metadata)?;
    if !opened_metadata.is_file() {
        return Err(StableLocalFileReadError::NonRegular);
    }
    let identity = local_file_identity(&opened_metadata);
    if identity.device != path_metadata.dev() || identity.inode != path_metadata.ino() {
        return Err(StableLocalFileReadError::Changed);
    }
    if identity.len > max_bytes {
        return Err(StableLocalFileReadError::ByteLimit);
    }

    let mut bytes = Vec::new();
    IoRead::by_ref(&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| StableLocalFileReadError::Read)?;
    if bytes.len() as u64 > max_bytes {
        return Err(StableLocalFileReadError::ByteLimit);
    }
    let after_metadata = file
        .metadata()
        .map_err(|_| StableLocalFileReadError::Metadata)?;
    if identity != local_file_identity(&after_metadata)
        || after_metadata.len() != bytes.len() as u64
    {
        return Err(StableLocalFileReadError::Changed);
    }
    let path_after =
        std::fs::symlink_metadata(path).map_err(|_| StableLocalFileReadError::Changed)?;
    if path_after.file_type().is_symlink()
        || !path_after.is_file()
        || local_file_identity(&path_after) != identity
    {
        return Err(StableLocalFileReadError::Changed);
    }

    Ok(StableLocalFile { bytes, identity })
}

fn local_file_identity(metadata: &std::fs::Metadata) -> LocalFileIdentity {
    LocalFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        len: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn ensure_distinct_view_output(input: &StableLocalFile, output_path: &Path) -> Result<(), String> {
    match std::fs::symlink_metadata(output_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("saved Agent Run view output must be a regular file".to_string());
            }
            if metadata.dev() == input.identity.device && metadata.ino() == input.identity.inode {
                return Err("saved Agent Run view output aliases its input".to_string());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("failed to inspect saved Agent Run view output".to_string()),
    }
}

fn ensure_distinct_projection_output(
    source_paths: &[PathBuf],
    output_path: &Path,
) -> Result<(), String> {
    let output_metadata = match std::fs::symlink_metadata(output_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("Agent Observation Record output must be a regular file".to_string());
            }
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("failed to inspect Agent Observation Record output".to_string()),
    };
    let output_canonical = if output_metadata.is_some() {
        Some(
            std::fs::canonicalize(output_path)
                .map_err(|_| "failed to resolve Agent Observation Record output".to_string())?,
        )
    } else {
        let parent = output_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        match std::fs::canonicalize(parent) {
            Ok(parent) => output_path.file_name().map(|name| parent.join(name)),
            Err(_) => None,
        }
    };

    for source_path in source_paths {
        let source_metadata = std::fs::metadata(source_path)
            .map_err(|_| "failed to inspect Agent Run source identity".to_string())?;
        if output_metadata.as_ref().is_some_and(|output| {
            output.dev() == source_metadata.dev() && output.ino() == source_metadata.ino()
        }) {
            return Err("Agent Observation Record output aliases an input source".to_string());
        }
        if let Some(output) = output_canonical.as_ref() {
            let source = std::fs::canonicalize(source_path)
                .map_err(|_| "failed to resolve Agent Run source identity".to_string())?;
            if &source == output {
                return Err("Agent Observation Record output aliases an input source".to_string());
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrivateOutputWriteError {
    ParentCreate,
    InvalidPath,
    Create,
    Write,
    Sync,
    Publish,
    ParentSync,
    Allocate,
}

impl std::fmt::Display for PrivateOutputWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ParentCreate => write!(formatter, "private output parent creation failed"),
            Self::InvalidPath => write!(formatter, "private output path is invalid"),
            Self::Create => write!(formatter, "private output creation failed"),
            Self::Write => write!(formatter, "private output write failed"),
            Self::Sync => write!(formatter, "private output sync failed"),
            Self::Publish => write!(formatter, "private output publication failed"),
            Self::ParentSync => write!(formatter, "private output parent sync failed"),
            Self::Allocate => write!(formatter, "private output allocation failed"),
        }
    }
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), PrivateOutputWriteError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|_| PrivateOutputWriteError::ParentCreate)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(PrivateOutputWriteError::InvalidPath)?;

    for _ in 0..128 {
        let id = NEXT_PRIVATE_OUTPUT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let temporary_path = parent.join(format!(
            ".{file_name}.apolysis-private-{}-{id}.tmp",
            std::process::id()
        ));
        let mut file = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(PrivateOutputWriteError::Create),
        };
        let result = (|| {
            file.write_all(bytes)
                .map_err(|_| PrivateOutputWriteError::Write)?;
            file.sync_all().map_err(|_| PrivateOutputWriteError::Sync)?;
            drop(file);
            std::fs::rename(&temporary_path, path).map_err(|_| PrivateOutputWriteError::Publish)?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|_| PrivateOutputWriteError::ParentSync)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary_path);
        }
        return result;
    }
    Err(PrivateOutputWriteError::Allocate)
}

async fn observe_command(args: Vec<String>) -> Result<i32, String> {
    let request = ObserveRequest::parse(args)?;
    match request.backend {
        ObserverBackendSelection::Fixture => {
            observe_fixture(
                FixtureObserveRequest::new(
                    request
                        .input_path
                        .expect("fixture request validation requires input"),
                    request.output_path,
                    request.session_id,
                )
                .with_kubernetes_metadata_path(request.kubernetes_metadata_path)
                .with_output_rotation(request.output_rotation),
            )?;
            Ok(0)
        }
        ObserverBackendSelection::Live => {
            let result = observe_live(LiveObserveRequest {
                object_path: request
                    .bpf_object_path
                    .expect("live request validation requires a BPF object")
                    .into(),
                output_path: request.output_path.into(),
                session_id: request.session_id,
                scope: request.live_scope,
                agent_run: request.agent_run,
                agent_registration_path: request.agent_registration_path.map(Into::into),
                agent_discovery: request.agent_discovery,
                duration: request.duration_seconds.map(Duration::from_secs),
                workspace_root: request.workspace_root.map(Into::into).unwrap_or(
                    std::env::current_dir().map_err(|error| {
                        format!("failed to resolve current workspace root: {error}")
                    })?,
                ),
                output_rotation: request.output_rotation,
                qualification_telemetry: None,
            })
            .await?;
            Ok(result.agent_exit_code.unwrap_or(0))
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct IntentIngestRequest {
    adapter: String,
    input_path: String,
    output_path: String,
    session_id: String,
    workspace_root: Option<PathBuf>,
}

#[derive(Debug, Eq, PartialEq)]
struct IntentHookRequest {
    harness: String,
    output_path: String,
    workspace_root: PathBuf,
    session_id: Option<String>,
    reason_output_path: String,
    allow_reason_summary: bool,
    shell_bridge: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct IntentCorrelateRequest {
    intent_input_path: String,
    timeline_input_path: String,
    output_path: String,
    summary: bool,
    reason_input_path: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct VerifyHashChainRequest {
    input_path: PathBuf,
    output_path: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
struct ProjectRunRequest {
    input_paths: Vec<PathBuf>,
    output_path: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
struct ViewRunRequest {
    input_path: PathBuf,
    output_path: PathBuf,
}

impl ProjectRunRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some(commands::RUN)
            || args.get(1).map(String::as_str) != Some(commands::PROJECT)
        {
            return Err(usage());
        }

        let mut input_paths = Vec::new();
        let mut output_path = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                options::INPUT => {
                    i += 1;
                    if input_paths.len() >= MAX_AGENT_RUN_PROJECTION_BATCHES {
                        return Err(
                            "Agent Run projection exceeded the input batch count limit".to_string()
                        );
                    }
                    input_paths.push(PathBuf::from(args.get(i).cloned().ok_or_else(|| {
                        format!("missing {} value\n{}", options::INPUT, usage())
                    })?));
                }
                options::OUTPUT => {
                    i += 1;
                    if output_path.is_some() {
                        return Err(format!("duplicate {}\n{}", options::OUTPUT, usage()));
                    }
                    output_path = Some(PathBuf::from(args.get(i).cloned().ok_or_else(|| {
                        format!("missing {} value\n{}", options::OUTPUT, usage())
                    })?));
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }
        if input_paths.is_empty() {
            return Err(format!("missing {}\n{}", options::INPUT, usage()));
        }
        Ok(Self {
            input_paths,
            output_path: output_path
                .ok_or_else(|| format!("missing {}\n{}", options::OUTPUT, usage()))?,
        })
    }
}

impl ViewRunRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some(commands::RUN)
            || args.get(1).map(String::as_str) != Some(commands::VIEW)
        {
            return Err(usage());
        }

        let mut input_path = None;
        let mut output_path = None;
        let mut i = 2;
        while i < args.len() {
            match args[i].as_str() {
                options::INPUT => {
                    i += 1;
                    if input_path.is_some() {
                        return Err(format!("duplicate {}\n{}", options::INPUT, usage()));
                    }
                    input_path = Some(PathBuf::from(args.get(i).cloned().ok_or_else(|| {
                        format!("missing {} value\n{}", options::INPUT, usage())
                    })?));
                }
                options::OUTPUT => {
                    i += 1;
                    if output_path.is_some() {
                        return Err(format!("duplicate {}\n{}", options::OUTPUT, usage()));
                    }
                    output_path = Some(PathBuf::from(args.get(i).cloned().ok_or_else(|| {
                        format!("missing {} value\n{}", options::OUTPUT, usage())
                    })?));
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }
        Ok(Self {
            input_path: input_path
                .ok_or_else(|| format!("missing {}\n{}", options::INPUT, usage()))?,
            output_path: output_path
                .ok_or_else(|| format!("missing {}\n{}", options::OUTPUT, usage()))?,
        })
    }
}

impl IntentIngestRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some(commands::INTENT)
            || args.get(1).map(String::as_str) != Some(commands::INGEST)
        {
            return Err(usage());
        }

        let mut adapter = None;
        let mut input_path = None;
        let mut output_path = None;
        let mut session_id = None;
        let mut workspace_root = None;
        let mut i = 2;

        while i < args.len() {
            match args[i].as_str() {
                options::ADAPTER => {
                    i += 1;
                    adapter = args.get(i).cloned();
                }
                options::INPUT => {
                    i += 1;
                    input_path = args.get(i).cloned();
                }
                options::OUTPUT => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                options::SESSION => {
                    i += 1;
                    session_id = args.get(i).cloned();
                }
                options::WORKSPACE_ROOT => {
                    i += 1;
                    workspace_root =
                        Some(PathBuf::from(args.get(i).cloned().ok_or_else(|| {
                            format!("missing {} value\n{}", options::WORKSPACE_ROOT, usage())
                        })?));
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        let adapter =
            adapter.ok_or_else(|| format!("missing {}\n{}", options::ADAPTER, usage()))?;
        if !matches!(
            adapter.as_str(),
            values::CODEX_JSONL
                | values::CLAUDE_JSONL
                | values::CURSOR_JSONL
                | values::PI_JSONL
                | values::OPENCODE_JSONL
        ) {
            return Err(format!("unsupported intent adapter '{adapter}'"));
        }

        Ok(Self {
            adapter,
            input_path: input_path
                .ok_or_else(|| format!("missing {}\n{}", options::INPUT, usage()))?,
            output_path: output_path
                .ok_or_else(|| format!("missing {}\n{}", options::OUTPUT, usage()))?,
            session_id: session_id
                .ok_or_else(|| format!("missing {}\n{}", options::SESSION, usage()))?,
            workspace_root,
        })
    }
}

impl IntentHookRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some(commands::INTENT)
            || args.get(1).map(String::as_str) != Some(commands::HOOK)
        {
            return Err(usage());
        }

        let mut harness = None;
        let mut output_path = None;
        let mut workspace_root = None;
        let mut session_id = None;
        let mut reason_output_path = None;
        let mut allow_reason_summary = false;
        let mut shell_bridge = None;
        let mut i = 2;

        while i < args.len() {
            match args[i].as_str() {
                options::HARNESS => {
                    i += 1;
                    harness = args.get(i).cloned();
                }
                options::OUTPUT => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                "--reason-output" => {
                    i += 1;
                    reason_output_path = Some(
                        args.get(i)
                            .filter(|s| !s.is_empty() && !s.starts_with("--"))
                            .ok_or("--reason-output requires a path")?
                            .clone(),
                    );
                }
                "--allow-reason-summary" => allow_reason_summary = true,
                "--shell-bridge" => {
                    i += 1;
                    shell_bridge = Some(
                        args.get(i)
                            .filter(|value| !value.is_empty() && !value.starts_with("--"))
                            .ok_or("--shell-bridge requires an absolute shell path")?
                            .clone(),
                    );
                }
                options::WORKSPACE_ROOT => {
                    i += 1;
                    workspace_root = args.get(i).cloned();
                }
                options::SESSION => {
                    i += 1;
                    let value = args
                        .get(i)
                        .filter(|value| !value.is_empty() && !value.starts_with("--"))
                        .ok_or("--session requires a nonempty capture session")?;
                    session_id = Some(value.clone());
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        let output_path = output_path.ok_or("missing --output")?;
        let reason_output_path =
            reason_output_path.unwrap_or_else(|| format!("{output_path}.reasons.jsonl"));
        Ok(Self {
            reason_output_path,
            allow_reason_summary,
            shell_bridge,
            harness: harness.ok_or_else(|| format!("missing {}\n{}", options::HARNESS, usage()))?,
            output_path,
            workspace_root: PathBuf::from(
                workspace_root
                    .ok_or_else(|| format!("missing {}\n{}", options::WORKSPACE_ROOT, usage()))?,
            ),
            session_id,
        })
    }
}

impl IntentCorrelateRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some(commands::INTENT)
            || args.get(1).map(String::as_str) != Some(commands::CORRELATE)
        {
            return Err(usage());
        }

        let mut intent_input_path = None;
        let mut timeline_input_path = None;
        let mut output_path = None;
        let mut summary = false;
        let mut reason_input_path = None;
        let mut i = 2;

        while i < args.len() {
            match args[i].as_str() {
                options::INTENT_INPUT => {
                    i += 1;
                    intent_input_path = args.get(i).cloned();
                }
                options::TIMELINE_INPUT => {
                    i += 1;
                    timeline_input_path = args.get(i).cloned();
                }
                options::OUTPUT => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                options::SUMMARY => summary = true,
                "--reason-input" => {
                    i += 1;
                    reason_input_path = Some(
                        args.get(i)
                            .filter(|s| !s.is_empty() && !s.starts_with("--"))
                            .ok_or("--reason-input requires a path")?
                            .clone(),
                    );
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        Ok(Self {
            intent_input_path: intent_input_path
                .ok_or_else(|| format!("missing {}\n{}", options::INTENT_INPUT, usage()))?,
            timeline_input_path: timeline_input_path
                .ok_or_else(|| format!("missing {}\n{}", options::TIMELINE_INPUT, usage()))?,
            output_path: output_path
                .ok_or_else(|| format!("missing {}\n{}", options::OUTPUT, usage()))?,
            summary,
            reason_input_path,
        })
    }
}

impl VerifyHashChainRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some(commands::VERIFY)
            || args.get(1).map(String::as_str) != Some(commands::HASH_CHAIN)
        {
            return Err(usage());
        }

        let mut input_path = None;
        let mut output_path = None;
        let mut i = 2;

        while i < args.len() {
            match args[i].as_str() {
                options::INPUT => {
                    i += 1;
                    input_path = args.get(i).cloned();
                }
                options::OUTPUT => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        Ok(Self {
            input_path: input_path
                .map(PathBuf::from)
                .ok_or_else(|| format!("missing {}\n{}", options::INPUT, usage()))?,
            output_path: output_path
                .map(PathBuf::from)
                .ok_or_else(|| format!("missing {}\n{}", options::OUTPUT, usage()))?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntentForCorrelation {
    declaration: serde_json::Value,
    session_id: String,
    intent_source: String,
    intent_id: String,
    source_event_id: Option<String>,
    tool_name: String,
    command: Option<String>,
    raw_event_id: Option<String>,
    harness_session_id: Option<String>,
    observation_mode: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObservedEventForCorrelation {
    session_id: String,
    event_type: String,
    raw_event_id: String,
    pid: u64,
    resource: String,
    process_command: Option<String>,
    process_executable: Option<String>,
    intent_id: Option<String>,
    report_missing_intent: bool,
    runtime: RuntimeForCorrelation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeForCorrelation {
    runtime: String,
    container_id: Option<String>,
    pod_uid: Option<String>,
    cgroup_id: Option<u64>,
}

impl Default for RuntimeForCorrelation {
    fn default() -> Self {
        Self {
            runtime: "local".to_string(),
            container_id: None,
            pod_uid: None,
            cgroup_id: None,
        }
    }
}

struct JsonValueLine(serde_json::Value);

impl JsonLine for JsonValueLine {
    fn to_json_line(&self) -> String {
        serde_json::to_string(&self.0).expect("serde_json::Value serialization cannot fail")
    }
}

/// Render a short, human-readable accountability digest from correlation records.
///
/// Findings only carry an `evidence_ref` (the raw event id), so this enriches
/// each one with the actual resource, event type, and process from the observed
/// timeline to make the "you said X, the kernel shows Y" verdict legible.
fn render_correlation_summary(
    records: &[serde_json::Value],
    events: &[ObservedEventForCorrelation],
) -> String {
    use std::fmt::Write as _;

    let event_by_id: std::collections::HashMap<(&str, &str), &ObservedEventForCorrelation> = events
        .iter()
        .map(|event| {
            (
                (event.session_id.as_str(), event.raw_event_id.as_str()),
                event,
            )
        })
        .collect();

    let mut matched = Vec::new();
    let mut findings = Vec::new();
    let mut candidates = Vec::new();
    let mut diagnostics = Vec::new();
    for record in records {
        match string_field(record, "record_type") {
            Some("intent_correlation") => matched.push(record),
            Some("accountability_finding") => findings.push(record),
            Some("intent_correlation_candidate") => candidates.push(record),
            Some("intent_correlation_diagnostic" | "intent_reason_diagnostic") => {
                diagnostics.push(record)
            }
            _ => {}
        }
    }

    let session = records
        .iter()
        .find_map(|record| string_field(record, "session_id"))
        .unwrap_or("unknown");

    let mut out = String::new();
    let _ = writeln!(
        out,
        "\nApolysis accountability summary  (session: {session})"
    );
    let _ = writeln!(
        out,
        "  {} observed event(s) linked by explicit identifier, {} finding(s)",
        matched.len(),
        findings.len()
    );
    let _ = writeln!(
        out,
        "  {} inferred/ambiguous candidate(s), {} correlation diagnostic(s)",
        candidates.len(),
        diagnostics.len()
    );

    for record in &matched {
        let resource = string_field(record, "resource").unwrap_or("");
        let command = string_field(record, "command").unwrap_or("");
        let tool_name = string_field(record, "tool_name").unwrap_or("");
        let basis = string_field(record, "match_basis").unwrap_or("");
        let _ = writeln!(out, "  \u{2713} matched   {resource}");
        let _ = writeln!(
            out,
            "            declared as: {tool_name} {command}  [{basis}]"
        );
        if let Some(reason) = record.get("declared_reason") {
            let code = string_field(reason, "reason_code").unwrap_or("unknown");
            let source = string_field(reason, "reason_source").unwrap_or("unknown");
            let _ = writeln!(out, "            declared reason: {code} [{source}]");
        }
    }

    for record in &findings {
        let kind = string_field(record, "kind").unwrap_or("finding");
        let decision = string_field(record, "decision").unwrap_or("review");
        let reason = string_field(record, "reason").unwrap_or("");
        let evidence_ref = string_field(record, "evidence_ref").unwrap_or("");
        let session = string_field(record, "session_id").unwrap_or("");
        let event = event_by_id.get(&(session, evidence_ref)).copied();
        let resource = event
            .map(|event| event.resource.as_str())
            .unwrap_or(evidence_ref);
        let event_type = event.map(|event| event.event_type.as_str()).unwrap_or("");
        let by = event
            .and_then(|event| event.process_command.as_deref())
            .unwrap_or("");
        let _ = writeln!(out, "  \u{26a0} {kind}   {event_type} {resource}");
        if !by.is_empty() {
            let _ = writeln!(out, "            by: {by}");
        }
        let _ = writeln!(out, "            {reason}  [{decision}]");
    }

    for record in &candidates {
        let _ = writeln!(
            out,
            "  ? candidate   {} [{}; {}]",
            string_field(record, "resource").unwrap_or(""),
            string_field(record, "match_basis").unwrap_or(""),
            string_field(record, "relation_status").unwrap_or("")
        );
    }
    for record in &diagnostics {
        let _ = writeln!(
            out,
            "  ! correlation gap   {}",
            string_field(record, "reason").unwrap_or("")
        );
    }

    if findings.is_empty() {
        let _ = writeln!(
            out,
            "  no accountability findings emitted; this does not establish complete coverage."
        );
    }

    out
}

fn correlate_intents(
    intent_input: &str,
    timeline_input: &str,
) -> Result<Vec<serde_json::Value>, String> {
    use std::collections::HashMap;

    let intents: Vec<IntentForCorrelation> = parse_intent_records(intent_input)?;
    let events: Vec<ObservedEventForCorrelation> = parse_observed_events(timeline_input)?;
    let mut records: Vec<serde_json::Value> = Vec::new();
    let mut matched_intents: Vec<bool> = vec![false; intents.len()];

    let mut by_session_intent_id: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    let mut by_session_raw_id: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    let mut by_session_command: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    let mut by_session_non_semantic: HashMap<&str, Vec<usize>> = HashMap::new();

    for (index, intent) in intents.iter().enumerate() {
        let session = intent.session_id.as_str();
        by_session_intent_id
            .entry((session, intent.intent_id.as_str()))
            .or_default()
            .push(index);
        if let Some(raw_id) = intent.raw_event_id.as_deref() {
            by_session_raw_id
                .entry((session, raw_id))
                .or_default()
                .push(index);
        }
        if intent.observation_mode.as_deref() != Some("semantic_only") {
            by_session_non_semantic
                .entry(session)
                .or_default()
                .push(index);
            if let Some(command) = intent.command.as_deref() {
                by_session_command
                    .entry((session, command))
                    .or_default()
                    .push(index);
            }
        }
    }

    for event in &events {
        let session = event.session_id.as_str();
        let by_raw = by_session_raw_id
            .get(&(session, event.raw_event_id.as_str()))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let mut matched = None;
        let mut gap = None;
        if let Some(id) = &event.intent_id {
            let by_id = by_session_intent_id
                .get(&(session, id.as_str()))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            match by_id {
                [index] if by_raw.is_empty() => {
                    matched = Some((*index, &intents[*index], "intent_id"));
                }
                [index] if by_raw == [*index] => {
                    matched = Some((*index, &intents[*index], "raw_event_id"));
                }
                [] => gap = Some("unrecognized_intent_id"),
                [_] => gap = Some("conflicting_identifiers"),
                _ => gap = Some("ambiguous_intent_id"),
            }
        } else {
            match by_raw {
                [index] => matched = Some((*index, &intents[*index], "raw_event_id")),
                [] => {
                    let exact = event
                        .process_command
                        .as_deref()
                        .and_then(|command| by_session_command.get(&(session, command)))
                        .map(Vec::as_slice)
                        .unwrap_or(&[]);
                    let (candidates, basis): (Vec<usize>, &str) = if !exact.is_empty() {
                        (exact.to_vec(), "process_command_exact")
                    } else if event.event_type == "exec" {
                        (
                            by_session_non_semantic
                                .get(session)
                                .map(Vec::as_slice)
                                .unwrap_or(&[])
                                .iter()
                                .copied()
                                .filter(|&index| {
                                    intents[index]
                                        .command
                                        .as_deref()
                                        .and_then(command_executable)
                                        .is_some_and(|executable| {
                                            executable_matches(
                                                executable,
                                                event.process_executable.as_deref(),
                                            ) || executable_matches(
                                                executable,
                                                Some(&event.resource),
                                            )
                                        })
                                })
                                .collect(),
                            "process_executable",
                        )
                    } else {
                        (Vec::new(), "process_executable")
                    };
                    for index in &candidates {
                        let intent = &intents[*index];
                        let mut candidate = intent_correlation_record(intent, event, basis);
                        candidate["record_type"] = "intent_correlation_candidate".into();
                        candidate["relation_status"] = if candidates.len() == 1 {
                            "inferred"
                        } else {
                            "ambiguous"
                        }
                        .into();
                        candidate["candidate_count"] = candidates.len().into();
                        records.push(candidate);
                    }
                }
                _ => gap = Some("ambiguous_raw_event_id"),
            }
        }
        if matched.as_ref().is_some_and(|(_, intent, _)| {
            intent.observation_mode.as_deref() == Some("semantic_only")
        }) {
            matched = None;
            gap = Some("semantic_only_runtime_event");
        }
        if let Some(reason) = gap {
            records.push(serde_json::json!({
                "record_type": "intent_correlation_diagnostic",
                "session_id": event.session_id,
                "raw_event_id": event.raw_event_id,
                "intent_id": event.intent_id,
                "reason": reason,
            }));
        }
        if let Some((index, intent, basis)) = matched {
            matched_intents[index] = true;
            records.push(intent_correlation_record(intent, event, basis));
        } else if event.report_missing_intent {
            records.push(accountability_finding_record(
                &event.session_id,
                FindingKind::MissingIntent,
                "observed attempt has no explicit identifier relation to a declared intent",
                &event.raw_event_id,
                &event.runtime,
            )?);
        }
    }

    for (intent, matched) in intents.iter().zip(matched_intents) {
        if !matched && intent.observation_mode.as_deref() != Some("semantic_only") {
            records.push(accountability_finding_record(
                &intent.session_id,
                FindingKind::UnobservedIntent,
                "declared intent has no explicit identifier relation to an observed event",
                &intent.intent_id,
                &RuntimeForCorrelation::default(),
            )?);
        }
    }

    Ok(records)
}

fn parse_intent_records(input: &str) -> Result<Vec<IntentForCorrelation>, String> {
    use std::collections::HashMap;

    let records: Vec<IntentForCorrelation> = parse_jsonl(input, "intent input")?
        .into_iter()
        .filter(|value| string_field(value, "record_type") == Some("intent"))
        .map(|mut value| {
            if let Some(object) = value.as_object_mut() {
                object.remove("timestamp_unix_ms");
            }
            Ok(IntentForCorrelation {
                declaration: value.clone(),
                session_id: required_string_field(&value, "session_id")?.to_string(),
                intent_source: required_string_field(&value, "intent_source")?.to_string(),
                intent_id: required_string_field(&value, "intent_id")?.to_string(),
                source_event_id: string_field(&value, "source_event_id").map(ToString::to_string),
                tool_name: required_string_field(&value, "tool_name")?.to_string(),
                command: string_field(&value, "command").map(ToString::to_string),
                raw_event_id: string_field(&value, "raw_event_id").map(ToString::to_string),
                harness_session_id: string_field(&value, "harness_session_id")
                    .map(ToString::to_string),
                observation_mode: string_field(&value, "observation_mode").map(ToString::to_string),
            })
        })
        .collect::<Result<_, String>>()?;
    let mut unique: Vec<IntentForCorrelation> = Vec::with_capacity(records.len());
    let mut by_key: HashMap<(String, String), Vec<usize>> = HashMap::new();
    for record in records {
        let indices = by_key
            .entry((record.session_id.clone(), record.intent_id.clone()))
            .or_default();
        if !indices.iter().any(|&idx| unique[idx] == record) {
            indices.push(unique.len());
            unique.push(record);
        }
    }
    Ok(unique)
}

fn parse_observed_events(input: &str) -> Result<Vec<ObservedEventForCorrelation>, String> {
    parse_jsonl(input, "timeline input")?
        .into_iter()
        .filter(|value| {
            string_field(value, "record_type") == Some("event")
                && string_field(value, "raw_event_id").is_some()
                && string_field(value, "event_type")
                    .map(|event_type| side_effect_event_type(event_type) || event_type == "exec")
                    .unwrap_or(false)
        })
        .map(|value| {
            let event_type = required_string_field(&value, "event_type")?.to_string();
            Ok(ObservedEventForCorrelation {
                session_id: required_string_field(&value, "session_id")?.to_string(),
                report_missing_intent: missing_intent_event_type(&event_type),
                event_type,
                raw_event_id: required_string_field(&value, "raw_event_id")?.to_string(),
                pid: value
                    .get("pid")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
                resource: required_string_field(&value, "resource")?.to_string(),
                process_command: string_field(&value, "process_command").map(ToString::to_string),
                process_executable: string_field(&value, "process_executable")
                    .map(ToString::to_string),
                intent_id: string_field(&value, "intent_id").map(ToString::to_string),
                runtime: RuntimeForCorrelation {
                    runtime: string_field(&value, "runtime")
                        .unwrap_or("local")
                        .to_string(),
                    container_id: string_field(&value, "container_id").map(ToString::to_string),
                    pod_uid: string_field(&value, "pod_uid").map(ToString::to_string),
                    cgroup_id: u64_field(&value, "cgroup_id"),
                },
            })
        })
        .collect()
}

fn parse_jsonl(input: &str, label: &str) -> Result<Vec<serde_json::Value>, String> {
    input
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let line = line.trim();
            if line.is_empty() {
                None
            } else {
                Some(
                    serde_json::from_str::<serde_json::Value>(line).map_err(|error| {
                        format!("failed to parse {label} line {}: {error}", index + 1)
                    }),
                )
            }
        })
        .collect()
}

fn command_executable(command: &str) -> Option<&str> {
    command.split_whitespace().next().filter(|value| {
        value.starts_with('/')
            || value.starts_with("./")
            || value.starts_with("../")
            || value
                .chars()
                .all(|ch| !matches!(ch, '\'' | '"' | '{' | '}' | '[' | ']'))
    })
}

/// Match a declared executable against an observed one, tolerant of path form.
/// A declared bare `cargo` matches an observed `/usr/bin/cargo`, and `./run.sh`
/// matches an absolute `/work/run.sh`, because agents declare a command name
/// while the kernel records the resolved executable path. Exact equality still
/// wins first; otherwise the file names must match and be non-empty.
fn executable_matches(declared: &str, observed: Option<&str>) -> bool {
    fn name(value: &str) -> Option<&str> {
        let value = value.strip_prefix("executable_ref:").unwrap_or(value);
        let basename = value.rsplit('/').next()?;
        (!basename.is_empty() && !matches!(basename, "unknown" | "executable:unavailable"))
            .then_some(basename)
    }
    match (name(declared), observed.and_then(name)) {
        (Some(declared), Some(observed)) => declared == observed,
        _ => false,
    }
}

/// Sum the observer's event-loss diagnostics in a timeline into
/// (dropped, truncated, observation gaps). Malformed input yields zeros.
// Native reports track truncation separately from a complete capture transaction.
#[cfg(target_os = "linux")]
fn native_capture_boundary_valid(rows: &[serde_json::Value], truncations: u64) -> bool {
    use apolysis_accountability::ProjectionIssueCode;
    use apolysis_core::CollectorLifecycleState;

    let metadata: Vec<_> = rows
        .iter()
        .filter(|row| {
            matches!(
                row["record_type"].as_str(),
                Some("collector_capability_manifest" | "collector_lifecycle" | "observation_gap")
            )
        })
        .cloned()
        .collect();
    if metadata.is_empty() {
        return true; // Legacy saved native captures predate lifecycle records.
    }
    let Ok(record) = project_agent_run([AgentRunRecordBatch::plain(metadata)]) else {
        return false;
    };
    let Some(terminal) = record.collector_lifecycle.last() else {
        return false;
    };
    let counters = terminal.counters;
    terminal.state == CollectorLifecycleState::Stopped
        && record.issues.iter().all(|issue| {
            matches!(
                issue.code,
                ProjectionIssueCode::NoRuntimeObservations | ProjectionIssueCode::CollectorLoss
            )
        })
        && counters.global_reserve_failures == 0
        && counters.global_map_pressure == 0
        && counters.global_abi_mismatches == 0
        && counters.global_decode_failures == 0
        && counters.scope_missing_entries == 0
        && counters.scope_missing_exits == 0
        && counters.scope_pending == 0
        && counters.global_truncations == truncations
}

fn observer_evidence_loss(timeline_input: &str) -> (u64, u64, u64) {
    let records = parse_jsonl(timeline_input, "timeline input").unwrap_or_default();
    let mut dropped = 0;
    let mut truncated = 0;
    let mut observation_gaps = 0;
    for value in &records {
        if string_field(value, "record_type") == Some("observation_gap") {
            observation_gaps += value
                .get("count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            continue;
        }
        if string_field(value, "record_type") != Some("observer_diagnostic") {
            continue;
        }
        let count = value
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        match string_field(value, "kind") {
            Some(
                "abi_mismatch" | "ring_buffer_reserve_failure" | "map_pressure" | "decode_failure",
            ) => {
                dropped += count;
            }
            Some("truncation") => truncated += count,
            _ => {}
        }
    }
    (dropped, truncated, observation_gaps)
}

/// The fail-loud incompleteness warning, or None when the evidence is whole.
fn evidence_loss_warning(dropped: u64, truncated: u64, observation_gaps: u64) -> Option<String> {
    if dropped == 0 && truncated == 0 && observation_gaps == 0 {
        return None;
    }
    Some(format!(
        "apolysis: ⚠ evidence may be incomplete — {dropped} event(s) dropped, \
         {observation_gaps} observation gap(s), {truncated} truncated. \
         A quiet timeline is not proof of absence."
    ))
}

fn intent_correlation_record(
    intent: &IntentForCorrelation,
    event: &ObservedEventForCorrelation,
    match_basis: &str,
) -> serde_json::Value {
    serde_json::json!({
        "record_type": "intent_correlation",
        "timestamp_unix_ms": now_unix_ms(),
        "session_id": event.session_id,
        "intent_source": intent.intent_source,
        "intent_id": intent.intent_id,
        "tool_name": intent.tool_name,
        "match_basis": match_basis,
        "relation_status": "exact",
        "raw_event_id": event.raw_event_id,
        "event_type": event.event_type,
        "pid": event.pid,
        "resource": event.resource,
        "process_command": event.process_command,
        "process_executable": event.process_executable,
        "command": intent.command,
    })
}

fn accountability_finding_record(
    session_id: &str,
    kind: FindingKind,
    reason: &str,
    evidence_ref: &str,
    runtime: &RuntimeForCorrelation,
) -> Result<serde_json::Value, String> {
    let finding = AccountabilityFinding {
        schema_version: FINDING_SCHEMA_V1,
        session_id: session_id.to_string(),
        kind,
        decision: FindingDecision::Review,
        reason: reason.to_string(),
        evidence_ref: evidence_ref.to_string(),
        runtime: RuntimeIdentity {
            runtime: runtime.runtime.clone(),
            container_id: runtime.container_id.clone(),
            pod_uid: runtime.pod_uid.clone(),
            cgroup_id: runtime.cgroup_id,
        },
        evidence_boundary: EvidenceBoundary::HostBoundary,
    };
    finding
        .to_record_value()
        .map_err(|error| format!("failed to serialize accountability finding: {error}"))
}

fn string_field<'a>(value: &'a serde_json::Value, field: &str) -> Option<&'a str> {
    value.get(field).and_then(serde_json::Value::as_str)
}

fn required_string_field<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str, String> {
    string_field(value, field).ok_or_else(|| format!("missing string field: {field}"))
}

fn u64_field(value: &serde_json::Value, field: &str) -> Option<u64> {
    value
        .get(field)
        .and_then(|value| value.as_u64().or_else(|| value.as_str()?.parse().ok()))
}

/// Observed event types (besides `exec`) that are correlated against declared
/// intent. Plain reads are included so a declared file read can still match an
/// observed one.
fn side_effect_event_type(event_type: &str) -> bool {
    matches!(
        event_type,
        "file_open"
            | "file_create"
            | "file_truncate"
            | "file_unlink"
            | "file_rename"
            | "network_connect"
            | "credential_read"
    )
}

/// Of the correlated side effects, the ones worth surfacing as a `missing_intent`
/// finding when they have no matching declared intent.
///
/// Plain reads (`file_open`) are excluded: every process opens hundreds of them
/// (shared libraries, config, source), so flagging each one buries the real
/// signal. The accountable undeclared side effects are credential reads, network
/// egress, and file mutations — a plain read that is not a credential is not, by
/// itself, a finding.
fn missing_intent_event_type(event_type: &str) -> bool {
    matches!(
        event_type,
        "file_create"
            | "file_truncate"
            | "file_unlink"
            | "file_rename"
            | "network_connect"
            | "credential_read"
    )
}

#[derive(Debug, Eq, PartialEq)]
struct ObserveRequest {
    backend: ObserverBackendSelection,
    input_path: Option<String>,
    output_path: String,
    session_id: String,
    kubernetes_metadata_path: Option<String>,
    bpf_object_path: Option<String>,
    live_scope: Option<LiveScope>,
    agent_run: Option<AgentRunRequest>,
    agent_registration_path: Option<String>,
    agent_discovery: Option<AgentDiscoveryRequest>,
    duration_seconds: Option<u64>,
    workspace_root: Option<String>,
    output_rotation: Option<JsonlRotationPolicy>,
}

#[derive(Debug, Eq, PartialEq)]
struct VisibilityRequest {
    runtime_profile: RuntimeVisibilityProfile,
    input_path: String,
    output_path: String,
    session_id: String,
    kubernetes_metadata_path: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
enum ObserverBackendSelection {
    Fixture,
    Live,
}

impl ObserveRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some(commands::OBSERVE) {
            return Err(usage());
        }

        let mut backend = None;
        let mut input_path = None;
        let mut output_path = None;
        let mut session_id = None;
        let mut kubernetes_metadata_path = None;
        let mut bpf_object_path = None;
        let mut scope_cgroup = None;
        let mut scope_pid = None;
        let mut agent_kind = None;
        let mut agent_command = None;
        let mut agent_registration_path = None;
        let mut agent_discover = false;
        let mut duration_seconds = None;
        let mut workspace_root = None;
        let mut output_max_bytes = None;
        let mut output_max_files = None;
        let mut i = 1;

        while i < args.len() {
            match args[i].as_str() {
                options::BACKEND => {
                    i += 1;
                    backend = args.get(i).cloned();
                }
                options::INPUT => {
                    i += 1;
                    input_path = args.get(i).cloned();
                }
                options::OUTPUT => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                options::OUTPUT_MAX_BYTES => {
                    i += 1;
                    output_max_bytes = parse_option::<u64>(&args, i, options::OUTPUT_MAX_BYTES)?;
                }
                options::OUTPUT_MAX_FILES => {
                    i += 1;
                    output_max_files = parse_option::<usize>(&args, i, options::OUTPUT_MAX_FILES)?;
                }
                options::SESSION => {
                    i += 1;
                    session_id = args.get(i).cloned();
                }
                options::KUBERNETES_METADATA => {
                    i += 1;
                    kubernetes_metadata_path = args.get(i).cloned();
                }
                options::BPF_OBJECT => {
                    i += 1;
                    bpf_object_path = args.get(i).cloned();
                }
                options::SCOPE_CGROUP => {
                    i += 1;
                    scope_cgroup = parse_option::<u64>(&args, i, options::SCOPE_CGROUP)?;
                }
                options::SCOPE_PID => {
                    i += 1;
                    scope_pid = parse_option::<u32>(&args, i, options::SCOPE_PID)?;
                }
                options::AGENT_KIND => {
                    i += 1;
                    agent_kind = args.get(i).cloned();
                }
                options::AGENT_RUN => {
                    i += 1;
                    if args.get(i).map(String::as_str) != Some(options::COMMAND_SEPARATOR) {
                        return Err(format!(
                            "missing {} after {}\n{}",
                            options::COMMAND_SEPARATOR,
                            options::AGENT_RUN,
                            usage()
                        ));
                    }
                    let command = args[(i + 1)..].to_vec();
                    if command.is_empty() {
                        return Err(format!(
                            "missing command after {} {}\n{}",
                            options::AGENT_RUN,
                            options::COMMAND_SEPARATOR,
                            usage()
                        ));
                    }
                    agent_command = Some(command);
                    break;
                }
                options::AGENT_REGISTRATION => {
                    i += 1;
                    agent_registration_path = Some(args.get(i).cloned().ok_or_else(|| {
                        format!("missing {} value\n{}", options::AGENT_REGISTRATION, usage())
                    })?);
                }
                options::AGENT_DISCOVER => {
                    agent_discover = true;
                }
                options::DURATION_SECONDS => {
                    i += 1;
                    duration_seconds = parse_option::<u64>(&args, i, options::DURATION_SECONDS)?;
                }
                options::WORKSPACE_ROOT => {
                    i += 1;
                    workspace_root = args.get(i).cloned();
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        let backend = match backend
            .ok_or_else(|| format!("missing {}\n{}", options::BACKEND, usage()))?
            .as_str()
        {
            values::FIXTURE => ObserverBackendSelection::Fixture,
            values::LIVE => ObserverBackendSelection::Live,
            unknown => return Err(format!("unknown observer backend '{unknown}'\n{}", usage())),
        };

        let agent_run = match (agent_kind.clone(), agent_command) {
            (Some(kind), Some(command)) => Some(AgentRunRequest::new(kind, command)?),
            (Some(_), None) if !agent_discover => {
                return Err(format!(
                    "{} requires {}\n{}",
                    options::AGENT_KIND,
                    options::AGENT_RUN,
                    usage()
                ));
            }
            (Some(_), None) => None,
            (None, Some(_)) => {
                return Err(format!(
                    "missing {} for {}\n{}",
                    options::AGENT_KIND,
                    options::AGENT_RUN,
                    usage()
                ));
            }
            (None, None) => None,
        };
        let agent_discovery = if agent_discover {
            let kind = agent_kind.ok_or_else(|| {
                format!(
                    "missing {} for {}\n{}",
                    options::AGENT_KIND,
                    options::AGENT_DISCOVER,
                    usage()
                )
            })?;
            Some(AgentDiscoveryRequest::new(kind)?)
        } else {
            None
        };

        if agent_run.is_some() && (scope_cgroup.is_some() || scope_pid.is_some()) {
            return Err(format!(
                "{} cannot be combined with {} or {}",
                options::AGENT_RUN,
                options::SCOPE_PID,
                options::SCOPE_CGROUP
            ));
        }
        if agent_registration_path.is_some() && (scope_cgroup.is_some() || scope_pid.is_some()) {
            return Err(format!(
                "{} cannot be combined with {} or {}",
                options::AGENT_REGISTRATION,
                options::SCOPE_PID,
                options::SCOPE_CGROUP
            ));
        }
        if agent_discovery.is_some() && (scope_cgroup.is_some() || scope_pid.is_some()) {
            return Err(format!(
                "{} cannot be combined with {} or {}",
                options::AGENT_DISCOVER,
                options::SCOPE_PID,
                options::SCOPE_CGROUP
            ));
        }
        if agent_run.is_some() && (agent_registration_path.is_some() || agent_discovery.is_some()) {
            return Err(format!(
                "{} cannot be combined with {} or {}",
                options::AGENT_RUN,
                options::AGENT_REGISTRATION,
                options::AGENT_DISCOVER
            ));
        }
        if agent_registration_path.is_some() && agent_discovery.is_some() {
            return Err(format!(
                "{} cannot be combined with {}",
                options::AGENT_REGISTRATION,
                options::AGENT_DISCOVER
            ));
        }

        let live_scope = match (scope_cgroup, scope_pid) {
            (Some(id), None) => Some(LiveScope::Cgroup(id)),
            (None, Some(pid)) => Some(LiveScope::ProcessTree(pid)),
            (None, None)
                if backend == ObserverBackendSelection::Live
                    && agent_run.is_none()
                    && agent_registration_path.is_none()
                    && agent_discovery.is_none() =>
            {
                return Err(live_scope_requirement());
            }
            (Some(_), Some(_)) => {
                return Err(live_scope_requirement());
            }
            (None, None) => None,
        };
        let output_rotation = match (output_max_bytes, output_max_files) {
            (Some(max_file_bytes), Some(max_archived_files)) => {
                if max_file_bytes == 0 {
                    return Err(format!(
                        "{} must be greater than zero",
                        options::OUTPUT_MAX_BYTES
                    ));
                }
                if max_archived_files == 0 {
                    return Err(format!(
                        "{} must be greater than zero",
                        options::OUTPUT_MAX_FILES
                    ));
                }
                Some(JsonlRotationPolicy {
                    max_file_bytes,
                    max_archived_files,
                })
            }
            (None, None) => None,
            (Some(_), None) => {
                return Err(format!(
                    "{} requires {}",
                    options::OUTPUT_MAX_BYTES,
                    options::OUTPUT_MAX_FILES
                ));
            }
            (None, Some(_)) => {
                return Err(format!(
                    "{} requires {}",
                    options::OUTPUT_MAX_FILES,
                    options::OUTPUT_MAX_BYTES
                ));
            }
        };

        match backend {
            ObserverBackendSelection::Fixture => {
                if bpf_object_path.is_some()
                    || live_scope.is_some()
                    || agent_run.is_some()
                    || agent_registration_path.is_some()
                    || agent_discovery.is_some()
                    || duration_seconds.is_some()
                    || workspace_root.is_some()
                {
                    return Err("live observer options require --backend live".to_string());
                }
                if input_path.is_none() {
                    return Err(format!("missing {}\n{}", options::INPUT, usage()));
                }
            }
            ObserverBackendSelection::Live => {
                if input_path.is_some() {
                    return Err("--input is only valid with --backend fixture".to_string());
                }
                if kubernetes_metadata_path.is_some() {
                    return Err(
                        "--kubernetes-metadata is not supported by --backend live in AuditObserver"
                            .to_string(),
                    );
                }
                if bpf_object_path.is_none() {
                    return Err(format!("missing {}\n{}", options::BPF_OBJECT, usage()));
                }
            }
        }

        Ok(Self {
            backend,
            input_path,
            output_path: output_path
                .ok_or_else(|| format!("missing {}\n{}", options::OUTPUT, usage()))?,
            session_id: session_id
                .ok_or_else(|| format!("missing {}\n{}", options::SESSION, usage()))?,
            kubernetes_metadata_path,
            bpf_object_path,
            live_scope,
            agent_run,
            agent_registration_path,
            agent_discovery,
            duration_seconds,
            workspace_root,
            output_rotation,
        })
    }
}

fn live_scope_requirement() -> String {
    "live observer requires exactly one of --scope-cgroup, --agent-run, --agent-registration, or --agent-discover".to_string()
}

fn parse_option<T>(args: &[String], index: usize, option: &str) -> Result<Option<T>, String>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = args
        .get(index)
        .ok_or_else(|| format!("missing {option} value\n{}", usage()))?;
    value
        .parse()
        .map(Some)
        .map_err(|error| format!("invalid {option} value '{value}': {error}"))
}

impl VisibilityRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some(commands::VISIBILITY) {
            return Err(usage());
        }

        let mut scenario = None;
        let mut input_path = None;
        let mut output_path = None;
        let mut session_id = None;
        let mut kubernetes_metadata_path = None;
        let mut i = 1;

        while i < args.len() {
            match args[i].as_str() {
                options::SCENARIO => {
                    i += 1;
                    scenario = args.get(i).cloned();
                }
                options::INPUT => {
                    i += 1;
                    input_path = args.get(i).cloned();
                }
                options::OUTPUT => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                options::SESSION => {
                    i += 1;
                    session_id = args.get(i).cloned();
                }
                options::KUBERNETES_METADATA => {
                    i += 1;
                    kubernetes_metadata_path = args.get(i).cloned();
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        let runtime_profile = RuntimeVisibilityProfile::parse(
            &scenario.ok_or_else(|| format!("missing {}\n{}", options::SCENARIO, usage()))?,
        )?;
        let session_id = session_id.unwrap_or_else(|| {
            format!(
                "visibility-{}-{}",
                std::process::id(),
                apolysis_core::now_unix_ms()
            )
        });

        Ok(Self {
            runtime_profile,
            input_path: input_path
                .ok_or_else(|| format!("missing {}\n{}", options::INPUT, usage()))?,
            output_path: output_path
                .ok_or_else(|| format!("missing {}\n{}", options::OUTPUT, usage()))?,
            session_id,
            kubernetes_metadata_path,
        })
    }
}

fn usage() -> String {
    cli::usage()
}

#[cfg(test)]
mod tests {
    use super::{
        accumulate_projection_input_budget, evidence_loss_warning, executable_matches,
        observer_evidence_loss, ProjectRunRequest,
    };
    use apolysis_accountability::{
        MAX_AGENT_RUN_PROJECTION_BATCHES, MAX_AGENT_RUN_PROJECTION_RECORDS,
    };
    use apolysis_store::MAX_SAVED_RUN_BYTES;

    #[test]
    fn evidence_loss_is_summed_and_warned() {
        let timeline = concat!(
            r#"{"record_type":"observer_diagnostic","session_id":"s","kind":"truncation","count":2,"detail":"x"}"#,
            "\n",
            r#"{"record_type":"observer_diagnostic","session_id":"s","kind":"ring_buffer_reserve_failure","count":3,"detail":"x"}"#,
            "\n",
            r#"{"record_type":"observer_diagnostic","session_id":"s","kind":"decode_failure","count":1,"detail":"x"}"#,
            "\n",
            r#"{"record_type":"observer_diagnostic","session_id":"s","kind":"abi_mismatch","count":1,"detail":"x"}"#,
            "\n",
            r#"{"record_type":"event","event_type":"exec","raw_event_id":"s:e:1"}"#,
            "\n",
        );
        assert_eq!(observer_evidence_loss(timeline), (5, 2, 0));
        assert!(evidence_loss_warning(5, 2, 0).is_some());
        // A whole timeline (no diagnostics) must not warn.
        assert_eq!(
            observer_evidence_loss(r#"{"record_type":"event"}"#),
            (0, 0, 0)
        );
        assert!(evidence_loss_warning(0, 0, 0).is_none());
    }

    #[test]
    fn executable_matches_by_name_across_path_forms() {
        // Agents declare a bare command; the kernel records the resolved path.
        assert!(executable_matches("cargo", Some("/usr/bin/cargo")));
        assert!(executable_matches("./run.sh", Some("/work/run.sh")));
        assert!(executable_matches(
            "/usr/bin/python3",
            Some("/usr/bin/python3")
        ));
        // Different executables must not match, and a missing path never matches.
        assert!(!executable_matches("cargo", Some("/usr/bin/rustc")));
        assert!(!executable_matches("cargo", None));
    }

    #[test]
    fn project_request_rejects_too_many_inputs_before_reading_them() {
        let mut args = vec!["run".to_string(), "project".to_string()];
        for _ in 0..=MAX_AGENT_RUN_PROJECTION_BATCHES {
            args.push("--input".to_string());
            args.push("timeline.jsonl".to_string());
        }
        args.push("--output".to_string());
        args.push("record.json".to_string());

        let error = ProjectRunRequest::parse(args).expect_err("batch limit must be preflighted");
        assert!(error.contains("batch count"), "{error}");
    }

    #[test]
    fn projection_input_budget_is_global_across_batches() {
        let mut total_bytes = MAX_SAVED_RUN_BYTES - 1;
        let mut total_records = MAX_AGENT_RUN_PROJECTION_RECORDS - 1;
        let error = accumulate_projection_input_budget(&mut total_bytes, &mut total_records, 2, 1)
            .expect_err("combined byte limit must fail");
        assert!(error.contains("byte limit"), "{error}");
        assert_eq!(total_bytes, MAX_SAVED_RUN_BYTES - 1);
        assert_eq!(total_records, MAX_AGENT_RUN_PROJECTION_RECORDS - 1);

        total_bytes = 0;
        total_records = MAX_AGENT_RUN_PROJECTION_RECORDS;
        let error = accumulate_projection_input_budget(&mut total_bytes, &mut total_records, 0, 1)
            .expect_err("combined record limit must fail");
        assert!(error.contains("record limit"), "{error}");
    }
}
