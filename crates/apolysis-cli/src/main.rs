// SPDX-License-Identifier: Apache-2.0

mod cli;

use std::path::{Path, PathBuf};
use std::time::Duration;

use apolysis_accountability::{
    AccountabilityFinding, EvidenceBoundary, FindingDecision, FindingKind, RuntimeIdentity,
    FINDING_SCHEMA_V1,
};
use apolysis_core::{now_unix_ms, JsonLine, SessionIntentRecord};
use apolysis_observer::{
    observe_fixture, observe_live, redact_command_text_for_persistence, AgentDiscoveryRequest,
    AgentRunRequest, FixtureObserveRequest, LiveObserveRequest, LiveScope,
};
use apolysis_runtime::{run_docker, run_local, DockerRunRequest, LocalRunRequest};
use apolysis_store::{HashChainStore, JsonlRotationPolicy};
use apolysis_visibility::{assess_visibility, RuntimeVisibilityProfile, VisibilityInput};
use cli::{commands, options, values};

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
    match args.first().map(String::as_str) {
        Some(commands::RUN) => run_command(args),
        Some(commands::OBSERVE) => observe_command(args).await,
        Some(commands::INTENT) => intent_command(args).await,
        Some(commands::VISIBILITY) => visibility_command(args).await,
        Some(commands::VERIFY) => verify_command(args).await,
        _ => Err(usage()),
    }
}

fn run_command(args: Vec<String>) -> Result<i32, String> {
    let request = RunRequest::parse(args)?;
    match request.runtime {
        RuntimeSelection::Local => {
            let result = run_local(LocalRunRequest::new(
                request.policy_path,
                request.output_path,
                request.command,
            ))?;
            Ok(result.exit_code)
        }
        RuntimeSelection::Docker { image, oci_runtime } => {
            let result = run_docker(
                DockerRunRequest::new(
                    request.policy_path,
                    request.output_path,
                    image,
                    request.command,
                )
                .with_oci_runtime(oci_runtime),
            )?;
            Ok(result.exit_code)
        }
    }
}

async fn intent_command(args: Vec<String>) -> Result<i32, String> {
    match args.get(1).map(String::as_str) {
        Some(commands::INGEST) => intent_ingest_command(args).await,
        Some(commands::CORRELATE) => intent_correlate_command(args).await,
        _ => Err(usage()),
    }
}

async fn intent_ingest_command(args: Vec<String>) -> Result<i32, String> {
    let request = IntentIngestRequest::parse(args)?;
    let input = tokio::fs::read_to_string(&request.input_path)
        .await
        .map_err(|error| format!("failed to read intent input: {error}"))?;
    let records = match request.adapter {
        IntentAdapterSelection::CodexJsonl => codex_intent_records(
            &input,
            &request.session_id,
            request.workspace_root.as_deref(),
        )?,
    };
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

async fn intent_correlate_command(args: Vec<String>) -> Result<i32, String> {
    let request = IntentCorrelateRequest::parse(args)?;
    let intent_input = tokio::fs::read_to_string(&request.intent_input_path)
        .await
        .map_err(|error| format!("failed to read intent input: {error}"))?;
    let timeline_input = tokio::fs::read_to_string(&request.timeline_input_path)
        .await
        .map_err(|error| format!("failed to read timeline input: {error}"))?;
    let records = correlate_intents(&intent_input, &timeline_input)?;
    let (dropped, truncated) = observer_evidence_loss(&timeline_input);
    if let Some(warning) = evidence_loss_warning(dropped, truncated) {
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
                    request.policy_path,
                    request.session_id,
                )
                .with_feedback_dir(request.feedback_dir)
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
                policy_path: request.policy_path.into(),
                session_id: request.session_id,
                feedback_dir: request.feedback_dir.map(Into::into),
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
            })
            .await?;
            Ok(result.agent_exit_code.unwrap_or(0))
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct IntentIngestRequest {
    adapter: IntentAdapterSelection,
    input_path: String,
    output_path: String,
    session_id: String,
    workspace_root: Option<PathBuf>,
}

#[derive(Debug, Eq, PartialEq)]
struct IntentCorrelateRequest {
    intent_input_path: String,
    timeline_input_path: String,
    output_path: String,
    summary: bool,
}

#[derive(Debug, Eq, PartialEq)]
struct VerifyHashChainRequest {
    input_path: PathBuf,
    output_path: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
enum IntentAdapterSelection {
    CodexJsonl,
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

        let adapter = match adapter
            .ok_or_else(|| format!("missing {}\n{}", options::ADAPTER, usage()))?
            .as_str()
        {
            values::CODEX_JSONL => IntentAdapterSelection::CodexJsonl,
            unknown => return Err(format!("unsupported intent adapter '{unknown}'")),
        };

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

fn codex_intent_records(
    input: &str,
    session_id: &str,
    workspace_root: Option<&Path>,
) -> Result<Vec<SessionIntentRecord>, String> {
    let workspace_root = match workspace_root {
        Some(path) => path.to_path_buf(),
        None => std::env::current_dir()
            .map_err(|error| format!("failed to resolve current workspace root: {error}"))?,
    };
    let mut records = Vec::new();

    for (index, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let value = serde_json::from_str::<serde_json::Value>(line).map_err(|error| {
            format!(
                "failed to parse codex-jsonl intent line {}: {error}",
                index + 1
            )
        })?;
        let Some(tool_call) = codex_tool_call(&value, index + 1) else {
            continue;
        };
        let command = tool_call.command.map(|command| {
            redact_command_text_for_persistence(session_id, &workspace_root, &command).value
        });
        let mut record = SessionIntentRecord::new(
            session_id,
            "codex",
            tool_call.intent_id,
            "tool_call",
            tool_call.tool_name.clone(),
        )
        .with_declared_action(declared_action_for_tool(&tool_call.tool_name));

        if let Some(source_event_id) = tool_call.source_event_id {
            record = record.with_source_event_id(source_event_id);
        }
        if let Some(target) = tool_call.target {
            record = record.with_target(target);
        }
        if let Some(command) = command {
            record = record.with_command(command);
        }
        records.push(record);
    }

    Ok(records)
}

#[derive(Debug, Eq, PartialEq)]
struct CodexToolCall {
    intent_id: String,
    source_event_id: Option<String>,
    tool_name: String,
    target: Option<String>,
    command: Option<String>,
}

fn codex_tool_call(value: &serde_json::Value, line_number: usize) -> Option<CodexToolCall> {
    let payload = value
        .get("payload")
        .or_else(|| value.get("item"))
        .unwrap_or(value);
    let item_type = payload
        .get("type")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("type").and_then(serde_json::Value::as_str))?;
    if !matches!(item_type, "function_call" | "tool_call") {
        return None;
    }

    let tool_name = payload
        .get("name")
        .or_else(|| payload.get("tool_name"))
        .and_then(serde_json::Value::as_str)?
        .to_string();
    let source_event_id = payload
        .get("id")
        .or_else(|| payload.get("call_id"))
        .or_else(|| value.get("id"))
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);
    let intent_id = source_event_id
        .as_ref()
        .map(|id| format!("codex:{id}"))
        .unwrap_or_else(|| format!("codex:line:{line_number}"));
    let arguments = payload.get("arguments").or_else(|| payload.get("args"));
    let command = arguments.and_then(command_from_arguments);

    Some(CodexToolCall {
        intent_id,
        source_event_id,
        tool_name,
        target: command.as_ref().map(|_| "workspace".to_string()),
        command,
    })
}

fn command_from_arguments(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(raw) => serde_json::from_str::<serde_json::Value>(raw)
            .ok()
            .and_then(|parsed| command_from_arguments(&parsed))
            .or_else(|| Some(raw.clone())),
        serde_json::Value::Object(map) => ["cmd", "command", "command_line", "shell"]
            .iter()
            .find_map(|key| {
                map.get(*key)
                    .and_then(serde_json::Value::as_str)
                    .map(ToString::to_string)
            })
            .or_else(|| {
                serde_json::to_string(value)
                    .ok()
                    .filter(|serialized| serialized != "{}")
            }),
        _ => None,
    }
}

fn declared_action_for_tool(tool_name: &str) -> &'static str {
    let normalized = tool_name.to_ascii_lowercase();
    if normalized.contains("exec") || normalized.contains("shell") || normalized.contains("command")
    {
        "shell.command"
    } else {
        "tool.call"
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IntentForCorrelation {
    session_id: String,
    intent_source: String,
    intent_id: String,
    command: Option<String>,
    raw_event_id: Option<String>,
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

    let event_by_id: std::collections::HashMap<&str, &ObservedEventForCorrelation> = events
        .iter()
        .map(|event| (event.raw_event_id.as_str(), event))
        .collect();

    let mut matched = Vec::new();
    let mut findings = Vec::new();
    for record in records {
        match string_field(record, "record_type") {
            Some("intent_correlation") => matched.push(record),
            Some("accountability_finding") => findings.push(record),
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
        "  {} side effect(s) matched declared intent, {} finding(s) with no declared intent",
        matched.len(),
        findings.len()
    );

    for record in &matched {
        let resource = string_field(record, "resource").unwrap_or("");
        let command = string_field(record, "command").unwrap_or("");
        let basis = string_field(record, "match_basis").unwrap_or("");
        let _ = writeln!(out, "  \u{2713} matched   {resource}");
        let _ = writeln!(out, "            declared as: {command}  [{basis}]");
    }

    for record in &findings {
        let kind = string_field(record, "kind").unwrap_or("finding");
        let decision = string_field(record, "decision").unwrap_or("review");
        let reason = string_field(record, "reason").unwrap_or("");
        let evidence_ref = string_field(record, "evidence_ref").unwrap_or("");
        let event = event_by_id.get(evidence_ref).copied();
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

    if findings.is_empty() {
        let _ = writeln!(
            out,
            "  no findings: every observed side effect matched a declared intent."
        );
    }

    out
}

fn correlate_intents(
    intent_input: &str,
    timeline_input: &str,
) -> Result<Vec<serde_json::Value>, String> {
    let intents = parse_intent_records(intent_input)?;
    let events = parse_observed_events(timeline_input)?;
    let mut records = Vec::new();
    let mut matched_intents = vec![false; intents.len()];

    for event in &events {
        let matched = intents
            .iter()
            .enumerate()
            .find(|(_, intent)| {
                intent.session_id == event.session_id
                    && intent.raw_event_id.as_deref() == Some(event.raw_event_id.as_str())
            })
            .map(|(index, intent)| (index, intent, "raw_event_id"))
            .or_else(|| {
                event.process_command.as_ref().and_then(|command| {
                    intents
                        .iter()
                        .enumerate()
                        .find(|(_, intent)| {
                            intent.session_id == event.session_id
                                && intent.command.as_deref() == Some(command.as_str())
                        })
                        .map(|(index, intent)| (index, intent, "process_command_exact"))
                })
            })
            .or_else(|| {
                if event.event_type != "exec" {
                    return None;
                }
                intents
                    .iter()
                    .enumerate()
                    .find(|(_, intent)| {
                        intent.session_id == event.session_id
                            && intent
                                .command
                                .as_deref()
                                .and_then(command_executable)
                                .map(|executable| {
                                    executable_matches(
                                        executable,
                                        event.process_executable.as_deref(),
                                    ) || executable_matches(executable, Some(&event.resource))
                                })
                                .unwrap_or(false)
                    })
                    .map(|(index, intent)| (index, intent, "process_executable"))
            });

        if let Some((index, intent, match_basis)) = matched {
            matched_intents[index] = true;
            records.push(intent_correlation_record(intent, event, match_basis));
        } else if event.report_missing_intent {
            records.push(accountability_finding_record(
                &event.session_id,
                FindingKind::MissingIntent,
                "observed side effect has no matching declared intent",
                &event.raw_event_id,
                &event.runtime,
            )?);
        }
    }

    for (intent, matched) in intents.iter().zip(matched_intents) {
        if !matched {
            records.push(accountability_finding_record(
                &intent.session_id,
                FindingKind::UnobservedIntent,
                "declared intent has no matching observed side effect",
                &intent.intent_id,
                &RuntimeForCorrelation::default(),
            )?);
        }
    }

    Ok(records)
}

fn parse_intent_records(input: &str) -> Result<Vec<IntentForCorrelation>, String> {
    parse_jsonl(input, "intent input")?
        .into_iter()
        .filter(|value| string_field(value, "record_type") == Some("intent"))
        .map(|value| {
            Ok(IntentForCorrelation {
                session_id: required_string_field(&value, "session_id")?.to_string(),
                intent_source: required_string_field(&value, "intent_source")?.to_string(),
                intent_id: required_string_field(&value, "intent_id")?.to_string(),
                command: string_field(&value, "command").map(ToString::to_string),
                raw_event_id: string_field(&value, "raw_event_id").map(ToString::to_string),
            })
        })
        .collect()
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
    let Some(observed) = observed else {
        return false;
    };
    if declared == observed {
        return true;
    }
    let declared_name = declared.rsplit('/').next().unwrap_or(declared);
    let observed_name = observed.rsplit('/').next().unwrap_or(observed);
    !declared_name.is_empty() && declared_name == observed_name
}

/// Sum the observer's event-loss diagnostics in a timeline into
/// (dropped, truncated). Best-effort: a malformed timeline yields (0, 0).
fn observer_evidence_loss(timeline_input: &str) -> (u64, u64) {
    let records = parse_jsonl(timeline_input, "timeline input").unwrap_or_default();
    let mut dropped = 0;
    let mut truncated = 0;
    for value in &records {
        if string_field(value, "record_type") != Some("observer_diagnostic") {
            continue;
        }
        let count = value
            .get("count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        match string_field(value, "kind") {
            Some("ring_buffer_reserve_failure" | "map_pressure" | "decode_failure") => {
                dropped += count;
            }
            Some("truncation") => truncated += count,
            _ => {}
        }
    }
    (dropped, truncated)
}

/// The fail-loud incompleteness warning, or None when the evidence is whole.
fn evidence_loss_warning(dropped: u64, truncated: u64) -> Option<String> {
    if dropped == 0 && truncated == 0 {
        return None;
    }
    Some(format!(
        "apolysis: ⚠ evidence may be incomplete — {dropped} event(s) dropped, \
         {truncated} truncated. A quiet timeline is not proof of absence."
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
        "match_basis": match_basis,
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
struct RunRequest {
    runtime: RuntimeSelection,
    policy_path: String,
    output_path: String,
    command: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
enum RuntimeSelection {
    Local,
    Docker {
        image: String,
        oci_runtime: Option<String>,
    },
}

impl RunRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some(commands::RUN) {
            return Err(usage());
        }

        let mut runtime = values::LOCAL.to_string();
        let mut image = None;
        let mut docker_runtime = None;
        let mut policy_path = None;
        let mut output_path = Some(cli::DEFAULT_TIMELINE_PATH.to_string());
        let mut command = Vec::new();
        let mut i = 1;

        while i < args.len() {
            match args[i].as_str() {
                options::POLICY => {
                    i += 1;
                    policy_path = args.get(i).cloned();
                }
                options::RUNTIME => {
                    i += 1;
                    runtime = args.get(i).cloned().ok_or_else(|| {
                        format!("missing {} value\n{}", options::RUNTIME, usage())
                    })?;
                }
                options::IMAGE => {
                    i += 1;
                    image = args.get(i).cloned();
                }
                options::DOCKER_RUNTIME => {
                    i += 1;
                    docker_runtime = args.get(i).cloned();
                }
                options::OUTPUT => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                options::COMMAND_SEPARATOR => {
                    command = args[(i + 1)..].to_vec();
                    break;
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        let policy_path =
            policy_path.ok_or_else(|| format!("missing {}\n{}", options::POLICY, usage()))?;
        let output_path =
            output_path.ok_or_else(|| format!("missing {} value\n{}", options::OUTPUT, usage()))?;
        if command.is_empty() {
            return Err(format!(
                "missing command after {}\n{}",
                options::COMMAND_SEPARATOR,
                usage()
            ));
        }

        let runtime = match runtime.as_str() {
            values::LOCAL => {
                if image.is_some() {
                    return Err(format!(
                        "{} requires {} {}\n{}",
                        options::IMAGE,
                        options::RUNTIME,
                        values::DOCKER,
                        usage()
                    ));
                }
                if docker_runtime.is_some() {
                    return Err(format!(
                        "{} requires {} {}\n{}",
                        options::DOCKER_RUNTIME,
                        options::RUNTIME,
                        values::DOCKER,
                        usage()
                    ));
                }
                RuntimeSelection::Local
            }
            values::DOCKER => RuntimeSelection::Docker {
                image: image.ok_or_else(|| format!("missing {}\n{}", options::IMAGE, usage()))?,
                oci_runtime: docker_runtime,
            },
            unknown => return Err(format!("unknown runtime '{unknown}'\n{}", usage())),
        };

        Ok(Self {
            runtime,
            policy_path,
            output_path,
            command,
        })
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ObserveRequest {
    backend: ObserverBackendSelection,
    input_path: Option<String>,
    output_path: String,
    policy_path: String,
    session_id: String,
    feedback_dir: Option<String>,
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
        let mut policy_path = None;
        let mut session_id = None;
        let mut feedback_dir = None;
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
                options::POLICY => {
                    i += 1;
                    policy_path = args.get(i).cloned();
                }
                options::SESSION => {
                    i += 1;
                    session_id = args.get(i).cloned();
                }
                options::FEEDBACK_DIR => {
                    i += 1;
                    feedback_dir = args.get(i).cloned();
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
            policy_path: policy_path
                .ok_or_else(|| format!("missing {}\n{}", options::POLICY, usage()))?,
            session_id: session_id
                .ok_or_else(|| format!("missing {}\n{}", options::SESSION, usage()))?,
            feedback_dir,
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
    "live observer requires exactly one of --scope-cgroup, --scope-pid, --agent-run, --agent-registration, or --agent-discover".to_string()
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
    use super::{evidence_loss_warning, executable_matches, observer_evidence_loss};

    #[test]
    fn evidence_loss_is_summed_and_warned() {
        let timeline = concat!(
            r#"{"record_type":"observer_diagnostic","session_id":"s","kind":"truncation","count":2,"detail":"x"}"#,
            "\n",
            r#"{"record_type":"observer_diagnostic","session_id":"s","kind":"ring_buffer_reserve_failure","count":3,"detail":"x"}"#,
            "\n",
            r#"{"record_type":"observer_diagnostic","session_id":"s","kind":"decode_failure","count":1,"detail":"x"}"#,
            "\n",
            r#"{"record_type":"event","event_type":"exec","raw_event_id":"s:e:1"}"#,
            "\n",
        );
        assert_eq!(observer_evidence_loss(timeline), (4, 2));
        assert!(evidence_loss_warning(4, 2).is_some());
        // A whole timeline (no diagnostics) must not warn.
        assert_eq!(observer_evidence_loss(r#"{"record_type":"event"}"#), (0, 0));
        assert!(evidence_loss_warning(0, 0).is_none());
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
}
