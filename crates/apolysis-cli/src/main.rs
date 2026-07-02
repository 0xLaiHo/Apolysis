// SPDX-License-Identifier: Apache-2.0

mod cli;

use std::path::{Path, PathBuf};
use std::time::Duration;

use apolysis_core::SessionIntentRecord;
use apolysis_observer::{
    observe_fixture, observe_live, redact_command_text_for_persistence, AgentDiscoveryRequest,
    AgentRunRequest, FixtureObserveRequest, LiveObserveRequest, LiveScope,
};
use apolysis_runtime::{run_docker, run_local, DockerRunRequest, LocalRunRequest};
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
                .with_kubernetes_metadata_path(request.kubernetes_metadata_path),
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
