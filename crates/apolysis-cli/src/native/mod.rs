// SPDX-License-Identifier: Apache-2.0

//! Native application supervision. The application keeps the user's terminal,
//! identity and environment. Only the independent capture helper uses sudo.

mod adapters;
mod report;
mod transport;

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use apolysis_observer::{
    observe_live_controlled, LiveObserveControl, LiveObserveRequest, LiveScope,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::oneshot;

use transport::{atomic_write, exit_code, receive, send, Launch, NativeChild, Terminal};

const HELP: &str = "apolysis observe --agent codex|claude|cursor|pi|opencode [options] -- [native arguments]\n\nRun without sudo. Only the collector requests elevation; the native application\nkeeps its interface, permissions, environment and original argument boundaries.\n\nOptions before --:\n  --workspace <directory>       Launch directory (default: current directory)\n  --output-dir <parent>         Private run directories (default: user state directory)\n  --bpf-object <path>           Matching observer object\n  --allow-reason-summary        Opt in to bounded, redacted declared text\n  --shell-bridge <shell>        Opt in to an inner shell for shell-tool attribution\n  --help                       Show this help\n\nArguments after -- belong exclusively to the selected application. Native help\nand version queries bypass capture and elevation. No application is selected by\ndefault. Reports do not claim task success from syscall attempts.";
const MAX_TIMELINE: u64 = 64 * 1024 * 1024;

#[derive(Debug, PartialEq)]
struct Options {
    agent: String,
    workspace: PathBuf,
    output: Option<PathBuf>,
    bpf: Option<PathBuf>,
    summary: bool,
    bridge: Option<String>,
    native: Vec<String>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let split = args
            .iter()
            .position(|arg| arg == "--")
            .unwrap_or(args.len());
        let mut result = Self {
            agent: String::new(),
            workspace: std::env::current_dir().map_err(|_| "cannot resolve launch directory")?,
            output: None,
            bpf: None,
            summary: false,
            bridge: None,
            native: args.get(split + 1..).unwrap_or_default().to_vec(),
        };
        let mut before = args[..split].iter();
        let mut seen = HashSet::new();
        while let Some(option) = before.next() {
            if !seen.insert(option) {
                return Err("duplicate native observation option".into());
            }
            if option == "--allow-reason-summary" {
                result.summary = true;
                continue;
            }
            if !matches!(
                option.as_str(),
                "--agent" | "--workspace" | "--output-dir" | "--bpf-object" | "--shell-bridge"
            ) {
                return Err(
                    "unknown observation option; put native application arguments after --".into(),
                );
            }
            let value = before
                .next()
                .filter(|value| !value.is_empty() && !value.starts_with("--"))
                .ok_or("observation option requires a value")?;
            match option.as_str() {
                "--agent" => result.agent = value.clone(),
                "--workspace" => result.workspace = value.into(),
                "--output-dir" => result.output = Some(value.into()),
                "--bpf-object" => result.bpf = Some(value.into()),
                "--shell-bridge" => result.bridge = Some(value.clone()),
                _ => unreachable!(),
            }
        }
        if result.agent.is_empty() {
            return Err("select a native application with --agent; there is no default".into());
        }
        adapters::executable_name(&result.agent)?;
        Ok(result)
    }
}

pub(crate) fn handles(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("_native-exec" | "_native-capture")
    ) || (args.first().map(String::as_str) == Some("observe")
        && args
            .iter()
            .skip(1)
            .take_while(|value| value.as_str() != "--")
            .any(|value| value == "--agent" || value == "--help" || value == "-h"))
}

pub(crate) async fn run(args: &[String]) -> Result<i32, String> {
    match args.first().map(String::as_str) {
        Some("_native-exec") if args.len() == 1 => return transport::exec_gated(),
        Some("_native-capture") if args.len() == 2 => return capture(Path::new(&args[1])).await,
        Some("observe") => {}
        _ => return Err("invalid internal native command".into()),
    }
    if args
        .iter()
        .skip(1)
        .take_while(|value| value.as_str() != "--")
        .any(|value| value == "--help" || value == "-h")
    {
        println!("{HELP}");
        return Ok(0);
    }
    let options = Options::parse(&args[1..])?;
    // SAFETY: geteuid has no memory arguments.
    if unsafe { libc::geteuid() } == 0 {
        return Err("run native observation as your normal user, without sudo; the collector requests elevation itself".into());
    }
    let executable = find_executable(adapters::executable_name(&options.agent)?)?;
    let workspace = fs::canonicalize(&options.workspace)
        .map_err(|_| "native launch directory does not exist")?;
    if adapters::informational_args(&options.native) {
        let status = std::process::Command::new(executable)
            .args(&options.native)
            .current_dir(&workspace)
            .env("PWD", &workspace)
            .status()
            .map_err(|_| "could not run native help or version")?;
        return Ok(exit_code(status));
    }
    let binary = std::env::current_exe().map_err(|_| "cannot locate apolysis executable")?;
    let bpf = resolve_bpf(options.bpf.as_deref())?;
    let output_parent = options.output.clone().unwrap_or_else(default_output);
    fs::create_dir_all(&output_parent).map_err(|_| "cannot create native evidence parent")?;
    let output_parent =
        fs::canonicalize(output_parent).map_err(|_| "cannot resolve native evidence parent")?;
    let root = tempfile::Builder::new()
        .prefix(&format!("native-{}-", options.agent))
        .tempdir_in(output_parent)
        .map_err(|_| "cannot create private native run directory")?
        .keep();
    let evidence = root.join("evidence");
    fs::create_dir(&evidence).map_err(|_| "cannot create native evidence directory")?;
    fs::set_permissions(&evidence, fs::Permissions::from_mode(0o700))
        .map_err(|_| "cannot protect native evidence directory")?;
    // The correlator appends through the store. Precreate its output privately
    // too, so native evidence permissions do not depend on the caller's umask.
    for name in [
        "intent.jsonl",
        "intent.jsonl.reasons.jsonl",
        "correlation.jsonl",
    ] {
        atomic_write(&evidence.join(name), b"")?;
    }
    let control = tempfile::Builder::new()
        .prefix("apolysis-native-control-")
        .tempdir()
        .map_err(|_| "cannot create native control directory")?;
    let session = format!(
        "native-{}-{}",
        options.agent,
        root.file_name()
            .ok_or("invalid native run directory")?
            .to_string_lossy()
    );
    let plan = adapters::prepare(&adapters::PrepareRequest {
        product: &options.agent,
        apolysis: &binary,
        executable: &executable,
        native_args: &options.native,
        workspace: &workspace,
        control: control.path(),
        evidence: &evidence,
        session: &session,
        allow_reason_summary: options.summary,
        shell_bridge: options.bridge.as_deref(),
    })?;
    let mut outcome = report::RunOutcome {
        agent: options.agent.clone(),
        session_id: session.clone(),
        exit_code: None,
        signal: None,
        interrupted: false,
        errors: Vec::new(),
        notes: plan.coverage_notes.clone(),
    };
    eprintln!(
        "Apolysis: starting native {}; evidence: {}",
        options.agent,
        evidence.display()
    );
    let request = CaptureRequest {
        pid: 0,
        start_ticks: 0,
        agent: options.agent.clone(),
        session,
        workspace: plan.workspace.clone(),
        bpf,
    };
    let mut native_status = None;
    let observed = supervise(
        &binary,
        &plan,
        &workspace,
        control.path(),
        &evidence,
        request,
        &mut native_status,
    )
    .await;
    if observed.is_err() {
        eprintln!("Apolysis: native launch or capture failed; see the incomplete report.");
    }
    let status = record_supervision_result(&mut outcome, observed, native_status);
    let _ = fs::remove_file(evidence.join("intent.jsonl.reasons.jsonl.prompt"));
    let correlation_args = vec![
        "intent".into(),
        "correlate".into(),
        "--intent-input".into(),
        evidence.join("intent.jsonl").to_string_lossy().into_owned(),
        "--reason-input".into(),
        evidence
            .join("intent.jsonl.reasons.jsonl")
            .to_string_lossy()
            .into_owned(),
        "--timeline-input".into(),
        evidence
            .join("timeline.jsonl")
            .to_string_lossy()
            .into_owned(),
        "--output".into(),
        evidence
            .join("correlation.jsonl")
            .to_string_lossy()
            .into_owned(),
    ];
    if crate::intent_correlate_command(correlation_args)
        .await
        .is_err()
    {
        outcome.errors.push("correlation_incomplete".into());
    }
    let rendered = report::render(&evidence, &outcome);
    atomic_write(&evidence.join("result.json"), rendered.json.as_bytes())?;
    atomic_write(&evidence.join("report.md"), rendered.markdown.as_bytes())?;
    atomic_write(&evidence.join("report.html"), rendered.html.as_bytes())?;
    eprint!("{}", rendered.summary);
    eprintln!(
        "Apolysis: report: {}",
        evidence.join("report.html").display()
    );
    if !rendered.complete {
        eprintln!("Apolysis: capture or attribution integrity is incomplete; application outcome is separate.");
    }
    Ok(completion_exit_code(status, rendered.complete))
}

fn record_supervision_result(
    outcome: &mut report::RunOutcome,
    observed: Result<(ExitStatus, bool), String>,
    native_status: Option<ExitStatus>,
) -> Option<ExitStatus> {
    let status = match observed {
        Ok((status, capture_ok)) => {
            if !capture_ok {
                outcome.errors.push("capture_incomplete".into());
            }
            Some(status)
        }
        Err(error) => {
            // Supervision errors are static local diagnostics. Native argv,
            // provider output and arbitrary hook errors never enter this path.
            outcome.errors.push("native_supervision_failed".into());
            outcome.interrupted = error.contains("interrupted") || error.contains("terminated");
            outcome.errors.push(error);
            native_status
        }
    };
    if let Some(status) = status {
        outcome.exit_code = status.code();
        outcome.signal = status.signal();
        // A failed export cannot retroactively change the native application's
        // observed exit into an interruption. Capture errors remain separate.
        outcome.interrupted = status.signal().is_some();
    }
    status
}

fn completion_exit_code(status: Option<ExitStatus>, complete: bool) -> i32 {
    match status {
        Some(status) if exit_code(status) != 0 => exit_code(status),
        Some(_) if complete => 0,
        _ => 2,
    }
}

fn default_output() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .filter(|value| Path::new(value).is_absolute())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state")
        })
        .join("apolysis/captures")
}

fn find_executable(name: &str) -> Result<PathBuf, String> {
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        let candidate = directory.join(name);
        if candidate.is_file()
            && candidate
                .metadata()
                .is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
        {
            return fs::canonicalize(candidate)
                .map_err(|_| "cannot resolve native executable".into());
        }
    }
    Err(format!("installed {name} is required in PATH"))
}

fn resolve_bpf(explicit: Option<&Path>) -> Result<PathBuf, String> {
    let path = explicit
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("APOLYSIS_BPF_OBJECT").map(PathBuf::from))
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ebpf/apolysis_observer.bpf.o")
        });
    fs::canonicalize(path).map_err(|_| {
        "observer BPF object is missing; build it with make build-ebpf or pass --bpf-object".into()
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureRequest {
    pid: u32,
    start_ticks: u64,
    agent: String,
    session: String,
    workspace: PathBuf,
    bpf: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum CaptureMessage {
    Ready,
    Done { complete: bool, bytes: u64 },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stop {
    exit_code: i32,
}

#[allow(clippy::too_many_arguments)]
async fn supervise(
    binary: &Path,
    plan: &adapters::Plan,
    launch_directory: &Path,
    control: &Path,
    evidence: &Path,
    mut request: CaptureRequest,
    native_status: &mut Option<ExitStatus>,
) -> Result<(ExitStatus, bool), String> {
    let mut setup_interrupt =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|_| "cannot install setup interrupt handler")?;
    let mut setup_terminate =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| "cannot install setup termination handler")?;
    let socket_path = control.join("capture.sock");
    let listener =
        UnixListener::bind(&socket_path).map_err(|_| "cannot create capture control socket")?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "cannot protect capture control socket")?;
    let launch = Launch {
        executable: plan.executable.to_string_lossy().into_owned(),
        args: plan.args.clone(),
    };
    let mut child =
        NativeChild::spawn(binary, &launch, launch_directory, &plan.environment).await?;
    request.pid = child.pid;
    request.start_ticks = process_start(child.pid)?;
    // The command recorded by sudo contains no native arguments, prompts, auth,
    // provider configuration or environment overrides.
    let mut helper = Command::new("sudo")
        .arg("--")
        .arg(binary)
        .arg("_native-capture")
        .arg(&socket_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "cannot start privileged collector")?;
    let result = async {
    let connected = tokio::time::timeout(Duration::from_secs(120), async {
        tokio::select! {
            connection = listener.accept() => connection.map(|(stream, _)| stream).map_err(|_| "capture connection failed".to_string()),
            _ = helper.wait() => Err("capture elevation failed".to_string()),
            _ = setup_interrupt.recv() => Err("capture setup interrupted".to_string()),
            _ = setup_terminate.recv() => Err("capture setup terminated".to_string()),
        }
    }).await.map_err(|_| "capture elevation timed out")??;
    if connected.peer_cred().map_err(|_| "cannot verify collector identity")?.uid() != 0 {
        return Err("collector peer is not privileged".into());
    }
    let (mut reader, mut writer) = connected.into_split();
    send(&mut writer, &request).await?;
    let first: CaptureMessage = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            message = receive(&mut reader) => message,
            _ = setup_interrupt.recv() => Err("capture setup interrupted".to_string()),
            _ = setup_terminate.recv() => Err("capture setup terminated".to_string()),
        }
    })
        .await.map_err(|_| "capture initialization timed out")??;
    if !matches!(first, CaptureMessage::Ready) {
        return Err("collector initialization failed before native launch".into());
    }
    let mut terminal = Terminal::new();
    terminal.foreground(child.pid)?;
    child.release().await?;
    let mut early = None;
    let status = tokio::select! {
        status = child.wait(&mut terminal) => status?,
        message = receive::<CaptureMessage, _>(&mut reader) => {
            early = Some(message?);
            child.signal_group(libc::SIGTERM);
            match tokio::time::timeout(Duration::from_secs(5), child.wait(&mut terminal)).await {
                Ok(status) => status?,
                Err(_) => {
                    child.signal_group(libc::SIGKILL);
                    tokio::time::timeout(Duration::from_secs(2), child.wait(&mut terminal))
                        .await.map_err(|_| "native application did not stop after collector failure")??
                },
            }
        }
    };
    // Retain the real application result before socket export, publication or
    // collector cleanup can fail independently of the application.
    *native_status = Some(status);
    terminal.restore();
    let message = if let Some(message) = early { message } else {
        send(&mut writer, &Stop { exit_code: exit_code(status) }).await?;
        tokio::time::timeout(Duration::from_secs(15), receive::<CaptureMessage, _>(&mut reader))
            .await.map_err(|_| "collector finalization timed out")??
    };
    let CaptureMessage::Done { complete, bytes } = message else {
        return Err("invalid collector completion".into());
    };
    if bytes > MAX_TIMELINE { return Err("capture export exceeds local report limit".into()); }
    let mut data = vec![0; bytes as usize];
    tokio::time::timeout(Duration::from_secs(30), reader.read_exact(&mut data))
        .await.map_err(|_| "capture export timed out")?
        .map_err(|_| "capture export interrupted")?;
    atomic_write(&evidence.join("timeline.jsonl"), &data)?;
    writer.shutdown().await.map_err(|_| "capture connection did not close")?;
    let helper_status = tokio::time::timeout(Duration::from_secs(10), helper.wait())
        .await.map_err(|_| "collector did not exit")?
        .map_err(|_| "collector exit unavailable")?;
    Ok((status, complete && helper_status.success()))
    }.await;
    // Socket halves are closed before graceful cleanup. Let the collector flush
    // and remove its root-private directory instead of killing it mid-destructor.
    drop(child);
    if result.is_err()
        && tokio::time::timeout(Duration::from_secs(5), helper.wait())
            .await
            .is_err()
    {
        let _ = helper.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(2), helper.wait()).await;
    }
    result
}

fn process_start(pid: u32) -> Result<u64, String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| "native process identity is unavailable")?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| "invalid native process identity".into())
}

async fn capture(socket: &Path) -> Result<i32, String> {
    // SAFETY: geteuid has no memory arguments.
    if unsafe { libc::geteuid() } != 0 {
        return Err("capture helper requires sudo".into());
    }
    let uid = std::env::var("SUDO_UID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|uid| *uid != 0)
        .ok_or("capture helper requires an invoking user")?;
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|_| "capture control is unavailable")?;
    if stream
        .peer_cred()
        .map_err(|_| "cannot verify capture supervisor")?
        .uid()
        != uid
    {
        return Err("capture supervisor identity mismatch".into());
    }
    let request: CaptureRequest = receive(&mut stream).await?;
    adapters::executable_name(&request.agent)?;
    if request.session.is_empty()
        || request.session.len() > 128
        || request.pid == 0
        || fs::metadata(format!("/proc/{}", request.pid))
            .map_err(|_| "native process missing")?
            .uid()
            != uid
        || process_start(request.pid)? != request.start_ticks
    {
        return Err("native capture process identity mismatch".into());
    }
    let private = tempfile::Builder::new()
        .prefix("apolysis-native-capture-")
        .tempdir()
        .map_err(|_| "cannot create private capture")?;
    let timeline = private.path().join("timeline.jsonl");
    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let observation = observe_live_controlled(
        LiveObserveRequest {
            object_path: request.bpf,
            output_path: timeline.clone(),
            session_id: request.session,
            scope: Some(LiveScope::ProcessTree(request.pid)),
            agent_run: None,
            agent_registration_path: None,
            agent_discovery: None,
            duration: None,
            workspace_root: request.workspace,
            output_rotation: None,
            qualification_telemetry: None,
        },
        LiveObserveControl {
            ready: ready_tx,
            stop: stop_rx,
            agent_kind: request.agent,
        },
    );
    tokio::pin!(observation);
    let first = tokio::select! {
        ready = ready_rx => ready.is_ok(),
        result = &mut observation => {
            send(&mut stream, &CaptureMessage::Done { complete: false, bytes: 0 }).await?;
            return Ok(if result.is_ok() { 0 } else { 2 });
        }
    };
    if !first {
        send(
            &mut stream,
            &CaptureMessage::Done {
                complete: false,
                bytes: 0,
            },
        )
        .await?;
        return Ok(2);
    }
    send(&mut stream, &CaptureMessage::Ready).await?;
    let observed = tokio::select! {
        stop = receive::<Stop, _>(&mut stream) => {
            match stop {
                Ok(stop) if (0..=255).contains(&stop.exit_code) => { let _ = stop_tx.send(stop.exit_code); },
                _ => drop(stop_tx),
            }
            observation.await
        },
        result = &mut observation => result,
    };
    let size = fs::metadata(&timeline).map(|m| m.len()).unwrap_or(0);
    let complete = observed.is_ok() && size > 0 && size <= MAX_TIMELINE;
    let bytes = if size <= MAX_TIMELINE { size } else { 0 };
    send(&mut stream, &CaptureMessage::Done { complete, bytes }).await?;
    if bytes > 0 {
        let mut file = tokio::fs::File::open(timeline)
            .await
            .map_err(|_| "cannot read private capture")?;
        tokio::io::copy(&mut file, &mut stream)
            .await
            .map_err(|_| "capture supervisor disconnected")?;
    }
    stream
        .shutdown()
        .await
        .map_err(|_| "capture export did not close")?;
    Ok(if complete { 0 } else { 2 })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }

    #[test]
    fn native_arguments_remain_opaque_after_separator() {
        let args = strings(&[
            "--agent",
            "claude",
            "--",
            "--model",
            "two words",
            "--agent",
            "literal",
            "--",
            "a\nb",
            "",
        ]);
        let options = Options::parse(&args).unwrap();
        assert_eq!(options.native, args[3..]);
        assert!(!options.summary);
        assert!(options.bridge.is_none());
    }

    #[test]
    fn native_selection_is_explicit_and_unknown_options_do_not_echo_input() {
        assert!(Options::parse(&[]).unwrap_err().contains("no default"));
        assert!(
            Options::parse(&strings(&["--agent", "claude", "--secret-value"]))
                .unwrap_err()
                .contains("after --")
        );
        assert!(
            !Options::parse(&strings(&["--agent", "claude", "--secret-value"]))
                .unwrap_err()
                .contains("secret-value")
        );
        assert!(Options::parse(&strings(&["--agent", "claude", "--agent", "pi"])).is_err());
    }

    #[test]
    fn dispatch_does_not_interpret_native_flags_as_observer_options() {
        assert!(!handles(&strings(&[
            "observe",
            "--backend",
            "live",
            "--agent-run",
            "--",
            "claude",
            "--agent",
            "reviewer"
        ])));
        assert!(handles(&strings(&[
            "observe", "--agent", "pi", "--", "--model", "value"
        ])));
    }

    #[test]
    fn process_identity_uses_start_time_not_only_pid() {
        assert!(process_start(std::process::id()).unwrap() > 0);
        assert!(process_start(u32::MAX).is_err());
    }

    fn empty_outcome() -> report::RunOutcome {
        report::RunOutcome {
            agent: "claude".into(),
            session_id: "native-status-test".into(),
            exit_code: None,
            signal: None,
            interrupted: false,
            errors: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn final_capture_failure_keeps_observed_native_exit_in_report_and_cli_status() {
        let directory = tempfile::tempdir().unwrap();
        for (native, code, signal, cli_code) in [
            (Some(ExitStatus::from_raw(0)), Some(0), None, 2),
            (Some(ExitStatus::from_raw(23 << 8)), Some(23), None, 23),
            (
                Some(ExitStatus::from_raw(libc::SIGTERM)),
                None,
                Some(libc::SIGTERM),
                128 + libc::SIGTERM,
            ),
            (None, None, None, 2),
        ] {
            let mut outcome = empty_outcome();
            let status = record_supervision_result(
                &mut outcome,
                Err("capture export interrupted".into()),
                native,
            );
            let rendered = report::render(directory.path(), &outcome);
            let value: serde_json::Value = serde_json::from_str(&rendered.json).unwrap();
            assert_eq!(value["application"]["exit_code"], serde_json::json!(code));
            assert_eq!(value["application"]["signal"], serde_json::json!(signal));
            assert!(!rendered.complete);
            assert!(outcome
                .errors
                .iter()
                .any(|error| error == "native_supervision_failed"));
            assert_eq!(completion_exit_code(status, rendered.complete), cli_code);
            if native.is_some() {
                assert_eq!(outcome.interrupted, signal.is_some());
            }
        }
    }

    #[test]
    fn incomplete_capture_never_turns_a_successful_native_exit_into_cli_success() {
        let mut outcome = empty_outcome();
        let status =
            record_supervision_result(&mut outcome, Ok((ExitStatus::from_raw(0), false)), None);
        assert_eq!(outcome.exit_code, Some(0));
        assert_eq!(outcome.errors, ["capture_incomplete"]);
        assert_eq!(completion_exit_code(status, false), 2);
        let mut healthy = empty_outcome();
        let success =
            record_supervision_result(&mut healthy, Ok((ExitStatus::from_raw(0), true)), None);
        assert!(healthy.errors.is_empty());
        assert_eq!(completion_exit_code(success, true), 0);
        assert_eq!(completion_exit_code(None, true), 2);
    }
}
