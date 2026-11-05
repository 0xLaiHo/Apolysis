// SPDX-License-Identifier: Apache-2.0

//! Experimental native conversation controller. User content travels over pipes;
//! privileged capture stays private and publication runs as the invoking user.

mod evidence;
mod platform;
mod protocol;

use std::collections::HashSet;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdout, Command};
use tokio::signal::unix::{signal, Signal, SignalKind};

const HELP: &str = "apolysis chat [--smoke] [--turn-timeout <seconds>] [--output-dir <parent>] [--policy <path>] [--bpf-object <path>]\nRequires explicit sudo from a non-root user, Claude authentication and live Linux BPF prerequisites. Creates an independent workspace. /exit or EOF ends the conversation. No Python runtime is used.";
const SMOKE: [&str; 3] = [
    "请在当前目录创建 greeting.txt，内容为 hello apolysis，然后告诉我完成了什么。本次验证请使用 shell 内置或常规命令，不要运行 Python。",
    "请读取刚才创建的文件，统计其中的单词数量，并用中文告诉我结果。仍使用 shell 内置或常规命令。",
    "谢谢。请只用一句话回复，不要调用工具。",
];

#[derive(Debug, PartialEq)]
struct Options {
    smoke: bool,
    timeout: Duration,
    output: PathBuf,
    policy: PathBuf,
    bpf: PathBuf,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut value = Self {
            smoke: false,
            timeout: Duration::from_secs(180),
            output: "target".into(),
            policy: "policies/local-dev.yaml".into(),
            bpf: "target/ebpf/apolysis_observer.bpf.o".into(),
        };
        let mut options = args.iter();
        let mut seen = HashSet::new();
        while let Some(option) = options.next() {
            if !seen.insert(option) {
                return Err("duplicate chat option".into());
            }
            if option == "--smoke" {
                value.smoke = true;
                continue;
            }
            if !matches!(
                option.as_str(),
                "--turn-timeout" | "--output-dir" | "--policy" | "--bpf-object"
            ) {
                return Err("unknown chat option; use apolysis chat --help".into());
            }
            let argument = options
                .next()
                .filter(|v| !v.is_empty() && !v.starts_with("--"))
                .ok_or("chat option requires a value")?;
            match option.as_str() {
                "--turn-timeout" => {
                    let seconds: u64 = argument.parse().map_err(|_| "invalid chat timeout")?;
                    if !(1..=3600).contains(&seconds) {
                        return Err("chat timeout must be between 1 and 3600 seconds".into());
                    }
                    value.timeout = Duration::from_secs(seconds);
                }
                "--output-dir" => value.output = argument.into(),
                "--policy" => value.policy = argument.into(),
                "--bpf-object" => value.bpf = argument.into(),
                _ => unreachable!(),
            }
        }
        Ok(value)
    }
}

pub(crate) async fn run(args: &[String]) -> Result<i32, String> {
    match args.first().map(String::as_str) {
        Some("hook") => return protocol::hook(&args[1..]),
        Some("launch") => return platform::launch(&args[1..]),
        Some("publish") => return platform::publish(&args[1..]),
        Some("--help" | "-h") if args.len() == 1 => {
            println!("{HELP}");
            return Ok(0);
        }
        _ => (),
    }
    let options = Options::parse(args)?;
    let user = platform::User::from_sudo()?;
    let binary = std::env::current_exe().map_err(|_| "cannot locate apolysis executable")?;
    let policy = std::fs::canonicalize(&options.policy)
        .map_err(|_| "chat policy missing; run from the checkout or pass --policy")?;
    let bpf = std::fs::canonicalize(&options.bpf)
        .map_err(|_| "chat BPF object missing; build it or pass --bpf-object")?;
    if !options.output.exists() {
        std::fs::create_dir_all(&options.output).map_err(|_| "cannot create chat output parent")?;
        platform::owned_dir(&options.output, &user)?;
    }
    let parent =
        std::fs::canonicalize(&options.output).map_err(|_| "cannot resolve chat output parent")?;
    let root = tempfile::Builder::new()
        .prefix("reason-chat-rust-")
        .tempdir_in(parent)
        .map_err(|_| "cannot create chat directory")?
        .keep();
    platform::owned_dir(&root, &user)?;
    let workspace = root.join("workspace");
    let outputs = root.join("evidence");
    platform::owned_dir(&workspace, &user)?;
    platform::owned_dir(&outputs, &user)?;
    for name in ["intent.jsonl", "intent.jsonl.reasons.jsonl"] {
        platform::owned_file(&outputs.join(name), b"", &user)?;
    }
    let session = format!(
        "rust-chat-{}-{}",
        apolysis_core::now_unix_ms(),
        root.file_name()
            .ok_or("invalid chat directory")?
            .to_string_lossy()
    );
    let control = tempfile::Builder::new()
        .prefix("apolysis-chat-control-")
        .tempdir()
        .map_err(|_| "cannot create private chat configuration")?;
    platform::owned_dir(control.path(), &user)?;
    // The root observer never opens a path that the model can replace. Only
    // invoking-user helper processes later publish snapshots to the user tree.
    let capture = tempfile::Builder::new()
        .prefix("apolysis-chat-capture-")
        .tempdir()
        .map_err(|_| "cannot create private capture")?;
    let timeline = capture.path().join("timeline.jsonl");
    let native = platform::native_command(
        &binary,
        &workspace,
        &outputs,
        control.path(),
        &session,
        &user,
    )?;
    let mut command = Command::new(&binary);
    command
        .args([
            "observe",
            "--backend",
            "live",
            "--session",
            &session,
            "--policy",
        ])
        .arg(policy)
        .arg("--output")
        .arg(&timeline)
        .arg("--bpf-object")
        .arg(bpf)
        .arg("--workspace-root")
        .arg(&workspace)
        .args(["--agent-kind", "claude", "--agent-run", "--"])
        .args(native)
        .current_dir(&workspace)
        .env("HOME", &user.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    // SAFETY: setsid is async-signal-safe; the closure allocates no memory and
    // creates a group whose lifetime belongs exclusively to this controller.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut process = ManagedProcess::spawn(&mut command)?;
    let stdout = process
        .child
        .stdout
        .take()
        .ok_or("missing native output pipe")?;
    let mut output = BufReader::new(stdout).lines();
    let mut interrupts =
        signal(SignalKind::interrupt()).map_err(|_| "cannot install chat interrupt handler")?;
    let mut termination =
        signal(SignalKind::terminate()).map_err(|_| "cannot install chat termination handler")?;
    println!("测试目录：{}", workspace.display());
    println!("证据目录：{}", outputs.display());
    println!("直接输入任务，每行一轮；/exit 或 Ctrl+D 退出。Ctrl+C 结束会话。仅启用 Bash，任务可写入测试目录。");
    let mut turns = Vec::new();
    let conversation = conversation(
        &options,
        &mut process.child,
        &mut output,
        &mut interrupts,
        &mut termination,
        &binary,
        &user,
        &timeline,
        &outputs,
        &mut turns,
    )
    .await;
    let normal_exit = process
        .close(Duration::from_secs(15), Duration::from_secs(5))
        .await;
    let mut failed = conversation.is_err();
    if failed {
        eprintln!("对话已中断或失败；原始模型输出未写入日志。");
    }
    let joined = correlate(&binary, &user, &timeline, &outputs).await;
    let correlation_status = if joined.is_ok() {
        "complete"
    } else {
        failed = true;
        "incomplete"
    };
    let smoke_status = if !options.smoke {
        "not_requested"
    } else if !failed && evidence::validate_smoke(&workspace, &outputs, &turns).is_ok() {
        "passed"
    } else {
        failed = true;
        "failed"
    };
    let mut result = evidence::capture_report(&outputs, &session, &turns, normal_exit)
        .unwrap_or_else(|_| {
            failed = true;
            json!({"session_id": session, "capture_status":"incomplete", "turns":turns,
               "kernel_events":null,"loss_or_failure_count":null,"truncations":null})
        });
    result["correlation_status"] = json!(correlation_status);
    result["conversation_status"] = json!(if failed {
        "interrupted_or_failed"
    } else {
        "finished"
    });
    result["smoke_status"] = json!(smoke_status);
    result["controller_runtime"] = json!("rust");
    publish(
        &binary,
        &user,
        &outputs.join("result.json"),
        &serde_json::to_vec_pretty(&result).map_err(|_| "cannot encode chat result")?,
    )
    .await?;
    println!("会话结束。证据：{}", outputs.display());
    println!(
        "采集状态={}；事件={}；丢失/失败={}；截断={}；回归={}",
        result["capture_status"],
        result["kernel_events"],
        result["loss_or_failure_count"],
        result["truncations"],
        result["smoke_status"]
    );
    Ok(i32::from(failed || result["capture_status"] != "complete"))
}

#[allow(clippy::too_many_arguments)]
async fn conversation(
    options: &Options,
    child: &mut Child,
    output: &mut Lines<BufReader<ChildStdout>>,
    interrupts: &mut Signal,
    termination: &mut Signal,
    binary: &Path,
    user: &platform::User,
    timeline: &Path,
    outputs: &Path,
    turns: &mut Vec<Value>,
) -> Result<(), String> {
    let mut input = BufReader::new(tokio::io::stdin()).lines();
    loop {
        let prompt = if options.smoke {
            let Some(prompt) = SMOKE.get(turns.len()) else {
                break;
            };
            println!("你：{prompt}");
            prompt.to_string()
        } else {
            print!("你：");
            std::io::stdout()
                .flush()
                .map_err(|_| "cannot display chat prompt")?;
            let line = tokio::select! {
                value = input.next_line() => value.map_err(|_| "cannot read terminal input")?,
                _ = interrupts.recv() => return Err("chat interrupted".into()),
                _ = termination.recv() => return Err("chat terminated".into()),
            };
            let Some(line) = line else {
                break;
            };
            line
        };
        if prompt.trim() == "/exit" {
            break;
        }
        if prompt.trim().is_empty() {
            continue;
        }
        let before: HashSet<String> = evidence::read_complete(&outputs.join("intent.jsonl"))?
            .iter()
            .filter_map(|r| r["intent_id"].as_str().map(str::to_owned))
            .collect();
        let wait = send_turn(child, output, &prompt);
        tokio::select! {
            value = tokio::time::timeout(options.timeout, wait) => value.map_err(|_| "model turn timed out")??,
            _ = interrupts.recv() => return Err("chat interrupted".into()),
            _ = termination.recv() => return Err("chat terminated".into()),
        }
        correlate(binary, user, timeline, outputs).await?;
        let calls = evidence::display_turn(outputs, &before)?;
        turns.push(json!({"turn": turns.len()+1,"tool_calls":calls}));
    }
    Ok(())
}

async fn send_turn(
    child: &mut Child,
    output: &mut Lines<BufReader<ChildStdout>>,
    prompt: &str,
) -> Result<(), String> {
    let mut data = serde_json::to_vec(&protocol::user_message(prompt))
        .map_err(|_| "cannot encode user message")?;
    data.push(b'\n');
    let stdin = child.stdin.as_mut().ok_or("native input pipe closed")?;
    stdin
        .write_all(&data)
        .await
        .map_err(|_| "native input pipe closed")?;
    stdin
        .flush()
        .await
        .map_err(|_| "native input pipe closed")?;
    while let Some(line) = output
        .next_line()
        .await
        .map_err(|_| "cannot read native stream")?
    {
        let value: Value =
            serde_json::from_str(&line).map_err(|_| "invalid native stream message")?;
        for text in protocol::assistant_text(&value) {
            println!("Claude：{text}");
        }
        if value["type"] == "result" {
            return if protocol::turn_succeeded(&value) {
                Ok(())
            } else {
                Err("model turn failed".into())
            };
        }
    }
    Err("native stream ended before completing a turn".into())
}

async fn publish(
    binary: &Path,
    user: &platform::User,
    path: &Path,
    data: &[u8],
) -> Result<(), String> {
    let mut child = Command::new(binary)
        .args(["chat", "publish"])
        .arg(path)
        .uid(user.uid)
        .gid(user.gid)
        .env("HOME", &user.home)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "cannot start unprivileged evidence writer")?;
    let mut input = child.stdin.take().ok_or("missing evidence writer pipe")?;
    input
        .write_all(data)
        .await
        .map_err(|_| "cannot send evidence snapshot")?;
    drop(input);
    let status = tokio::time::timeout(Duration::from_secs(15), child.wait())
        .await
        .map_err(|_| "evidence publication timed out")?
        .map_err(|_| "evidence writer failed")?;
    if status.success() {
        Ok(())
    } else {
        Err("evidence publication failed".into())
    }
}

async fn correlate(
    binary: &Path,
    user: &platform::User,
    timeline: &Path,
    outputs: &Path,
) -> Result<(), String> {
    let data = std::fs::read(timeline).map_err(|_| "private capture is missing")?;
    publish(binary, user, &outputs.join("timeline.jsonl"), &data).await?;
    let rows = evidence::read_complete(timeline)?;
    let snapshot: String = rows.iter().map(|r| format!("{r}\n")).collect();
    let private = TempDir::with_prefix("apolysis-chat-join-")
        .map_err(|_| "cannot create private join directory")?;
    std::fs::set_permissions(private.path(), std::fs::Permissions::from_mode(0o711))
        .map_err(|_| "cannot prepare join directory")?;
    let input = private.path().join("timeline.jsonl");
    let output = private.path().join("correlation.jsonl");
    platform::owned_file(&input, snapshot.as_bytes(), user)?;
    platform::owned_file(&output, b"", user)?;
    let mut command = Command::new(binary);
    command
        .args(["intent", "correlate", "--intent-input"])
        .arg(outputs.join("intent.jsonl"))
        .arg("--reason-input")
        .arg(outputs.join("intent.jsonl.reasons.jsonl"))
        .arg("--timeline-input")
        .arg(input)
        .arg("--output")
        .arg(&output)
        .uid(user.uid)
        .gid(user.gid)
        .env("HOME", &user.home)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(30), command.status())
        .await
        .map_err(|_| "reason correlation timed out")?
        .map_err(|_| "cannot start reason correlation")?;
    if !status.success() {
        return Err("reason correlation failed".into());
    }
    publish(
        binary,
        user,
        &outputs.join("correlation.jsonl"),
        &std::fs::read(output).map_err(|_| "correlation output missing")?,
    )
    .await
}

struct ManagedProcess {
    child: Child,
    group: Option<i32>,
}

impl ManagedProcess {
    fn spawn(command: &mut Command) -> Result<Self, String> {
        let child = command
            .spawn()
            .map_err(|_| "cannot start managed observer")?;
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .ok_or("invalid managed process identity")?;
        Ok(Self {
            child,
            group: Some(group),
        })
    }

    fn signal_group(&self, signal: i32) {
        if let Some(group) = self.group {
            // SAFETY: group is a positive PID returned by our own setsid child.
            unsafe {
                libc::kill(-group, signal);
            }
        }
    }

    async fn close(&mut self, grace: Duration, terminate: Duration) -> bool {
        drop(self.child.stdin.take());
        let result: Option<ExitStatus> = match tokio::time::timeout(grace, self.child.wait()).await
        {
            Ok(Ok(status)) => Some(status),
            _ => {
                self.signal_group(libc::SIGTERM);
                let _ = tokio::time::timeout(terminate, self.child.wait()).await;
                None
            }
        };
        self.signal_group(libc::SIGKILL);
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = tokio::time::timeout(terminate, self.child.wait()).await;
        }
        self.group = None;
        result.is_some_and(|status| status.success())
    }
}

impl Drop for ManagedProcess {
    fn drop(&mut self) {
        self.signal_group(libc::SIGKILL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_reject_unknown_duplicate_missing_and_unbounded_values() {
        for invalid in [
            &["--bad"][..],
            &["--smoke", "--smoke"],
            &["--policy"],
            &["--turn-timeout", "0"],
            &["--turn-timeout", "3601"],
            &["--turn-timeout", "-1"],
        ] {
            assert!(Options::parse(&args(invalid)).is_err());
        }
        assert!(
            Options::parse(&args(&["--smoke", "--turn-timeout", "300"]))
                .unwrap()
                .smoke
        );
    }

    fn process(code: &str) -> ManagedProcess {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", code])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        ManagedProcess::spawn(&mut command).unwrap()
    }

    #[tokio::test]
    async fn eof_allows_normal_exit_and_nonzero_is_not_success() {
        let mut success = process("cat >/dev/null; exit 0");
        assert!(
            success
                .close(Duration::from_secs(2), Duration::from_secs(1))
                .await
        );
        let mut failure = process("cat >/dev/null; exit 7");
        assert!(
            !failure
                .close(Duration::from_secs(2), Duration::from_secs(1))
                .await
        );
    }

    #[tokio::test]
    async fn normal_leader_exit_still_cleans_up_background_children() {
        let mut child = process("sleep 60 & echo $!; exit 0");
        let mut output = BufReader::new(child.child.stdout.take().unwrap()).lines();
        let pid: u32 = output.next_line().await.unwrap().unwrap().parse().unwrap();
        assert!(
            child
                .close(Duration::from_secs(2), Duration::from_secs(1))
                .await
        );
        for _ in 0..100 {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"));
            if stat.as_ref().is_err()
                || stat
                    .as_ref()
                    .is_ok_and(|s| s.rsplit_once(')').unwrap().1.trim_start().starts_with('Z'))
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("owned background process survived cleanup");
    }

    #[tokio::test]
    async fn forced_stop_never_reports_normal_completion() {
        let mut child = process("trap '' TERM; echo ready; sleep 60");
        let mut output = BufReader::new(child.child.stdout.take().unwrap()).lines();
        assert_eq!(output.next_line().await.unwrap().as_deref(), Some("ready"));
        assert!(
            !child
                .close(Duration::from_millis(30), Duration::from_millis(30))
                .await
        );
        assert!(child.child.try_wait().unwrap().is_some());
    }

    #[tokio::test]
    async fn turn_timeout_also_covers_a_blocked_native_input_pipe() {
        let mut child = process("sleep 60");
        let mut output = BufReader::new(child.child.stdout.take().unwrap()).lines();
        assert!(tokio::time::timeout(
            Duration::from_millis(30),
            send_turn(&mut child.child, &mut output, &"x".repeat(1024 * 1024))
        )
        .await
        .is_err());
        assert!(
            !child
                .close(Duration::from_millis(30), Duration::from_millis(30))
                .await
        );
    }
}
