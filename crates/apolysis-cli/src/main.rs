// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

use apolysis_core::{CanonicalEvent, EventSource, EventType, RuntimeKind, SandboxSession};
use apolysis_store::JsonlStore;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let request = RunRequest::parse(args)?;
    let session_id = format!(
        "local-{}-{}",
        std::process::id(),
        apolysis_core::now_unix_ms()
    );
    let session = SandboxSession::new(&session_id, RuntimeKind::Local, &request.policy_path);
    let actor = request.command.join(" ");
    let mut store = JsonlStore::create(&request.output_path)
        .map_err(|error| format!("failed to create timeline: {error}"))?;

    // M1 writes manual local-run events.  The future eBPF observer will replace
    // these synthetic records with kernel-derived process/file/network events.
    store
        .append(&CanonicalEvent::new(
            &session.id,
            EventSource::Manual,
            EventType::SessionStarted,
            std::process::id(),
            0,
            "apolysis",
            "local-session",
            "start",
        ))
        .map_err(|error| format!("failed to write session event: {error}"))?;
    store
        .append(&CanonicalEvent::new(
            &session.id,
            EventSource::Manual,
            EventType::Exec,
            std::process::id(),
            0,
            &actor,
            "process",
            "exec",
        ))
        .map_err(|error| format!("failed to write exec event: {error}"))?;

    let status = Command::new(&request.command[0])
        .args(&request.command[1..])
        .status()
        .map_err(|error| format!("failed to start command: {error}"))?;

    store
        .append(&CanonicalEvent::new(
            &session.id,
            EventSource::Manual,
            EventType::ProcessExit,
            std::process::id(),
            0,
            &actor,
            "process",
            format!("exit:{}", status.code().unwrap_or(-1)),
        ))
        .map_err(|error| format!("failed to write exit event: {error}"))?;
    store
        .flush()
        .map_err(|error| format!("failed to flush timeline: {error}"))?;

    std::process::exit(status.code().unwrap_or(1));
}

#[derive(Debug, Eq, PartialEq)]
struct RunRequest {
    policy_path: String,
    output_path: String,
    command: Vec<String>,
}

impl RunRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some("run") {
            return Err(usage());
        }

        let mut policy_path = None;
        let mut output_path = Some(".apolysis/timeline.jsonl".to_string());
        let mut command = Vec::new();
        let mut i = 1;

        while i < args.len() {
            match args[i].as_str() {
                "--policy" => {
                    i += 1;
                    policy_path = args.get(i).cloned();
                }
                "--output" => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                "--" => {
                    command = args[(i + 1)..].to_vec();
                    break;
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        let policy_path = policy_path.ok_or_else(|| format!("missing --policy\n{}", usage()))?;
        let output_path =
            output_path.ok_or_else(|| format!("missing --output value\n{}", usage()))?;
        if command.is_empty() {
            return Err(format!("missing command after --\n{}", usage()));
        }

        Ok(Self {
            policy_path,
            output_path,
            command,
        })
    }
}

fn usage() -> String {
    "usage: apolysis run --policy <path> [--output <path>] -- <command> [args...]".to_string()
}
