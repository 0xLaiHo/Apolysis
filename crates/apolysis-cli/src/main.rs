// SPDX-License-Identifier: Apache-2.0

use apolysis_runtime::{run_local, LocalRunRequest};

fn main() {
    let exit_code = match run(std::env::args().skip(1).collect()) {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("apolysis: {error}");
            2
        }
    };
    std::process::exit(exit_code);
}

fn run(args: Vec<String>) -> Result<i32, String> {
    let request = RunRequest::parse(args)?;
    let result = run_local(LocalRunRequest::new(
        request.policy_path,
        request.output_path,
        request.command,
    ))?;
    Ok(result.exit_code)
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
