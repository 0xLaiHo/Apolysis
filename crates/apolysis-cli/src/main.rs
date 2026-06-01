// SPDX-License-Identifier: Apache-2.0

use apolysis_observer::{observe_fixture, FixtureObserveRequest};
use apolysis_runtime::{run_docker, run_local, DockerRunRequest, LocalRunRequest};
use apolysis_visibility::{assess_visibility, RuntimeVisibilityProfile, VisibilityInput};

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
    match args.first().map(String::as_str) {
        Some("run") => run_command(args),
        Some("observe") => observe_command(args),
        Some("visibility") => visibility_command(args),
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

fn visibility_command(args: Vec<String>) -> Result<i32, String> {
    let request = VisibilityRequest::parse(args)?;
    let host_events = std::fs::read_to_string(&request.input_path)
        .map_err(|error| format!("failed to read visibility input: {error}"))?;
    let kubernetes_metadata = if let Some(path) = request.kubernetes_metadata_path {
        let input = std::fs::read_to_string(&path)
            .map_err(|error| format!("failed to read kubernetes metadata: {error}"))?;
        Some(apolysis_kubernetes::KubernetesMetadata::parse(&input)?)
    } else {
        None
    };
    let assessment = assess_visibility(
        VisibilityInput::new(request.session_id, request.runtime_profile, host_events)
            .with_kubernetes_metadata(kubernetes_metadata),
    )?;
    let mut store = apolysis_store::JsonlStore::create(&request.output_path)
        .map_err(|error| format!("failed to create visibility output: {error}"))?;
    store
        .append(&assessment)
        .map_err(|error| format!("failed to write visibility assessment: {error}"))?;
    store
        .flush()
        .map_err(|error| format!("failed to flush visibility output: {error}"))?;
    Ok(0)
}

fn observe_command(args: Vec<String>) -> Result<i32, String> {
    let request = ObserveRequest::parse(args)?;
    match request.backend {
        ObserverBackendSelection::Fixture => {
            observe_fixture(
                FixtureObserveRequest::new(
                    request.input_path,
                    request.output_path,
                    request.policy_path,
                    request.session_id,
                )
                .with_feedback_dir(request.feedback_dir)
                .with_kubernetes_metadata_path(request.kubernetes_metadata_path),
            )?;
            Ok(0)
        }
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
        if args.first().map(String::as_str) != Some("run") {
            return Err(usage());
        }

        let mut runtime = "local".to_string();
        let mut image = None;
        let mut docker_runtime = None;
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
                "--runtime" => {
                    i += 1;
                    runtime = args
                        .get(i)
                        .cloned()
                        .ok_or_else(|| format!("missing --runtime value\n{}", usage()))?;
                }
                "--image" => {
                    i += 1;
                    image = args.get(i).cloned();
                }
                "--docker-runtime" => {
                    i += 1;
                    docker_runtime = args.get(i).cloned();
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

        let runtime = match runtime.as_str() {
            "local" => {
                if image.is_some() {
                    return Err(format!("--image requires --runtime docker\n{}", usage()));
                }
                if docker_runtime.is_some() {
                    return Err(format!(
                        "--docker-runtime requires --runtime docker\n{}",
                        usage()
                    ));
                }
                RuntimeSelection::Local
            }
            "docker" => RuntimeSelection::Docker {
                image: image.ok_or_else(|| format!("missing --image\n{}", usage()))?,
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
    input_path: String,
    output_path: String,
    policy_path: String,
    session_id: String,
    feedback_dir: Option<String>,
    kubernetes_metadata_path: Option<String>,
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
}

impl ObserveRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some("observe") {
            return Err(usage());
        }

        let mut backend = None;
        let mut input_path = None;
        let mut output_path = None;
        let mut policy_path = None;
        let mut session_id = None;
        let mut feedback_dir = None;
        let mut kubernetes_metadata_path = None;
        let mut i = 1;

        while i < args.len() {
            match args[i].as_str() {
                "--backend" => {
                    i += 1;
                    backend = args.get(i).cloned();
                }
                "--input" => {
                    i += 1;
                    input_path = args.get(i).cloned();
                }
                "--output" => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                "--policy" => {
                    i += 1;
                    policy_path = args.get(i).cloned();
                }
                "--session" => {
                    i += 1;
                    session_id = args.get(i).cloned();
                }
                "--feedback-dir" => {
                    i += 1;
                    feedback_dir = args.get(i).cloned();
                }
                "--kubernetes-metadata" => {
                    i += 1;
                    kubernetes_metadata_path = args.get(i).cloned();
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        let backend = match backend
            .ok_or_else(|| format!("missing --backend\n{}", usage()))?
            .as_str()
        {
            "fixture" => ObserverBackendSelection::Fixture,
            unknown => return Err(format!("unknown observer backend '{unknown}'\n{}", usage())),
        };

        Ok(Self {
            backend,
            input_path: input_path.ok_or_else(|| format!("missing --input\n{}", usage()))?,
            output_path: output_path.ok_or_else(|| format!("missing --output\n{}", usage()))?,
            policy_path: policy_path.ok_or_else(|| format!("missing --policy\n{}", usage()))?,
            session_id: session_id.ok_or_else(|| format!("missing --session\n{}", usage()))?,
            feedback_dir,
            kubernetes_metadata_path,
        })
    }
}

impl VisibilityRequest {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        if args.first().map(String::as_str) != Some("visibility") {
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
                "--scenario" => {
                    i += 1;
                    scenario = args.get(i).cloned();
                }
                "--input" => {
                    i += 1;
                    input_path = args.get(i).cloned();
                }
                "--output" => {
                    i += 1;
                    output_path = args.get(i).cloned();
                }
                "--session" => {
                    i += 1;
                    session_id = args.get(i).cloned();
                }
                "--kubernetes-metadata" => {
                    i += 1;
                    kubernetes_metadata_path = args.get(i).cloned();
                }
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        let runtime_profile = RuntimeVisibilityProfile::parse(
            &scenario.ok_or_else(|| format!("missing --scenario\n{}", usage()))?,
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
            input_path: input_path.ok_or_else(|| format!("missing --input\n{}", usage()))?,
            output_path: output_path.ok_or_else(|| format!("missing --output\n{}", usage()))?,
            session_id,
            kubernetes_metadata_path,
        })
    }
}

fn usage() -> String {
    "usage: apolysis run [--runtime local|docker] [--image <image>] [--docker-runtime <oci-runtime>] --policy <path> [--output <path>] -- <command> [args...]\n       apolysis observe --backend fixture --input <path> --session <id> --policy <path> --output <path> [--feedback-dir <path>] [--kubernetes-metadata <path>]\n       apolysis visibility --scenario docker-default|docker-gvisor|kubernetes-gvisor|kubernetes-kata|firecracker-prototype --input <path> --output <path> [--session <id>] [--kubernetes-metadata <path>]".to_string()
}
