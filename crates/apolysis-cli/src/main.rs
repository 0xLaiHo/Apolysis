// SPDX-License-Identifier: Apache-2.0

mod cli;

use apolysis_observer::{observe_fixture, FixtureObserveRequest};
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
        Some(commands::OBSERVE) => observe_command(args),
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
                unknown => return Err(format!("unknown argument '{unknown}'\n{}", usage())),
            }
            i += 1;
        }

        let backend = match backend
            .ok_or_else(|| format!("missing {}\n{}", options::BACKEND, usage()))?
            .as_str()
        {
            values::FIXTURE => ObserverBackendSelection::Fixture,
            unknown => return Err(format!("unknown observer backend '{unknown}'\n{}", usage())),
        };

        Ok(Self {
            backend,
            input_path: input_path
                .ok_or_else(|| format!("missing {}\n{}", options::INPUT, usage()))?,
            output_path: output_path
                .ok_or_else(|| format!("missing {}\n{}", options::OUTPUT, usage()))?,
            policy_path: policy_path
                .ok_or_else(|| format!("missing {}\n{}", options::POLICY, usage()))?,
            session_id: session_id
                .ok_or_else(|| format!("missing {}\n{}", options::SESSION, usage()))?,
            feedback_dir,
            kubernetes_metadata_path,
        })
    }
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
