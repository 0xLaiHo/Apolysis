// SPDX-License-Identifier: Apache-2.0

use std::{env, ffi::OsString, fmt, path::PathBuf};

use apolysis_gateway_server::{
    serve_with_post_commit_response_barrier, serve_with_pre_operation_barrier, GatewayServerConfig,
    GatewayServerError, QualificationOperation,
};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), QualificationServerError> {
    let arguments = QualificationArguments::parse(env::args_os())?;
    let server_config = GatewayServerConfig::from_args(arguments.server_arguments)
        .map_err(QualificationServerError::Server)?;
    match arguments.phase {
        QualificationPhase::PostCommit => {
            serve_with_post_commit_response_barrier(
                server_config,
                arguments.operation,
                arguments.marker,
            )
            .await
        }
        QualificationPhase::PreOperation => {
            serve_with_pre_operation_barrier(
                server_config,
                arguments.operation,
                arguments.marker,
                arguments
                    .release
                    .ok_or(QualificationServerError::Arguments)?,
            )
            .await
        }
    }
    .map_err(QualificationServerError::Server)
}

struct QualificationArguments {
    server_arguments: Vec<OsString>,
    operation: QualificationOperation,
    marker: PathBuf,
    phase: QualificationPhase,
    release: Option<PathBuf>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QualificationPhase {
    PostCommit,
    PreOperation,
}

impl QualificationPhase {
    fn parse(value: &str) -> Result<Self, QualificationServerError> {
        match value {
            "post_commit" => Ok(Self::PostCommit),
            "pre_operation" => Ok(Self::PreOperation),
            _ => Err(QualificationServerError::Arguments),
        }
    }
}

impl QualificationArguments {
    fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, QualificationServerError> {
        let mut arguments = arguments.into_iter();
        let program = arguments
            .next()
            .ok_or(QualificationServerError::Arguments)?;
        let mut server_arguments = vec![program];
        let mut operation = None;
        let mut marker = None;
        let mut phase = None;
        let mut release = None;

        while let Some(option) = arguments.next() {
            let value = arguments
                .next()
                .ok_or(QualificationServerError::Arguments)?;
            match option.to_str() {
                Some("--qualification-operation") if operation.is_none() => {
                    let value = value.to_str().ok_or(QualificationServerError::Arguments)?;
                    operation = Some(
                        QualificationOperation::parse(value)
                            .map_err(QualificationServerError::Server)?,
                    );
                }
                Some("--qualification-marker") if marker.is_none() => {
                    marker = Some(PathBuf::from(value));
                }
                Some("--qualification-phase") if phase.is_none() => {
                    let value = value.to_str().ok_or(QualificationServerError::Arguments)?;
                    phase = Some(QualificationPhase::parse(value)?);
                }
                Some("--qualification-release") if release.is_none() => {
                    release = Some(PathBuf::from(value));
                }
                Some(
                    "--qualification-operation"
                    | "--qualification-marker"
                    | "--qualification-phase"
                    | "--qualification-release",
                ) => {
                    return Err(QualificationServerError::Arguments);
                }
                _ => {
                    server_arguments.push(option);
                    server_arguments.push(value);
                }
            }
        }

        let phase = phase.unwrap_or(QualificationPhase::PostCommit);
        if (phase == QualificationPhase::PreOperation) != release.is_some() {
            return Err(QualificationServerError::Arguments);
        }

        Ok(Self {
            server_arguments,
            operation: operation.ok_or(QualificationServerError::Arguments)?,
            marker: marker.ok_or(QualificationServerError::Arguments)?,
            phase,
            release,
        })
    }
}

#[derive(Debug)]
enum QualificationServerError {
    Arguments,
    Server(GatewayServerError),
}

impl fmt::Display for QualificationServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments => formatter.write_str(
                "qualification server requires one local operation and marker configuration",
            ),
            Self::Server(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for QualificationServerError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_local_qualification_options_from_the_production_cli() {
        let arguments = QualificationArguments::parse(
            [
                "qualification-server",
                "--listen",
                "127.0.0.1:0",
                "--qualification-operation",
                "ingest",
                "--qualification-marker",
                "/tmp/private/reached",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .unwrap();

        assert_eq!(arguments.operation, QualificationOperation::Ingest);
        assert_eq!(arguments.marker, PathBuf::from("/tmp/private/reached"));
        assert_eq!(arguments.phase, QualificationPhase::PostCommit);
        assert_eq!(arguments.release, None);
        assert_eq!(
            arguments.server_arguments,
            ["qualification-server", "--listen", "127.0.0.1:0"]
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rejects_duplicate_or_missing_local_options() {
        let duplicate = [
            "qualification-server",
            "--qualification-operation",
            "open_run",
            "--qualification-operation",
            "ingest",
            "--qualification-marker",
            "/tmp/private/reached",
        ];
        assert!(QualificationArguments::parse(duplicate.into_iter().map(OsString::from)).is_err());

        let missing = [
            "qualification-server",
            "--qualification-operation",
            "open_run",
        ];
        assert!(QualificationArguments::parse(missing.into_iter().map(OsString::from)).is_err());
    }

    #[test]
    fn keeps_pre_operation_release_options_out_of_the_production_cli() {
        let arguments = QualificationArguments::parse(
            [
                "qualification-server",
                "--listen",
                "127.0.0.1:0",
                "--qualification-operation",
                "open_run",
                "--qualification-marker",
                "/tmp/private/reached",
                "--qualification-phase",
                "pre_operation",
                "--qualification-release",
                "/tmp/private/release",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .unwrap();

        assert_eq!(
            arguments.server_arguments,
            ["qualification-server", "--listen", "127.0.0.1:0"]
                .into_iter()
                .map(OsString::from)
                .collect::<Vec<_>>()
        );
        assert_eq!(arguments.phase, QualificationPhase::PreOperation);
        assert_eq!(
            arguments.release,
            Some(PathBuf::from("/tmp/private/release"))
        );
    }
}
