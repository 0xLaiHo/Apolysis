// SPDX-License-Identifier: Apache-2.0

use std::{env, ffi::OsString, fmt, path::PathBuf};

use apolysis_gateway_server::{
    serve_with_post_commit_response_barrier, serve_with_pre_operation_barrier, GatewayServerConfig,
    GatewayServerError, QualificationOperation,
};

const MAX_IJSON_INTEGER: u64 = 9_007_199_254_740_991;

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
                arguments.fixed_now_unix_ms,
                arguments.transaction_now_unix_ms,
                arguments.first_transaction_now_unix_ms,
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
    fixed_now_unix_ms: Option<u64>,
    transaction_now_unix_ms: Option<u64>,
    first_transaction_now_unix_ms: Option<u64>,
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
        let mut fixed_now_unix_ms = None;
        let mut transaction_now_unix_ms = None;
        let mut first_transaction_now_unix_ms = None;

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
                Some("--qualification-now-unix-ms") if fixed_now_unix_ms.is_none() => {
                    let value = value
                        .to_str()
                        .ok_or(QualificationServerError::Arguments)?
                        .parse::<u64>()
                        .map_err(|_| QualificationServerError::Arguments)?;
                    if !(1..=MAX_IJSON_INTEGER).contains(&value) {
                        return Err(QualificationServerError::Arguments);
                    }
                    fixed_now_unix_ms = Some(value);
                }
                Some("--qualification-transaction-now-unix-ms")
                    if transaction_now_unix_ms.is_none() =>
                {
                    let value = value
                        .to_str()
                        .ok_or(QualificationServerError::Arguments)?
                        .parse::<u64>()
                        .map_err(|_| QualificationServerError::Arguments)?;
                    if !(1..=MAX_IJSON_INTEGER).contains(&value) {
                        return Err(QualificationServerError::Arguments);
                    }
                    transaction_now_unix_ms = Some(value);
                }
                Some("--qualification-first-transaction-now-unix-ms")
                    if first_transaction_now_unix_ms.is_none() =>
                {
                    let value = value
                        .to_str()
                        .ok_or(QualificationServerError::Arguments)?
                        .parse::<u64>()
                        .map_err(|_| QualificationServerError::Arguments)?;
                    if !(1..=MAX_IJSON_INTEGER).contains(&value) {
                        return Err(QualificationServerError::Arguments);
                    }
                    first_transaction_now_unix_ms = Some(value);
                }
                Some(
                    "--qualification-operation"
                    | "--qualification-marker"
                    | "--qualification-phase"
                    | "--qualification-release"
                    | "--qualification-now-unix-ms"
                    | "--qualification-transaction-now-unix-ms"
                    | "--qualification-first-transaction-now-unix-ms",
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
        let operation = operation.ok_or(QualificationServerError::Arguments)?;
        if (phase == QualificationPhase::PreOperation) != release.is_some() {
            return Err(QualificationServerError::Arguments);
        }
        if fixed_now_unix_ms.is_some() && phase != QualificationPhase::PreOperation {
            return Err(QualificationServerError::Arguments);
        }
        if transaction_now_unix_ms.is_some()
            && (phase != QualificationPhase::PreOperation || fixed_now_unix_ms.is_none())
        {
            return Err(QualificationServerError::Arguments);
        }
        if transaction_now_unix_ms.is_some_and(|transaction_now_unix_ms| {
            !operation.supports_transaction_time_qualification()
                || fixed_now_unix_ms
                    .is_none_or(|fixed_now_unix_ms| transaction_now_unix_ms <= fixed_now_unix_ms)
        }) {
            return Err(QualificationServerError::Arguments);
        }
        if first_transaction_now_unix_ms.is_some_and(|first_transaction_now_unix_ms| {
            transaction_now_unix_ms.is_none()
                || fixed_now_unix_ms != Some(first_transaction_now_unix_ms)
        }) {
            return Err(QualificationServerError::Arguments);
        }

        Ok(Self {
            server_arguments,
            operation,
            marker: marker.ok_or(QualificationServerError::Arguments)?,
            phase,
            release,
            fixed_now_unix_ms,
            transaction_now_unix_ms,
            first_transaction_now_unix_ms,
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

    fn pre_operation_arguments_with_fixed_time_for(operation: &str, value: &str) -> Vec<OsString> {
        [
            "qualification-server",
            "--qualification-operation",
            operation,
            "--qualification-marker",
            "/tmp/private/reached",
            "--qualification-phase",
            "pre_operation",
            "--qualification-release",
            "/tmp/private/release",
            "--qualification-now-unix-ms",
            value,
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    fn pre_operation_arguments_with_fixed_time(value: &str) -> Vec<OsString> {
        pre_operation_arguments_with_fixed_time_for("ingest", value)
    }

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

    #[test]
    fn keeps_fixed_qualification_time_out_of_the_production_cli() {
        let arguments = QualificationArguments::parse(
            [
                "qualification-server",
                "--listen",
                "127.0.0.1:0",
                "--qualification-operation",
                "ingest",
                "--qualification-marker",
                "/tmp/private/reached",
                "--qualification-phase",
                "pre_operation",
                "--qualification-release",
                "/tmp/private/release",
                "--qualification-now-unix-ms",
                "123456789",
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
        assert_eq!(arguments.fixed_now_unix_ms, Some(123_456_789));
    }

    #[test]
    fn accepts_the_maximum_persistable_fixed_qualification_time() {
        let arguments = QualificationArguments::parse(pre_operation_arguments_with_fixed_time(
            "9007199254740991",
        ))
        .unwrap();

        assert_eq!(arguments.fixed_now_unix_ms, Some(9_007_199_254_740_991));
    }

    #[test]
    fn rejects_invalid_fixed_qualification_times() {
        for value in ["0", "9007199254740992", "-1", "not-a-time"] {
            assert!(
                QualificationArguments::parse(pre_operation_arguments_with_fixed_time(value))
                    .is_err(),
                "expected fixed qualification time {value:?} to be rejected"
            );
        }
    }

    #[test]
    fn rejects_fixed_time_outside_one_pre_operation_configuration() {
        let post_commit = [
            "qualification-server",
            "--qualification-operation",
            "ingest",
            "--qualification-marker",
            "/tmp/private/reached",
            "--qualification-now-unix-ms",
            "123456789",
        ];
        assert!(
            QualificationArguments::parse(post_commit.into_iter().map(OsString::from)).is_err()
        );

        let mut duplicate = pre_operation_arguments_with_fixed_time("123456789");
        duplicate.extend([
            OsString::from("--qualification-now-unix-ms"),
            OsString::from("123456790"),
        ]);
        assert!(QualificationArguments::parse(duplicate).is_err());
    }

    #[test]
    fn rejects_transaction_time_without_a_fixed_admission_time() {
        let arguments = [
            "qualification-server",
            "--qualification-operation",
            "ingest",
            "--qualification-marker",
            "/tmp/private/reached",
            "--qualification-phase",
            "pre_operation",
            "--qualification-release",
            "/tmp/private/release",
            "--qualification-transaction-now-unix-ms",
            "123456790",
        ];

        assert!(QualificationArguments::parse(arguments.into_iter().map(OsString::from)).is_err());
    }

    #[test]
    fn accepts_transaction_time_only_for_routes_that_recheck_it() {
        for operation in ["open_run", "bind_runtime", "ingest"] {
            let mut arguments = pre_operation_arguments_with_fixed_time_for(operation, "123456789");
            arguments.extend([
                OsString::from("--qualification-transaction-now-unix-ms"),
                OsString::from("123456790"),
            ]);

            let parsed = QualificationArguments::parse(arguments)
                .unwrap_or_else(|_| panic!("{operation} must support split transaction time"));
            assert_eq!(parsed.transaction_now_unix_ms, Some(123_456_790));
        }

        let mut finish = pre_operation_arguments_with_fixed_time_for("finish_run", "123456789");
        finish.extend([
            OsString::from("--qualification-transaction-now-unix-ms"),
            OsString::from("123456790"),
        ]);
        assert!(QualificationArguments::parse(finish).is_err());
    }

    #[test]
    fn rejects_a_transaction_time_that_does_not_advance_admission_time() {
        for transaction_time in ["123456788", "123456789"] {
            let mut arguments = pre_operation_arguments_with_fixed_time("123456789");
            arguments.extend([
                OsString::from("--qualification-transaction-now-unix-ms"),
                OsString::from(transaction_time),
            ]);

            assert!(QualificationArguments::parse(arguments).is_err());
        }
    }

    #[test]
    fn rejects_a_first_transaction_time_without_a_later_transaction_time() {
        let mut arguments = pre_operation_arguments_with_fixed_time("123456789");
        arguments.extend([
            OsString::from("--qualification-first-transaction-now-unix-ms"),
            OsString::from("123456789"),
        ]);

        assert!(QualificationArguments::parse(arguments).is_err());
    }
}
