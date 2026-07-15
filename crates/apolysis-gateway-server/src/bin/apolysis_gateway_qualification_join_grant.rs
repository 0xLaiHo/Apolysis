// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, env, ffi::OsString, fmt, path::PathBuf};

use apolysis_gateway_server::{register_qualification_join_grant, GatewayServerError};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), QualificationJoinGrantError> {
    let arguments = QualificationJoinGrantArguments::parse(env::args_os())?;
    register_qualification_join_grant(
        &arguments.database_url_file,
        &arguments.replay_key_file,
        &arguments.issuer_certificate_file,
        &arguments.joining_certificate_file,
        &arguments.run_id,
        &arguments.proof_file,
        arguments.expires_at_unix_ms,
    )
    .await
    .map_err(QualificationJoinGrantError::Server)
}

#[derive(Debug, Eq, PartialEq)]
struct QualificationJoinGrantArguments {
    database_url_file: PathBuf,
    replay_key_file: PathBuf,
    issuer_certificate_file: PathBuf,
    joining_certificate_file: PathBuf,
    run_id: String,
    proof_file: PathBuf,
    expires_at_unix_ms: u64,
}

impl QualificationJoinGrantArguments {
    fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, QualificationJoinGrantError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments
            .next()
            .ok_or(QualificationJoinGrantError::Arguments)?;
        let mut options = BTreeMap::new();
        while let Some(option) = arguments.next() {
            let option = option
                .into_string()
                .map_err(|_| QualificationJoinGrantError::Arguments)?;
            let value = arguments
                .next()
                .ok_or(QualificationJoinGrantError::Arguments)?;
            if options.insert(option, value).is_some() {
                return Err(QualificationJoinGrantError::Arguments);
            }
        }
        const EXPECTED_OPTIONS: [&str; 7] = [
            "--database-url-file",
            "--expires-at-unix-ms",
            "--issuer-certificate",
            "--joining-certificate",
            "--proof-file",
            "--replay-key",
            "--run-id",
        ];
        if options.len() != EXPECTED_OPTIONS.len()
            || options
                .keys()
                .any(|option| !EXPECTED_OPTIONS.contains(&option.as_str()))
        {
            return Err(QualificationJoinGrantError::Arguments);
        }

        let database_url_file = required_path(&mut options, "--database-url-file")?;
        let replay_key_file = required_path(&mut options, "--replay-key")?;
        let issuer_certificate_file = required_path(&mut options, "--issuer-certificate")?;
        let joining_certificate_file = required_path(&mut options, "--joining-certificate")?;
        let proof_file = required_path(&mut options, "--proof-file")?;
        let run_id = required_utf8(&mut options, "--run-id")?;
        let expires_at_unix_ms = required_utf8(&mut options, "--expires-at-unix-ms")?
            .parse::<u64>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or(QualificationJoinGrantError::Arguments)?;

        Ok(Self {
            database_url_file,
            replay_key_file,
            issuer_certificate_file,
            joining_certificate_file,
            run_id,
            proof_file,
            expires_at_unix_ms,
        })
    }
}

fn required_path(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
) -> Result<PathBuf, QualificationJoinGrantError> {
    let path = PathBuf::from(
        options
            .remove(name)
            .ok_or(QualificationJoinGrantError::Arguments)?,
    );
    if !path.is_absolute() {
        return Err(QualificationJoinGrantError::Arguments);
    }
    Ok(path)
}

fn required_utf8(
    options: &mut BTreeMap<String, OsString>,
    name: &str,
) -> Result<String, QualificationJoinGrantError> {
    options
        .remove(name)
        .ok_or(QualificationJoinGrantError::Arguments)?
        .into_string()
        .map_err(|_| QualificationJoinGrantError::Arguments)
}

#[derive(Debug)]
enum QualificationJoinGrantError {
    Arguments,
    Server(GatewayServerError),
}

impl fmt::Display for QualificationJoinGrantError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arguments => formatter
                .write_str("qualification join-grant helper requires exact private-file arguments"),
            Self::Server(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for QualificationJoinGrantError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_the_local_private_file_contract() {
        let arguments = QualificationJoinGrantArguments::parse(
            [
                "helper",
                "--database-url-file",
                "/tmp/private/database.url",
                "--replay-key",
                "/tmp/private/replay.key",
                "--issuer-certificate",
                "/tmp/private/issuer.pem",
                "--joining-certificate",
                "/tmp/private/joining.pem",
                "--run-id",
                "run_qualification_01",
                "--proof-file",
                "/tmp/private/proof",
                "--expires-at-unix-ms",
                "1783894800000",
            ]
            .into_iter()
            .map(OsString::from),
        )
        .unwrap();

        assert_eq!(arguments.run_id, "run_qualification_01");
        assert_eq!(arguments.expires_at_unix_ms, 1_783_894_800_000);
        assert_eq!(arguments.proof_file, PathBuf::from("/tmp/private/proof"));
    }

    #[test]
    fn rejects_unknown_duplicate_relative_or_missing_options() {
        for arguments in [
            vec!["helper", "--unknown", "value"],
            vec![
                "helper",
                "--database-url-file",
                "/tmp/database.url",
                "--database-url-file",
                "/tmp/database.url",
            ],
            vec![
                "helper",
                "--database-url-file",
                "relative/database.url",
                "--replay-key",
                "/tmp/replay.key",
                "--issuer-certificate",
                "/tmp/issuer.pem",
                "--joining-certificate",
                "/tmp/joining.pem",
                "--run-id",
                "run_01",
                "--proof-file",
                "/tmp/proof",
                "--expires-at-unix-ms",
                "1",
            ],
        ] {
            assert!(QualificationJoinGrantArguments::parse(
                arguments.into_iter().map(OsString::from)
            )
            .is_err());
        }
    }
}
