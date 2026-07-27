// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, ffi::OsString, path::PathBuf};

use super::{
    certificate::read_client_certificate,
    input::{
        read_database_url, require_only_options, required_path, required_string,
        validate_contract_identifier,
    },
    policy::read_registration,
    store::AuthorityStore,
};
use crate::GatewayServerError;

/// Parse and execute the intentionally narrow authority-administration CLI.
pub async fn run_authority_command() -> Result<(), GatewayServerError> {
    match AuthorityCommand::from_args(std::env::args_os())? {
        AuthorityCommand::Migrate { database_url_file } => {
            let database_url = read_database_url(&database_url_file)?;
            AuthorityStore::migrate(&database_url).await
        }
        AuthorityCommand::RegisterSource {
            database_url_file,
            registration,
            client_certificate,
        } => {
            let database_url = read_database_url(&database_url_file)?;
            let document = read_registration(&registration)?;
            let certificate = read_client_certificate(&client_certificate)?;
            let store = AuthorityStore::connect(&database_url).await?;
            store.register_source(document, certificate).await
        }
        AuthorityCommand::RotatePolicy {
            database_url_file,
            registration,
            current_client_certificate,
            reason,
        } => {
            let database_url = read_database_url(&database_url_file)?;
            let document = read_registration(&registration)?;
            let current_certificate = read_client_certificate(&current_client_certificate)?;
            let store = AuthorityStore::connect(&database_url).await?;
            store
                .rotate_policy(document, current_certificate, &reason)
                .await
        }
        AuthorityCommand::RotateCredential {
            database_url_file,
            registration,
            current_client_certificate,
            new_client_certificate,
            reason,
        } => {
            let database_url = read_database_url(&database_url_file)?;
            let document = read_registration(&registration)?;
            let current_certificate = read_client_certificate(&current_client_certificate)?;
            let replacement_certificate = read_client_certificate(&new_client_certificate)?;
            let store = AuthorityStore::connect(&database_url).await?;
            store
                .rotate_credential(
                    document,
                    current_certificate,
                    replacement_certificate,
                    &reason,
                )
                .await
        }
        AuthorityCommand::RevokeCredential {
            database_url_file,
            client_certificate,
            reason,
        } => {
            let database_url = read_database_url(&database_url_file)?;
            let certificate = read_client_certificate(&client_certificate)?;
            let store = AuthorityStore::connect(&database_url).await?;
            store
                .revoke_credential(certificate.fingerprint, &reason)
                .await
        }
    }
}

#[derive(Debug)]
enum AuthorityCommand {
    Migrate {
        database_url_file: PathBuf,
    },
    RegisterSource {
        database_url_file: PathBuf,
        registration: PathBuf,
        client_certificate: PathBuf,
    },
    RotatePolicy {
        database_url_file: PathBuf,
        registration: PathBuf,
        current_client_certificate: PathBuf,
        reason: String,
    },
    RotateCredential {
        database_url_file: PathBuf,
        registration: PathBuf,
        current_client_certificate: PathBuf,
        new_client_certificate: PathBuf,
        reason: String,
    },
    RevokeCredential {
        database_url_file: PathBuf,
        client_certificate: PathBuf,
        reason: String,
    },
}

impl AuthorityCommand {
    fn from_args(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, GatewayServerError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        let command = arguments
            .next()
            .ok_or_else(|| GatewayServerError::configuration("Authority command is required"))?
            .into_string()
            .map_err(|_| {
                GatewayServerError::configuration("Authority command names must be UTF-8")
            })?;
        let mut options = BTreeMap::new();
        while let Some(option) = arguments.next() {
            let option = option.into_string().map_err(|_| {
                GatewayServerError::configuration("Authority option names must be UTF-8")
            })?;
            let value = arguments.next().ok_or_else(|| {
                GatewayServerError::configuration("Authority option is missing its value")
            })?;
            if options.insert(option, value).is_some() {
                return Err(GatewayServerError::configuration(
                    "Authority option was supplied more than once",
                ));
            }
        }

        match command.as_str() {
            "migrate" => {
                require_only_options(&options, &["--database-url-file"])?;
                Ok(Self::Migrate {
                    database_url_file: required_path(&mut options, "--database-url-file")?,
                })
            }
            "register-source" => {
                require_only_options(
                    &options,
                    &[
                        "--database-url-file",
                        "--registration",
                        "--client-certificate",
                    ],
                )?;
                Ok(Self::RegisterSource {
                    database_url_file: required_path(&mut options, "--database-url-file")?,
                    registration: required_path(&mut options, "--registration")?,
                    client_certificate: required_path(&mut options, "--client-certificate")?,
                })
            }
            "rotate-policy" => {
                require_only_options(
                    &options,
                    &[
                        "--database-url-file",
                        "--registration",
                        "--current-client-certificate",
                        "--reason",
                    ],
                )?;
                let database_url_file = required_path(&mut options, "--database-url-file")?;
                let registration = required_path(&mut options, "--registration")?;
                let current_client_certificate =
                    required_path(&mut options, "--current-client-certificate")?;
                let reason = required_string(&mut options, "--reason")?;
                validate_contract_identifier(&reason, "Authority change reason is invalid")?;
                Ok(Self::RotatePolicy {
                    database_url_file,
                    registration,
                    current_client_certificate,
                    reason,
                })
            }
            "rotate-credential" => {
                require_only_options(
                    &options,
                    &[
                        "--database-url-file",
                        "--registration",
                        "--current-client-certificate",
                        "--new-client-certificate",
                        "--reason",
                    ],
                )?;
                let database_url_file = required_path(&mut options, "--database-url-file")?;
                let registration = required_path(&mut options, "--registration")?;
                let current_client_certificate =
                    required_path(&mut options, "--current-client-certificate")?;
                let new_client_certificate =
                    required_path(&mut options, "--new-client-certificate")?;
                let reason = required_string(&mut options, "--reason")?;
                validate_contract_identifier(&reason, "Authority change reason is invalid")?;
                Ok(Self::RotateCredential {
                    database_url_file,
                    registration,
                    current_client_certificate,
                    new_client_certificate,
                    reason,
                })
            }
            "revoke-credential" => {
                require_only_options(
                    &options,
                    &["--database-url-file", "--client-certificate", "--reason"],
                )?;
                let database_url_file = required_path(&mut options, "--database-url-file")?;
                let client_certificate = required_path(&mut options, "--client-certificate")?;
                let reason = required_string(&mut options, "--reason")?;
                validate_contract_identifier(&reason, "Revocation reason is invalid")?;
                Ok(Self::RevokeCredential {
                    database_url_file,
                    client_certificate,
                    reason,
                })
            }
            _ => Err(GatewayServerError::configuration(
                "Authority command is unsupported",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::AuthorityCommand;

    #[test]
    fn parses_policy_rotation_with_an_explicit_current_certificate() {
        let command = AuthorityCommand::from_args(
            [
                "authority",
                "rotate-policy",
                "--database-url-file",
                "/run/apolysis/database.url",
                "--registration",
                "/run/apolysis/registration.json",
                "--current-client-certificate",
                "/run/apolysis/current.pem",
                "--reason",
                "scheduled_policy_rotation",
            ]
            .into_iter()
            .map(Into::into),
        )
        .expect("valid policy-rotation command");

        match command {
            AuthorityCommand::RotatePolicy {
                database_url_file,
                registration,
                current_client_certificate,
                reason,
            } => {
                assert_eq!(database_url_file, Path::new("/run/apolysis/database.url"));
                assert_eq!(registration, Path::new("/run/apolysis/registration.json"));
                assert_eq!(
                    current_client_certificate,
                    Path::new("/run/apolysis/current.pem")
                );
                assert_eq!(reason, "scheduled_policy_rotation");
            }
            _ => panic!("policy rotation parsed as the wrong authority command"),
        }
    }

    #[test]
    fn parses_credential_rotation_with_explicit_old_and_new_certificates() {
        let command = AuthorityCommand::from_args(
            [
                "authority",
                "rotate-credential",
                "--database-url-file",
                "/run/apolysis/database.url",
                "--registration",
                "/run/apolysis/registration.json",
                "--current-client-certificate",
                "/run/apolysis/current.pem",
                "--new-client-certificate",
                "/run/apolysis/replacement.pem",
                "--reason",
                "scheduled_credential_rotation",
            ]
            .into_iter()
            .map(Into::into),
        )
        .expect("valid credential-rotation command");

        match command {
            AuthorityCommand::RotateCredential {
                database_url_file,
                registration,
                current_client_certificate,
                new_client_certificate,
                reason,
            } => {
                assert_eq!(database_url_file, Path::new("/run/apolysis/database.url"));
                assert_eq!(registration, Path::new("/run/apolysis/registration.json"));
                assert_eq!(
                    current_client_certificate,
                    Path::new("/run/apolysis/current.pem")
                );
                assert_eq!(
                    new_client_certificate,
                    Path::new("/run/apolysis/replacement.pem")
                );
                assert_eq!(reason, "scheduled_credential_rotation");
            }
            _ => panic!("credential rotation parsed as the wrong authority command"),
        }
    }

    #[test]
    fn rotation_commands_reject_private_key_inputs() {
        for arguments in [
            vec![
                "authority",
                "rotate-policy",
                "--database-url-file",
                "/run/apolysis/database.url",
                "--registration",
                "/run/apolysis/registration.json",
                "--current-client-certificate",
                "/run/apolysis/current.pem",
                "--private-key",
                "/run/apolysis/client.key",
                "--reason",
                "scheduled_rotation",
            ],
            vec![
                "authority",
                "rotate-credential",
                "--database-url-file",
                "/run/apolysis/database.url",
                "--registration",
                "/run/apolysis/registration.json",
                "--current-client-certificate",
                "/run/apolysis/current.pem",
                "--new-client-certificate",
                "/run/apolysis/replacement.pem",
                "--private-key",
                "/run/apolysis/client.key",
                "--reason",
                "scheduled_rotation",
            ],
        ] {
            let error = AuthorityCommand::from_args(arguments.into_iter().map(Into::into))
                .expect_err("authority rotation must never accept private-key input");

            assert_eq!(
                error.to_string(),
                "Authority received an unsupported option"
            );
        }
    }

    #[test]
    fn rotation_commands_report_a_rotation_specific_reason_error() {
        let error = AuthorityCommand::from_args(
            [
                "authority",
                "rotate-policy",
                "--database-url-file",
                "/run/apolysis/database.url",
                "--registration",
                "/run/apolysis/registration.json",
                "--current-client-certificate",
                "/run/apolysis/current.pem",
                "--reason",
                "not a contract identifier",
            ]
            .into_iter()
            .map(Into::into),
        )
        .expect_err("invalid authority-change reason must fail before file access");

        assert_eq!(error.to_string(), "Authority change reason is invalid");
    }
}
