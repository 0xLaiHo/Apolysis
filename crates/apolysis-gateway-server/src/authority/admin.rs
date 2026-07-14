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
