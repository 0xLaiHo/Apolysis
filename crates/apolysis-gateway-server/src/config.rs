// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeMap,
    ffi::OsString,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use crate::GatewayServerError;

const REQUIRED_OPTIONS: [&str; 7] = [
    "--listen",
    "--database-url-file",
    "--tls-certificate",
    "--tls-private-key",
    "--client-ca",
    "--replay-key",
    "--ready-file",
];

/// Validated process configuration for the direct-mTLS Gateway listener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayServerConfig {
    listen: SocketAddr,
    database_url_file: PathBuf,
    tls_certificate: PathBuf,
    tls_private_key: PathBuf,
    client_ca: PathBuf,
    replay_key: PathBuf,
    ready_file: PathBuf,
}

impl GatewayServerConfig {
    /// Parse the production server's deliberately small flag interface.
    pub fn from_args(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, GatewayServerError> {
        let mut arguments = arguments.into_iter();
        let _program = arguments.next();
        let mut options = BTreeMap::new();

        while let Some(option) = arguments.next() {
            let option = option.into_string().map_err(|_| {
                GatewayServerError::configuration("Gateway option names must be UTF-8")
            })?;
            if !REQUIRED_OPTIONS.contains(&option.as_str()) {
                return Err(GatewayServerError::configuration(
                    "Gateway received an unsupported option",
                ));
            }
            let value = arguments.next().ok_or_else(|| {
                GatewayServerError::configuration("Gateway option is missing its value")
            })?;
            if options.insert(option, value).is_some() {
                return Err(GatewayServerError::configuration(
                    "Gateway option was supplied more than once",
                ));
            }
        }

        let listen = required_string(&mut options, "--listen")?
            .parse::<SocketAddr>()
            .map_err(|_| GatewayServerError::configuration("Gateway listen address is invalid"))?;
        let database_url_file = required_path(&mut options, "--database-url-file")?;
        let tls_certificate = required_path(&mut options, "--tls-certificate")?;
        let tls_private_key = required_path(&mut options, "--tls-private-key")?;
        let client_ca = required_path(&mut options, "--client-ca")?;
        let replay_key = required_path(&mut options, "--replay-key")?;
        let ready_file = required_path(&mut options, "--ready-file")?;

        for path in [
            &database_url_file,
            &tls_certificate,
            &tls_private_key,
            &client_ca,
            &replay_key,
            &ready_file,
        ] {
            require_absolute(path)?;
        }

        Ok(Self {
            listen,
            database_url_file,
            tls_certificate,
            tls_private_key,
            client_ca,
            replay_key,
            ready_file,
        })
    }

    pub(crate) fn listen(&self) -> SocketAddr {
        self.listen
    }

    pub(crate) fn database_url_file(&self) -> &Path {
        &self.database_url_file
    }

    pub(crate) fn tls_certificate(&self) -> &Path {
        &self.tls_certificate
    }

    pub(crate) fn tls_private_key(&self) -> &Path {
        &self.tls_private_key
    }

    pub(crate) fn client_ca(&self) -> &Path {
        &self.client_ca
    }

    pub(crate) fn replay_key(&self) -> &Path {
        &self.replay_key
    }

    pub(crate) fn ready_file(&self) -> &Path {
        &self.ready_file
    }
}

fn required_string(
    options: &mut BTreeMap<String, OsString>,
    option: &'static str,
) -> Result<String, GatewayServerError> {
    options
        .remove(option)
        .ok_or_else(|| GatewayServerError::configuration("Gateway is missing a required option"))?
        .into_string()
        .map_err(|_| GatewayServerError::configuration("Gateway option values must be UTF-8"))
}

fn required_path(
    options: &mut BTreeMap<String, OsString>,
    option: &'static str,
) -> Result<PathBuf, GatewayServerError> {
    let path = PathBuf::from(options.remove(option).ok_or_else(|| {
        GatewayServerError::configuration("Gateway is missing a required option")
    })?);
    if path.as_os_str().is_empty() {
        return Err(GatewayServerError::configuration(
            "Gateway file option must not be empty",
        ));
    }
    Ok(path)
}

fn require_absolute(path: &Path) -> Result<(), GatewayServerError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(GatewayServerError::configuration(
            "Gateway file paths must be absolute",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::GatewayServerConfig;

    #[test]
    fn rejects_relative_secret_paths() {
        let error = GatewayServerConfig::from_args(
            [
                "gateway",
                "--listen",
                "127.0.0.1:0",
                "--database-url-file",
                "database.url",
                "--tls-certificate",
                "/run/apolysis/server.pem",
                "--tls-private-key",
                "/run/apolysis/server.key",
                "--client-ca",
                "/run/apolysis/ca.pem",
                "--replay-key",
                "/run/apolysis/replay.key",
                "--ready-file",
                "/run/apolysis/ready",
            ]
            .into_iter()
            .map(Into::into),
        )
        .expect_err("relative secret path must be rejected");

        assert_eq!(error.to_string(), "Gateway file paths must be absolute");
    }
}
