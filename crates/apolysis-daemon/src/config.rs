// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub state_dir: PathBuf,
    pub max_sessions: usize,
    pub max_pending: usize,
    pub max_connections: usize,
    pub request_timeout: Duration,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/apolysis/apolysisd.sock"),
            state_dir: PathBuf::from("/var/lib/apolysis"),
            max_sessions: 4_096,
            max_pending: 4_096,
            max_connections: 128,
            request_timeout: Duration::from_secs(5),
        }
    }
}

impl DaemonConfig {
    pub fn from_args(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let mut config = Self::default();
        let args: Vec<String> = args.into_iter().collect();
        let mut index = 0;
        while index < args.len() {
            let option = &args[index];
            index += 1;
            let value = args
                .get(index)
                .ok_or_else(|| format!("missing value for {option}"))?;
            match option.as_str() {
                "--socket" => config.socket_path = value.into(),
                "--state-dir" => config.state_dir = value.into(),
                "--max-sessions" => config.max_sessions = parse_usize(option, value)?,
                "--max-pending" => config.max_pending = parse_usize(option, value)?,
                "--max-connections" => config.max_connections = parse_usize(option, value)?,
                "--request-timeout-ms" => {
                    config.request_timeout = Duration::from_millis(parse_u64(option, value)?)
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
            index += 1;
        }
        if config.max_connections == 0 {
            return Err("--max-connections must be greater than zero".to_string());
        }
        if config.request_timeout.is_zero() {
            return Err("--request-timeout-ms must be greater than zero".to_string());
        }
        Ok(config)
    }
}

fn parse_u64(option: &str, value: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|error| format!("invalid value for {option}: {error}"))
}

fn parse_usize(option: &str, value: &str) -> Result<usize, String> {
    value
        .parse()
        .map_err(|error| format!("invalid value for {option}: {error}"))
}
