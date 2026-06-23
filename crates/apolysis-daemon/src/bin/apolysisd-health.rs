// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    match run(std::env::args().skip(1).collect()) {
        Ok(response) => {
            println!("{response}");
        }
        Err(error) => {
            eprintln!("apolysisd-health: {error}");
            std::process::exit(1);
        }
    }
}

fn run(args: Vec<String>) -> Result<String, String> {
    let config = HealthConfig::from_args(args)?;
    let mut stream = UnixStream::connect(&config.socket)
        .map_err(|error| format!("failed to connect {}: {error}", config.socket.display()))?;
    stream
        .set_read_timeout(Some(config.timeout))
        .map_err(|error| format!("failed to set read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(config.timeout))
        .map_err(|error| format!("failed to set write timeout: {error}"))?;

    let request = br#"{"type":"health"}"#;
    stream
        .write_all(&(request.len() as u32).to_be_bytes())
        .map_err(|error| format!("failed to write request length: {error}"))?;
    stream
        .write_all(request)
        .map_err(|error| format!("failed to write request body: {error}"))?;

    let mut length = [0_u8; 4];
    stream
        .read_exact(&mut length)
        .map_err(|error| format!("failed to read response length: {error}"))?;
    let length = u32::from_be_bytes(length) as usize;
    if length > 64 * 1024 {
        return Err(format!("response frame too large: {length} bytes"));
    }
    let mut response = vec![0_u8; length];
    stream
        .read_exact(&mut response)
        .map_err(|error| format!("failed to read response body: {error}"))?;
    let response_value = serde_json::from_slice::<serde_json::Value>(&response)
        .map_err(|error| format!("daemon returned invalid JSON: {error}"))?;
    if config.require_liveness
        && response_value
            .get("liveness")
            .and_then(|value| value.as_bool())
            != Some(true)
    {
        return Err(format!("liveness requirement failed: {response_value}"));
    }
    if config.require_readiness
        && response_value
            .get("readiness")
            .and_then(|value| value.as_bool())
            != Some(true)
    {
        return Err(format!("readiness requirement failed: {response_value}"));
    }
    String::from_utf8(response).map_err(|error| format!("daemon returned non-UTF-8 JSON: {error}"))
}

#[derive(Debug, Eq, PartialEq)]
struct HealthConfig {
    socket: PathBuf,
    timeout: Duration,
    require_liveness: bool,
    require_readiness: bool,
}

impl HealthConfig {
    fn from_args(args: Vec<String>) -> Result<Self, String> {
        let mut socket = PathBuf::from("/run/apolysis/apolysisd.sock");
        let mut timeout = Duration::from_secs(2);
        let mut require_liveness = false;
        let mut require_readiness = false;
        let mut index = 0;
        while index < args.len() {
            let option = &args[index];
            index += 1;
            match option.as_str() {
                "--require-liveness" => require_liveness = true,
                "--require-readiness" => require_readiness = true,
                "--socket" => {
                    let value = args
                        .get(index)
                        .ok_or_else(|| format!("missing value for {option}"))?;
                    socket = value.into();
                    index += 1;
                }
                "--timeout-ms" => {
                    let value = args
                        .get(index)
                        .ok_or_else(|| format!("missing value for {option}"))?;
                    let millis = value
                        .parse::<u64>()
                        .map_err(|error| format!("invalid value for --timeout-ms: {error}"))?;
                    if millis == 0 {
                        return Err("--timeout-ms must be greater than zero".to_string());
                    }
                    timeout = Duration::from_millis(millis);
                    index += 1;
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }
        Ok(Self {
            socket,
            timeout,
            require_liveness,
            require_readiness,
        })
    }
}
