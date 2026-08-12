// SPDX-License-Identifier: Apache-2.0

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use apolysis_accountability::{decode_intent_frame, MAX_INTENT_FRAME_BYTES};
use apolysis_daemon::{DaemonResponse, DAEMON_SCHEMA_V1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

const MAX_CONTROL_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

fn main() {
    match run(std::env::args().skip(1).collect()) {
        Ok(response) => {
            let mut stdout = std::io::stdout().lock();
            if stdout
                .write_all(&response)
                .and_then(|()| stdout.write_all(b"\n"))
                .is_err()
            {
                eprintln!("apolysisd-control: failed to write response");
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("apolysisd-control: {error}");
            std::process::exit(1);
        }
    }
}

fn run(args: Vec<String>) -> Result<Vec<u8>, &'static str> {
    let config = ControlConfig::from_args(args)?;
    let deadline = Instant::now()
        .checked_add(config.timeout)
        .ok_or("invalid timeout")?;
    let request = read_bounded_stdin(deadline)?;
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is invalid")?
        .as_millis()
        .try_into()
        .map_err(|_| "system clock is invalid")?;
    let typed_request =
        decode_intent_frame(&request, now_unix_ms).map_err(|_| "request rejected")?;
    let request = serde_json::to_vec(&typed_request).map_err(|_| "request rejected")?;
    if request.len() > MAX_INTENT_FRAME_BYTES {
        return Err("request rejected");
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| "daemon exchange failed")?;
    let exchange_budget = remaining(deadline)?;
    let response = runtime
        .block_on(async {
            tokio::time::timeout(exchange_budget, exchange(&config.socket, &request)).await
        })
        .map_err(|_| "daemon exchange timed out")??;
    validate_response(&response)?;
    let response = serde_json::to_vec(&response).map_err(|_| "daemon response rejected")?;
    remaining(deadline)?;
    Ok(response)
}

async fn exchange(path: &Path, request: &[u8]) -> Result<DaemonResponse, &'static str> {
    let expected_socket = validate_socket(path)?;
    let mut stream = UnixStream::connect(path)
        .await
        .map_err(|_| "daemon unavailable")?;
    let peer_uid = stream
        .peer_cred()
        .map_err(|_| "daemon peer rejected")?
        .uid();
    if peer_uid != expected_socket.uid {
        return Err("daemon peer rejected");
    }
    if validate_socket(path)? != expected_socket {
        return Err("daemon socket changed");
    }

    let length = u32::try_from(request.len()).map_err(|_| "request rejected")?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .map_err(|_| "daemon exchange failed")?;
    stream
        .write_all(request)
        .await
        .map_err(|_| "daemon exchange failed")?;

    let mut response_length = [0_u8; 4];
    stream
        .read_exact(&mut response_length)
        .await
        .map_err(|_| "daemon exchange failed")?;
    let response_length = u32::from_be_bytes(response_length) as usize;
    if response_length == 0 || response_length > MAX_CONTROL_RESPONSE_BYTES {
        return Err("daemon response rejected");
    }
    let mut response = vec![0_u8; response_length];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|_| "daemon exchange failed")?;
    serde_json::from_slice(&response).map_err(|_| "daemon response rejected")
}

fn validate_response(response: &DaemonResponse) -> Result<(), &'static str> {
    let schema_version = match response {
        DaemonResponse::Ack { schema_version, .. }
        | DaemonResponse::Health { schema_version, .. }
        | DaemonResponse::Session { schema_version, .. }
        | DaemonResponse::SessionList { schema_version, .. }
        | DaemonResponse::RetentionPurge { schema_version, .. }
        | DaemonResponse::Error { schema_version, .. } => *schema_version,
    };
    if schema_version != DAEMON_SCHEMA_V1 {
        return Err("daemon response rejected");
    }
    if matches!(response, DaemonResponse::Error { .. }) {
        return Err("daemon rejected request");
    }
    Ok(())
}

fn read_bounded_stdin(deadline: Instant) -> Result<Vec<u8>, &'static str> {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let mut request = Vec::with_capacity(MAX_INTENT_FRAME_BYTES.min(8 * 1024));
    let mut chunk = [0_u8; 8 * 1024];
    while request.len() <= MAX_INTENT_FRAME_BYTES {
        wait_until_readable(stdin.as_raw_fd(), deadline)?;
        let remaining_capacity = MAX_INTENT_FRAME_BYTES + 1 - request.len();
        let read_capacity = remaining_capacity.min(chunk.len());
        match stdin.read(&mut chunk[..read_capacity]) {
            Ok(0) => return Ok(request),
            Ok(read) => request.extend_from_slice(&chunk[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("failed to read request"),
        }
    }
    Ok(request)
}

fn wait_until_readable(fd: std::os::fd::RawFd, deadline: Instant) -> Result<(), &'static str> {
    loop {
        let duration = remaining(deadline)?;
        let timeout_ms = duration.as_millis().max(1).min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            if descriptor.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                return Err("failed to read request");
            }
            return Ok(());
        }
        if result == 0 {
            return Err("request timed out");
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err("failed to read request");
        }
    }
}

fn remaining(deadline: Instant) -> Result<Duration, &'static str> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or("operation timed out")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

fn validate_socket(path: &Path) -> Result<SocketIdentity, &'static str> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| "daemon unavailable")?;
    let mode = metadata.permissions().mode() & 0o7777;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || mode != 0o660
    {
        return Err("daemon socket rejected");
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode,
    })
}

struct ControlConfig {
    socket: PathBuf,
    timeout: Duration,
}

impl ControlConfig {
    fn from_args(args: Vec<String>) -> Result<Self, &'static str> {
        let mut socket = PathBuf::from("/run/apolysis/apolysisd.sock");
        let mut timeout = Duration::from_secs(2);
        let mut args = args.into_iter();
        while let Some(argument) = args.next() {
            match argument.as_str() {
                "--socket" => {
                    socket = args
                        .next()
                        .map(PathBuf::from)
                        .ok_or("missing socket path")?;
                }
                "--timeout-ms" => {
                    let milliseconds = args
                        .next()
                        .ok_or("missing timeout")?
                        .parse::<u64>()
                        .map_err(|_| "invalid timeout")?;
                    if milliseconds == 0 {
                        return Err("invalid timeout");
                    }
                    timeout = Duration::from_millis(milliseconds);
                }
                _ => return Err("unknown argument"),
            }
        }
        Ok(Self { socket, timeout })
    }
}
