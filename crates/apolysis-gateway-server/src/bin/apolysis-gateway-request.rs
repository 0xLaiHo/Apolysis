// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use apolysis_contracts::OpenRunRequest;
use apolysis_gateway::canonical_request_digest;

const MAX_INPUT_BYTES: u64 = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("apolysis-gateway-request: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), RequestCliError> {
    let command = parse_command()?;
    match command {
        Command::OpenRun { input, output } => sign_open_run(&input, &output),
    }
}

enum Command {
    OpenRun { input: PathBuf, output: PathBuf },
}

fn parse_command() -> Result<Command, RequestCliError> {
    let mut args = env::args_os();
    let _program = args.next();
    let Some(command) = args.next() else {
        return Err(RequestCliError::Usage);
    };
    if command != OsStr::new("open-run") {
        return Err(RequestCliError::Usage);
    }

    let mut input = None;
    let mut output = None;
    while let Some(flag) = args.next() {
        let destination = match flag.to_str() {
            Some("--input") if input.is_none() => &mut input,
            Some("--output") if output.is_none() => &mut output,
            _ => return Err(RequestCliError::Usage),
        };
        let Some(path) = args.next() else {
            return Err(RequestCliError::Usage);
        };
        *destination = Some(PathBuf::from(path));
    }

    match (input, output) {
        (Some(input), Some(output)) => Ok(Command::OpenRun { input, output }),
        _ => Err(RequestCliError::Usage),
    }
}

fn sign_open_run(input: &Path, output: &Path) -> Result<(), RequestCliError> {
    let bytes = read_bounded(input)?;
    let mut wire: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| RequestCliError::InvalidRequest)?;
    let unsigned: OpenRunRequest =
        serde_json::from_value(wire.clone()).map_err(|_| RequestCliError::InvalidRequest)?;
    let digest = canonical_request_digest("open_run", &unsigned)
        .map_err(|_| RequestCliError::DigestConstruction)?;

    let object = wire
        .as_object_mut()
        .ok_or(RequestCliError::InvalidRequest)?;
    object.insert(
        "request_digest".to_string(),
        serde_json::Value::String(digest),
    );

    // Reconstruct the public contract after signing so the emitted request is
    // exactly the shape the Gateway accepts, then run its semantic checks.
    let signed: OpenRunRequest =
        serde_json::from_value(wire).map_err(|_| RequestCliError::InvalidRequest)?;
    signed
        .validate()
        .map_err(|_| RequestCliError::InvalidRequest)?;
    let mut encoded = serde_json::to_vec(&signed).map_err(|_| RequestCliError::Serialization)?;
    encoded.push(b'\n');

    write_new_private_file(output, &encoded)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, RequestCliError> {
    let file = File::open(path).map_err(|_| RequestCliError::InputOpen)?;
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RequestCliError::InputRead)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(RequestCliError::InputTooLarge);
    }
    Ok(bytes)
}

fn write_new_private_file(path: &Path, contents: &[u8]) -> Result<(), RequestCliError> {
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(RequestCliError::OutputExists);
        }
        Err(_) => return Err(RequestCliError::OutputCreate),
    };
    let mut cleanup = IncompleteOutput::new(path, &file);
    file.write_all(contents)
        .map_err(|_| RequestCliError::OutputWrite)?;
    file.sync_all().map_err(|_| RequestCliError::OutputWrite)?;
    cleanup.commit();
    Ok(())
}

struct IncompleteOutput<'a> {
    path: &'a Path,
    identity: Option<(u64, u64)>,
    committed: bool,
}

impl<'a> IncompleteOutput<'a> {
    fn new(path: &'a Path, file: &File) -> Self {
        Self {
            path,
            identity: file
                .metadata()
                .ok()
                .map(|metadata| (metadata.dev(), metadata.ino())),
            committed: false,
        }
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for IncompleteOutput<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let same_file = self.identity.is_some_and(|(device, inode)| {
            fs::symlink_metadata(self.path)
                .ok()
                .is_some_and(|metadata| metadata.dev() == device && metadata.ino() == inode)
        });
        if same_file {
            let _cleanup_result = fs::remove_file(self.path);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestCliError {
    Usage,
    InputOpen,
    InputRead,
    InputTooLarge,
    InvalidRequest,
    DigestConstruction,
    Serialization,
    OutputExists,
    OutputCreate,
    OutputWrite,
}

impl fmt::Display for RequestCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Usage => "usage: open-run --input FILE --output FILE",
            Self::InputOpen => "unable to open the input file",
            Self::InputRead => "unable to read the input file",
            Self::InputTooLarge => "input exceeds the one-megabyte limit",
            Self::InvalidRequest => "input is not a valid open-run request",
            Self::DigestConstruction => "unable to construct the canonical request digest",
            Self::Serialization => "unable to serialize the signed request",
            Self::OutputExists => "output file already exists",
            Self::OutputCreate => "unable to create the output file",
            Self::OutputWrite => "unable to write the output file",
        })
    }
}

impl std::error::Error for RequestCliError {}
