// SPDX-License-Identifier: Apache-2.0

mod archive;
mod elf;
mod systemd;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
pub const MAX_PACKAGE_BYTES: u64 = 600 * 1024 * 1024;
pub const MAX_ARCHIVE_BYTES: u64 = 530 * 1024 * 1024;
pub const MAX_CHECKSUM_BYTES: u64 = 256;
pub const CHUNK_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACT_SET_BYTES: u64 = 512 * 1024 * 1024;

macro_rules! ensure {
    ($condition:expr, $message:expr $(,)?) => {
        if !$condition {
            return Err(crate::VerifierError::new($message));
        }
    };
}

pub(crate) use ensure;

#[derive(Debug)]
pub struct VerifierError {
    message: String,
}

impl VerifierError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for VerifierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for VerifierError {}

pub type Result<T> = std::result::Result<T, VerifierError>;

pub(crate) trait ResultContext<T> {
    fn context(self, message: impl FnOnce() -> String) -> Result<T>;
}

impl<T, E> ResultContext<T> for std::result::Result<T, E>
where
    E: fmt::Display,
{
    fn context(self, message: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|error| VerifierError::new(format!("{}: {error}", message())))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ArtifactContract {
    pub path: &'static str,
    pub kind: &'static str,
    pub mode: &'static str,
    pub maximum_bytes: u64,
}

pub(crate) const ARTIFACT_CONTRACTS: [ArtifactContract; 5] = [
    ArtifactContract {
        path: "bin/apolysis",
        kind: "cli_binary",
        mode: "0755",
        maximum_bytes: 128 * 1024 * 1024,
    },
    ArtifactContract {
        path: "bin/apolysisd",
        kind: "daemon_binary",
        mode: "0755",
        maximum_bytes: 256 * 1024 * 1024,
    },
    ArtifactContract {
        path: "bin/apolysisd-health",
        kind: "health_binary",
        mode: "0755",
        maximum_bytes: 64 * 1024 * 1024,
    },
    ArtifactContract {
        path: "ebpf/apolysis_observer.bpf.o",
        kind: "core_bpf_object",
        mode: "0644",
        maximum_bytes: 32 * 1024 * 1024,
    },
    ArtifactContract {
        path: "systemd/apolysisd.service",
        kind: "systemd_unit",
        mode: "0644",
        maximum_bytes: 1024 * 1024,
    },
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseManifest {
    schema_version: u64,
    release_version: String,
    target: String,
    created_at_unix_ms: u64,
    package: PackageMetadata,
    artifacts: Vec<ManifestArtifact>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PackageMetadata {
    name: String,
    format: String,
    sha256_file: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestArtifact {
    path: String,
    kind: String,
    sha256: String,
    size_bytes: u64,
    mode: String,
}

pub fn verify_release(output_dir: &Path, verification_dir: &Path) -> Result<()> {
    validate_output_directory(output_dir)?;
    validate_verification_directory(verification_dir)?;

    let manifest_path = output_dir.join("apolysis-release-manifest.json");
    let manifest_bytes = bounded_bytes(&manifest_path, MAX_MANIFEST_BYTES)?;
    let manifest: ReleaseManifest = serde_json::from_slice(&manifest_bytes)
        .context(|| "invalid release manifest JSON".to_owned())?;
    let artifacts = validate_manifest(&manifest)?;

    let package_name = format!(
        "apolysis-{}-{}.tar.gz",
        manifest.release_version, manifest.target
    );
    let package_path = output_dir.join(&package_name);
    let checksum_path = output_dir.join(format!("{package_name}.sha256"));
    let mut package_file = open_regular(&package_path, MAX_PACKAGE_BYTES)?;
    let package_digest = sha256_reader(&mut package_file, &package_name)?;
    let expected_checksum = format!("{package_digest}  {package_name}\n");
    let checksum_bytes = bounded_bytes(&checksum_path, MAX_CHECKSUM_BYTES)?;
    ensure!(
        checksum_bytes == expected_checksum.as_bytes(),
        "release checksum file mismatch"
    );
    package_file
        .seek(SeekFrom::Start(0))
        .context(|| format!("cannot rewind release package {package_name}"))?;

    let archive_path = verification_dir.join("release.tar");
    archive::decompress_single_gzip(&mut package_file, &archive_path)?;
    let package_base = package_name
        .strip_suffix(".tar.gz")
        .ok_or_else(|| VerifierError::new("release package does not use tar.gz"))?;
    let observed = archive::verify_archive(&archive_path, package_base, &manifest_bytes)?;

    for (path, manifest_artifact) in artifacts {
        let observed_artifact = observed
            .artifacts
            .get(path)
            .ok_or_else(|| VerifierError::new(format!("archive artifact is missing: {path}")))?;
        ensure!(
            observed_artifact.sha256 == manifest_artifact.sha256,
            format!("artifact digest mismatch: {path}")
        );
        ensure!(
            observed_artifact.size_bytes == manifest_artifact.size_bytes,
            format!("artifact size mismatch: {path}")
        );
    }

    let userspace_machine = match manifest.target.as_str() {
        "x86_64-unknown-linux-gnu" => 62,
        "aarch64-unknown-linux-gnu" => 183,
        _ => return Err(VerifierError::new("unsupported release target")),
    };
    for path in ["bin/apolysis", "bin/apolysisd", "bin/apolysisd-health"] {
        let artifact = observed
            .artifacts
            .get(path)
            .ok_or_else(|| VerifierError::new(format!("archive artifact is missing: {path}")))?;
        elf::validate_userspace(
            &artifact.metadata,
            artifact.size_bytes,
            path,
            userspace_machine,
        )?;
    }
    let bpf = observed
        .artifacts
        .get("ebpf/apolysis_observer.bpf.o")
        .ok_or_else(|| VerifierError::new("archive eBPF object is missing"))?;
    elf::validate_bpf(&bpf.metadata, bpf.size_bytes)?;

    systemd::validate_unit(&observed.unit_text)?;
    prepare_external_verification(verification_dir, &observed.unit_text, &bpf.metadata)?;
    Ok(())
}

fn validate_manifest(manifest: &ReleaseManifest) -> Result<BTreeMap<&str, &ManifestArtifact>> {
    ensure!(
        manifest.schema_version == 2,
        "release manifest must use schema v2"
    );
    let _timestamp = manifest.created_at_unix_ms;
    ensure!(
        is_safe_component(&manifest.release_version),
        "unsafe release version"
    );
    ensure!(is_safe_component(&manifest.target), "unsafe release target");

    let package_name = format!(
        "apolysis-{}-{}.tar.gz",
        manifest.release_version, manifest.target
    );
    ensure!(
        manifest.package
            == (PackageMetadata {
                name: package_name.clone(),
                format: "tar.gz".to_owned(),
                sha256_file: format!("{package_name}.sha256"),
            }),
        "manifest package metadata mismatch"
    );

    let mut artifacts = BTreeMap::new();
    for artifact in &manifest.artifacts {
        ensure!(
            artifacts.insert(artifact.path.as_str(), artifact).is_none(),
            "duplicate manifest artifact path"
        );
    }
    let expected_paths: BTreeSet<&str> = ARTIFACT_CONTRACTS
        .iter()
        .map(|contract| contract.path)
        .collect();
    ensure!(
        artifacts.keys().copied().collect::<BTreeSet<_>>() == expected_paths,
        "manifest artifact set mismatch"
    );

    let mut total_size = 0_u64;
    for contract in ARTIFACT_CONTRACTS {
        let artifact = artifacts.get(contract.path).ok_or_else(|| {
            VerifierError::new(format!("manifest artifact is missing: {}", contract.path))
        })?;
        ensure!(
            artifact.kind == contract.kind && artifact.mode == contract.mode,
            format!("manifest contract mismatch: {}", contract.path)
        );
        ensure!(
            artifact.size_bytes <= contract.maximum_bytes,
            format!("oversized artifact: {}", contract.path)
        );
        ensure!(
            is_lower_hex_digest(&artifact.sha256),
            format!("invalid manifest digest: {}", contract.path)
        );
        total_size = total_size
            .checked_add(artifact.size_bytes)
            .ok_or_else(|| VerifierError::new("release artifact size total overflow"))?;
    }
    ensure!(
        total_size <= MAX_ARTIFACT_SET_BYTES,
        "release artifact set exceeds its total size bound"
    );
    Ok(artifacts)
}

fn validate_output_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .context(|| format!("cannot inspect release output {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "release output is not a plain directory"
    );
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "release output has the wrong owner"
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "release output is group/world writable"
    );
    Ok(())
}

fn validate_verification_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .context(|| format!("cannot inspect verification directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "verification path is not a plain directory"
    );
    ensure!(
        metadata.uid() == unsafe { libc::geteuid() },
        "verification directory has the wrong owner"
    );
    ensure!(
        metadata.mode() & 0o077 == 0,
        "verification directory is not private"
    );
    Ok(())
}

pub(crate) fn open_regular(path: &Path, maximum_bytes: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .context(|| format!("cannot safely open release file {}", path.display()))?;
    let metadata = file
        .metadata()
        .context(|| format!("cannot inspect release file {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && metadata.nlink() == 1 && metadata.len() <= maximum_bytes,
        format!("unsafe release file: {}", display_name(path))
    );
    Ok(file)
}

fn bounded_bytes(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>> {
    let file = open_regular(path, maximum_bytes)?;
    let capacity = usize::try_from(maximum_bytes.min(CHUNK_BYTES as u64))
        .context(|| format!("invalid byte bound for {}", path.display()))?;
    let mut payload = Vec::with_capacity(capacity);
    file.take(maximum_bytes + 1)
        .read_to_end(&mut payload)
        .context(|| format!("cannot read release file {}", path.display()))?;
    ensure!(
        payload.len() as u64 <= maximum_bytes,
        format!("oversized release file: {}", display_name(path))
    );
    Ok(payload)
}

fn sha256_reader(file: &mut File, name: &str) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    loop {
        let count = file
            .read(&mut buffer)
            .context(|| format!("cannot read release package {name}"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex_digest(digest.finalize().as_slice()))
}

pub(crate) fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn is_safe_component(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn prepare_external_verification(
    verification_dir: &Path,
    unit_text: &str,
    bpf_object: &[u8],
) -> Result<()> {
    write_new_file(
        &verification_dir.join("apolysis_observer.bpf.o"),
        bpf_object,
        0o600,
    )?;
    let daemon_path = verification_dir.join("apolysisd");
    write_new_file(&daemon_path, b"#!/bin/sh\nexit 0\n", 0o755)?;
    fs::set_permissions(&daemon_path, fs::Permissions::from_mode(0o755)).context(|| {
        format!(
            "cannot make verification daemon executable: {}",
            daemon_path.display()
        )
    })?;

    const EXPECTED_EXEC: &str = "ExecStart=/usr/local/bin/apolysisd ";
    ensure!(
        unit_text.matches(EXPECTED_EXEC).count() == 1,
        "systemd unit ExecStart contract mismatch"
    );
    let daemon_text = daemon_path.to_str().ok_or_else(|| {
        VerifierError::new("verification directory is not valid UTF-8 for systemd")
    })?;
    let prepared_unit = unit_text.replacen(EXPECTED_EXEC, &format!("ExecStart={daemon_text} "), 1);
    write_new_file(
        &verification_dir.join("apolysisd.service"),
        prepared_unit.as_bytes(),
        0o600,
    )
}

fn write_new_file(path: &Path, payload: &[u8], mode: u32) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .context(|| format!("cannot create verification file {}", path.display()))?;
    file.write_all(payload)
        .context(|| format!("cannot write verification file {}", path.display()))?;
    file.sync_all()
        .context(|| format!("cannot sync verification file {}", path.display()))
}

fn display_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}
