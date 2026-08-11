// SPDX-License-Identifier: Apache-2.0

use crate::{
    ensure, hex_digest, open_regular, ArtifactContract, Result, ResultContext, VerifierError,
    ARTIFACT_CONTRACTS, CHUNK_BYTES, MAX_ARCHIVE_BYTES, MAX_MANIFEST_BYTES,
};
use flate2::bufread::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const TAR_BLOCK_BYTES: usize = 512;
const README_MAX_BYTES: u64 = 2 * 1024 * 1024;
const USERSPACE_METADATA_BYTES: usize = 1024 * 1024;

pub(crate) struct ObservedArtifact {
    pub sha256: String,
    pub size_bytes: u64,
    pub metadata: Vec<u8>,
}

pub(crate) struct VerifiedArchive {
    pub artifacts: BTreeMap<String, ObservedArtifact>,
    pub unit_text: String,
}

struct MemberContract {
    maximum_bytes: u64,
    expected_mode: u32,
    metadata_limit: usize,
    capture_content: bool,
    artifact: bool,
}

pub(crate) fn decompress_single_gzip(package: &mut File, archive_path: &Path) -> Result<()> {
    let reader = BufReader::with_capacity(CHUNK_BYTES, package);
    let mut decoder = GzDecoder::new(reader);
    let mut archive = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(archive_path)
        .context(|| {
            format!(
                "cannot create bounded archive file {}",
                archive_path.display()
            )
        })?;
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    let mut archive_size = 0_u64;
    loop {
        let count = decoder
            .read(&mut buffer)
            .context(|| "package has an invalid or truncated gzip stream".to_owned())?;
        if count == 0 {
            break;
        }
        archive_size = archive_size
            .checked_add(count as u64)
            .ok_or_else(|| VerifierError::new("expanded archive size overflow"))?;
        ensure!(
            archive_size <= MAX_ARCHIVE_BYTES,
            "expanded archive exceeds its bound"
        );
        archive
            .write_all(&buffer[..count])
            .context(|| "cannot write bounded archive".to_owned())?;
    }
    let mut compressed = decoder.into_inner();
    ensure!(
        compressed
            .fill_buf()
            .context(|| "cannot inspect the gzip stream boundary".to_owned())?
            .is_empty(),
        "package has trailing or concatenated gzip data"
    );
    archive
        .sync_all()
        .context(|| "cannot sync bounded archive".to_owned())
}

pub(crate) fn verify_archive(
    archive_path: &Path,
    package_base: &str,
    manifest_bytes: &[u8],
) -> Result<VerifiedArchive> {
    let mut archive = open_regular(archive_path, MAX_ARCHIVE_BYTES)?;
    let directories = expected_directories(package_base);
    let files = expected_files(package_base)?;
    let expected_names: BTreeSet<String> = directories
        .iter()
        .cloned()
        .chain(files.keys().cloned())
        .collect();
    let mut seen = BTreeSet::new();
    let mut artifacts = BTreeMap::new();
    let mut archived_manifest = None;
    let mut unit_text = None;

    loop {
        let header = read_tar_block(&mut archive)?
            .ok_or_else(|| VerifierError::new("archive lacks an end marker"))?;
        if is_zero_block(&header) {
            let second = read_tar_block(&mut archive)?
                .ok_or_else(|| VerifierError::new("archive has only one zero end block"))?;
            ensure!(
                is_zero_block(&second),
                "archive has only one zero end block"
            );
            ensure_zero_tail(&mut archive)?;
            break;
        }

        verify_header_checksum(&header)?;
        let type_flag = header[156];
        ensure!(
            !matches!(type_flag, b'x' | b'g' | b'S' | b'L' | b'K'),
            "archive contains extended PAX, sparse, or long-name metadata"
        );
        let raw_name = tar_path(&header)?;
        let is_directory = type_flag == b'5';
        let is_regular = matches!(type_flag, 0 | b'0');
        ensure!(
            is_directory || is_regular,
            "archive contains a link or special file"
        );
        let canonical_name = canonical_tar_name(&raw_name, is_directory)?;
        ensure!(
            expected_names.contains(&canonical_name),
            "archive contains an unexpected path"
        );
        ensure!(
            seen.insert(canonical_name.clone()),
            "archive contains a duplicate canonical path"
        );
        ensure!(
            parse_octal(&header[108..116], "archive uid")? == 0
                && parse_octal(&header[116..124], "archive gid")? == 0,
            "archive member ownership is not normalized"
        );
        ensure!(
            c_string(&header[265..297], "archive user name")?.is_empty()
                && c_string(&header[297..329], "archive group name")?.is_empty(),
            "archive member owner names are not normalized"
        );
        ensure!(
            c_string(&header[157..257], "archive link name")?.is_empty(),
            "archive member has a link target"
        );

        let mode = parse_octal(&header[100..108], "archive mode")?;
        let size = parse_size(&header[124..136])?;
        if is_directory {
            ensure!(size == 0, "archive directory is malformed");
            ensure!(mode & 0o7777 == 0o755, "archive directory mode mismatch");
        } else {
            let contract = files.get(&canonical_name).ok_or_else(|| {
                VerifierError::new("archive file is absent from the release contract")
            })?;
            ensure!(
                size <= contract.maximum_bytes,
                "archive member exceeds its size bound"
            );
            ensure!(
                mode & 0o7777 == u64::from(contract.expected_mode),
                format!("archive mode mismatch: {canonical_name}")
            );
            let relative_path = canonical_name
                .strip_prefix(package_base)
                .and_then(|path| path.strip_prefix('/'))
                .ok_or_else(|| VerifierError::new("archive path escaped its package root"))?;
            let observed = read_member(&mut archive, size, contract, relative_path)?;
            if contract.artifact {
                artifacts.insert(relative_path.to_owned(), observed.artifact);
            }
            if relative_path == "apolysis-release-manifest.json" {
                archived_manifest = observed.content;
            } else if relative_path == "systemd/apolysisd.service" {
                let bytes = observed
                    .content
                    .ok_or_else(|| VerifierError::new("systemd unit content was not captured"))?;
                unit_text = Some(
                    String::from_utf8(bytes)
                        .context(|| "systemd unit is not valid UTF-8".to_owned())?,
                );
            }
            consume_padding(&mut archive, size)?;
            continue;
        }
        consume_padding(&mut archive, size)?;
    }

    ensure!(seen == expected_names, "archive member set mismatch");
    ensure!(
        archived_manifest.as_deref() == Some(manifest_bytes),
        "published and archived manifests differ"
    );
    let expected_artifacts: BTreeSet<&str> = ARTIFACT_CONTRACTS
        .iter()
        .map(|contract| contract.path)
        .collect();
    ensure!(
        artifacts
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == expected_artifacts,
        "archive artifact set mismatch"
    );
    Ok(VerifiedArchive {
        artifacts,
        unit_text: unit_text.ok_or_else(|| VerifierError::new("systemd unit is missing"))?,
    })
}

struct ReadMember {
    artifact: ObservedArtifact,
    content: Option<Vec<u8>>,
}

fn read_member(
    archive: &mut File,
    size: u64,
    contract: &MemberContract,
    relative_path: &str,
) -> Result<ReadMember> {
    let mut remaining = size;
    let mut digest = Sha256::new();
    let metadata_capacity = usize::try_from(size.min(contract.metadata_limit as u64))
        .context(|| format!("invalid metadata bound for {relative_path}"))?;
    let mut metadata = Vec::with_capacity(metadata_capacity);
    let mut content = if contract.capture_content {
        Some(Vec::with_capacity(usize::try_from(size).context(|| {
            format!("invalid content bound for {relative_path}")
        })?))
    } else {
        None
    };
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(CHUNK_BYTES as u64))
            .context(|| format!("invalid member length for {relative_path}"))?;
        archive
            .read_exact(&mut buffer[..wanted])
            .context(|| format!("archive member is truncated: {relative_path}"))?;
        digest.update(&buffer[..wanted]);
        if metadata.len() < contract.metadata_limit {
            let take = wanted.min(contract.metadata_limit - metadata.len());
            metadata.extend_from_slice(&buffer[..take]);
        }
        if let Some(bytes) = &mut content {
            bytes.extend_from_slice(&buffer[..wanted]);
        }
        remaining -= wanted as u64;
    }
    Ok(ReadMember {
        artifact: ObservedArtifact {
            sha256: hex_digest(digest.finalize().as_slice()),
            size_bytes: size,
            metadata,
        },
        content,
    })
}

fn expected_directories(package_base: &str) -> BTreeSet<String> {
    [
        package_base.to_owned(),
        format!("{package_base}/bin"),
        format!("{package_base}/ebpf"),
        format!("{package_base}/systemd"),
        format!("{package_base}/docs"),
    ]
    .into_iter()
    .collect()
}

fn expected_files(package_base: &str) -> Result<BTreeMap<String, MemberContract>> {
    let mut files = BTreeMap::from([
        (
            format!("{package_base}/apolysis-release-manifest.json"),
            MemberContract {
                maximum_bytes: MAX_MANIFEST_BYTES,
                expected_mode: 0o644,
                metadata_limit: 0,
                capture_content: true,
                artifact: false,
            },
        ),
        (
            format!("{package_base}/README.md"),
            MemberContract {
                maximum_bytes: README_MAX_BYTES,
                expected_mode: 0o644,
                metadata_limit: 0,
                capture_content: false,
                artifact: false,
            },
        ),
        (
            format!("{package_base}/README.zh-CN.md"),
            MemberContract {
                maximum_bytes: README_MAX_BYTES,
                expected_mode: 0o644,
                metadata_limit: 0,
                capture_content: false,
                artifact: false,
            },
        ),
        (
            format!("{package_base}/docs/jsonl-schema-v1.md"),
            MemberContract {
                maximum_bytes: README_MAX_BYTES,
                expected_mode: 0o644,
                metadata_limit: 0,
                capture_content: false,
                artifact: false,
            },
        ),
    ]);
    for contract in ARTIFACT_CONTRACTS {
        let metadata_limit = artifact_metadata_limit(contract)?;
        files.insert(
            format!("{package_base}/{}", contract.path),
            MemberContract {
                maximum_bytes: contract.maximum_bytes,
                expected_mode: parse_contract_mode(contract)?,
                metadata_limit,
                capture_content: contract.path == "systemd/apolysisd.service",
                artifact: true,
            },
        );
    }
    Ok(files)
}

fn artifact_metadata_limit(contract: ArtifactContract) -> Result<usize> {
    if matches!(
        contract.path,
        "bin/apolysis" | "bin/apolysisd" | "bin/apolysisd-health"
    ) {
        Ok(USERSPACE_METADATA_BYTES)
    } else if contract.path == "ebpf/apolysis_observer.bpf.o" {
        usize::try_from(contract.maximum_bytes)
            .context(|| "eBPF artifact bound does not fit memory".to_owned())
    } else {
        Ok(0)
    }
}

fn parse_contract_mode(contract: ArtifactContract) -> Result<u32> {
    u32::from_str_radix(contract.mode, 8)
        .context(|| format!("invalid contract mode for {}", contract.path))
}

fn read_tar_block(archive: &mut File) -> Result<Option<[u8; TAR_BLOCK_BYTES]>> {
    let mut block = [0_u8; TAR_BLOCK_BYTES];
    let first = archive
        .read(&mut block[..1])
        .context(|| "cannot read archive header".to_owned())?;
    if first == 0 {
        return Ok(None);
    }
    archive
        .read_exact(&mut block[1..])
        .context(|| "archive is not block aligned".to_owned())?;
    Ok(Some(block))
}

fn is_zero_block(block: &[u8; TAR_BLOCK_BYTES]) -> bool {
    block.iter().all(|byte| *byte == 0)
}

fn ensure_zero_tail(archive: &mut File) -> Result<()> {
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    loop {
        let count = archive
            .read(&mut buffer)
            .context(|| "cannot inspect archive end padding".to_owned())?;
        if count == 0 {
            break;
        }
        ensure!(
            buffer[..count].iter().all(|byte| *byte == 0),
            "archive has data after its end marker"
        );
    }
    Ok(())
}

fn verify_header_checksum(header: &[u8; TAR_BLOCK_BYTES]) -> Result<()> {
    let expected = parse_octal(&header[148..156], "archive header checksum")?;
    let actual: u64 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    ensure!(expected == actual, "archive header checksum mismatch");
    Ok(())
}

fn parse_size(field: &[u8]) -> Result<u64> {
    ensure!(
        field.first().is_some_and(|byte| byte & 0x80 == 0),
        "archive uses a non-canonical base-256 size"
    );
    parse_octal(field, "archive member size")
}

fn parse_octal(field: &[u8], label: &str) -> Result<u64> {
    let mut start = 0;
    while start < field.len() && field[start] == b' ' {
        start += 1;
    }
    let mut end = field.len();
    while end > start && matches!(field[end - 1], 0 | b' ') {
        end -= 1;
    }
    if start == end {
        return Ok(0);
    }
    ensure!(
        field[start..end]
            .iter()
            .all(|byte| (b'0'..=b'7').contains(byte)),
        format!("{label} is not canonical octal")
    );
    let digits =
        std::str::from_utf8(&field[start..end]).context(|| format!("{label} is not ASCII"))?;
    u64::from_str_radix(digits, 8).context(|| format!("{label} overflows"))
}

fn tar_path(header: &[u8; TAR_BLOCK_BYTES]) -> Result<String> {
    let name = c_string(&header[0..100], "archive path")?;
    let prefix = c_string(&header[345..500], "archive path prefix")?;
    ensure!(!name.is_empty(), "archive has an empty member path");
    if prefix.is_empty() {
        Ok(name)
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn c_string(field: &[u8], label: &str) -> Result<String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    ensure!(
        field[end..].iter().all(|byte| *byte == 0),
        format!("{label} has non-canonical bytes after NUL")
    );
    std::str::from_utf8(&field[..end])
        .map(str::to_owned)
        .context(|| format!("{label} is not valid UTF-8"))
}

fn canonical_tar_name(raw_name: &str, directory: bool) -> Result<String> {
    let name = if directory {
        raw_name.strip_suffix('/').unwrap_or(raw_name)
    } else {
        ensure!(
            !raw_name.ends_with('/'),
            "archive regular-file path has a trailing slash"
        );
        raw_name
    };
    ensure!(
        !name.is_empty() && !name.starts_with('/'),
        "archive path is not canonical"
    );
    ensure!(
        name.split('/')
            .all(|component| !component.is_empty() && component != "." && component != ".."),
        "archive path is not canonical"
    );
    ensure!(
        !directory || raw_name == name || raw_name == format!("{name}/"),
        "archive directory path is not canonical"
    );
    Ok(name.to_owned())
}

fn consume_padding(archive: &mut File, size: u64) -> Result<()> {
    let padding = (TAR_BLOCK_BYTES as u64 - size % TAR_BLOCK_BYTES as u64) % TAR_BLOCK_BYTES as u64;
    if padding == 0 {
        return Ok(());
    }
    let padding_size = usize::try_from(padding)
        .context(|| "archive padding size does not fit memory".to_owned())?;
    let mut bytes = vec![0_u8; padding_size];
    archive
        .read_exact(&mut bytes)
        .context(|| "archive member padding is truncated".to_owned())?;
    ensure!(
        bytes.iter().all(|byte| *byte == 0),
        "archive member padding is not canonical"
    );
    Ok(())
}
