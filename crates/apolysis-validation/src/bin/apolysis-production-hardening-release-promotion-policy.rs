// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use apolysis_validation::{
    evaluate_production_hardening_release_promotion_policy,
    ProductionHardeningReleasePromotionPolicyEvidence, ProductionHardeningReleasePromotionRequest,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Eq, PartialEq)]
struct CliArgs {
    release_manifest: PathBuf,
    registry_attachment: PathBuf,
    archive_manifest: PathBuf,
    request: PathBuf,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis-production-hardening-release-promotion-policy: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let args = parse_args(args)?;
    let release_manifest_bytes = fs::read(&args.release_manifest).map_err(|error| {
        format!(
            "failed to read release manifest {}: {error}",
            args.release_manifest.display()
        )
    })?;
    let registry_attachment_bytes = fs::read(&args.registry_attachment).map_err(|error| {
        format!(
            "failed to read registry attachment {}: {error}",
            args.registry_attachment.display()
        )
    })?;
    let archive_manifest_bytes = fs::read(&args.archive_manifest).map_err(|error| {
        format!(
            "failed to read archive manifest {}: {error}",
            args.archive_manifest.display()
        )
    })?;
    let request_bytes = fs::read(&args.request).map_err(|error| {
        format!(
            "failed to read promotion request {}: {error}",
            args.request.display()
        )
    })?;

    let request: ProductionHardeningReleasePromotionRequest = parse_json(
        &request_bytes,
        &format!("promotion request {}", args.request.display()),
    )?;
    let evidence = ProductionHardeningReleasePromotionPolicyEvidence {
        release_manifest_sha256: sha256_hex(&release_manifest_bytes),
        registry_attachment_sha256: sha256_hex(&registry_attachment_bytes),
        release_manifest: parse_json(
            &release_manifest_bytes,
            &format!("release manifest {}", args.release_manifest.display()),
        )?,
        registry_attachment: parse_json(
            &registry_attachment_bytes,
            &format!("registry attachment {}", args.registry_attachment.display()),
        )?,
        archive_manifest: parse_json(
            &archive_manifest_bytes,
            &format!("archive manifest {}", args.archive_manifest.display()),
        )?,
    };

    let report = evaluate_production_hardening_release_promotion_policy(request, evidence);
    let output = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("failed to serialize promotion policy report: {error}"))?;
    println!("{output}");
    if report.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn parse_args(args: Vec<String>) -> Result<CliArgs, String> {
    let mut release_manifest = None;
    let mut registry_attachment = None;
    let mut archive_manifest = None;
    let mut request = None;
    let mut iter = args.into_iter();
    while let Some(flag) = iter.next() {
        let value = iter
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--release-manifest" => release_manifest = Some(PathBuf::from(value)),
            "--registry-attachment" => registry_attachment = Some(PathBuf::from(value)),
            "--archive-manifest" => archive_manifest = Some(PathBuf::from(value)),
            "--request" => request = Some(PathBuf::from(value)),
            _ => return Err(format!("unknown argument: {flag}")),
        }
    }
    Ok(CliArgs {
        release_manifest: release_manifest.ok_or_else(usage)?,
        registry_attachment: registry_attachment.ok_or_else(usage)?,
        archive_manifest: archive_manifest.ok_or_else(usage)?,
        request: request.ok_or_else(usage)?,
    })
}

fn usage() -> String {
    "usage: apolysis-production-hardening-release-promotion-policy --release-manifest <path> --registry-attachment <path> --archive-manifest <path> --request <path>".to_string()
}

fn parse_json<T: serde::de::DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("failed to parse {label}: {error}"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .as_slice()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
