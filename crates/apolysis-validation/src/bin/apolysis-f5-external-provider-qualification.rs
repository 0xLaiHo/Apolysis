// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Component, Path, PathBuf};

use apolysis_validation::{
    evaluate_f5_external_provider_qualification_bundle, F5ExternalProviderQualificationBundle,
    F5ExternalProviderQualificationFailure,
};
use sha2::{Digest, Sha256};

#[derive(Debug, Eq, PartialEq)]
struct CliArgs {
    bundle: PathBuf,
    bundle_root: Option<PathBuf>,
}

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("apolysis-f5-external-provider-qualification: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    let args = parse_args(args)?;
    let bundle_json = fs::read_to_string(&args.bundle).map_err(|error| {
        format!(
            "failed to read external provider qualification bundle {}: {error}",
            args.bundle.display()
        )
    })?;
    let bundle: F5ExternalProviderQualificationBundle = serde_json::from_str(&bundle_json)
        .map_err(|error| {
            format!("failed to parse external provider qualification bundle JSON: {error}")
        })?;
    let mut report = evaluate_f5_external_provider_qualification_bundle(bundle.clone());
    if let Some(root) = args.bundle_root {
        let artifact_failures = verify_retained_artifacts(&bundle, &root);
        if !artifact_failures.is_empty() {
            report.approval = None;
            report.failures.extend(artifact_failures);
            report.passed = false;
        }
    }
    let output = serde_json::to_string_pretty(&report).map_err(|error| {
        format!("failed to serialize external provider qualification report: {error}")
    })?;
    println!("{output}");
    if report.passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn parse_args(args: Vec<String>) -> Result<CliArgs, String> {
    let mut bundle = None;
    let mut bundle_root = None;
    let mut index = 0;
    while index < args.len() {
        let flag = &args[index];
        let Some(value) = args.get(index + 1) else {
            return Err(usage());
        };
        match flag.as_str() {
            "--bundle" => bundle = Some(PathBuf::from(value)),
            "--bundle-root" => bundle_root = Some(PathBuf::from(value)),
            _ => return Err(usage()),
        }
        index += 2;
    }
    Ok(CliArgs {
        bundle: bundle.ok_or_else(usage)?,
        bundle_root,
    })
}

fn usage() -> String {
    "usage: apolysis-f5-external-provider-qualification --bundle <path> [--bundle-root <path>]"
        .to_string()
}

fn verify_retained_artifacts(
    bundle: &F5ExternalProviderQualificationBundle,
    root: &Path,
) -> Vec<F5ExternalProviderQualificationFailure> {
    let mut failures = Vec::new();
    let Ok(canonical_root) = fs::canonicalize(root) else {
        failures.push(F5ExternalProviderQualificationFailure {
            field: "bundle_root".to_string(),
            message: "bundle root must exist before retained artifact verification".to_string(),
        });
        return failures;
    };
    for entry in &bundle.entries {
        verify_retained_artifact(
            &mut failures,
            &canonical_root,
            "evidence_ref",
            "retained evidence artifact",
            &entry.evidence_ref,
            &entry.evidence_sha256,
        );
        verify_retained_artifact(
            &mut failures,
            &canonical_root,
            "report_ref",
            "retained report artifact",
            &entry.report_ref,
            &entry.report_sha256,
        );
    }
    failures
}

fn verify_retained_artifact(
    failures: &mut Vec<F5ExternalProviderQualificationFailure>,
    root: &Path,
    field: &str,
    label: &str,
    reference: &str,
    expected_sha256: &str,
) {
    let reference_path = Path::new(reference);
    if reference.trim().is_empty()
        || reference_path.is_absolute()
        || reference_path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::Prefix(_) | Component::RootDir
            )
        })
    {
        failures.push(F5ExternalProviderQualificationFailure {
            field: field.to_string(),
            message: format!("{label} reference must be a bounded relative path"),
        });
        return;
    }

    let path = root.join(reference_path);
    let Ok(canonical_path) = fs::canonicalize(&path) else {
        failures.push(F5ExternalProviderQualificationFailure {
            field: field.to_string(),
            message: format!("{label} must exist under bundle root"),
        });
        return;
    };
    if !canonical_path.starts_with(root) {
        failures.push(F5ExternalProviderQualificationFailure {
            field: field.to_string(),
            message: format!("{label} reference must stay under bundle root"),
        });
        return;
    }
    let Ok(bytes) = fs::read(&canonical_path) else {
        failures.push(F5ExternalProviderQualificationFailure {
            field: field.to_string(),
            message: format!("{label} must be readable under bundle root"),
        });
        return;
    };

    let expected = expected_sha256.strip_prefix("sha256:").unwrap_or_default();
    let actual = sha256_hex(&bytes);
    if expected != actual {
        failures.push(F5ExternalProviderQualificationFailure {
            field: format!("{field}_sha256"),
            message: format!("{label} sha256 does not match"),
        });
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
