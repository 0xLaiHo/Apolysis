// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("release artifact verification: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> apolysis_release_verifier::Result<()> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let output_dir = arguments.next().map(PathBuf::from).ok_or_else(|| {
        apolysis_release_verifier::VerifierError::new(
            "usage: apolysis-release-verifier <output-dir> <verification-dir>",
        )
    })?;
    let verification_dir = arguments.next().map(PathBuf::from).ok_or_else(|| {
        apolysis_release_verifier::VerifierError::new(
            "usage: apolysis-release-verifier <output-dir> <verification-dir>",
        )
    })?;
    if arguments.next().is_some() {
        return Err(apolysis_release_verifier::VerifierError::new(
            "usage: apolysis-release-verifier <output-dir> <verification-dir>",
        ));
    }

    apolysis_release_verifier::verify_release(&output_dir, &verification_dir)
}
