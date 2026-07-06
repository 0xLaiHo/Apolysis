# Signed Release Artifact Dry Run

Use this procedure after the repository AWS OIDC and KMS settings are
configured, but before pushing a final release tag. It proves that the Release
Artifacts workflow can build the Linux CLI, build the CO-RE BPF object, sign
the release manifest with AWS KMS, package retained signing evidence, and
upload the resulting Actions artifact bundle.

This is still a workflow-dispatch dry run. It does not create a GitHub Release
and does not upload release assets through the tag-only `gh release upload`
step.

The signed dry run is dispatched from `main`, so it proves the branch OIDC
subject only. The final `v0.2.0` tag publication uses a different GitHub OIDC
subject. Before pushing the final tag, confirm the AWS IAM role trust policy
allows `repo:0xLaiHo/Apolysis:ref:refs/tags/v0.2.0` or a bounded
`repo:0xLaiHo/Apolysis:ref:refs/tags/v*` release-tag pattern for
`sts:AssumeRoleWithWebIdentity`.

## Required Repository Settings

The GitHub repository must have these settings before the run:

- `ProductionHardening_AWS_ROLE_TO_ASSUME`: GitHub secret containing the AWS
  IAM role ARN trusted by GitHub OIDC.
- `ProductionHardening_AWS_KMS_KEY_ID`: GitHub secret containing the AWS KMS
  signing key id, alias, or ARN.
- `ProductionHardening_AWS_REGION`: GitHub variable containing the AWS region.
- `APOLYSIS_RELEASE_SIGNING_EVIDENCE_RUN_ID`: GitHub variable pointing to the
  latest retained successful signing-evidence workflow run. Update it after
  each successful signed dry run.

The KMS key must be an AWS-managed `SIGN_VERIFY` asymmetric RSA key, enabled,
with `AWS_KMS` origin, and it must support the configured release signing
algorithm.

## Run The Signed Dry Run

Choose a non-release version label:

```bash
version="v0.2.0-signed-dry-run.$(date -u +%Y%m%d%H%M%S)"
```

Start the workflow from `main` and require signing evidence:

```bash
gh workflow run release-artifacts.yml \
  --repo 0xLaiHo/Apolysis \
  --ref main \
  -f version="$version" \
  -f require_signing_evidence=true
```

Find and wait for the run:

```bash
run_id="$(gh run list \
  --repo 0xLaiHo/Apolysis \
  --workflow release-artifacts.yml \
  --branch main \
  --limit 1 \
  --json databaseId \
  --jq '.[0].databaseId')"

gh run watch "$run_id" --repo 0xLaiHo/Apolysis --exit-status
```

Download the Actions artifact bundle:

```bash
mkdir -p "target/release-signed-dry-run/$run_id"
gh run download "$run_id" \
  --repo 0xLaiHo/Apolysis \
  --name apolysis-linux-x86_64-release-artifacts \
  --dir "target/release-signed-dry-run/$run_id"
```

## Verify The Signed Bundle

Verify the detached checksum:

```bash
cd "target/release-signed-dry-run/$run_id"
sha256sum -c "apolysis-${version}-x86_64-unknown-linux-gnu.tar.gz.sha256"
```

The bundle must include:

- `apolysis-${version}-x86_64-unknown-linux-gnu.tar.gz`
- `apolysis-${version}-x86_64-unknown-linux-gnu.tar.gz.sha256`
- `apolysis-release-manifest.json`
- `apolysis-release-signing-manifest.json`
- `apolysis-release-signing-evidence.json`
- `apolysis-release-signing-report.json`
- `apolysis-regulated-release-signing-evidence-report.json`

Check the signing manifest and evidence:

```bash
jq '{release_signing_ready, provider, release_manifest_sha256}' \
  apolysis-release-signing-manifest.json

jq '{source, provider, key_uri, signature_verified, release_manifest_sha256}' \
  apolysis-release-signing-evidence.json
```

Expected signed dry-run state:

- `release_signing_ready` is `true`.
- `provider` is `cloud_kms`.
- `key_uri` starts with `awskms://`.
- `signature_verified` is `true`.
- `release_manifest_sha256` matches the SHA-256 of
  `apolysis-release-manifest.json`.

Inspect the release package:

```bash
tar -tzf "apolysis-${version}-x86_64-unknown-linux-gnu.tar.gz" | sort
```

The tarball must contain entries under a package root, including:

- `apolysis-${version}-x86_64-unknown-linux-gnu/bin/apolysis`
- `apolysis-${version}-x86_64-unknown-linux-gnu/ebpf/apolysis_observer.bpf.o`
- `apolysis-${version}-x86_64-unknown-linux-gnu/apolysis-release-manifest.json`
- `apolysis-${version}-x86_64-unknown-linux-gnu/README.md`
- `apolysis-${version}-x86_64-unknown-linux-gnu/README.zh-CN.md`
- `apolysis-${version}-x86_64-unknown-linux-gnu/docs/jsonl-schema-v1.md`

After the verification passes, update the retained evidence pointer:

```bash
gh variable set APOLYSIS_RELEASE_SIGNING_EVIDENCE_RUN_ID \
  --repo 0xLaiHo/Apolysis \
  --body "$run_id"
```

## Live Validation Evidence

On 2026-07-04, run `28694166781` passed against `main` for
`v0.2.0-signed-dry-run.20260704035609`.

Local verification confirmed:

- detached checksum verification passed;
- release signing manifest reported `release_signing_ready:true`;
- signing provider was `cloud_kms` with an `awskms://` key URI;
- signing evidence reported `signature_verified:true`;
- release signing evidence, release signing report, and regulated-release
  signing report were present in the artifact bundle;
- the tarball contained the CLI, CO-RE BPF object, release manifest, README
  files, and JSONL schema under the package root.

The repository variable `APOLYSIS_RELEASE_SIGNING_EVIDENCE_RUN_ID` was updated
to `28694166781` after this verification.

## Publishing Boundary

Passing this dry run means the signed artifact path is ready for release
candidate review. It is not the final `v0.2.0` publication by itself.

For final publication:

- follow the dedicated
  [v0.2.0 Release Publication](v0.2.0-release-publication.md) checklist;
  the checked-in path is `docs/v0.2.0-release-publication.md`;
- create a dedicated `release/<version>` branch from `main`;
- rerun release validation on the branch;
- push the final `v*` tag only after review;
- confirm the tag-triggered workflow uploads the tarball, checksum, release
  manifest, signing manifest, signing evidence, signing report, and regulated
  release signing report to the GitHub Release.
