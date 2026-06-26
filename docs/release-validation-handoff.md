# Release Validation Handoff

This handoff describes how to reproduce the regulated-release validation flow
without committing provider credentials or generated evidence.

## Scope

The regulated-release validation flow checks four external-provider controls:

- AWS KMS or external HSM signing evidence.
- Cloud WORM/object-lock archive evidence.
- Immutable registry promotion and readback evidence.
- Managed service-mesh evidence.

Generated evidence belongs under `target/` and must not be committed. Provider
credentials, kubeconfigs, signing material, tokens, and captured private
workload data must stay outside the repository.

## Reproducible Evidence Packages

`scripts/test-regulated-release-evidence-package.sh` supports fixed timestamps
for reproducible package archives:

```bash
APOLYSIS_REGULATED_RELEASE_EVIDENCE_PACKAGE_TIMESTAMP_UNIX_MS=1782399000000 \
APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT=<provider-root> \
APOLYSIS_REQUIRE_REGULATED_RELEASE_EVIDENCE_PACKAGE=1 \
  ./scripts/test-regulated-release-evidence-package.sh
```

`SOURCE_DATE_EPOCH` is also honored when the explicit millisecond timestamp is
not set. The timestamp is passed to the downstream final external-provider
bundle builder and is used for tar/gzip metadata normalization.

## Required Aggregate

For required-mode validation, provide retained provider artifacts and readback
metadata explicitly:

```bash
APOLYSIS_REQUIRE_REGULATED_RELEASE=1 \
APOLYSIS_RUN_REGULATED_RELEASE_FINAL_PROVIDER_CLOSURE=1 \
APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_SOURCE=local_artifact_root \
APOLYSIS_REGULATED_RELEASE_PROVIDER_ARTIFACT_ROOT=<provider-root> \
APOLYSIS_REGULATED_RELEASE_RETAINED_EVIDENCE_PACKAGE_ROOT=<retention-root> \
APOLYSIS_REGULATED_RELEASE_EXTERNAL_RETENTION_READBACK_EVIDENCE=<external-readback.json> \
APOLYSIS_REGULATED_RELEASE_IMMUTABLE_REGISTRY_READBACK_EVIDENCE=<registry-readback.json> \
APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_APPROVER=<approver> \
APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_DECISION=approve_regulated_release \
APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_APPROVED_AT=<timestamp> \
APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_RATIONALE=<rationale> \
APOLYSIS_REGULATED_RELEASE_FINAL_SIGNOFF_NO_SECRET_MATERIAL_RECORDED=1 \
  ./scripts/test-regulated-release.sh
```

The final report must show:

- `passed: true`
- `regulated_release_ready: true`
- `pre_signoff_regulated_release_ready: true`
- `final_release_signoff_ready: true`
- `missing_requirements: []`

## Provider Artifact Naming

The final provider bundle environment gate discovers registry artifacts by
filename patterns. If a provider root uses generic registry names, include
compatibility copies such as:

```text
dockerhub-registry-promotion-evidence.json
dockerhub-registry-promotion-report.json
```

The compatibility files should copy the same evidence content; do not rewrite
or invent provider results.

## Privacy Checklist

Before committing or publishing handoff material:

- Confirm `target/` artifacts are ignored.
- Run a repository secret-pattern scan outside `target/`.
- Confirm final aggregate `secret_scan_findings` arrays are empty.
- Do not print or commit kubeconfig, cloud credentials, Docker tokens, or R2
  temporary credentials.
