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

## Operator Preflight

Run the no-secret handoff check before collecting or replaying provider
evidence:

```bash
make test-release-validation-handoff
```

Run the repo-local CI contract check before changing the release-validation
GitHub Actions workflow:

```bash
make test-release-validation-ci
```

Run the release-validation preflight gate before publishing or transferring a
retained evidence set. Required mode fails closed unless every retained input,
live-provider readback, final sign-off field, and secret-scan expectation is
present:

```bash
make test-release-validation-preflight
```

For an operator evidence set, pass the retained artifact paths explicitly:

```bash
APOLYSIS_REQUIRE_RELEASE_VALIDATION_PREFLIGHT=1 \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_PROVIDER_ROOT=<provider-root> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_AGGREGATE_REPORT=<aggregate-report.json> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_EXTERNAL_RETENTION_READBACK_EVIDENCE=<external-readback.json> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_IMMUTABLE_REGISTRY_READBACK_EVIDENCE=<registry-readback.json> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_FINAL_SIGNOFF=<final-signoff.json> \
APOLYSIS_RELEASE_VALIDATION_PREFLIGHT_INDEX=<output-dir>/apolysis-release-validation-evidence-index.json \
  ./scripts/release-validation-preflight.sh
```

The preflight writes `apolysis-release-validation-preflight-report.json` and an
evidence index with each retained artifact path, kind, size, and SHA-256 digest.
Both outputs belong under ignored `target/` paths or another explicit external
handoff location.

For live Kubernetes provider validation, use the user's default Vultr VKE test
cluster by passing the kubeconfig path by reference:

```bash
KUBECONFIG=/home/mactavish/vultr-k8s/vke-a88389c3-f720-412d-9579-c83d3c21eabb.yaml \
APOLYSIS_CONFIRM_PRODUCTION_HARDENING_VKE_CLUSTER_READINESS=1 \
  ./scripts/test-production-hardening-vke-cluster-readiness.sh

KUBECONFIG=/home/mactavish/vultr-k8s/vke-a88389c3-f720-412d-9579-c83d3c21eabb.yaml \
APOLYSIS_CONFIRM_PRODUCTION_HARDENING_VKE_SERVICE_MESH_PROVIDER=1 \
  ./scripts/test-production-hardening-vke-service-mesh-provider.sh
```

Do not copy this kubeconfig into the repository, print its contents, or commit
credentials derived from it.

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

The downstream bundle builder also accepts
`APOLYSIS_PRODUCTION_HARDENING_FINAL_EXTERNAL_BUNDLE_TIMESTAMP_UNIX_MS`. The
evidence-package gate passes the fixed timestamp through so both layers use the
same reproducible archive time.

## Required Inputs

The required aggregate consumes retained provider artifacts. A release operator
must prepare these inputs outside the source tree or under ignored `target/`
paths:

- Signing evidence and report from AWS KMS or external HSM validation.
- Retained provider artifact root containing signing, WORM/object-lock archive,
  immutable registry, and managed service-mesh evidence.
- Retained evidence package root for the generated archive and package report.
- External retention readback evidence proving object-lock/WORM provider state.
- Immutable registry readback evidence proving digest-pinned promotion and
  mutation/delete denial.
- Final sign-off fields: approver, approval timestamp, rationale,
  `approve_regulated_release` decision, and no-secret assertion.
- Release-validation preflight report plus evidence index for the retained
  artifact set when handing the evidence to another operator or release system.

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

## Cleanup and Retention Checks

After live provider validation:

- Confirm temporary Kubernetes validation namespaces are gone:
  `istio-system` and any `apolysis-production-hardening-*` namespace must not
  remain unless an operator intentionally retained them for debugging.
- Confirm provider evidence remains in ignored `target/` directories or another
  explicit external retention location.
- Confirm the final aggregate report has `missing_requirements: []` and empty
  `secret_scan_findings` arrays.
- Confirm the release-validation preflight report has
  `release_validation_preflight_ready: true`, `missing_requirements: []`, and
  points to the generated evidence index.
- Confirm generated tarballs can be reproduced when a fixed timestamp is used.
- Confirm no kubeconfig, cloud credentials, Docker tokens, R2 credentials,
  signing private keys, or captured private workload data appear in the Git
  diff.

## Privacy Checklist

Before committing or publishing handoff material:

- Confirm `target/` artifacts are ignored.
- Run a repository secret-pattern scan outside `target/`.
- Confirm final aggregate `secret_scan_findings` arrays are empty.
- Confirm the preflight evidence index `secret_scan_findings` array is empty.
- Do not print or commit kubeconfig, cloud credentials, Docker tokens, or R2
  temporary credentials.
