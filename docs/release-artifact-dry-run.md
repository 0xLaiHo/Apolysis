# Release Artifact Dry Run

Use this procedure before publishing a demo or a new public release. It proves
that the GitHub Actions release path can build the Linux CLI, the CO-RE BPF
object, the release manifest, and the checksum bundle from the current `main`
branch without creating or mutating a published GitHub Release.

This is a workflow-dispatch dry run. It uploads an Actions artifact bundle only.
A tag push is the path that creates or updates a GitHub Release and runs
`gh release upload`.

## Run The Dry Run

Choose a non-release version label that cannot be confused with a published tag:

```bash
version="v0.2.0-dry-run.$(date +%Y%m%d%H%M%S)"
```

Start the workflow:

```bash
gh workflow run release-artifacts.yml \
  --ref main \
  -f version="$version" \
  -f require_signing_evidence=false
```

Find the run and wait for it:

```bash
run_id="$(gh run list \
  --workflow release-artifacts.yml \
  --branch main \
  --limit 1 \
  --json databaseId \
  --jq '.[0].databaseId')"

gh run watch "$run_id" --exit-status
```

Download the artifact bundle:

```bash
mkdir -p target/release-artifact-dry-run
gh run download "$run_id" \
  --name apolysis-linux-x86_64-release-artifacts \
  --dir target/release-artifact-dry-run
```

## Verify The Bundle

The dry run should produce these files:

- `apolysis-${version}-x86_64-unknown-linux-gnu.tar.gz`
- `apolysis-${version}-x86_64-unknown-linux-gnu.tar.gz.sha256`
- `apolysis-release-manifest.json`
- `apolysis-release-signing-manifest.json`

Verify the detached checksum:

```bash
cd target/release-artifact-dry-run
sha256sum -c "apolysis-${version}-x86_64-unknown-linux-gnu.tar.gz.sha256"
```

Inspect the signing manifest:

```bash
jq '{release_signing_ready, fail_closed_required, missing_requirements}' \
  apolysis-release-signing-manifest.json
```

For this dry run, `release_signing_ready:false` is expected because
`require_signing_evidence=false` and no retained signing evidence is attached.
This proves the unsigned path is explicit. A release candidate or tag release
that is meant to be trusted should attach retained signing evidence and should
not ship with `release_signing_ready:false`.

Inspect package contents:

```bash
tar -tzf "apolysis-${version}-x86_64-unknown-linux-gnu.tar.gz" | sort
```

The tarball must contain:

- `bin/apolysis`
- `ebpf/apolysis_observer.bpf.o`
- `apolysis-release-manifest.json`
- `README.md`
- `README.zh-CN.md`
- `docs/jsonl-schema-v1.md`

## Publishing Boundary

This dry run is not a published GitHub Release and should not be promoted as a
user-facing release artifact. It validates that the artifact build is healthy
before P1 demo recording and before a real release branch or tag.

For a real release:

- use a dedicated `release/<version>` branch from `main`;
- attach retained signing evidence when `require_signing_evidence=true`;
- before pushing the final tag, set
  `APOLYSIS_RELEASE_SIGNING_EVIDENCE_RUN_ID` to the GitHub Actions run id that
  contains the retained release-signing evidence artifacts;
- push the final `v*` tag only after release validation and review;
- verify the GitHub Release contains the tarball, checksum, release manifest,
  signing manifest, and retained signing evidence artifacts.
