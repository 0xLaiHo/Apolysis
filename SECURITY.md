# Security Policy

Apolysis records evidence. It does not make an unsafe runtime safe by itself,
and it should not be treated as a replacement for Docker, gVisor, Kata,
Firecracker, Kubernetes, an MCP gateway, or an approval system.

## Supported Versions

Security reports are accepted for the current `main` branch and the latest
published release line. Older development branches are not supported unless a
maintainer explicitly marks them as active.

## Reporting A Vulnerability

Use GitHub's private vulnerability reporting when available. If private
reporting is unavailable, open a minimal public issue that says a vulnerability
report exists, but do not include exploit details or sensitive logs in the
issue.

Please include:

- Affected commit, release, or deployment path.
- Whether the issue requires live eBPF, Kubernetes, Docker, signing, release
  artifacts, or provider credentials.
- Reproduction steps using fixtures whenever possible.
- Expected impact on confidentiality, integrity, availability, or audit
  accuracy.

## Do Not Include Secrets

Do not include secrets, API keys, kubeconfigs, provider credentials, signing
material, private timeline captures, or raw workload data in a report. Redact
paths, argv, socket values, labels, annotations, and payloads when they may
identify a private environment.

## Scope

In-scope examples:

- Incorrect runtime evidence attribution.
- PID reuse, process-tree, or cgroup scoping failures that mix unrelated
  workload evidence into a session.
- Redaction failures that persist secret-looking argv, path, socket, payload,
  label, annotation, or credential material.
- Release artifact, manifest, checksum, signing, or retention bugs that could
  misrepresent what was built or retained.
- Policy feedback or enforcement metadata that overstates blocking guarantees.

Out-of-scope examples:

- Requests to make Apolysis a full sandbox provider.
- Vulnerabilities in a user's agent harness, model provider, cloud account, or
  container runtime unless Apolysis materially worsens the result.
- Reports that require committing private captures or credentials.

Maintainers will acknowledge valid private reports, triage severity, and track
fixes through a focused branch and pull request when code or documentation must
change.
