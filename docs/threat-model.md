# Apolysis Threat Model

This page defines the narrow security model for the current Apolysis release
line. It is intentionally short so users can decide whether Apolysis fits their
environment before reading roadmap history.

## Product Boundary

Apolysis is an operator-owned runtime evidence recorder for AI agent sessions.
It observes process, file, network, credential-path, runtime metadata, policy,
and release evidence from outside the agent harness.

## Not A Sandbox

Apolysis is not a sandbox, approval UI, model gateway, identity provider, SIEM,
or central query product. Runtime isolation remains the job of Docker, gVisor,
Kata, Firecracker, Kubernetes, cloud sandboxes, host policy, and platform
configuration.

## Trust Boundaries

- Agent harness: untrusted for final audit truth.
- Agent workload: untrusted code and subprocesses.
- Apolysis userspace: trusted to normalize, redact, correlate, and persist
  records.
- Kernel observer path: trusted to provide host-side event evidence within the
  loaded probe scope.
- Runtime metadata sources: trusted only for identity correlation, not for
  proving guest semantics when strong isolation collapses host visibility.
- Operator storage: trusted to protect retained timelines, release manifests,
  checksums, and evidence packages.

## Primary Assets

- Timeline JSONL records and hash-chain continuity.
- Session identity, process-tree scope, and event-correlation IDs.
- Redaction guarantees for argv, paths, socket values, labels, annotations, and
  payloads.
- Release artifacts, manifests, checksums, and retained validation evidence.
- Operator credentials and kubeconfigs, which must never be captured or
  committed.

## In Scope Threats

- A malicious or buggy agent creates subprocesses that are not attributed to the
  session.
- PID reuse, thread fork behavior, or cgroup scope drift causes evidence from
  another workload to enter the session.
- A runtime adapter claims stronger visibility than host-side evidence can
  prove.
- Redaction misses secret-looking command, path, socket, or metadata values.
- Policy output implies pre-operation blocking when the active backend only
  supports audit or post-event action.
- Release artifacts or evidence packages are incomplete, unverifiable, or
  inconsistent with the build inputs.

## Out Of Scope

- Preventing all malicious behavior from an agent workload.
- Proving guest-level process semantics for runtimes that hide them without a
  guest collector.
- Replacing Kubernetes policy, network policy, IAM, sandbox configuration, or
  human approval workflows.
- Centralized long-term log search and alerting; users should ship JSONL to
  their existing log stack.

## Default Controls

- Prefer Apolysis-managed agent launch over manual PID selection.
- Fail closed when registration or discovery cannot disambiguate an agent.
- Keep schema changes append-only within a version.
- Persist redaction and truncation markers explicitly.
- Keep privileged live gates opt-in and document their host assumptions.
