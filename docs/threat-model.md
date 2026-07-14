# Apolysis Threat Model

This page defines the narrow security model for the current Apolysis release
line. It is intentionally short so users can decide whether Apolysis fits their
environment before reading roadmap history.

## Product Boundary

Apolysis is an operator-owned runtime evidence recorder for AI agent sessions.
It observes process, file, network, credential-path, runtime metadata, policy,
and release evidence from outside the agent harness.

The W1–W2 contracts additionally specify a future authenticated write Gateway,
versioned projection plane, organization-scoped Query API, and Web Console.
Those components are target boundaries, not capabilities of the current
release. Their requirements below must be implemented and validated before the
central-plane claim is made.

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

### W1–W2 target trust boundaries

- Source principal: transport-authenticated and bound to one organization,
  source registration, capability, and allowed operation; source payload fields
  are not authority.
- Execution Evidence Gateway: trusted to authorize sources, enforce privacy and
  idempotency, assign durable ingest order, and preserve gaps; it is not a read
  plane.
- Projection workers: trusted to derive versioned views without upgrading source
  trust, filling gaps, or erasing ambiguity.
- Query API: trusted to enforce organization and role authorization for every
  view, cursor, object reference, stream, and export.
- Web Console: untrusted for product verdicts and unable to access privileged
  collectors, Gateway credentials, storage credentials, or internal tables.
- Provider-controlled host: opaque unless the provider exposes a documented,
  capability-scoped source; provider claims are not customer-observed kernel
  evidence.

## Primary Assets

- Timeline JSONL records and hash-chain continuity.
- Session identity, process-tree scope, and event-correlation IDs.
- Redaction guarantees for argv, paths, socket values, labels, annotations, and
  payloads.
- Release artifacts, manifests, checksums, and retained validation evidence.
- Operator credentials and kubeconfigs, which must never be captured or
  committed.

W1–W2 target assets additionally include source registrations, run/join leases,
organization bindings, accepted source envelopes, deduplication and gap state,
versioned projections, Query cursors, object grants, live-stream positions, and
deletion tombstones. These are design assets until their components exist.

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

### W1–W2 target threats

- **Hook spoofing:** a compromised agent or workspace emits fabricated lifecycle,
  tool, approval, or outcome records using a hook's name.
- **Remote-ingest spoofing:** a caller supplies another organization, source,
  provider, or run identifier in an otherwise valid request.
- **Cross-run confusion:** reused process, trace, repository, Pod, container,
  cgroup, or provider identifiers attach evidence to the wrong Agent Run.
- **Source replay and equivocation:** a source repeats an event, resets sequence,
  fills one event identity with different content, or hides a sequence gap.
- **Compromised source:** a validly authenticated agent or source lies, omits
  terminal records, disables redaction, or attempts to broaden its capability.
- **Clock manipulation:** source timestamps reorder the display or imply a causal
  relationship that durable source identity does not support.
- **False clean projection:** sampling, truncation, loss, expired leases, stale
  projections, or opaque provider hosts are rendered as complete or successful.
- **Cross-organization read:** a run identifier, cursor, stream reconnect token,
  object reference, cache key, or export leaks another organization's data.
- **Deletion residue:** revoked or deleted content remains reachable through a
  projection, search index, cache, live stream, object grant, or export.
- **Privilege inversion:** a browser reaches the write Gateway, privileged
  daemon, Runtime Witness, host socket, host path, database, or object
  credential.
- **Untrusted rendering:** prompt, tool, path, repository, provider, or Finding
  text causes script execution, unsafe links, or misleading visual semantics in
  the Console.

## Out Of Scope

- Preventing all malicious behavior from an agent workload.
- Proving guest-level process semantics for runtimes that hide them without a
  guest collector.
- Replacing Kubernetes policy, network policy, IAM, sandbox configuration, or
  human approval workflows.
- Centralized long-term log search and alerting; users should ship JSONL to
  their existing log stack.

The current release remains outside centralized long-term search. Bounded,
organization-scoped run queries and the Minimum Console described in the W1–W2
target contract are not excluded from the production MVP.

## Default Controls

- Prefer Apolysis-managed agent launch over manual PID selection.
- Fail closed when registration or discovery cannot disambiguate an agent.
- Keep schema changes append-only within a version.
- Persist redaction and truncation markers explicitly.
- Keep privileged live gates opt-in and document their host assumptions.
- Keep the pre-release GitHub Action candidate's executable, BPF object, and
  privileged output outside workspace control. Pin the release bundle with an
  Action-embedded digest, reject already-root and primary-GID-0 runners, disable archive ownership
  restoration, stage privileged inputs, the managed command, and output in
  root-owned directories, suppress inherited shell/function/loader startup,
  invoke the observer without a root shell, launch managed work with
  `no_new_privs` and cleared supplementary groups, export only an expected
  root-sealed regular evidence file, and never rely on same-UID workflow command
  files for privileged paths or command success. Pin the artifact uploader to a
  reviewed full commit and fail if the verified file is absent.
- Treat the candidate's pinned v0.3.0 executable as an explicit privacy
  exception. Staging removes the top-level `run` text from launch metadata, but
  v0.3.0 may persist child exec arguments and reconstructed process-command
  content. Do not publish an immutable hardened
  Action ref until a post-content-off bundle is pinned and the live privacy gate
  passes.
- Treat ephemeral trusted workflow definitions as a separate prerequisite.
  Rejecting privileged path overrides does not make secret-bearing untrusted
  Pull Requests, `pull_request_target`, or arbitrary self-hosted runners safe.
  The wrapper blocks direct setuid privilege regain, but same-UID workspace,
  step-script, command-file, cached-action, and uploader state remains outside
  its integrity claim. Detached children remain a runner-isolation concern even
  though a non-sudo child cannot directly write the sealed local artifact.

## Required W1–W2 Target Controls

- Derive organization and source authorization from the authenticated transport
  principal; reject request-supplied authority and cross-organization probes
  without disclosing resource existence.
- Separate create from join when opening a run. Each joining semantic, runtime,
  provider, or outcome source receives its own scoped lease, stream, sequence,
  capability, and trust profile.
- Deduplicate by scoped event identity and canonical digest. Preserve source
  sequence, durable ingest sequence, clock uncertainty, replay conflicts, and
  gap history independently.
- Keep exact, inferred, ambiguous, and unattributed relations distinct through
  storage, projection, display, and export.
- Derive coverage and outcomes on the server. Semantic partial, opaque, and
  unavailable; execution partial, opaque, and incomplete; outcome unconfirmed
  and unknown; comparison mismatch and unresolved; and all lost or stale states
  never render as success or “no findings.”
- Disable prompt, response, raw payload, raw argv, and raw object collection by
  default. Reject or redact content outside the registered privacy policy before
  durable acceptance.
- Route fixture, standalone live, and daemon observer output through the same
  content-off persistence seam. Persist only executable references and explicit
  argv/truncation markers; never persist reconstructed process commands or
  managed-agent command fingerprints by default.
- Authorize object access independently from possession of a reference. Audit
  raw reads, exports, retention changes, and Finding workflow actions.
- Propagate revocation, redaction, and deletion through write records,
  projections, indexes, caches, streams, grants, objects, and exports; deny
  reads while propagation is uncertain.
- Serve the Console only through a non-privileged Query API with bounded
  pagination and resumable, reauthorized streams. The browser never connects to
  the Gateway or privileged collector.
- Treat all rendered source text as untrusted; enforce safe text rendering,
  restrictive content security policy, same-origin or allowlisted cross-origin
  policy, and non-color-only status semantics.

The normative details are in [`docs/contracts/`](contracts/README.md).
