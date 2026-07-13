# W1–W2 Scope and Environment Profiles

Status: frozen product scope for W1–W2. An authenticated Gateway application
core and non-durable memory conformance adapter are now implementation inputs;
they do not imply that the target production Gateway, durable storage, Query,
or Console runtime capabilities are implemented.

## Primary user and decision

The primary operator is an AppSec, AI-platform, developer-platform, or
runtime-security team responsible for agents in at least two supported
environment profiles. The first product decision is whether a run, action,
change, investigation, review, or release may proceed given its authority,
evidence, coverage, and verified outcome.

Apolysis is useful only when it reduces investigation uncertainty or changes a
real review or policy decision. More telemetry alone is not the product gate.

## Five environment profiles

Machine contracts use these exact profile values:

| Profile | Contract value |
| --- | --- |
| Local CLI or IDE | `local_cli_or_ide` |
| CI runner or remote development workspace | `ci_runner_or_remote_workspace` |
| Vendor-hosted coding-agent sandbox | `vendor_hosted_coding_sandbox` |
| Customer-built agent service | `customer_built_agent_service` |
| Fully managed agent runtime | `fully_managed_agent_runtime` |

### 1. Local CLI or IDE

- **Deployment:** agent hook, wrapper, or local MCP integration; optional eBPF
  Runtime Witness on supported Linux or WSL hosts.
- **Identity:** authenticated local principal plus propagated run, agent, turn,
  and tool-call identifiers when the integration exposes them.
- **Trust:** hooks provide semantic claims; the Runtime Witness independently
  reports only operations visible at its host boundary; Git and test read-back
  provide outcome evidence.
- **Unsupported claim:** non-Linux execution is not host-verified, and unmanaged
  processes are not silently attributed to a run.

### 2. CI runner or remote development workspace

- **Deployment:** workflow hooks and artifacts on every runner; optional Runtime
  Witness only on customer-controlled supported Linux workers.
- **Identity:** organization, repository, workflow, job, runner, commit, Pull
  Request, and workload identity bound to the run when available.
- **Trust:** workflow and hook records are semantic/provider evidence; commits,
  checks, and artifacts are outcome evidence; host evidence is available only
  where the customer controls the worker.
- **Unsupported claim:** hosted-runner internals are opaque unless the provider
  supplies an explicit capability; a successful job is not proof of every
  claimed effect.

### 3. Vendor-hosted coding-agent sandbox

- **Deployment:** provider hook or API, session record, GitHub integration, and
  outcome read-back; no customer kernel component.
- **Identity:** provider organization, actor, session, repository, branch,
  commit, Pull Request, and check identifiers.
- **Trust:** provider data is retained as provider-attested semantic or outcome
  evidence, never upgraded to customer-observed execution evidence.
- **Unsupported claim:** Apolysis cannot claim complete process, file, or network
  execution visibility inside a vendor-controlled sandbox.

### 4. Customer-built agent service

- **Deployment:** SDK processor or versioned OTLP input, MCP/A2A identity, and
  optional Runtime Witness on a controlled VM, container host, or Kubernetes
  node.
- **Identity:** workload principal, service, deployment, trace, span, agent,
  delegation, MCP call, A2A task, and runtime identifiers.
- **Trust:** SDK and protocol inputs describe logical activity; runtime inputs
  describe only visible operations; application, Git, Kubernetes, or provider
  read-back independently checks outcomes.
- **Unsupported claim:** sampled traces and host-only views do not prove complete
  guest semantics or remote mutations.

### 5. Fully managed agent runtime

- **Deployment:** provider SDK/OTel integration, audit API, workload identity,
  and external outcome verification; no assumed kernel access.
- **Identity:** provider organization, workload, session/run, trace, agent, tool,
  resource, and audit identifiers when exposed.
- **Trust:** evidence is provider-attested and capability-scoped. Independent
  read-back is required before a claimed remote mutation is verified.
- **Unsupported claim:** provider evidence is not a kernel-complete or
  customer-host-observed account of execution.

## First integration sequence

The first integrations are intentionally bounded:

1. migrate the existing Codex path to the shared source and run contracts;
2. add Claude Code and GitHub Copilot lifecycle hooks plus GitHub outcome
   context;
3. provide an OpenAI Agents SDK processor and versioned OTLP input for
   customer-built services;
4. observe MCP stdio and Streamable HTTP through an evidence tap or a narrowly
   scoped policy adapter;
5. ingest A2A task, context, identity, and delegation lifecycle without becoming
   a general A2A gateway;
6. bind Kubernetes workload, audit, and read-back evidence where the customer
   controls the cluster.

AgentSight- and ActPlane-specific adapters are deferred until the preceding
paths show repeat usage.

## Explicit non-goals

Apolysis is not:

- an agent orchestrator, model router, general tool gateway, or MCP/A2A broker;
- a sandbox, IAM provider, Kubernetes admission controller, or replacement for
  runtime isolation;
- a kernel enforcement engine or a promise to block arbitrary post-event
  evidence;
- a SIEM, fleet-wide evidence custody product, or general-purpose tracing
  backend in the production MVP;
- a source of synthetic causality, global completeness, or success inferred
  from missing evidence;
- a store for prompt, response, raw payload, or raw argv content by default.

Policy is bounded to deterministic decisions at integrations that can confirm
actuation, such as synchronous pre-tool hooks or inline MCP policy adapters.
Post-tool, provider, OTLP, and eBPF evidence may create findings but cannot be
marketed as pre-operation blocking.

## W1–W2 exit boundary

The scope is ready for implementation only when schemas and fixtures cover the
record, lifecycle, coverage, authorization, gap, attribution, redaction, and
unknown-outcome cases; three qualified design partners have actually approved
their own deployment and data boundaries; and the approval record contains
named evidence rather than placeholders. Contract documents alone do not close
the partner gate.
