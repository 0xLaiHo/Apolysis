# Apolysis Domain

Apolysis describes bounded runtime observations of Agent execution on
operator-controlled Linux systems. It reports what its supported collector
observed without treating missing evidence as proof that an action did not
occur.

## Runs and scope

**Agent Run**:
A bounded period in which an Agent and the processes it starts pursue one
declared task inside an Observation Scope.
_Avoid_: Session, job, trace

**Agent**:
The autonomous participant whose runtime activity is being observed.
_Avoid_: Model, bot, workload process

**Observation Scope**:
The runtime boundary whose activity belongs to one Agent Run.
_Avoid_: Tenant, authority scope, global host

**Runtime Identity**:
The stable identity of a process or workload boundary used to distinguish it
from reused or coincidentally matching runtime identifiers.
_Avoid_: PID, process name

## Observations

**Runtime Observation**:
A process, file, network, or credential-related operation reported within a
Collector Capability and Observation Scope.
_Avoid_: Syscall truth, proven effect, semantic event

**Operation Outcome**:
The supported status of a Runtime Observation: attempted, succeeded, failed,
denied, pending, or unknown.
_Avoid_: Tool result, verified external outcome

**Agent Observation Record**:
The aggregate account of one Agent Run, including its scope, runtime
identities, Runtime Observations, Collector Health, findings, and Observation
Gaps.
_Avoid_: Agent Execution Record, evidence plane, flat event stream

**Collector Capability**:
A versioned declaration of the runtime operations and outcomes a collector can
observe within a stated environment boundary.
_Avoid_: Complete coverage, universal syscall support

**Collector Health**:
The reported operating state of a collector during an Agent Run, including
whether it was healthy, degraded, failed, or stopped unexpectedly.
_Avoid_: Clean result, host trust

**Observation Gap**:
An explicit account of activity that may be missing, lost, truncated,
unsupported, ambiguous, or outside the Observation Scope.
_Avoid_: Warning, absence proof, successful run

## Attribution and findings

**Exact Relation**:
A relationship established by a stable runtime identity within its declared
boundary.
_Avoid_: Causal proof, certain relation

**Inferred Relation**:
A relationship supported by correlation evidence rather than a stable runtime
identity.
_Avoid_: Exact relation, causal link

**Ambiguous Relation**:
A relationship for which more than one plausible target remains.
_Avoid_: Best match, inferred relation

**Unattributed Observation**:
A Runtime Observation inside an Agent Run that cannot responsibly be assigned
to a more specific runtime identity.
_Avoid_: Unknown Agent, orphan event

**Finding**:
A reviewable condition derived from Runtime Observations and their declared
limits; it does not claim that an operation was prevented.
_Avoid_: Enforcement, policy decision, verdict
