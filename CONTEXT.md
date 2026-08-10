# Apolysis Domain

Apolysis describes bounded runtime observations of Agent execution on
operator-controlled Linux systems. It reports what its supported collector
observed without treating missing evidence as proof that an action did not
occur.

## Runs and scope

**Agent Run**:
A bounded period in which an Agent and its attributed process tree pursue one
declared task inside an Observation Scope.
_Avoid_: Session, job, trace

**Agent**:
The autonomous participant whose runtime activity is being observed.
_Avoid_: Model, bot, workload process

**Observation Scope**:
The runtime boundary whose activity belongs to one Agent Run.
_Avoid_: Tenant, authority scope, global host

**Protected Attach**:
Admission of an already-running Agent into an Observation Scope after its
currently visible root and process tree are qualified. It does not establish
selection continuity before candidates are anchored or claim earlier history.
_Avoid_: Manual attach, PID attach, complete history

**Collection Boundary**:
The point from which a Collector Capability applies to an Agent Run; activity
before it is unknown history represented by an Observation Gap.
_Avoid_: Run start, complete history, backfill

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

**Agent Observation Summary**:
A bounded derived view of one Agent Observation Record that keeps evidence
state, Collector Health, review state, and typed counts independent. Missing or
incomplete evidence is never summarized as a clean result.
_Avoid_: Run verdict, clean status, success proof

**Evidence State**:
The projection state of one Agent Observation Record: complete, active,
incomplete, failed, or indeterminate. It reports evidence boundaries, not Agent
task success.
_Avoid_: Agent success, clean verdict

**Review State**:
Whether bounded findings require review, no findings were reported over
complete evidence, or the result is indeterminate. No findings reported is not
proof that no relevant action occurred.
_Avoid_: Clean result, policy verdict, absence proof

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
