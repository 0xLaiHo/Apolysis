# Apolysis Domain

Apolysis describes the evidence, coverage, and accountability of an agent run
without treating an agent's own report as final truth.

## Runs and actors

**Agent Run**:
A bounded period in which one authority permits an agent and its delegates to
pursue a declared objective in one or more execution environments.
_Avoid_: Session, job, trace

**Agent Execution Record**:
The aggregate account of an Agent Run, including its actors, actions, evidence,
coverage, outcomes, findings, and unresolved gaps.
_Avoid_: Flat event, receipt, timeline

**Authority**:
The person, service, or policy boundary that permits an Agent Run or action.
_Avoid_: Owner, initiator

**Principal**:
An authenticated human or workload identity that acts within an Authority's
scope.
_Avoid_: User, account

**Agent**:
The primary autonomous participant responsible for pursuing an Agent Run's
objective.
_Avoid_: Model, bot, process

**Delegate**:
An agent or remote actor to which another Agent delegates part of its work.
_Avoid_: Child process, helper

**Tool Call**:
A declared request by an Agent or Delegate to a named tool or protocol endpoint.
_Avoid_: Command, effect

## Evidence and outcomes

**Evidence Source**:
A producer that contributes evidence under a declared identity, capability, and
trust boundary.
_Avoid_: Sensor, logger

**Semantic Evidence**:
Evidence about declared agent, delegation, approval, tool, or protocol activity.
_Avoid_: Intent log, agent truth

**Execution Evidence**:
Evidence about operations observed at a controlled runtime boundary.
_Avoid_: Syscall truth, complete execution

**Outcome Evidence**:
Evidence that independently checks whether a claimed external result exists.
_Avoid_: Tool response, success message

**Observed Effect**:
An operation or state transition reported by an Evidence Source, within that
source's capability and trust boundary.
_Avoid_: Proven outcome, side effect

**Claimed Outcome**:
A result reported by an Agent, tool, protocol, or provider but not necessarily
independently checked.
_Avoid_: Verified result, success

**Verified Outcome**:
A Claimed Outcome that an appropriate independent source has confirmed.
_Avoid_: Tool success, observed call

**Coverage Gap**:
An explicit account of expected evidence that is missing, lost, sampled,
unsupported, opaque, or incomplete.
_Avoid_: Warning, clean result

## Coverage and attribution

**Semantic Coverage**:
The degree to which expected agent, delegation, tool, and protocol lifecycle
evidence is present.
_Avoid_: Trace completeness, confidence

**Execution Coverage**:
The degree to which relevant operations were visible at a controlled runtime
boundary.
_Avoid_: Host confidence, overall coverage

**Outcome Coverage**:
The degree to which claimed external results were independently checked.
_Avoid_: Success rate, overall coverage

**Exact Relation**:
A relationship established by an explicitly propagated identifier within its
declared trust boundary.
_Avoid_: Certain relation, causal proof

**Inferred Relation**:
A relationship supported by correlation evidence but not an authoritative
identifier.
_Avoid_: Exact relation, causal link

**Ambiguous Relation**:
A relationship for which more than one plausible target remains.
_Avoid_: Best match, inferred relation

**Unattributed Evidence**:
Evidence associated with an Agent Run but not responsibly assignable to a more
specific actor or action.
_Avoid_: Unknown agent, orphan event

## Findings and control

**Finding**:
A durable, evidence-backed condition that may change an investigation, review,
or policy decision.
_Avoid_: Alert, event, verdict

**Policy Decision**:
A deterministic allow, warn, deny, or require-approval result returned at a
supported decision point.
_Avoid_: Enforcement, finding

**Actuation**:
Confirmation from an integration that it applied a Policy Decision.
_Avoid_: Decision, intended enforcement
