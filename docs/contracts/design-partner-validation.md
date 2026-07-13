# Design-Partner Validation and Approval

Status: **not approved**. This document is a qualification and approval
template. It records no design-partner enrollment or consent.

As of 2026-07-13, no partner name, operator approval, deployment approval, data
boundary approval, or W1–W2 partner exit gate is recorded in this repository.
Placeholders must never be interpreted as evidence. Approval must be supplied by
an authorized representative of the actual partner and reviewed through a Pull
Request without committing confidential or personal data.

## Qualification gate

A partner qualifies only when all of the following are documented:

- one organization operates agents in at least two of the five supported
  environment profiles;
- a named role, represented in the private approval record by an authorized
  individual, owns the investigation or policy decision;
- one representative workflow can be exercised without fabricated telemetry;
- deployment, identity, trust, privacy, retention, and unsupported-capability
  boundaries are explicit;
- the workflow ends in a decision Apolysis could realistically change;
- the partner agrees to a measurable correctness or investigation-time test.

A logo, informal conversation, repository star, demo attendance, or willingness
to receive updates does not qualify.

## Portfolio gate

W1–W2 requires three independently qualified partners, each covering at least
two environment profiles. Collectively, the partners should cover an endpoint
or IDE path, a CI or hosted path, and a customer-controlled service or
Kubernetes path. If fewer than three qualify and approve, narrow the initial
customer profile before building the shared backend; do not mark the gate
complete.

| Slot | Qualification | Environment profiles | Approval state |
| --- | --- | --- | --- |
| A | Unfilled | Not recorded | Not approved |
| B | Unfilled | Not recorded | Not approved |
| C | Unfilled | Not recorded | Not approved |

Do not replace “Unfilled” with a partner identity in this public template.
Store the minimum non-sensitive evidence here and keep confidential commercial,
personal, credential, and captured run data outside the repository.

## Partner workflow record

Copy this section into a reviewable, privacy-safe record for each qualified
partner.

### Qualification

- Partner reference (non-sensitive alias):
- Partner organization type:
- Operator role:
- Decision owner role:
- Environment profile 1:
- Environment profile 2:
- Additional environment profile:
- Qualification reviewer and date:
- Qualification evidence reference:

### Investigation workflow

- Trigger and business context:
- Agent/harness/provider:
- Authority and principal source:
- Run start and terminal signal:
- Expected semantic sources:
- Expected execution source or explicit opaque boundary:
- Claimed outcome:
- Independent outcome verifier:
- Decision changed by the result:
- Current baseline process:
- Current median completion time or other baseline measure:
- Representative failure, source-loss, and outcome-mismatch cases:

### Deployment and trust boundary

- Integration/deployment path:
- Source authentication and organization binding:
- Runtime binding method:
- Source capabilities and sampling:
- Exact, inferred, ambiguous, or unattributed relations expected:
- Privileged components and operator:
- Unsupported claims shown to the partner:
- Installation, rollback, and cleanup owner:

### Data boundary

- Data categories enabled:
- Content-off categories confirmed:
- Edge and Gateway redaction profile:
- Retention tier and shorter object lifetime, if any:
- Object-read roles and purpose:
- Export restrictions:
- Data residency/provider requirements:
- Deletion and revocation acceptance criteria:
- Partner privacy/security approver role:

### Measurable success criteria

At minimum, record pass/fail thresholds for:

- a representative run appearing without manual evidence conversion;
- correct separation of semantic, execution, and outcome coverage;
- correct presentation of semantic `partial`/`opaque`/`unavailable`, execution
  `partial`/`opaque`/`incomplete`, outcome `unconfirmed`/`unknown`, source-loss,
  and outcome-comparison `mismatch` cases;
- operator correctness on the named investigation task compared with baseline;
- investigation or review time compared with baseline;
- absence of unauthorized raw content and cross-organization access;
- installation, steady-state overhead, rollback, and cleanup acceptance.

Thresholds must be agreed before the pilot result is collected. A retrospective
threshold chosen to fit the result is not approval evidence.

## Approval record

All boxes begin unchecked. A partner's approval applies only to the named
workflow and contract revision.

- [ ] The partner approves the deployment path and privileged boundary.
- [ ] The partner approves the source identity and trust model.
- [ ] The partner approves content-off defaults, redaction, retention, object
  access, deletion, and export boundaries.
- [ ] The partner confirms the unsupported capability and claim boundaries.
- [ ] The partner approves the first investigation workflow.
- [ ] The partner approves the predeclared success criteria and baseline.
- [ ] The project reviewer verified evidence references without committing
  secrets or captured private data.

Approval metadata:

- Contract revision/commit:
- Partner-authorized approver role:
- Approval date:
- Private approval evidence reference:
- Project reviewer:
- Exceptions and expiry/review date:

An empty field, unchecked box, project-team signature without partner evidence,
or Pull Request merge is **not** partner approval.

## Pilot result record

- Pilot date and build revision:
- Synthetic/live classification:
- Runs attempted/completed/incomplete:
- Environment profiles exercised:
- Coverage and source-gap results:
- Investigation correctness result:
- Investigation time result:
- Privacy/authorization negative-test result:
- Runtime overhead result:
- Rollback/cleanup result:
- Partner decision: approve, approve with exception, revise, or stop:
- Follow-up evidence reference:

Live captured evidence must remain in the partner-approved storage boundary.
Only redacted aggregates and opaque references belong in the repository.
