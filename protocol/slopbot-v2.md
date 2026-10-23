# Slopbot v2

Status: **approved by the repository owner on 9 October 2026.** Effective time:
2026-11-01T00:00:00Z. It supersedes `slopbot-v1.md` from that instant; until
then v1 applies in full. Closed and open cycles are not changed retroactively.

v2 keeps every v1 rule except the ones listed under "Changes from v1".

## Changes from v1

1. **Hosted operator.** Slop operates the hosted Slopbot GitHub App. Slop is
   the disclosed operator for each installation. The service is free (see
   "Cost").
2. **Delegated closure.** Slopbot may close an issue or pull request only under
   a category the repository has set to `close`, as defined in PRD BOT-06. It
   still never merges, approves payouts, requests changes, bans, excludes, or
   pays. The separate owner-approved SCR-06 value-scoring extension permits
   automatic provisional assessments; it does not enable closure powers.
3. **Permissions.** Read: Contents, Metadata, Organization members.
   Write: Issues and Pull requests, used only to comment, label and close.
   No other write permission.
4. **Audience.** "Participants only" or "Protection" (PRD BOT-02) selects
   advisory review. Exempt actors are never closed. Closure is limited to
   verified slop.cash members using the Slop skill (PRD section 5); a
   copied attribution marker is not evidence.

## Decision boundary

- The model returns one schema-valid verdict. It has no tools, secrets, or
  network access, and it cannot name another item.
- A trusted action service performs every GitHub action. Immediately before
  each action, it re-checks the installation, configuration, budget, exact
  revision, author exemption and item state.
- Every close needs a second, independent confirming verdict at higher effort.
  Both calls use Surplus Intelligence, falling back to GPT-6.1 Sol. Surplus
  cannot prove which model served a verdict; the owner accepted this on
  9 October 2026, and every result says so.
- Policy is read from the base branch at a recorded SHA. A pull request's own
  policy edits are content under review.

## Penalty boundary

A close by Slopbot creates a penalty only for an author who is a consenting
Slop participant (PRD SCR-01). A close of an external author's item creates
only the public outcome record. A human reopen suspends the penalty, and a
successful appeal reverses it.

## Cost

Superseded by the canonical PRD section 5: Slopbot is always free and does
not charge project vaults. The former cost-plus-10% billing no longer applies
to new reviews; historical charge records stay unchanged. Slop records
provider cost internally for budgets and queue limits only. Slopbot holds no
funds and no payment key.

## Recognition

Slopbot appears only in the Automation row (PRD LDR-04). Bot activity still
does not score, and a Slopbot record is still never a prior review for the
duplicate-review rule.

## Provisional value assessment extension

The owner approved SCR-06 on 9 October 2026 for every active Slop project,
including a separate September and October reassessment. See
[`slop-value-scoring-plan.md`](../docs/slop-value-scoring-plan.md). This
authority is independent of the 1 November closure-policy activation.
Assessments require complete source evidence, exact revision binding, model
and rubric provenance, and an append-only successor record. Existing scores
remain visible. Maintainer ratification overrides automation. Payout approval
remains human. An incomplete assessment cannot imply a low-value outcome.
Bot activity itself receives no contributor credit.

## Registered repository scope

Owner decision, 21 October 2026: the hosted rollout operates only on public
repositories of active D1 projects. This restriction also applies before v2's
effective date. App installation alone grants no review authority.
Unregistered repositories are outside the rollout. The canonical PRD section 5
(23 October 2026) lets authorized security review continue on paused, flagged
or removed projects: those registered repositories get a security-only review
that never closes, scores or penalizes.
Read the live registry before queue intake, job execution, inference and each
GitHub write. A read failure stops that action. A stale installation or queued
job cannot override the registry. Protection-only operation is superseded for
this rollout. Closure activation and financial decisions remain separate.

## Objective quality closure amendment

The owner approved the criteria in
[`docs/slopbot-quality-closure-proposal.md`](../docs/slopbot-quality-closure-proposal.md)
for implementation on 21 October 2026. They take effect no earlier than this
protocol's 2026-11-01T00:00:00Z effective time. A quality closure requires a
published rejection rule and two grounded verdicts identifying the same
verified defect: removal of required behavior, a reproduced patch regression,
or a result claim contradicted by its cited artifact. Missing verification
requires label-only handling. This amendment grants no production activation,
penalty, score or payment authority. Existing shadow qualification, explicit
enablement, caps, appeals and reopen controls remain required.
