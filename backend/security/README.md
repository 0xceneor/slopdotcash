# Private security bounty cases

PRD section 8 ("Report and decide privately", "Pay a private award"), section
10, SEC-01 to SEC-18 and MVP-13 (issue #910). Program terms are public; cases
are not.

## Program terms

A project opts in with the optional `securityBounty` section of its D1
manifest (`src/lib/security-bounty.mjs`). An application may include it only
as `pending-approval` with `pledged` funding. Admins open, pause or close the
program by appending a manifest revision on `/admin`. A program cannot be
removed, because its approvers govern restricted case access after closure.

- `amount.grossMinor` is the published gross award per finding, in integer
  minor units divisible by four, so the 75/25 researcher/Slop split is exact.
  Shares are derived, never stored. Awards are discretionary: the owner may
  award a different amount or none (see "Awards").
- `rewardMode: "bounty-only"` requires a `$0` monthly pool with payments
  disabled. `separate` keeps the project's ordinary rewards.
- `status: "open"` requires `funding.state: "verified-available"` with an
  evidence reference. A pledge never opens paid capacity. The funds an owner
  can reserve are `amount.grossMinor × capacity.awards` of the current
  revision, minus every reservation in that currency (awaiting owner decision:
  see "Open decisions").
- `approvers.dispute` must not include a technical or financial approver.
- `intake.repository` must be one of the project repositories.

`/projects/:id/terms.json` and `/projects/:id/security` publish these terms.

## Routes

| Route | Access | Purpose |
|---|---|---|
| `GET /api/v1/security-programs/:id/intake` | public, edge cached 30 s | GitHub private vulnerability reporting readiness: `ready`, `disabled`, `forbidden` or `unavailable`. Only `ready` returns the GitHub handoff URL. `automatic` is `ready`, `app-not-installed`, `unavailable` or `off` |
| `GET /api/v1/security-cases` | session | Cases the caller can see now, shaped per role |
| `POST /api/v1/security-cases` | session | `claim`: a reporter links a GitHub advisory ID. `record`: a technical approver records a verified advisory with GitHub's receipt time. `import`: a maintainer imports direct GitHub reports |
| `GET /api/v1/security-cases/:id` | session and role | One case; logs the read |
| `POST /api/v1/security-cases/:id/actions` | session and role | One human decision with `expectedRevision` and `idempotencyKey` |
| `GET /api/v1/security-submissions` | session | The caller's own automatic submissions: state, attempt, GHSA, GitHub time, failure code, case id |
| `POST /api/v1/security-submissions` | session | Creates (or replays) a `slop` draft or a `direct` verification and returns the intake App authorization URL |
| `GET /api/v1/security-submissions/authorize/callback` | GitHub redirect | PKCE exchange, `/user` identity binding, grant cookie |
| `POST /api/v1/security-submissions/:id/{authorize,send,reconcile,verify}` | reporter only | Reauthorize, send privately, reconcile an uncertain send, verify a direct report |

A caller without a role gets the same 404 as for a missing case. Writes need
this site's `Origin` and a JSON content type. Responses are `private,
no-store` and `noindex`. Errors never log case data.

## Automatic private intake

PRD section 8 ("Private reporting is automatic"), SEC-07, SEC-10, SEC-17.
Every `security-submissions` route returns 404 unless
`SLOP_PRIVATE_INTAKE_MODE=on` and all intake App secrets are set
(`GITHUB_INTAKE_APP_CLIENT_ID`, `GITHUB_INTAKE_APP_CLIENT_SECRET`,
`GITHUB_INTAKE_APP_ID`, `GITHUB_INTAKE_APP_PRIVATE_KEY`,
`SLOP_INTAKE_GRANT_KEY`). The dedicated intake GitHub App (repository
security advisories read and write, metadata read, no webhooks) still needs
owner approval in the PRD and a maintainer installation on each program
repository. Until then intake stays off and the manual flow below applies.

- Authorization: a per-submission PKCE consent for the intake App. The
  callback checks that `/user` is the account that began the consent and
  stores the user token only in an AES-GCM encrypted HttpOnly
  `__Secure-slop_intake_grant` cookie (path `/api/v1/security-submissions`,
  2 hours) bound to the submission and the site session. No access or
  refresh token is stored in D1. GitHub records the reporter as the author.
- `security_submissions` (migration 0059) holds no report content. States:
  `draft`, `submitting`, `uncertain`, `submitted`, `receipt-verified`,
  `failed`, `abandoned`. Every transition is a revision compare-and-set
  with an insert-only event in the same batch. `submitting` commits before
  GitHub is called; a lost answer, a 5xx, a malformed 201 or a 201 naming
  another author is `uncertain`.
- Marker: the description gets one line, `Report reference: <32 hex>`, a
  random value per submission. It names neither the submission nor Slop,
  because it stays in the text if the advisory is published
  (OPEN_QUESTION 9); the consent notice says so.
- Reconcile before retry: an uncertain send lists the reporter's advisories
  since the first attempt with their own token and matches the marker line
  and author. Only a complete listing without a match, taken at least
  5 minutes after the attempt began, reopens the draft for another send;
  an earlier empty listing or a listing error stays `uncertain`. Several
  matches adopt the earliest and show the rest to the technical approvers
  only. A resend that GitHub accepts lists again and adopts an earlier copy
  that landed late, recording the accepted one as a duplicate. A
  `submitting` row older than 60 seconds becomes `uncertain` and is never
  resent. A `submitted` row Slop cannot verify within 24 hours fails as
  `unverifiable`; it is never resent and no longer blocks a new report.
- Receipt: GitHub's advisory must name the program repository and the
  reporter as author (a reporter credit never counts), carry the marker
  (Slop origin) and have a past `created_at`. A direct report must also be
  a private vulnerability report (GitHub's `submission` object) in
  `triage`, `draft` or `published`; anything else fails as
  `not-private-report` and uses the manual claim path. The verified case,
  its `submit` or `submit-direct` event (the reporter's own action; the
  detail records `verifiedBy: "github"`), routing fields, the access log and the inbox rows commit with the
  submission transition. The receipt time is GitHub's `created_at`
  (`receivedAtSource: "github-verified"`), the verifier is the sentinel
  `github`, and `receipt_evidence_digest` stores the SHA-256 of the
  advisory fields GitHub returned.
- Direct reports: "Already reported on GitHub? Verify it" runs the same
  receipt check on a GHSA the reporter filed themselves; GitHub's original
  `created_at` is kept. Without the App installed, the manual claim and
  verify-link path below remains the fallback.
- Analysis: `report-analysis.ts` recommends only, from GitHub's structured
  severity and CVSS fields. Its result is in the restricted event detail
  only; the case's owner, neutral next action and due time (the published
  acknowledgement target) do not depend on it, because the reporter sees
  them. It never sets severity, receipt, award or disclosure.
- After verified receipt, `analysis.ts` schedules a private proposal using the
  configured advisory reader and analysis provider. It records unavailable
  when either is absent. Only maintainers and assigned triagers see the proposal.
  Provider selection requires an explicit configuration; this change does not
  activate a provider or authorize sending live private evidence.
- Maintainers can import reports filed directly on GitHub through `mode: import`.
  This uses the same case and analysis records, not a second submission system.
  `SECURITY_ADVISORY_READ_TOKEN` needs advisory-read access to the program
  repository. It cannot submit a report as the researcher.

## Roles

Roles are computed on every request from the session and the current project
revision, so a revision or a revoked session removes access at once.

- Reporter: their own cases, never another report, root cause or triager.
- Any registered user may report; project membership is not required.
- Technical approver (security maintainer, the project owner or maintainer
  authority of PRD section 10): every case of the project; decides findings,
  awards, remediation and disclosure; prepares the unsigned payment.
- Triager: only assigned cases; request information and remediation.
- Financial approver: only cases with an approved (or older reserved) award,
  and only award and payment fields; prepares the unsigned payment.
- Dispute reviewer: only cases with an appeal or a related-party award
  review.
- Platform admins, sponsors and the public: nothing.

A reporter never acts on their own case. PRD section 10 names two
authorities: the project owner or maintainer decides technical, award and
disclosure questions, so the decider may also approve the award and prepare
its payment. The technical decider cannot decide the appeal or the
related-party review, and the related-party reviewer cannot decide an appeal
of that review, or review the same case again once an appeal has returned it
for a new decision.

## States

Migration `0026_private_security_cases.sql` keeps independent receipt,
remediation, award, payment and disclosure states. `0059` adds automatic
submissions and receipt evidence; `0061` adds chosen award amounts and analyses. Triggers keep the
frozen receipt, events, reservations, membership history, submissions and
finished analyses append-only.

Each case shows one derived next step for the viewer (`nextStep`, with
`nextStepDueAt` from the program's acknowledgement target while the report
waits for a first response, or the payment deadline). Nobody maintains a
separate task field. Owner actions: `request-information`, `decide`, `award`,
`remediation`; access and disclosure tools (`assign-triager`,
`revoke-triager`, `disclosure`) stay available but the page shows disclosure
first only once a fix exists or a disclosure decision was recorded.

Triager assignment and revocation commit only together with their audit
event at the next case revision. A stale request changes no membership.

## Awards

PRD section 8: critical bugs and potential loss of funds are priorities, not
an automatic payout promise. `decide` records outcome, severity, loss and
scope as guidance. A confirmed finding with paid terms then waits for the
owner's award decision (`award`, or an `award` object inside `decide`):

- `decision: "none"` makes the award `ineligible` (shown as "No award"). The
  reporter can appeal it.
- `decision: "amount"` with `grossMinor`, `paymentDeadline` and confirmation
  approves that exact gross amount and reserves it in the same batch. The
  reservation insert itself checks that the program's unreserved verified
  funds cover it; otherwise nothing is written (`409 insufficient_funds`). A
  pledge reserves nothing (`409 funds_unavailable`). Only a security
  maintainer of the program decides; a reporter never decides their own case.

One root cause reserves once per project (`root_cause_reserved`). A reserved
or approved award is never redecided or withdrawn. A related-party reporter
(declared, a program approver, or the sponsor account) gets a proposed amount
that reserves nothing until an independent dispute reviewer approves it
(`decide-related-party`); the approval then reserves the proposed amount if
funds exist. Once related, a case stays related, and earlier reviewers stay
recorded.

Older cases keep their records: a `reserved` award from before discretionary
awards is approved at its reserved amount, and a `capacity-exhausted` award
waits for the owner's award decision like any `pending` one. The removed
`approve-award`, `reserve-award`, `verify-link`, `reject-link`, `triage` and
`next-action` events stay readable in history.

A reporter may appeal a duplicate, out-of-scope or rejected finding, or a
confirmed finding without an award. `uphold` restores the receipt unchanged;
`return` sends it back to a new decision and reopens the award decision.

## Disclosure approval records

A disclosure decision records its private human-approval evidence reference.
Approving redacted text also binds the exact content SHA-256. Recording disclosure
requires the latest disclosure decision to approve those same bytes, and retains
that approval's case revision. Changed bytes need a new approval. Any approved
embargo change is explicit in the immutable event; omission means no change.
These records do not publish content or schedule disclosure. Reporter recognition
consent stays separate. Older events remain unchanged and cannot authorize a new
disclosure without an exact content approval.

## Private settlement

The 22 October 2026 product decision uses the existing escrow rails with a
75% reporter share and 25% Slop share. Migration
`0057_private_security_payments.sql` separates settlement intents, payment
records, attempts and finalized vault snapshots from ordinary payments.
Canonical wallet possession and binding authorizations remain shared.

Payment uses the reserved gross amount of the approved award. An admin must
record a reviewed `securityBounty.settlement` policy with a
separate vault and `feeBasisPoints: 2500`. The vault must not appear in
any other payment program. USDC awards require a matching reviewed USDC rail;
USD awards cannot be converted implicitly. The reporter accepts the selected
rail's public chain visibility before the maintainer or delegated payer prepares an
immutable unsigned commitment. Report state stays independent of payment
state, and no payment authorizes disclosure. Onchain records expose actor numbers, addresses,
times and amounts. They contain a random source commitment, never report data.

The owner submits the unsigned commitment outside Slop. The private worker
uses the existing finalized-event verifier and recovery engine, with the
25% fee policy and the exact approved private intent. Public payment queries,
notifications and aggregates never use these tables. A lost response is
uncertain until verified chain evidence resolves it. No action can manually
mark an award paid. Missing wallets retain their award; the canonical wallet
proof and delay apply when a wallet is added or changed.

Generate the reviewed private deployment inventory with
`bun scripts/prepare-payment-deployments.ts testnet <network> --security-bounty`
and the existing stack generator with `--scope security-bounty`.
Production retains the existing attester-only policy; this change does not
authorize a Slop signer or mainnet dispatch. Test stacks use isolated databases.
Without an approved and verified matching vault, the case shows
`rail-unavailable` and cannot prepare settlement.

Solana wallet co-signing uses the existing authenticated
`/api/v1/payments/wallets/solana-bind/prepare` and `complete` endpoints.
The lookup resolves the signed-in reporter's private obligation and records
an audited access. Private binding requests use the separate
`SECURITY_SOLANA_IDENTITY_ATTESTER` service binding; they never fall back to
the ordinary attester. Missing service configuration fails closed.

## Remaining hosted acceptance

- Email: the restricted verified-destination pilot is implemented in
  `workers/notify/security.ts`; deployment and inbox delivery remain launch
  gates. See `workers/notify/README.md`. Every case inbox insert also queues
  one private outbox row in the same transaction. Only current case roles
  with operator-verified destinations receive generic notices. An email
  never contains a case identifier, amount, project or advisory. The inbox
  action **Acknowledge** records the recipient's authenticated response;
  **Mark read** is a separate state and never acknowledges a notice.
- On the manual path GitHub advisory content is never fetched; maintainers
  verify claims by hand on GitHub. Automatic intake reads only the
  reporter's own advisory with the reporter's token and keeps only its
  digest. Its GitHub behaviour (user tokens on `/reports`, error shapes,
  listing visibility) is not yet qualified on a real repository.
