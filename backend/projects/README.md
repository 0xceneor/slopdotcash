# Project registry API

The D1 database `slop-private` is the only project inventory. Projects are
added on slop.cash, not by pull request. This module serves the registry,
takes applications, and lets admins review them. It runs in the Pages
Function `functions/api/v1/[[path]].ts` before the payments, points, Slopbot
and private trace APIs.

## Tables

Migrations `0019_project_registry.sql`,
`0020_project_application_github_check.sql`,
`0023_project_enforcements.sql` and
`0027_project_enforcement_owner_appeals.sql` create:

- `project_applications`: submitted manifests, applicant GitHub identity,
  the referrer the applicant named (PRJ-05, migration
  `0055_project_referrer.sql`), review status, decision, and admin email
  outcome. One pending application per project id and per repository.
- `project_revisions`: the append-only manifest history. Triggers refuse
  update and delete.
- `projects`: the current pointer to the newest revision, plus the referrer
  copied once from the approved application. Triggers require a matching
  appended revision for every insert and update, refuse delete, and refuse
  any change to the referrer.
- `project_repositories`: makes each repository unique across the registry.
- `project_enforcements`: the append-only ADM-06 record of each Quarantine,
  Ban, reinstatement request and appeal decision, with the ADM-05 audit
  fields (actor, role, reason, evidence reference, before and after revision,
  decision source, result). Triggers refuse update, delete and a gap in the
  per-project sequence.

The registry starts empty. Projects listed before it were removed; their ids
and repository ids survive only in `src/lib/legacy-projects.json` so contributor
points and profiles still validate.

## Routes

| Route | Access | Purpose |
|---|---|---|
| `GET /api/v1/projects` | public, edge cached | Current manifests |
| `GET /api/v1/projects/:id` | public, edge cached | One current manifest, revision and digest |
| `GET /api/v1/project-revisions` | public, edge cached | Full revision history with SHA-256 digests |
| `GET /api/v1/project-github/owned-repositories` | session | The signed-in maintainer's public repositories |
| `GET /api/v1/project-github/repositories/:owner/:name` | session | Public repository facts for `/projects/new` |
| `GET /api/v1/project-revisions/:id/:revision` | public, immutable | One approved revision's exact stored `manifestText` and digest, for generated-skill installers |
| `GET /api/v1/project-session` | public | GitHub identity and admin flag, or `null` when signed out |
| `POST /api/v1/project-applications` | session | Submits a manifest with an optional `referrer` login, records the GitHub check, and emails the admins |
| `GET /api/v1/project-applications/mine` | session | The applicant's own applications |
| `GET /api/v1/admin/project-applications?status=` | admin | Review queue |
| `POST /api/v1/admin/project-applications/:id/approve` | admin | Lists the project as paused (optional `reason`) |
| `POST /api/v1/admin/project-applications/:id/reject` | admin | Rejects with a required `reason` |
| `GET /api/v1/admin/projects` | admin | Registry with revisions |
| `PUT /api/v1/admin/projects/:id/manifest` | admin | Appends a revision (`manifest`, `expectedRevision`, `reason`) |
| `POST /api/v1/admin/projects/:id/enforcement-preview` | moderator | Plans an enforcement action and writes nothing |
| `POST /api/v1/admin/projects/:id/enforcement` | moderator | Records the previewed action (`action`, `reason`, `evidenceReference`, `expectedRevision`, `expectedSequence`) |

`GET /api/v1/projects` also returns `restrictions`: the project id, state,
appeal state and start time of every quarantined or banned project, and
`sourceProjectId`, the project whose records hold the restriction. A reader
treats those projects as paused and retired. `GET /api/v1/projects/:id`
answers HTTP 410 for a restricted project.

Deeper `/api/v1/projects/:id/...` paths belong to the private trace API.

The site catch-all Function (`functions/[[path]].ts`, `skill-publication.ts`)
serves these public artifacts from the current D1 revision:

| Path | Content |
|---|---|
| `/.well-known/slop/projects.json` | Repository-to-project routing for every project that publishes skills |
| `/projects/:id/terms.json` | Steward, authority and terms of the current revision |
| `/projects/:id/skill.md` (alias `SKILL.md`) | Generated contributor skill |
| `/projects/:id/review-skill.md` (alias `review/SKILL.md`) | Generated reviewer skill |
| `/projects/:id/[review-]{mission,codex,claude,claude-code,manual}.md` | Workflow and per-client install guides |
| `/projects/:id/[review-]skill-manifest.json` | Template revision, registry binding, guide renderer and archive routing |
| `/projects/:id/downloads/<skill>.skill` and `.skill.sha256` | Deterministic skill archive and checksum |

Project updates use `POST /api/v1/project-applications` with `manifest`,
`expectedRevision`, and a public `reason`. Migration
`0039_project_update_applications.sql` stores the base revision and reason.
An update needs proven repository control and cannot change repository identity.
It stays pending until an admin approves it. Approval appends a paused revision
and records the application decision in the same D1 transaction. A changed base
revision returns `409`; the applicant must review the current project and submit
again. Activation still requires clearance for the new revision.

## Caching

Public reads and artifacts use the Workers Cache API with a 30 second TTL
(`edge-cache.ts`). An approval or a revision deletes every key of that project
in the writing colo; other colos expire within the TTL. Each public project
request also reads one enforcement generation counter from D1 and keys the
cache on it, so a Quarantine or a Ban replaces every cached list, skill and
archive in every colo on the next request. Admin and session routes are never
cached. Page views never read a chain. For a project with a security scan,
the public project read, the skill artifacts and discovery read the
integration-branch head on GitHub once per cache miss, to compare it with the
scanned commit (`backend/vetting/README.md`).

## Generated skills

Each project's contributor and reviewer skills come from the canonical
templates `skills/project-contributor-template/` and
`skills/project-reviewer-template/` and the manifest's maintainer-authored
`contribution` fields: approved scope, contribution guide, supported tasks,
required tests, review expectations, security contact, closure policy and
maintainer notes. `src/lib/project-skill.mjs` renders them: `SKILL.md` gets
four strictly validated identifiers (skill name, project id, repository,
integration branch), and the maintainer text goes only into the generated
`project.json` as data, so it never becomes part of the instructions.
`src/lib/project-skill-publication.mjs` builds the raw skill, mission, guides,
`skill-manifest.json`, `PROVENANCE.json` and a deterministic stored-ZIP
archive from that output. The build publishes the template bytes with their
SHA-256 digests, the renderer source digests, the commit and the
`templateSha256` input digest at `/skill-templates/index.json`; the Function
refuses a file whose digest differs.

The trust root is the pair (template revision on `main`, D1 revision digest)
(PRD SKL-04). `PROVENANCE.json` and the skill manifest bind the registry
revision and its manifest SHA-256. The installer (`src/lib/install-command.ts`)
and the skill's own run gate (`scripts/skill-kit/skill-authority.mjs`)
authorize the template revision under the GitHub rules, fetch
`/api/v1/project-revisions/:id/:revision`, check its digest, render the same
bytes again in Python, and refuse any difference or a move back to an older
revision.

## Reward asset

`rewardAsset` names one network (`base`, `solana`, `robinhood`, `ethereum`)
and either that network's stablecoin or one ERC-20 or classic SPL token. The
API reads a token's decimals (and an EVM symbol) once over RPC when the asset
is submitted or changed (`token-metadata.ts`), stores them in the manifest, and
keeps them on later revisions of the same asset. `REWARD_RPC_<NETWORK>` Pages
variables may replace the public RPC endpoints. A token, or a network outside
the Base and Solana USDC rail without a reviewed escrow, keeps payments
disabled; the asset is display metadata until a reviewed payout path exists.

## GitHub lookups

`/projects/new` reads repository facts through the same-origin
`project-github` routes, which need a site session. The server reads public
GitHub data, with the optional `SLOP_GITHUB_READ_TOKEN` secret for a higher
rate limit, and caches each answer for five minutes. The browser never calls
`api.github.com` for setup.

## Trust rules

- A session is the site sign-in cookie that `/login` creates through the
  identity Worker (`backend/points/handler.ts`). The registry mints no session
  of its own.
- Writes must carry this site's `Origin` and a JSON content type, so a
  cross-site form cannot submit one.
- Admins are the GitHub actor IDs in the `ADMIN_GITHUB_IDS` Pages variable.
  Admin status is checked on every request, never stored.
- An application must be a paused, unverified, unfunded community project with
  payments disabled, no funding addresses or commitments, no escrow deployment,
  no root skill publication, generated skills from the canonical templates,
  and the maintainer-authored `contribution` fields. Authority, terms, money,
  listing tier, and activation are added only by admin revisions.
- The API reads public GitHub facts once per submission
  (`SLOP_GITHUB_READ_TOKEN` is optional). The repository id, node id, name,
  and owner must match the manifest, or the application is refused. Every
  other repository and every alias must also be a public GitHub repository,
  and an alias must be a name of the repository it is listed under. An
  application names at most 5 repositories and aliases in all, so one
  submission makes a bounded number of GitHub reads. Whether the applicant
  owns each user repository, or is a public member of each owning
  organization, is stored as `githubCheck` for the admin. Every application
  waits for an admin (PRD PRJ-02). One account may keep 3 applications
  waiting.
- `/admin` previews the exact generated contributor and reviewer skills before
  an admin approves or activates a revision.
- A revision activates, and its skills and discovery entry are served, only
  when a secure-VM scan cleared its exact content at the live
  integration-branch head and skill template input digest. See
  `backend/vetting/README.md` (PRD VET-01).
- An admin delists a project by appending a paused, `retired` revision.
- Quarantine, Ban project and Request reinstatement (PRD ADM-06) need an admin
  who is also in the `PROJECT_MODERATOR_GITHUB_IDS` Pages variable. While that
  variable is unset, the actions are closed and `/admin` says so. Each action
  needs a reason, an evidence reference, the server preview and a
  confirmation bound to the previewed revision and record sequence.
- A Quarantine or a Ban records the enforcement and, in the same D1 batch,
  appends the paused, `retired` revision. When the current manifest cannot
  pass that revision, the record says `revision_pending`, the restriction
  still closes every public route, `/admin` shows the pending revision, and
  `bun run projects:sync` withholds that project and its revisions from the
  snapshot, with a warning, until an admin appends the paused, `retired`
  revision. Every other project still syncs.
- A restriction binds the GitHub repository id and every repository path. A
  restricted project cannot get a revision that is not paused and retired, and
  no application for the same repository can be submitted or approved.
  Another project already listed for the same repository closes on public
  routes with it. Its restriction names the restricted project as
  `sourceProjectId`, and an appeal is filed on that project. The other project
  can only get a paused, retired revision that claims the same repositories.
- The project steward named in the manifest, or the applicant whose
  application listed the project, may file the reinstatement request with
  `POST /api/v1/project-appeals` (`projectId`, `reason`,
  `evidenceReference`). The record names the role `project-steward` or
  `project-applicant` and the source `owner-request`
  (`0027_project_enforcement_owner_appeals.sql`). A moderator may also file
  it at `/admin`. Only a moderator decides it.
- Reinstatement needs an open reinstatement request and a moderator who did
  not place the restriction. Both preview and confirmation require a clean
  scan of the current restricted revision, requested after the latest restriction,
  at the live integration-branch head and current skill template. Missing,
  stale or incomplete clearance returns `vetting_required`. For a confirmed
  malicious finding, the signed scanner result records a Ban through this same
  enforcement path. The issuer is the service signing-key digest and standing
  rule, never a fabricated GitHub account. A clean scan alone never removes that finding. The independent decision
  stores its exact clean scan and reviewed malicious scan IDs in
  `project_vetting_reinstatements`, atomically with the reinstatement. Later
  findings are not covered by that decision and block clearance again.
  It is refused with `revision_pending` while the
  paused, `retired` revision of the restriction is still pending. It appends a paused `community` revision only if
  the project was listed when the restriction began; it never restores
  featuring, activation or money. A denial keeps the restriction.
- Two standing rules act without a moderator (PRD section 8; see
  `backend/vetting/README.md`). The second distinct active contributor flag
  appends a `quarantine` record whose issuer is `contributor-flags`, and a
  clean fresh scan requested at or after that flag-only pause appends a signed
  `vetting-service` reinstatement. Neither appends a revision. A moderator
  decides every other restriction, including a flag pause escalated by a
  confirmed malicious result.
- Each enforcement record adds, in the same D1 batch, one `/inbox` row for the
  applicant who listed the project and one for its GitHub steward (PRD
  NOT-01). A reinstatement request also adds a row for each moderator who
  did not place the restriction. No row carries the reason or the evidence
  reference.
- Every revision must pass `assertProjectPolicyTransition`, the review-budget
  rule, and the registry uniqueness checks. A revision that makes a project
  active requires the generated templates and the `contribution` fields. Root
  skill publication is retired.
- A stale `expectedRevision` fails with HTTP 409 instead of overwriting.
- The application is stored before the admin email. A failed or missing
  notifier is recorded as `adminNotification: "failed"` and shown in the admin
  queue.

## Publication

The site reads the registry from `GET /api/v1/projects` when a page loads
(`src/main.tsx`), so an approved project or a saved revision appears within a
minute, without a build. Every non-PR deploy still runs `bun run
projects:sync` against its own origin for build-time ingestion, which decides
which active repositories to collect; an origin that does not serve the
registry API yet keeps the committed snapshot. `bun run projects:check` proves
the committed snapshot is canonical and that every active project carries its
contribution fields.

Approval rechecks a pending new application against the current application rules
and GitHub repository and alias identities. A changed identity refuses approval.
An unavailable GitHub check leaves the application pending for a later retry.
Valid aliases remain allowed; maintainer update applications use their existing
revision and policy checks.
