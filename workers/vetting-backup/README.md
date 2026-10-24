# Private scanner byte backups

This Worker implements the daily raw-byte backup part of the approved scanner
evidence policy in issue #909 and PRD section 8. It has no HTTP read route. It
does not touch contributor traces or declare the
external evidence controls operational.

At 02:17 UTC, the scheduled handler starts one snapshot for that UTC date.
The queue copies `vetting/` objects that existed at the snapshot start. A page
contains at most 32 objects. Each stored object is at most the existing 8 MiB
evidence-part limit. Large logical evidence files already use several parts.
Copies retain each original R2 key and SHA-256 in private page receipts. Both
source and copied bytes are read and checked. Missing or changed bytes fail
the page. A completion receipt is written only after every page succeeds.

The start receipt, page receipts and byte copies are create-only. Duplicate
delivery reuses the verified page and continues from its cursor. A failed
page is retried five times and then moves to the private failure queue. A
failure queue entry or a missing daily `complete.json` needs investigation;
neither is a successful backup. D1 permits only one active storage cycle.
The single-consumer queue completes copying before it enters cleanup. A later
cron resumes that cycle instead of starting an overlapping snapshot. A stuck
cycle blocks deletion; investigate and replay its failed queue work.

The backup bucket must have the approved 30-day lifecycle rule. Each day uses
a separate prefix, so deleting an original does not make an older backup live
longer than that rule. A raw-byte backup does not back up D1 assessment,
inventory, policy or audit rows. Coordinated D1/R2 recovery and hosted
recovery verification remain separate required controls.

`restoreCheck` verifies the completion receipt and page hash chain, reads the
selected copied bytes, and restores them under a separate `restore-checks/`
prefix in a supplied private destination. It checks the restored bytes too.
It cannot replace a live evidence key. Use an isolated destination with its
own disposal policy for a live restoration exercise; this source does not
claim that exercise has occurred.

## Raw-evidence retention

Raw deletion is separately disabled unless `EVIDENCE_RETENTION_MODE` is
`enabled`. After a complete snapshot, the same single-consumer queue selects
at most 16 objects whose case closed at least 90 days ago, using the D1 clock.
Open and recently closed cases are not eligible. Closure comes from migration
0066 and the policy-owner route in the evidence API.

Before deleting an object, the worker checks that every exact part exists in
that day's backup and verifies its digest and size against the immutable
inventory. It deletes only canonical scanner keys and verifies their absence.
A durable deletion receipt is written afterward. A failed or interrupted
object can be retried: its backup is checked again and already absent parts
remain absent. Manifests, case closures and deletion receipts are retained.
A missing backup, invalid key or failed delete prevents completion.

Keep `max_concurrency = 1` and `max_batch_size = 1` on the queue. Do not call
backup or cleanup routines concurrently from another service. The active D1
cycle excludes a new scheduled snapshot until all cleanup messages finish.
The backup bucket's 30-day lifecycle still governs old copies after deletion.
Keep deletion disabled until the hosted backup and restoration check passes.

## Access-log retention

The same daily scheduled invocation removes scanner access audit entries older
than one calendar year, using the D1 clock. Migration 0067 replaces the blanket
no-delete trigger with a guard that still refuses deletion of newer or invalidly
dated records. Updates remain forbidden. A date index bounds the selection work.
The cleanup acts only on `vetting_evidence_audit`; it does not remove case closure,
assessment, contributor-trace or payment records. A cleanup failure fails the
scheduled invocation; it does not qualify as a completed retention run.

Both environments bind their existing private D1 database. Migrations must apply
before this Worker releases, as the checked-in deployment workflow requires.
The real local D1 workflow applies the migrations, refuses premature deletion,
keeps both records while disabled, and removes only an old entry when scheduled.
Hosted scheduling and retention still need release verification.

## Release

The checked-in workflow is the only deployment path. Production requires the
protected `main` release; staging uses `development`. Set the respective
`SLOP_VETTING_BACKUP_RELEASE` or `SLOP_VETTING_BACKUP_STAGING_RELEASE` repository
variable to `enabled` only after the private source/backup buckets, 30-day
backup lifecycle, work queue and failure queue exist. The release script
checks the workflow branch and commit, deploys that commit, and verifies that
100% of traffic is assigned to its tagged version. There are no new API keys. The separate
`SLOP_VETTING_RETENTION_RELEASE` and `SLOP_VETTING_RETENTION_STAGING_RELEASE`
variables enable raw deletion only through the reviewed release workflow.
The checked-in local configuration is off by default.

## Verification

Run `node workers/vetting-backup/workflow.mjs` from the repository root. It
uses local workerd R2 and a real queue consumer with 65 harmless objects. It
checks pagination, duplicate scheduling, restore integrity, source
preservation, exclusion of non-scanner objects, and refusal of corrupted
source or backup bytes. It does not prove hosted scheduling, lifecycle
deletion, D1 recovery or production access controls.
