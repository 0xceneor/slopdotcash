# Private scanner byte backups

This Worker implements the daily raw-byte backup part of the approved scanner
evidence policy in issue #909 and PRD section 8. It has no HTTP read route. It
does not touch contributor traces, delete source evidence, or declare the
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
neither is a successful backup. Do not delete source objects while a snapshot
is running. Physical retention needs that coordination before activation.

The backup bucket must have the approved 30-day lifecycle rule. Each day uses
a separate prefix, so deleting an original does not make an older backup live
longer than that rule. A raw-byte backup does not back up D1 assessment,
inventory, policy or audit rows. D1 recovery, case-closure retention and the
one-year access-log policy remain separate required controls.

`restoreCheck` verifies the completion receipt and page hash chain, reads the
selected copied bytes, and restores them under a separate `restore-checks/`
prefix in a supplied private destination. It checks the restored bytes too.
It cannot replace a live evidence key. Use an isolated destination with its
own disposal policy for a live restoration exercise; this source does not
claim that exercise has occurred.

## Release

The checked-in workflow is the only deployment path. Production requires the
protected `main` release; staging uses `development`. Set the respective
`SLOP_VETTING_BACKUP_RELEASE` or `SLOP_VETTING_BACKUP_STAGING_RELEASE` repository
variable to `enabled` only after the private source/backup buckets, 30-day
backup lifecycle, work queue and failure queue exist. The release script
checks the workflow branch and commit, deploys that commit, and verifies that
100% of traffic is assigned to its tagged version. There are no new API keys.
The checked-in local configuration is off by default.

## Verification

Run `node workers/vetting-backup/workflow.mjs` from the repository root. It
uses local workerd R2 and a real queue consumer with 65 harmless objects. It
checks pagination, duplicate scheduling, restore integrity, source
preservation, exclusion of non-scanner objects, and refusal of corrupted
source or backup bytes. It does not prove hosted scheduling, lifecycle
deletion, D1 recovery or production access controls.
