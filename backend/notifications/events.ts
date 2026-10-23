/**
 * Inbox event statements (PRD NOT-01, migrations 0024 and 0063). Each writer
 * adds one of these to the same D1 batch as its source change, after that
 * change, so the notification commits only with it. Every statement reads its
 * facts back from the committed source row, so a change that did not happen
 * writes nothing, and the (event_key, recipient) key makes a replay a no-op:
 * one source transition is one event.
 *
 * Notices report outcomes and exceptions, not routine admission steps:
 * setup completion (`project_ready`), failed checks (`project_scan_failed`,
 * `project_installation_lost`), flag pauses (`project_paused_by_flags`,
 * `flag_pause_review`), payment exceptions (`payout_held`,
 * `payout_exception`) and private report receipts
 * (`security_report_received`). Only private case notices that ask a role
 * holder to act (`security_case`) carry an acknowledgment and escalation;
 * every other notice is read state only.
 */

type Preparer<S> = {
  prepare(query: string): { bind(...values: unknown[]): S };
};

const INSERT = `INSERT INTO notifications (
  event_key, recipient_github_id, kind, subject, detail, action_path,
  source_at, created_at
)`;
const ONCE = "ON CONFLICT (event_key, recipient_github_id) DO NOTHING";

/**
 * Historical admission path: an admin decision on a pending project
 * application reaches the applicant. Self-service setup reports completion
 * through `notifyProjectRevision` (`project_ready`) instead; remove this
 * writer with the admin application path. Its rows stay valid history.
 */
export function notifyApplicationDecision<S>(
  db: Preparer<S>,
  applicationId: string,
  decidedAt: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'project-application:' || id || ':' || status,
              applicant_github_id, 'application_' || status, project_id,
              decision_reason,
              CASE status WHEN 'approved' THEN '/projects/' || project_id
                          ELSE '/projects/new' END,
              decided_at, ?
         FROM project_applications
        WHERE id = ? AND status IN ('approved', 'rejected') AND decided_at = ?
       ${ONCE}`,
    )
    .bind(decidedAt, applicationId, decidedAt);
}

/** SQL that keeps only canonical GitHub account ids as recipients. */
const GITHUB_ID = (column: string) =>
  `typeof(${column}) = 'text' AND length(${column}) BETWEEN 1 AND 20
   AND ${column} GLOB '[1-9]*' AND ${column} NOT GLOB '*[^0-9]*'`;

/**
 * The people who answer for a project: the applicant who listed it (legacy
 * admission path) and its current GitHub steward. `project` is a SQL
 * expression for the project id.
 */
const PROJECT_OWNERS = (project: string) => `(
  SELECT a.applicant_github_id AS recipient
    FROM projects p
    JOIN project_applications a ON a.id = p.source_application_id
   WHERE p.id = ${project}
  UNION
  SELECT json_extract(manifest, '$.steward.github.actorId')
    FROM projects
   WHERE id = ${project}
)`;

/**
 * A manifest revision reaches the applicant who listed the project and its
 * GitHub steward, never the person who published it. A revision that makes
 * the project active, from nothing or from paused, is setup completion or a
 * return to work and is reported as `project_ready`; any other later revision
 * is `project_revision`. A paused first revision is the legacy approval,
 * which has its own event, so it writes nothing here.
 */
export function notifyProjectRevision<S>(
  db: Preparer<S>,
  projectId: string,
  revision: number,
  manifestSha256: string,
  at: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'project-revision:' || r.project_id || ':' || r.revision,
              recipient,
              CASE WHEN r.ready THEN 'project_ready' ELSE 'project_revision' END,
              r.project_id, CASE WHEN r.ready THEN NULL ELSE r.reason END,
              '/projects/' || r.project_id, r.created_at, ?4
         FROM (
           SELECT rev.*,
                  json_extract(rev.manifest, '$.status') = 'active' AND
                  COALESCE((SELECT json_extract(prior.manifest, '$.status')
                              FROM project_revisions prior
                             WHERE prior.project_id = rev.project_id
                               AND prior.revision = rev.revision - 1),
                           'none') <> 'active' AS ready
             FROM project_revisions rev
            WHERE rev.project_id = ?1 AND rev.revision = ?2
              AND rev.manifest_sha256 = ?3 AND rev.created_at = ?4
         ) r
         JOIN (
           SELECT a.applicant_github_id AS recipient
             FROM projects p
             JOIN project_applications a ON a.id = p.source_application_id
            WHERE p.id = ?1
           UNION
           SELECT json_extract(manifest, '$.steward.github.actorId')
             FROM project_revisions
            WHERE project_id = ?1 AND revision = ?2
              AND json_type(manifest, '$.steward.github.actorId') = 'text'
         )
        WHERE (r.revision > 1 OR r.ready)
          AND recipient IS NOT r.actor_github_id
          AND ${GITHUB_ID("recipient")}
       ${ONCE}`,
    )
    .bind(projectId, revision, manifestSha256, at);
}

/**
 * A completed scan that could not establish clearance (state `incomplete`)
 * reaches the project's owners, once per assessment. A malicious result is
 * reported by its enforcement record instead; a clean result needs no notice
 * because the project status shows it.
 */
export function notifyProjectScanFailed<S>(
  db: Preparer<S>,
  assessmentId: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'project-scan:' || v.id, owners.recipient, 'project_scan_failed',
              v.project_id, NULL, '/projects/' || v.project_id,
              v.completed_at, v.completed_at
         FROM vetting_assessments v
         JOIN ${PROJECT_OWNERS("(SELECT project_id FROM vetting_assessments WHERE id = ?1)")} owners
        WHERE v.id = ?1 AND v.state = 'incomplete' AND v.completed_at IS NOT NULL
          AND ${GITHUB_ID("owners.recipient")}
       ${ONCE}`,
    )
    .bind(assessmentId);
}

/**
 * Slopbot's GitHub installation was suspended or removed at `at`. Each
 * project with a registered repository under that account reaches its
 * owners once, because reviews stop until Slopbot is installed again.
 */
export function notifySlopbotInstallationLost<S>(
  db: Preparer<S>,
  installationId: number,
  at: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'slopbot-installation:' || i.installation_id || ':' || ?2 || ':' || p.id,
              owners.recipient, 'project_installation_lost', p.id, NULL,
              '/projects/' || p.id, ?2, ?2
         FROM slopbot_installations i
         JOIN projects p ON EXISTS (
           SELECT 1 FROM project_repositories r
            WHERE r.project_id = p.id
              AND substr(r.repository_key, 1, length(i.account_login) + 1) =
                  lower(i.account_login) || '/'
         )
         JOIN (
           SELECT p2.id AS project_id, a.applicant_github_id AS recipient
             FROM projects p2
             JOIN project_applications a ON a.id = p2.source_application_id
           UNION
           SELECT id, json_extract(manifest, '$.steward.github.actorId')
             FROM projects
         ) owners ON owners.project_id = p.id
        WHERE i.installation_id = ?1
          AND (i.removed_at = ?2 OR i.suspended_at = ?2)
          AND ${GITHUB_ID("owners.recipient")}
       ${ONCE}`,
    )
    .bind(installationId, at);
}

/** A finalized reservation: an award is now set aside for the contributor. */
export function notifyAwardReserved<S>(
  db: Preparer<S>,
  obligationId: string,
  at: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'payment-reserved:' || id, github_user_id, 'award_reserved',
              project_id, NULL, '/earnings', created_at, ?
         FROM payment_obligations WHERE id = ?
       ${ONCE}`,
    )
    .bind(at, obligationId);
}

/** A finalized payout transaction to the contributor's authorized wallet. */
export function notifyPaymentPaid<S>(
  db: Preparer<S>,
  obligationId: string,
  transactionId: string,
  at: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'payment-paid:' || o.id, o.github_user_id, 'payment_paid',
              o.project_id, NULL, '/earnings', e.observed_at, ?
         FROM payment_obligations o
         JOIN payment_events e
           ON e.obligation_id = o.id AND e.kind = 'paid'
          AND e.transaction_id = o.paid_transaction
        WHERE o.id = ? AND o.state = 'paid' AND o.paid_transaction = ?
       ${ONCE}`,
    )
    .bind(at, obligationId, transactionId);
}

/** A held payout; each hold is its own event, keyed by its time. */
export function notifyPayoutHeld<S>(
  db: Preparer<S>,
  obligationId: string,
  heldAt: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'payout-held:' || q.obligation_id || ':' || q.updated_at,
              o.github_user_id, 'payout_held', o.project_id, NULL,
              '/earnings', q.updated_at, ?
         FROM payment_outbox q
         JOIN payment_obligations o ON o.id = q.obligation_id
        WHERE q.obligation_id = ? AND q.state = 'held' AND q.updated_at = ?
       ${ONCE}`,
    )
    .bind(heldAt, obligationId, heldAt);
}

/** A new or replacement payout wallet is an account-security event. */
export function notifyWalletChanged<S>(
  db: Preparer<S>,
  claimId: string,
  at: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'wallet-claim:' || id, github_user_id, 'wallet_changed', chain,
              NULL, '/account#wallets', created_at, ?
         FROM wallet_claims WHERE id = ?
       ${ONCE}`,
    )
    .bind(at, claimId);
}

/**
 * A held payout is a payout exception for the project's GitHub steward
 * (migration 0029). The row names only the project, never the contributor or
 * a wallet. A payment database without the project registry has no steward
 * row and writes nothing.
 */
export function notifyPayoutException<S>(
  db: Preparer<S>,
  obligationId: string,
  heldAt: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'payout-exception:' || q.obligation_id || ':' || q.updated_at,
              json_extract(p.manifest, '$.steward.github.actorId'),
              'payout_exception', o.project_id, NULL,
              '/projects/' || o.project_id, q.updated_at, ?
         FROM payment_outbox q
         JOIN payment_obligations o ON o.id = q.obligation_id
         JOIN projects p ON p.id = o.project_id
        WHERE q.obligation_id = ? AND q.state = 'held' AND q.updated_at = ?
          AND ${GITHUB_ID("json_extract(p.manifest, '$.steward.github.actorId')")}
       ${ONCE}`,
    )
    .bind(heldAt, obligationId, heldAt);
}

/**
 * An ADM-06 enforcement record reaches the applicant who listed the project
 * and its current GitHub steward. The row carries no reason or evidence
 * reference: those stay in the admin panel. The project page shows the
 * public restriction state.
 */
export function notifyProjectEnforcement<S>(
  db: Preparer<S>,
  recordId: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'project-enforcement:' || e.id, recipient,
              CASE e.action
                WHEN 'quarantine' THEN 'project_quarantined'
                WHEN 'ban' THEN 'project_banned'
                WHEN 'request_reinstatement' THEN 'reinstatement_requested'
                WHEN 'reinstate' THEN 'project_reinstated'
                WHEN 'deny_reinstatement' THEN 'reinstatement_denied' END,
              e.project_id, NULL, '/projects/' || e.project_id,
              e.created_at, e.created_at
         FROM project_enforcements e
         JOIN ${PROJECT_OWNERS("(SELECT project_id FROM project_enforcements WHERE id = ?1)")}
        WHERE e.id = ?1 AND ${GITHUB_ID("recipient")}
          AND e.action IN ('quarantine', 'ban', 'request_reinstatement',
                           'reinstate', 'deny_reinstatement')
       ${ONCE}`,
    )
    .bind(recordId);
}

/**
 * VET-06 bans reach configured operators and known affected contributors.
 * Membership resolves immutable contribution actor IDs to inbox identities.
 * Payment records also reach contributors who have no points membership.
 * Superseded and zero-credit outcomes do not select an affected contributor.
 * This reads no private trace records and copies no security evidence.
 */
export function notifyVettingBanAudience<S>(
  db: Preparer<S>,
  recordId: string,
  operatorGithubIds: readonly string[],
): S {
  return db
    .prepare(
      `${INSERT}
    SELECT 'project-enforcement:' || e.id, audience.recipient,
           'project_banned', e.project_id, NULL,
           CASE WHEN audience.recipient IN (SELECT value FROM json_each(?2))
                THEN '/admin' ELSE '/projects/' || e.project_id END,
           e.created_at, e.created_at
      FROM project_enforcements e
      JOIN (
        SELECT value AS recipient FROM json_each(?2)
        UNION
        SELECT m.github_id FROM points_revisions r
          JOIN points_members m ON m.actor_id = json_extract(r.payload, '$.award.actor.id')
         WHERE json_extract(r.payload, '$.award.projectId') =
               (SELECT project_id FROM project_enforcements WHERE id = ?1)
           AND json_extract(r.payload, '$.award.amount') > 0
           AND NOT EXISTS (SELECT 1 FROM points_revisions successor WHERE successor.previous = r.id)
        UNION
        SELECT github_user_id FROM payment_obligations
         WHERE project_id = (SELECT project_id FROM project_enforcements WHERE id = ?1)
        UNION
        SELECT github_user_id FROM payment_direct_transfers
         WHERE project_id = (SELECT project_id FROM project_enforcements WHERE id = ?1)
      ) audience
     WHERE e.id = ?1 AND e.action = 'ban' AND e.actor_role = 'vetting-service'
       AND ${GITHUB_ID("audience.recipient")}
    ${ONCE}`,
    )
    .bind(recordId, JSON.stringify(operatorGithubIds));
}

/**
 * A reinstatement request reaches the moderators who may decide it: the
 * caller passes only those who did not place the restriction (ELG-02).
 */
export function notifyReinstatementReviewers<S>(
  db: Preparer<S>,
  recordId: string,
  reviewers: readonly string[],
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'reinstatement-review:' || e.id, r.value, 'reinstatement_review',
              e.project_id, NULL, '/admin', e.created_at, e.created_at
         FROM project_enforcements e, json_each(?2) r
        WHERE e.id = ?1 AND e.action = 'request_reinstatement'
          AND r.value <> e.actor_github_id AND ${GITHUB_ID("r.value")}
       ${ONCE}`,
    )
    .bind(recordId, JSON.stringify(reviewers));
}

/**
 * Two distinct contributor flags paused the project (PRD sections 4 and 8).
 * The pause is the `quarantine` enforcement record; the caller asserts that
 * flags caused it. The project's owners get `project_paused_by_flags` under
 * the record's enforcement event key, so this replaces, never duplicates,
 * `notifyProjectEnforcement` for that record. Each moderator in `moderators`
 * gets one `flag_pause_review` notice. Neither notice carries the flag
 * evidence or the reporters.
 */
export function notifyProjectFlagPause<S>(
  db: Preparer<S>,
  recordId: string,
  moderators: readonly string[],
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'project-enforcement:' || e.id, owners.recipient,
              'project_paused_by_flags', e.project_id, NULL,
              '/projects/' || e.project_id, e.created_at, e.created_at
         FROM project_enforcements e
         JOIN ${PROJECT_OWNERS("(SELECT project_id FROM project_enforcements WHERE id = ?1)")} owners
        WHERE e.id = ?1 AND e.action = 'quarantine'
          AND ${GITHUB_ID("owners.recipient")}
       UNION ALL
       SELECT 'flag-pause-review:' || e.id, m.value, 'flag_pause_review',
              e.project_id, NULL, '/admin', e.created_at, e.created_at
         FROM project_enforcements e, json_each(?2) m
        WHERE e.id = ?1 AND e.action = 'quarantine' AND ${GITHUB_ID("m.value")}
       ${ONCE}`,
    )
    .bind(recordId, JSON.stringify(moderators));
}

/**
 * A private security case event (SEC-09). The row holds only the private case
 * reference and a sign-in link: no project, title, severity, amount, reason
 * or advisory. It is written only when this request's own audit event landed
 * at `revision`, so a stale or replayed request writes nothing, and never to
 * the person who acted. `awardState` additionally requires that award state
 * after the change.
 */
export function notifySecurityCase<S>(
  db: Preparer<S>,
  input: {
    caseId: string;
    revision: number;
    idempotencyKey: string;
    recipients: readonly string[];
    awardState?: string;
  },
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'security-case:' || e.case_id || ':' || e.case_revision, r.value,
              'security_case', e.case_id, NULL, '/security', e.at, e.at
         FROM security_case_events e, json_each(?4) r
        WHERE e.case_id = ?1 AND e.case_revision = ?2
          AND e.idempotency_key = ?3 AND r.value <> e.actor_github_id
          AND ${GITHUB_ID("r.value")}
          AND (?5 IS NULL OR (SELECT award_state FROM security_cases
                               WHERE id = e.case_id) = ?5)
       ${ONCE}`,
    )
    .bind(
      input.caseId,
      input.revision,
      input.idempotencyKey,
      JSON.stringify(input.recipients),
      input.awardState ?? null,
    );
}

/**
 * Verified receipt of a private report reaches its reporter once per case
 * (PRD section 8). The row holds only the private case reference and a
 * sign-in link. Its private mail uses the receipt template, which asks for
 * no acknowledgment and never escalates for a missed one.
 */
export function notifySecurityReportReceived<S>(
  db: Preparer<S>,
  caseId: string,
): S {
  return db
    .prepare(
      `${INSERT}
       SELECT 'security-receipt:' || c.id, c.reporter_github_id,
              'security_report_received', c.id, NULL, '/security',
              c.verified_at, c.verified_at
         FROM security_cases c
        WHERE c.id = ? AND c.submission_state = 'verified'
          AND c.verified_at IS NOT NULL
          AND ${GITHUB_ID("c.reporter_github_id")}
       ${ONCE}`,
    )
    .bind(caseId);
}
