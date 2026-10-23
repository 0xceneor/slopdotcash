// Automatic closure scope (PRD section 5): only verified slop.cash members
// using the Slop skill, never project maintainers. This is an authority
// boundary, separate from the review itself: advisory review stays broad.
import type { Exemption } from "./github";
import type { D1Database } from "./persistence";

export type ClosureEvidence = {
  itemKind: "issue" | "pull_request";
  exemption: Exemption;
  /** A slop.cash member record matched by the author's immutable GitHub ID. */
  member: boolean;
  /** An authenticated Slop skill run by the same author linked to this PR. */
  verifiedSkillRun: boolean;
};

export type ClosureEligibility =
  | { eligible: true; why: string }
  | { eligible: false; why: string };

/** Every condition must hold. The "Made via @slopdotcash" marker is never an
 * input: anyone can paste it, so it proves neither membership nor authorship.
 */
export function closureEligibility(
  evidence: ClosureEvidence,
): ClosureEligibility {
  if (evidence.exemption === "exempt")
    return { eligible: false, why: "maintainers are never closed by Slopbot" };
  if (evidence.exemption !== "not-exempt")
    return { eligible: false, why: "maintainer status unknown" };
  // The Slop skill submits pull requests only; it never opens issues.
  if (evidence.itemKind !== "pull_request")
    return {
      eligible: false,
      why: "only Slop-skill pull requests can be closed",
    };
  if (!evidence.member)
    return {
      eligible: false,
      why: "author is not a verified slop.cash member",
    };
  if (!evidence.verifiedSkillRun)
    return {
      eligible: false,
      why: "no verified Slop skill run for this pull request",
    };
  return { eligible: true, why: "verified Slop-skill participant" };
}

export async function isMember(
  db: D1Database,
  githubId: number,
): Promise<boolean> {
  const row = await db
    .prepare("SELECT 1 AS ok FROM points_members WHERE github_id = ?")
    .bind(String(githubId))
    .first();
  return row !== null;
}

/** A run the author created through an authenticated Slop session for this
 * project's repository, whose recorded pull_request_opened event names this
 * exact pull request. The session comes from the author's own GitHub login, so
 * a copied marker, receipt or footer cannot produce this record for another
 * person. GitHub-sourced events are written only by the webhook processor.
 */
export async function hasVerifiedSkillRun(
  db: D1Database,
  item: {
    authorId: number;
    projectId: string;
    owner: string;
    repo: string;
    number: number;
    nodeId: string;
  },
): Promise<boolean> {
  const repository = `${item.owner}/${item.repo}`.toLowerCase();
  const row = await db
    .prepare(`SELECT 1 AS ok FROM run_progress_events e
      JOIN trace_runs r ON r.id = e.run_id AND r.github_user_id = e.github_user_id
      WHERE e.github_user_id = ? AND e.kind = 'pull_request_opened'
        AND r.project_id = ? AND lower(r.repository) = ?
        AND (e.github_object_id = ? OR lower(e.github_url) = ?)
      LIMIT 1`)
    .bind(
      String(item.authorId),
      item.projectId,
      repository,
      item.nodeId,
      `https://github.com/${repository}/pull/${item.number}`,
    )
    .first();
  return row !== null;
}
