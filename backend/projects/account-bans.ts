import type { D1Database } from "../d1";

/** One bound GitHub ID; also used inside writes to close decision races. */
export const PARTICIPATION_BAN_QUERY = `    SELECT 1 AS banned, e.id AS enforcementId FROM project_maintainer_bans b
    JOIN project_enforcements e ON e.id = b.enforcement_id
    WHERE b.github_id = ? AND NOT EXISTS (
      SELECT 1 FROM project_account_reinstatements released
      WHERE released.ban_enforcement_id = b.enforcement_id
        AND released.github_id = b.github_id
    ) LIMIT 1
`;

/** Account decisions use immutable GitHub IDs, never a current project role. */
export async function hasParticipationBan(
  db: D1Database,
  githubId: string,
): Promise<boolean> {
  return (
    (await db
      .prepare(PARTICIPATION_BAN_QUERY)
      .bind(githubId)
      .first<{ banned: number }>()) !== null
  );
}
