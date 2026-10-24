// The one published penalty table (owner decision D7, PRD section 11). Units
// are Slop Score thirds. A debit applies once per pull request and reverses
// once, on an upheld appeal or a maintainer reopen. A closure alone never
// authorizes a debit: only a confirmed close of a closure-eligible author
// (D6) reaches recordPenalty. Changes to this table apply prospectively.
import type { Category } from "./contracts";
import type { D1Database } from "./persistence";

export const PENALTY_TABLE_VERSION = "slopbot-penalties-v1";

export type PenaltyRule = {
  /** "label" means Slopbot never closes this category. */
  action: "close" | "label";
  debitThirds: number;
  moderatorReview: boolean;
};

const NO_DEBIT: PenaltyRule = {
  action: "close",
  debitThirds: 0,
  moderatorReview: false,
};
// A clear violation of a project rule that the verdict quotes verbatim.
const QUOTED_RULE: PenaltyRule = {
  action: "close",
  debitThirds: 1,
  moderatorReview: false,
};

export const PENALTY_TABLE: Readonly<
  Record<Exclude<Category, "none">, PenaltyRule>
> = {
  spam: { action: "close", debitThirds: 3, moderatorReview: false },
  scam: { action: "close", debitThirds: 24, moderatorReview: true },
  low_quality: NO_DEBIT,
  duplicate: NO_DEBIT,
  out_of_scope: { action: "label", debitThirds: 0, moderatorReview: false },
  busywork: QUOTED_RULE,
  gaming: QUOTED_RULE,
  // Not in the published table: no debit.
  empty: NO_DEBIT,
  missing_evidence: NO_DEBIT,
};

export function penaltyFor(category: Category): PenaltyRule | null {
  return category === "none" ? null : PENALTY_TABLE[category];
}

export type Penalty = {
  item_node_id: string;
  author_github_id: string;
  category: Category;
  debit_thirds: number;
  period: string;
  moderator_review: number;
  reversed_at: string | null;
};

/** Records the table debit for one confirmed close. A replay or retry of the
 * same pull request keeps the first row. Returns null when the table sets no
 * debit. The row carries the UTC month of the close; the score that consumes
 * it never takes that month below zero and never changes an approved,
 * scheduled or paid award.
 */
export async function recordPenalty(
  db: D1Database,
  input: {
    itemNodeId: string;
    repositoryId: number;
    projectId: string;
    authorId: number;
    category: Category;
    reviewKey: string;
    closedAt: Date;
  },
): Promise<Penalty | null> {
  const rule = penaltyFor(input.category);
  if (rule === null || rule.debitThirds === 0) return null;
  await db
    .prepare(
      `INSERT OR IGNORE INTO slopbot_penalties
       (item_node_id, repository_id, project_id, author_github_id, category,
        table_version, debit_thirds, period, moderator_review, review_key, recorded_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.itemNodeId,
      input.repositoryId,
      input.projectId,
      String(input.authorId),
      input.category,
      PENALTY_TABLE_VERSION,
      rule.debitThirds,
      input.closedAt.toISOString().slice(0, 7),
      rule.moderatorReview ? 1 : 0,
      input.reviewKey,
      new Date().toISOString(),
    )
    .run();
  return activePenalty(db, input.itemNodeId);
}

export async function activePenalty(
  db: D1Database,
  itemNodeId: string,
): Promise<Penalty | null> {
  return db
    .prepare(
      `SELECT item_node_id, author_github_id, category, debit_thirds, period,
        moderator_review, reversed_at
       FROM slopbot_penalties WHERE item_node_id = ? AND reversed_at IS NULL`,
    )
    .bind(itemNodeId)
    .first<Penalty>();
}

/** Reverses the debit once. Later appeals, reopens and retries change nothing. */
export async function reversePenalty(
  db: D1Database,
  itemNodeId: string,
  reason: "appeal_upheld" | "maintainer_reopen",
): Promise<boolean> {
  const result = await db
    .prepare(
      "UPDATE slopbot_penalties SET reversed_at = ?, reversal = ? WHERE item_node_id = ? AND reversed_at IS NULL",
    )
    .bind(new Date().toISOString(), reason, itemNodeId)
    .run();
  return (result.meta?.changes ?? 0) === 1;
}
