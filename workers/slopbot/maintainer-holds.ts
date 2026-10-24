// An uncertain finding goes to the maintainer first (PRD section 5). After
// MAINTAINER_HOLD_DAYS without maintainer action, Slopbot adds its label only.
import type { Category, Job } from "./contracts";
import type { D1Database } from "./persistence";

export const MAINTAINER_HOLD_DAYS = 7;
const REQUEUE_AFTER_MS = 24 * 60 * 60 * 1000;

type ReviewJob = Extract<Job, { kind: "review" }>;
export type HoldJob = Extract<Job, { kind: "maintainer_hold" }>;
export type Hold = {
  review_key: string;
  item_node_id: string;
  revision: string;
  category: Category;
  held_at: string;
  due_at: string;
};

export async function recordMaintainerHold(
  db: D1Database,
  reviewKey: string,
  job: ReviewJob,
  item: { nodeId: string; revision: string; category: Category },
): Promise<string> {
  const heldAt = new Date();
  const dueAt = new Date(
    heldAt.getTime() + MAINTAINER_HOLD_DAYS * 24 * 60 * 60 * 1000,
  );
  // Serialize only the queue contract, never verdicts or source text.
  const hold: HoldJob = {
    kind: "maintainer_hold",
    reviewKey,
    deliveryId: `hold:${reviewKey}`,
    installationId: job.installationId,
    repositoryId: job.repositoryId,
    owner: job.owner,
    repo: job.repo,
    itemKind: job.itemKind,
    number: job.number,
  };
  // A retried review keeps the first hold and its original deadline.
  await db
    .prepare(
      `INSERT OR IGNORE INTO slopbot_maintainer_holds
       (review_key, job_json, item_node_id, revision, category, held_at, due_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      reviewKey,
      JSON.stringify(hold),
      item.nodeId,
      item.revision,
      item.category,
      heldAt.toISOString(),
      dueAt.toISOString(),
    )
    .run();
  const row = await db
    .prepare("SELECT due_at FROM slopbot_maintainer_holds WHERE review_key = ?")
    .bind(reviewKey)
    .first<{ due_at: string }>();
  if (!row) throw new Error("Maintainer hold was not stored");
  return row.due_at;
}

/** Queue each due hold. A lost queue message is sent again after a day; the
 * one-time resolution and the unique label action prevent a duplicate label.
 */
export async function dispatchMaintainerHolds(
  db: D1Database,
  queue: { send(job: Job): Promise<void> },
): Promise<number> {
  const at = new Date();
  const result = await db
    .prepare(
      `SELECT json_group_array(json(job_json)) AS items FROM (
      SELECT job_json FROM slopbot_maintainer_holds
      WHERE resolved_at IS NULL AND due_at <= ? AND (queued_at IS NULL OR queued_at <= ?)
      ORDER BY due_at, review_key LIMIT 100)`,
    )
    .bind(
      at.toISOString(),
      new Date(at.getTime() - REQUEUE_AFTER_MS).toISOString(),
    )
    .first<{ items: string }>();
  const pending = JSON.parse(result?.items ?? "[]") as HoldJob[];
  for (const job of pending) {
    await queue.send(job);
    await db
      .prepare(
        "UPDATE slopbot_maintainer_holds SET queued_at = ? WHERE review_key = ? AND resolved_at IS NULL",
      )
      .bind(at.toISOString(), job.reviewKey)
      .run();
  }
  return pending.length;
}

export async function openHold(
  db: D1Database,
  reviewKey: string,
): Promise<Hold | null> {
  return db
    .prepare(
      "SELECT review_key, item_node_id, revision, category, held_at, due_at FROM slopbot_maintainer_holds WHERE review_key = ? AND resolved_at IS NULL",
    )
    .bind(reviewKey)
    .first<Hold>();
}

export async function resolveHold(
  db: D1Database,
  reviewKey: string,
  outcome: "labeled" | "maintainer_acted" | "superseded",
) {
  await db
    .prepare(
      "UPDATE slopbot_maintainer_holds SET resolved_at = ?, outcome = ? WHERE review_key = ? AND resolved_at IS NULL",
    )
    .bind(new Date().toISOString(), outcome, reviewKey)
    .run();
}
