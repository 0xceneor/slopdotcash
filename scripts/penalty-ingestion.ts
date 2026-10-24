/**
 * Reads the unreversed Slopbot penalty debits (PRD section 7) for each UTC
 * month that the score window overlaps, from the hosted Slopbot feed, and
 * resolves each author to the GitHub identity that the score ledger uses.
 * Read only: no model calls, no D1 write and no payment authority. A feed
 * outage is a ValueFeedUnavailableError, so the release keeps the last
 * published snapshot; it never publishes a score without its debits.
 */
import { canonicalActorAvatarUrl } from "../src/lib/leaderboard";
import type { ScorePenalty } from "../src/lib/leaderboard-types";
import {
  TARGET_REPOSITORIES,
  type TargetRepository,
} from "../src/lib/repositories.mjs";
import type { GitHubClient } from "../workers/slopbot/github";
import {
  PENALTY_FEED_PAGE_SIZE,
  PENALTY_FEED_SCHEMA,
  type PenaltyFeedRecord,
} from "../workers/slopbot/penalties";
import { fetchHostedJson } from "./value-ingestion";

const FEED_ORIGIN = "https://slopbot.slop.cash";
const MAX_PAGES_PER_MONTH = 100;

/** Every `YYYY-MM` from the month of `from` through the month of `to`. */
export function windowPeriods(from: string, to: string): string[] {
  const periods: string[] = [];
  const end = to.slice(0, 7);
  const cursor = new Date(`${from.slice(0, 7)}-01T00:00:00.000Z`);
  while (cursor.toISOString().slice(0, 7) <= end) {
    periods.push(cursor.toISOString().slice(0, 7));
    cursor.setUTCMonth(cursor.getUTCMonth() + 1);
  }
  return periods;
}

const positiveInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) > 0;

type FeedRecord = PenaltyFeedRecord & {
  itemKind: "issue" | "pull_request";
  itemNumber: number;
};

function assertFeedRecord(
  value: unknown,
  period: string,
): asserts value is FeedRecord {
  const record = value as Record<string, unknown> | null;
  if (
    typeof record !== "object" ||
    record === null ||
    typeof record.itemNodeId !== "string" ||
    record.itemNodeId.length === 0 ||
    !positiveInteger(record.repositoryId) ||
    (record.itemKind !== "issue" && record.itemKind !== "pull_request") ||
    !positiveInteger(record.itemNumber) ||
    !positiveInteger(record.authorGithubId) ||
    typeof record.category !== "string" ||
    typeof record.tableVersion !== "string" ||
    !positiveInteger(record.debitThirds) ||
    record.period !== period ||
    typeof record.recordedAt !== "string" ||
    !Number.isFinite(Date.parse(record.recordedAt)) ||
    new Date(record.recordedAt).toISOString() !== record.recordedAt ||
    record.recordedAt.slice(0, 7) !== period
  )
    throw new Error("Penalty feed record is invalid");
}

async function feedMonth(period: string, transport: typeof fetch) {
  const records: FeedRecord[] = [];
  let after = "";
  for (let page = 0; page < MAX_PAGES_PER_MONTH; page += 1) {
    const url = new URL("/v1/penalties", FEED_ORIGIN);
    url.searchParams.set("period", period);
    url.searchParams.set("after", after);
    const body = (await fetchHostedJson(
      url,
      transport,
      "Penalty feed",
    )) as Record<string, unknown> | null;
    if (
      body?.schemaVersion !== PENALTY_FEED_SCHEMA ||
      body.period !== period ||
      !Array.isArray(body.records) ||
      body.records.length > PENALTY_FEED_PAGE_SIZE ||
      !(
        body.nextAfter === null ||
        (typeof body.nextAfter === "string" && body.nextAfter > after)
      )
    )
      throw new Error("Penalty feed page has invalid identity or pagination");
    for (const record of body.records) {
      assertFeedRecord(record, period);
      if (record.itemNodeId <= after)
        throw new Error("Penalty feed records are out of order");
      after = record.itemNodeId;
      records.push(record);
    }
    if (body.nextAfter === null) return records;
    if (body.nextAfter !== after)
      throw new Error("Penalty feed cursor skips records");
  }
  throw new Error("Penalty feed exceeds its page bound");
}

export async function loadPenaltyInputs(
  github: Pick<GitHubClient, "get">,
  window: { from: string; to: string },
  transport: typeof fetch = fetch,
): Promise<ScorePenalty[]> {
  const records: Awaited<ReturnType<typeof feedMonth>> = [];
  for (const period of windowPeriods(window.from, window.to))
    records.push(...(await feedMonth(period, transport)));
  if (records.length === 0) return [];
  // D1 keys a debit by GitHub's numeric repository ID; the score keys it by
  // the registry identity. Each collected repository is resolved once.
  const repositories = new Map<number, TargetRepository>();
  for (const repository of TARGET_REPOSITORIES) {
    const live = await github.get<{ id?: unknown; node_id?: unknown }>(
      `/repos/${repository.owner}/${repository.name}`,
    );
    if (
      !live ||
      !positiveInteger(live.id) ||
      (repository.expectedNodeId !== null &&
        live.node_id !== repository.expectedNodeId)
    )
      throw new Error(
        `Penalty ingestion cannot resolve ${repository.id} on GitHub`,
      );
    repositories.set(live.id, repository);
  }
  const actors = new Map<number, ScorePenalty["actor"] | null>();
  const penalties: ScorePenalty[] = [];
  for (const record of records) {
    // A repository outside the collected registry is outside every score.
    const repository = repositories.get(record.repositoryId);
    if (!repository) continue;
    if (!actors.has(record.authorGithubId)) {
      const user = await github.get<Record<string, unknown>>(
        `/user/${record.authorGithubId}`,
      );
      if (
        user !== null &&
        (user.id !== record.authorGithubId ||
          typeof user.node_id !== "string" ||
          typeof user.login !== "string" ||
          typeof user.avatar_url !== "string" ||
          typeof user.html_url !== "string")
      )
        throw new Error("GitHub penalty author identity is incomplete");
      actors.set(
        record.authorGithubId,
        user === null
          ? null
          : {
              id: user.node_id as string,
              login: user.login as string,
              avatarUrl: canonicalActorAvatarUrl(user.avatar_url as string),
              url: user.html_url as string,
              kind: user.type === "User" ? "User" : "Unknown",
            },
      );
    }
    // A deleted account has no score left to reduce.
    const actor = actors.get(record.authorGithubId);
    if (!actor) continue;
    const pull = record.itemKind === "pull_request";
    penalties.push({
      id: record.itemNodeId,
      actor,
      repository: repository.id,
      period: record.period,
      occurredAt: record.recordedAt,
      category: record.category,
      tableVersion: record.tableVersion,
      debitThirds: record.debitThirds,
      source: {
        kind: pull ? "pull-request" : "issue",
        number: record.itemNumber,
        url: `https://github.com/${repository.owner}/${repository.name}/${pull ? "pull" : "issues"}/${record.itemNumber}`,
      },
    });
  }
  return penalties;
}
