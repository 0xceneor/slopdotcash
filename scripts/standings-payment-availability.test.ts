import { expect, test } from "bun:test";
import { contributorStandings } from "../src/lib/contributor-standings";
import type { DirectTransfer } from "../src/lib/payments/contracts";
import type { DataState } from "../src/lib/use-snapshot";
import { archivedPaidCycleIndex, snapshotFixture } from "../tests/fixtures";

const state: DataState = {
  status: "ready",
  snapshot: snapshotFixture(),
  views: [],
  cycleIndex: archivedPaidCycleIndex(),
};
const payment: DirectTransfer = {
  projectId: "eliza",
  contributionMonth: "2026-07",
  githubUserId: "101",
  login: "direct-recipient",
  network: "base-mainnet",
  chain: "base",
  recipient: "fixture-recipient",
  amountMicro: "2000000",
  transactionId: "fixture-transaction",
  blockTime: "2026-08-16T00:00:00.000Z",
};

test("an unavailable direct-payment source does not publish partial Paid totals", () => {
  const result = contributorStandings(state, null, null, "eliza");
  const archived = result.rows.find((row) => row.actor.id === "U_archived");
  expect(archived?.points).toBeNull();
  expect(archived?.money).toBeNull();
});

test("a completed empty direct-payment source retains verified cycle payments", () => {
  const result = contributorStandings(state, null, null, "eliza", []);
  expect(result.rows.find((row) => row.actor.id === "U_archived")?.money).toBe(
    1_000_000n,
  );
});

test("a recovered source restores Paid ordering without manufacturing points", () => {
  const result = contributorStandings(state, null, null, "eliza", [payment]);
  const paid = result.rows
    .filter((row) => row.money !== null && row.money > 0n)
    .sort((a, b) => ((a.money ?? 0n) > (b.money ?? 0n) ? -1 : 1));
  expect(paid.map((row) => [row.actor.login, row.money])).toEqual([
    ["direct-recipient", 2_000_000n],
    ["archive-only", 1_000_000n],
  ]);
  expect(paid.find((row) => row.actor.id === "U_archived")?.points).toBeNull();
});
