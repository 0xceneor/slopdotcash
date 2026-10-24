/** Real migrations and registry tables; GitHub authority is a controlled stub here (see scripts/owner-award-authority.test.ts). */

import type { Database } from "bun:sqlite";
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";
import { monthlyBasesSql } from "../../scripts/prepare-monthly-rewards";
import type { PaymentsAccount } from "../../src/lib/payments/contracts";
import { escrowAwardOrigin } from "../../src/lib/payments/escrow-cycle";
import { parseMonthlySchedule } from "../../src/lib/payments/monthly-allocation";
import type { ProjectRecord } from "../../src/lib/project-contracts";
import { sqliteD1 } from "../../tests/sqlite-d1";
import { sha256Hex } from "../../workers/identity/crypto";
import type { JournalStore } from "../../workers/payment-executor/core";
import { signMonthlyAllocation } from "../../workers/payment-executor/monthly";
import { runMonthlyCoordinator } from "../../workers/payments/index";
import {
  CloudflareProjectPersistence,
  type ProjectD1Database,
} from "../projects/cloudflare-persistence";
import { handlePaymentsApi } from "./handler";
import {
  coordinateMonthlyPayments,
  MonthlyPaymentError,
  monthlyOwnerService,
} from "./monthly";
import { prepareMonthlyAttestation } from "./monthly-attestation";

const testAttester = privateKeyToAccount(`0x${"01".repeat(32)}`);
const deployment = {
  network: "base-sepolia",
  vault: "0x1000000000000000000000000000000000000001",
  programId: null,
  upgradeAuthority: null,
  projectPda: null,
  networkDomain: null,
  asset: "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
  owner: "0x2000000000000000000000000000000000000002",
  identityAuthority: testAttester.address.toLowerCase(),
  feeRecipient: "0x4000000000000000000000000000000000000004",
  deploymentTransaction: `0x${"ab".repeat(32)}`,
  sourceCommit: "0123456789abcdef0123456789abcdef01234567",
  codeSha256: "ab".repeat(32),
  bindingDelaySeconds: "60",
  rotationDelaySeconds: null,
  factory: "0x5000000000000000000000000000000000000005",
  factoryCodeSha256: "cd".repeat(32),
  registrar: "0x6000000000000000000000000000000000000006",
};
const OWNER = "900000071";
const A = "101";
const B = "202";
// Owner decision D1, read from the reviewed Pages configuration: the cutoff of
// 2026-11 is 72 hours after the month ends.
const schedule = parseMonthlySchedule(
  (
    Bun.TOML.parse(readFileSync("wrangler.toml", "utf8")) as {
      vars: Record<string, string>;
    }
  ).vars.MONTHLY_PAYMENT_SCHEDULE,
);
const beforeCutoff = new Date("2026-12-03T23:30:00.000Z");
const afterCutoff = new Date("2026-12-04T00:00:00.000Z");

let db: ProjectD1Database;
let sqlite: Database;
let project: ProjectRecord;
let restricted = false;
let clock = afterCutoff;

beforeEach(async () => {
  ({ db, sqlite } = sqliteD1(
    readdirSync("migrations")
      .filter((name) => name.endsWith(".sql"))
      .sort(),
  ));
  const manifest = JSON.parse(
    readFileSync("tests/fixtures/projects/eliza.json", "utf8"),
  );
  manifest.reward.feeBasisPoints = 200;
  manifest.reward.chain = "base";
  manifest.escrow = {
    schemaVersion: "1",
    effectiveCycle: "2026-11",
    chain: "base",
    feeBasisPoints: 200,
    withdrawalFeeBasisPoints: 200,
    feeMode: "deduct-from-gross",
    deployments: [deployment],
  };
  const text = JSON.stringify(manifest);
  const digest = await sha256Hex(text);
  sqlite
    .prepare(
      "INSERT INTO project_revisions(project_id,revision,manifest,manifest_sha256,reason,created_at) VALUES(?,1,?,?,?,?)",
    )
    .run(manifest.id, text, digest, "Fixture", "2026-10-01T00:00:00.000Z");
  sqlite
    .prepare(
      "INSERT INTO projects(id,status,revision,manifest,manifest_sha256,created_at,updated_at) VALUES(?,?,1,?,?,?,?)",
    )
    .run(
      manifest.id,
      manifest.status,
      text,
      digest,
      "2026-10-01T00:00:00.000Z",
      "2026-10-01T00:00:00.000Z",
    );
  const stored = await new CloudflareProjectPersistence(db).getProject(
    manifest.id,
  );
  if (!stored) throw new Error("fixture project missing");
  project = stored;
  sqlite.exec(
    monthlyBasesSql(
      {
        period: "2026-11",
        skipped: [],
        bases: [
          {
            projectId: project.id,
            period: "2026-11",
            manifest: text,
            manifestSha256: digest,
            sourceSnapshotSha256: "5".repeat(64),
            capBase: "1000",
            rows: [
              {
                githubUserId: A,
                login: "first",
                grossBase: "600",
                sourceDigest: escrowAwardOrigin(project.id, "2026-11", A),
              },
              {
                githubUserId: B,
                login: "second",
                grossBase: "400",
                sourceDigest: escrowAwardOrigin(project.id, "2026-11", B),
              },
            ],
          },
        ],
      },
      "2026-12-01T00:11:00.000Z",
    ),
  );
  restricted = false;
  clock = afterCutoff;
});
afterEach(() => sqlite.close());

const projects = () => ({
  getProject: (id: string) =>
    new CloudflareProjectPersistence(db).getProject(id),
  restricted: async () => restricted,
});
const coordinate = (now: Date, configured = schedule) =>
  coordinateMonthlyPayments({
    db,
    projects: projects(),
    networks: ["base-sepolia"],
    schedule: configured,
    now,
  });
const owner = () =>
  monthlyOwnerService({
    db,
    ...projects(),
    networks: () => ["base-sepolia"],
    verifyAuthority: async () => {},
    schedule: () => schedule,
    now: () => clock,
  });
const actor = { githubId: OWNER, githubLogin: "owner" };
function vault(free: string, observedAt = afterCutoff.toISOString()) {
  sqlite
    .prepare(
      "INSERT INTO vault_snapshots(project_id,network,chain,vault,asset_address,asset_decimals,total_deposited,total_paid,total_payout_fees,total_gross_withdrawn,total_withdrawal_fees,total_service_fees,free_balance,reserved_principal,reserved_fees,accrued_fees,reserved,block_number,block_time,observed_at) VALUES(?,?,?,?,?,6,'5000','0','0','0','0','0',?,'0','0','0','0','100',?,?) ON CONFLICT(project_id,network,vault) DO UPDATE SET free_balance=excluded.free_balance,observed_at=excluded.observed_at,block_number=CAST(CAST(block_number AS INTEGER)+1 AS TEXT)",
    )
    .run(
      project.id,
      "base-sepolia",
      "base",
      deployment.vault,
      deployment.asset,
      free,
      observedAt,
      observedAt,
    );
}
const count = (table: string) =>
  (sqlite.prepare(`SELECT COUNT(*) n FROM ${table}`).get() as { n: number }).n;
async function rejects(promise: Promise<unknown>, code: string) {
  const error = await promise.then(
    () => null,
    (reason: unknown) => reason,
  );
  expect(error).toBeInstanceOf(MonthlyPaymentError);
  expect((error as MonthlyPaymentError).code).toBe(code);
}

describe("monthly coordinator", () => {
  test("freezes the current private allocations once at the cutoff and creates each obligation once when funded", async () => {
    clock = beforeCutoff;
    const changed = await owner().changeAllocation(
      project.id,
      "2026-11",
      actor,
      {
        githubUserId: B,
        grossBase: "300",
        expectedSequence: 0,
      },
    );
    expect(changed.proposal?.allocations.map((row) => row.grossBase)).toEqual([
      "600",
      "300",
    ]);
    expect((await coordinate(beforeCutoff)).frozen).toEqual([]);
    expect(count("monthly_payment_runs")).toBe(0);

    const first = await coordinate(afterCutoff);
    expect(first.frozen).toEqual([`${project.id}/2026-11`]);
    // No finalized vault reading yet: nothing is created.
    expect(first.waiting).toEqual([
      { key: `${project.id}/2026-11`, reason: "stale-funding" },
    ]);
    vault("899");
    expect((await coordinate(afterCutoff)).waiting).toEqual([
      { key: `${project.id}/2026-11`, reason: "underfunded" },
    ]);
    expect((await coordinate(afterCutoff)).waiting).toEqual([
      { key: `${project.id}/2026-11`, reason: "underfunded" },
    ]);
    expect(count("monthly_payment_obligations")).toBe(0);
    // The steward gets one Inbox payout exception for the month, however
    // often the coordinator retries; it names no amount or contributor.
    expect(
      sqlite
        .prepare(
          "SELECT event_key,recipient_github_id,kind,subject,action_path FROM notifications",
        )
        .all(),
    ).toEqual([
      {
        event_key: `monthly-underfunded:${project.id}:2026-11`,
        recipient_github_id: project.manifest.steward.github.actorId,
        kind: "payout_exception",
        subject: project.id,
        action_path: `/projects/${project.id}/awards`,
      },
    ]);
    vault("900");
    expect((await coordinate(afterCutoff)).created).toEqual([
      `${project.id}/2026-11`,
    ]);
    const again = await coordinate(afterCutoff);
    expect([again.frozen, again.created, again.waiting]).toEqual([[], [], []]);
    expect(
      sqlite
        .prepare(
          "SELECT github_user_id,gross_base,fee_base,source_digest FROM monthly_payment_obligations ORDER BY github_user_id",
        )
        .all(),
    ).toEqual([
      {
        github_user_id: A,
        gross_base: "600",
        fee_base: "12",
        source_digest: escrowAwardOrigin(project.id, "2026-11", A),
      },
      {
        github_user_id: B,
        gross_base: "300",
        fee_base: "6",
        source_digest: escrowAwardOrigin(project.id, "2026-11", B),
      },
    ]);
    // A finalized month accepts no change, through the service or directly.
    await rejects(
      owner().changeAllocation(project.id, "2026-11", actor, {
        githubUserId: B,
        grossBase: "1",
        expectedSequence: 1,
      }),
      "month_frozen",
    );
    expect(() =>
      sqlite
        .prepare(
          "INSERT INTO monthly_allocation_changes VALUES(?,?,2,?,'1',?,?)",
        )
        .run(project.id, "2026-11", B, OWNER, afterCutoff.toISOString()),
    ).toThrow("monthly allocations frozen");
    // The owner's late finalization reuses the automatic snapshot.
    const view = await owner().finalize(project.id, "2026-11", actor, 1);
    expect(view.run?.trigger).toBe("automatic");
    expect(count("monthly_payment_runs")).toBe(1);
    expect(view.run?.awards.map((award) => award.state)).toEqual([
      "awaiting-reservation",
      "awaiting-reservation",
    ]);
  });

  test("a contributor's account shows the approved monthly award from the freeze until the vault reserves it", async () => {
    const token = "c".repeat(43);
    sqlite
      .prepare(
        "INSERT INTO points_members(actor_id,github_id,login,joined_at,public) VALUES('node-first',?,'first',?,0)",
      )
      .run(A, afterCutoff.toISOString());
    sqlite
      .prepare("INSERT INTO points_sessions VALUES(?,?,?)")
      .run(await sha256Hex(token), "node-first", "2027-01-01T00:00:00.000Z");
    const account = async () =>
      (await (
        await handlePaymentsApi(
          new Request("https://slop.cash/api/v1/payments/me", {
            headers: { cookie: `__Host-slop_points=${token}` },
          }),
          { db, now: () => clock },
        )
      ).json()) as PaymentsAccount;
    // A proposal under the owner's review is private; nothing is shown.
    expect((await account()).monthlyAwards).toEqual([]);
    await coordinate(afterCutoff);
    vault("899");
    expect((await coordinate(afterCutoff)).waiting).toEqual([
      { key: `${project.id}/2026-11`, reason: "underfunded" },
    ]);
    const award = {
      projectId: project.id,
      period: "2026-11",
      network: "base-sepolia",
      chain: "base" as const,
      assetAddress: deployment.asset,
      assetDecimals: 6,
      grossBase: "600",
      feeBase: "12",
      netBase: "588",
    };
    // Approved and frozen, but the vault cannot cover the month yet.
    expect(await account()).toMatchObject({
      monthlyAwards: [{ ...award, state: "underfunded" }],
      payments: [],
      balances: [],
    });
    vault("1000");
    expect((await coordinate(afterCutoff)).created).toEqual([
      `${project.id}/2026-11`,
    ]);
    expect((await account()).monthlyAwards).toEqual([
      { ...award, state: "awaiting-reservation" },
    ]);
    // The finalized chain projection records the reservation: the award is
    // now a reserved payment that waits for the contributor's wallet.
    sqlite
      .prepare(
        "INSERT INTO payment_obligations(id,project_id,github_user_id,network,chain,vault,asset_address,asset_decimals,gross_base,fee_base,source_digest,state,created_at,paid_transaction) VALUES(?,?,?,?,?,?,?,6,'600','12',?,'reserved',?,NULL)",
      )
      .run(
        `0x${"8".repeat(64)}`,
        project.id,
        A,
        "base-sepolia",
        "base",
        deployment.vault,
        deployment.asset,
        escrowAwardOrigin(project.id, "2026-11", A),
        afterCutoff.toISOString(),
      );
    const reserved = await account();
    expect(reserved.monthlyAwards).toEqual([]);
    expect(reserved.payments).toMatchObject([
      {
        projectId: project.id,
        grossBase: "600",
        netBase: "588",
        state: "reserved",
        deliveryState: "needs_wallet",
      },
    ]);
  });

  test("without a defined cutoff nothing is frozen automatically, but the owner can finalize", async () => {
    expect((await coordinate(afterCutoff, null)).frozen).toEqual([]);
    expect(count("monthly_payment_runs")).toBe(0);
    vault("1000");
    const view = await owner().finalize(project.id, "2026-11", actor, 0);
    expect(view.run).toMatchObject({ trigger: "owner", funded: true });
    expect(count("monthly_payment_obligations")).toBe(2);
    expect((await coordinate(afterCutoff, null)).created).toEqual([]);
  });

  test("an owner who turns the default off, a restricted project and an unserved vault are not distributed automatically", async () => {
    expect(await owner().setAutomatic(project.id, actor, false)).toEqual({
      automatic: false,
    });
    expect((await coordinate(afterCutoff)).waiting).toEqual([
      { key: `${project.id}/2026-11`, reason: "automatic-off" },
    ]);
    await owner().setAutomatic(project.id, actor, true);
    restricted = true;
    expect((await coordinate(afterCutoff)).waiting).toEqual([
      { key: `${project.id}/2026-11`, reason: "project-restricted" },
    ]);
    await rejects(
      owner().finalize(project.id, "2026-11", actor, 0),
      "project_restricted",
    );
    restricted = false;
    const unserved = await coordinateMonthlyPayments({
      db,
      projects: projects(),
      networks: ["solana-devnet"],
      schedule,
      now: afterCutoff,
    });
    expect(unserved.waiting).toEqual([
      { key: `${project.id}/2026-11`, reason: "vault-not-served" },
    ]);
    expect(count("monthly_payment_runs")).toBe(0);
  });

  test("an award reserved earlier needs no new funds and cannot be planned twice", async () => {
    sqlite
      .prepare(
        "INSERT INTO payment_obligations(id,project_id,github_user_id,network,chain,vault,asset_address,asset_decimals,gross_base,fee_base,source_digest,state,created_at,paid_transaction) VALUES(?,?,?,?,?,?,?,6,'600','12',?,'reserved',?,NULL)",
      )
      .run(
        `0x${"9".repeat(64)}`,
        project.id,
        A,
        "base-sepolia",
        "base",
        deployment.vault,
        deployment.asset,
        escrowAwardOrigin(project.id, "2026-11", A),
        afterCutoff.toISOString(),
      );
    await coordinate(afterCutoff);
    vault("400");
    expect((await coordinate(afterCutoff)).created).toEqual([
      `${project.id}/2026-11`,
    ]);
    const view = await owner().view(project.id, "2026-11", actor);
    expect(view.run?.awards.map((award) => [award.login, award.state])).toEqual(
      [
        ["first", "reserved"],
        ["second", "awaiting-reservation"],
      ],
    );
    const expected = {
      network: "base-sepolia",
      manifestSha256: project.manifestSha256,
      snapshotSha256: view.run?.snapshotSha256 ?? "",
    };
    await rejects(
      owner().commitment(project.id, "2026-11", actor, {
        ...expected,
        githubUserId: A,
      }),
      "award_reserved",
    );
    const plan = await owner().commitment(project.id, "2026-11", actor, {
      ...expected,
      githubUserId: B,
    });
    expect(plan).toMatchObject({
      schemaVersion: "2",
      cycleId: "2026-11",
      deployment: { vault: deployment.vault },
      award: {
        githubUserId: B,
        sourceDigest: escrowAwardOrigin(project.id, "2026-11", B),
        gross: "400",
        fee: "8",
        net: "392",
      },
    });
    await rejects(
      owner().commitment(project.id, "2026-11", actor, {
        ...expected,
        githubUserId: B,
        snapshotSha256: "0".repeat(64),
      }),
      "snapshot_changed",
    );
  });

  test("an underfunded month has no obligation to reserve, and earlier unreserved obligations hold their funds", async () => {
    await coordinate(afterCutoff);
    vault("999");
    await coordinate(afterCutoff);
    const view = await owner().view(project.id, "2026-11", actor);
    expect(view.run?.funded).toBe(false);
    expect(view.run?.awards.map((award) => award.state)).toEqual([
      "underfunded",
      "underfunded",
    ]);
    await rejects(
      owner().commitment(project.id, "2026-11", actor, {
        network: "base-sepolia",
        manifestSha256: project.manifestSha256,
        snapshotSha256: view.run?.snapshotSha256 ?? "",
        githubUserId: A,
      }),
      "award_unfunded",
    );
    // A refreshed balance can arrive after the read but before the batch.
    vault("5000");
    const originalBatch = db.batch.bind(db);
    db.batch = async (statements) => {
      vault("0");
      return originalBatch(statements);
    };
    await coordinate(afterCutoff);
    db.batch = originalBatch;
    expect(count("monthly_payment_obligations")).toBe(0);
    expect((await owner().view(project.id, "2026-11", actor)).run?.funded).toBe(
      false,
    );
    // A stale vault reading never funds a month.
    vault("5000", "2026-11-30T00:00:00.000Z");
    expect((await coordinate(afterCutoff)).waiting).toEqual([
      { key: `${project.id}/2026-11`, reason: "stale-funding" },
    ]);
    vault("5000");
    expect((await coordinate(afterCutoff)).created).toEqual([
      `${project.id}/2026-11`,
    ]);
    expect(count("monthly_payment_obligations")).toBe(2);
  });

  test("after the cutoff the automatic default fixes the allocations until they are frozen", async () => {
    await rejects(
      owner().changeAllocation(project.id, "2026-11", actor, {
        githubUserId: B,
        grossBase: "100",
        expectedSequence: 0,
      }),
      "cutoff_passed",
    );
    await owner().setAutomatic(project.id, actor, false);
    const view = await owner().changeAllocation(project.id, "2026-11", actor, {
      githubUserId: B,
      grossBase: "100",
      expectedSequence: 0,
    });
    expect(view.proposal?.allocations.map((row) => row.grossBase)).toEqual([
      "600",
      "100",
    ]);
  });

  test("a month before the first automatic period is never frozen automatically", async () => {
    const later = parseMonthlySchedule(
      '{"firstPeriod":"2026-12","cutoffSecondsAfterPeriodEnd":259200}',
    );
    expect((await coordinate(afterCutoff, later)).waiting).toEqual([
      { key: `${project.id}/2026-11`, reason: "before-first-period" },
    ]);
    expect(count("monthly_payment_runs")).toBe(0);
  });

  test("private changes stay within the cap, never pay their author and are serialized", async () => {
    clock = beforeCutoff;
    const service = owner();
    await rejects(
      service.changeAllocation(project.id, "2026-11", actor, {
        githubUserId: B,
        grossBase: "401",
        expectedSequence: 0,
      }),
      "invalid_allocation",
    );
    const self = await service
      .changeAllocation(
        project.id,
        "2026-11",
        { githubId: A, githubLogin: "first" },
        { githubUserId: A, grossBase: "700", expectedSequence: 0 },
      )
      .catch((error: MonthlyPaymentError) => error);
    expect(self).toMatchObject({ status: 403, code: "invalid_allocation" });
    await service.changeAllocation(project.id, "2026-11", actor, {
      githubUserId: B,
      grossBase: "100",
      expectedSequence: 0,
    });
    await rejects(
      service.changeAllocation(project.id, "2026-11", actor, {
        githubUserId: A,
        grossBase: "100",
        expectedSequence: 0,
      }),
      "allocations_changed",
    );
    await rejects(
      service.finalize(project.id, "2026-11", actor, 0),
      "allocations_changed",
    );
    // The view shows current amounts, never who changed them or when.
    const view = await service.view(project.id, "2026-11", actor);
    expect(JSON.stringify(view)).not.toContain(OWNER);
    expect(view.proposal?.allocations.map((row) => row.grossBase)).toEqual([
      "600",
      "100",
    ]);
  });

  test("an open month cannot be finalized", async () => {
    clock = new Date("2026-11-30T23:00:00.000Z");
    await rejects(
      owner().finalize(project.id, "2026-11", actor, 0),
      "month_open",
    );
  });

  test("private bounty programs never run the monthly coordinator", async () => {
    expect(
      await runMonthlyCoordinator({
        PAYMENT_SCOPE: "security-bounty",
      } as never),
    ).toBeNull();
  });
});

describe("monthly attestation input", () => {
  async function prepare(
    options: { now?: Date; blocked?: boolean; digest?: string } = {},
  ) {
    const row = sqlite
      .prepare(
        "SELECT snapshot_sha256 digest FROM monthly_payment_runs WHERE project_id=? AND period=?",
      )
      .get(project.id, "2026-11") as { digest: string } | null;
    if (!schedule) throw new Error("Fixture schedule missing");
    return prepareMonthlyAttestation(
      {
        db,
        ...projects(),
        recipientsRestricted: async () => options.blocked ?? false,
        networks: ["base-sepolia"],
        schedule,
        now: options.now ?? afterCutoff,
      },
      {
        projectId: project.id,
        period: "2026-11",
        network: "base-sepolia",
        snapshotSha256: options.digest ?? row?.digest ?? "0".repeat(64),
      },
    );
  }
  test("uses only the frozen owner-adjusted awards, even after a later funding observation", async () => {
    clock = beforeCutoff;
    await owner().changeAllocation(project.id, "2026-11", actor, {
      githubUserId: B,
      grossBase: "300",
      expectedSequence: 0,
    });
    vault("2000");
    await coordinate(afterCutoff);
    const plan = await prepare();
    expect(plan.entries.map((e) => [e.githubUserId, e.grossMicro])).toEqual([
      [A, "600"],
      [B, "300"],
    ]);
    expect(plan.totalGrossBase).toBe("900");
    vault("5000");
    expect(await prepare()).toEqual(plan);
    await rejects(prepare({ digest: "f".repeat(64) }), "snapshot_changed");
    expect(count("payment_obligations")).toBe(0);
  });
  test("refuses the root before the cutoff, after its window, and when the whole month is unfunded", async () => {
    vault("500");
    await coordinate(afterCutoff);
    await rejects(prepare({ now: beforeCutoff }), "monthly_window_closed");
    await rejects(
      prepare({ now: new Date("2027-01-04T00:00:00.000Z") }),
      "monthly_window_closed",
    );
    await rejects(prepare(), "award_unfunded");
    vault("1000");
    await coordinate(afterCutoff);
    expect((await prepare()).totalGrossBase).toBe("1000");
  });
  test("rechecks restrictions and the owner's opt-out after the month was frozen", async () => {
    vault("1000");
    await coordinate(afterCutoff);
    await rejects(prepare({ blocked: true }), "recipient_restricted");
    restricted = true;
    await rejects(prepare(), "project_restricted");
    restricted = false;
    sqlite
      .prepare(
        "INSERT INTO monthly_payment_settings(project_id,sequence,automatic,actor_id,created_at) VALUES(?,1,0,?,?)",
      )
      .run(project.id, OWNER, afterCutoff.toISOString());
    await rejects(prepare(), "automatic_off");
    expect(count("monthly_payment_obligations")).toBe(2);
  });
  test("rejects a forged frozen payload even when its metadata still names the real project", async () => {
    vault("1000");
    await coordinate(afterCutoff);
    // Simulate storage corruption outside the normal immutable API.
    const row = sqlite
      .prepare("SELECT snapshot FROM monthly_payment_runs")
      .get() as { snapshot: string };
    const bad = JSON.parse(row.snapshot);
    bad.awards[0].grossBase = "601";
    for (const trigger of sqlite
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name='monthly_payment_runs'",
      )
      .all() as { name: string }[])
      sqlite.exec(`DROP TRIGGER ${trigger.name}`);
    sqlite
      .prepare("UPDATE monthly_payment_runs SET snapshot=?")
      .run(JSON.stringify(bad));
    await rejects(prepare(), "snapshot_changed");
  });
});

test("monthly signing preserves its first intent through retry and refuses a changed root", async () => {
  vault("1000");
  await coordinate(afterCutoff);
  if (!schedule) throw new Error("Fixture schedule missing");
  const { digest } = sqlite
    .prepare("SELECT snapshot_sha256 digest FROM monthly_payment_runs")
    .get() as { digest: string };
  const records = new Map<string, unknown>();
  const journal: JournalStore = {
    async get<T>(key: string) {
      return records.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T) {
      records.set(key, structuredClone(value));
    },
    async transaction<T>(fn: (store: JournalStore) => Promise<T>) {
      return fn(journal);
    },
  };
  let signatures = 0;
  const deps = {
    db,
    ...projects(),
    recipientsRestricted: async () => false,
    networks: ["base-sepolia"],
    schedule,
    now: () => afterCutoff,
    journal,
    verifyDeployment: async () => {}, // Chain preflight has independent RPC integration coverage.
    sign: async (plan: { messageHex: string }) => {
      signatures++;
      return (await testAttester.sign({ hash: `0x${plan.messageHex}` })).slice(
        2,
      );
    },
  };
  const request = {
    projectId: project.id,
    period: "2026-11",
    network: "base-sepolia" as const,
    snapshotSha256: digest,
  };
  const first = await signMonthlyAllocation(deps, request);
  expect(await signMonthlyAllocation(deps, request)).toEqual(first);
  expect(signatures).toBe(1);
  // A saved intent survives an interrupted signer and cannot be replaced.
  const [key, value] = [...records.entries()][0] as [
    string,
    { messageHex: string },
  ];
  records.set(key, { ...value, messageHex: "a".repeat(64) });
  await expect(signMonthlyAllocation(deps, request)).rejects.toThrow(
    "already bound",
  );
  expect(signatures).toBe(1);
});

test("monthly signing never publishes when the signer fails or an opt-out arrives during signing", async () => {
  vault("1000");
  await coordinate(afterCutoff);
  if (!schedule) throw new Error("Fixture schedule missing");
  const { digest } = sqlite
    .prepare("SELECT snapshot_sha256 digest FROM monthly_payment_runs")
    .get() as { digest: string };
  const records = new Map<string, unknown>();
  const journal: JournalStore = {
    async get<T>(key: string) {
      return records.get(key) as T | undefined;
    },
    async put<T>(key: string, value: T) {
      records.set(key, structuredClone(value));
    },
    async transaction<T>(fn: (store: JournalStore) => Promise<T>) {
      return fn(journal);
    },
  };
  const deps = {
    db,
    ...projects(),
    recipientsRestricted: async () => false,
    networks: ["base-sepolia"],
    schedule,
    now: () => afterCutoff,
    journal,
    verifyDeployment: async () => {},
    sign: async () => {
      throw new Error("signer unavailable");
    },
  };
  const request = {
    projectId: project.id,
    period: "2026-11",
    network: "base-sepolia" as const,
    snapshotSha256: digest,
  };
  await expect(signMonthlyAllocation(deps, request)).rejects.toThrow(
    "signer unavailable",
  );
  expect([...records.values()]).toHaveLength(1);
  expect([...records.values()][0]).not.toHaveProperty("authorization");
  await rejects(
    signMonthlyAllocation(
      {
        ...deps,
        sign: async (plan) => {
          sqlite
            .prepare(
              "INSERT INTO monthly_payment_settings(project_id,sequence,automatic,actor_id,created_at) VALUES(?,1,0,?,?)",
            )
            .run(project.id, OWNER, afterCutoff.toISOString());
          return (
            await testAttester.sign({ hash: `0x${plan.messageHex}` })
          ).slice(2);
        },
      },
      request,
    ),
    "automatic_off",
  );
  expect([...records.values()][0]).not.toHaveProperty("authorization");
});
