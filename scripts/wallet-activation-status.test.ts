// PRD section 11, Wallet activation: a changed payout wallet is eligible as
// soon as the account and wallet-control proof exist. The waiting period is
// zero. The account status must not publish the removed one-day hold.
import { expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import { handlePaymentsApi } from "../backend/payments/handler";
import type { PaymentsAccount } from "../src/lib/payments/contracts";
import { sqliteD1 } from "../tests/sqlite-d1";
import { sha256Hex } from "../workers/identity/crypto";

const NOW = "2026-10-24T12:00:00.000Z";
const AUTHORIZED_AT = "2026-10-24T11:30:00.000Z";

test("an authorized successor wallet is eligible immediately", async () => {
  const { db, sqlite } = sqliteD1(
    readdirSync(new URL("../migrations", import.meta.url))
      .filter((name) => name.endsWith(".sql"))
      .sort(),
  );
  const token = "c".repeat(43);
  sqlite
    .prepare(
      "INSERT INTO points_members(actor_id,github_id,login,joined_at,public) VALUES(?,?,?,?,0)",
    )
    .run("node-wallet", "424242", "wallet-tester", NOW);
  sqlite
    .prepare(
      "INSERT INTO points_sessions(token_hash,actor_id,expires_at) VALUES(?,?,?)",
    )
    .run(await sha256Hex(token), "node-wallet", "2027-01-01T00:00:00.000Z");
  const claim = (
    id: string,
    address: string,
    chain: string,
    digest: string,
    supersedes: string | null,
    createdAt: string,
  ) => {
    sqlite
      .prepare(
        `INSERT INTO wallet_claims(id,github_user_id,github_login,wallet_address,source,source_body_sha256,observed_at,record_sha256,supersedes_claim_id,created_at,chain)
         VALUES(?,?,?,?, 'd1_registry',?,?,?,?,?,?)`,
      )
      .run(
        id,
        "424242",
        "wallet-tester",
        address,
        digest,
        createdAt,
        digest,
        supersedes,
        createdAt,
        chain,
      );
  };
  const authorize = (id: string) => {
    sqlite
      .prepare(
        "INSERT INTO payment_wallet_challenges(id,claim_id,github_user_id,message,expires_at,consumed_at) VALUES(?,?,?,?,?,?)",
      )
      .run(
        `challenge-${id}`,
        id,
        "424242",
        `proof ${id}`,
        "2026-10-24T12:00:00.000Z",
        AUTHORIZED_AT,
      );
    sqlite
      .prepare(
        "INSERT INTO payment_wallet_authorizations(claim_id,github_user_id,authorized_at,challenge_id,signature) VALUES(?,?,?,?,?)",
      )
      .run(id, "424242", AUTHORIZED_AT, `challenge-${id}`, `sig-${id}`);
  };
  claim(
    "root-base",
    `0x${"11".repeat(20)}`,
    "base",
    "a".repeat(64),
    null,
    "2026-10-20T00:00:00.000Z",
  );
  claim(
    "next-base",
    `0x${"22".repeat(20)}`,
    "base",
    "b".repeat(64),
    "root-base",
    "2026-10-24T11:00:00.000Z",
  );
  authorize("next-base");
  claim(
    "root-solana",
    "So11111111111111111111111111111111111111112",
    "solana",
    "c".repeat(64),
    null,
    "2026-10-20T00:00:00.000Z",
  );
  authorize("root-solana");

  const response = await handlePaymentsApi(
    new Request("https://slop.cash/api/v1/payments/me", {
      headers: { cookie: `__Host-slop_points=${token}` },
    }),
    { db, now: () => new Date(NOW) },
  );
  expect(response.status).toBe(200);
  const account = (await response.json()) as PaymentsAccount;
  const byChain = Object.fromEntries(
    account.wallets.map((wallet) => [wallet.chain, wallet]),
  );
  expect(byChain.base).toMatchObject({
    claimId: "next-base",
    authorized: true,
    activationEligibleAt: null,
  });
  expect(byChain.solana).toMatchObject({
    claimId: "root-solana",
    authorized: true,
    activationEligibleAt: null,
  });
});
