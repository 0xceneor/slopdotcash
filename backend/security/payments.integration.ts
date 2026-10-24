/** Synthetic SEC-12 workflow on an actual local EVM chain and migrated database.
 * No public RPC, real wallet, live award, or payment signer is used. */
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { privateKeyToAccount } from "viem/accounts";
import {
  buildBindCalldata,
  evmBindingTypedData,
  evmVaultKey,
} from "../../contracts/evm/adapter";
import {
  captureUpgrade,
  deployUpgradeableFactory,
} from "../../contracts/evm/integration/upgrade";
import { sqliteD1 } from "../../tests/sqlite-d1";
import {
  createEvmExecutor,
  type JournalStore,
} from "../../workers/payment-executor/core";
import {
  type PaymentDeployment,
  readDeploymentVaultTotals,
} from "../../workers/payments";
import { type DispatchPayment, dispatchPayment } from "../payments/dispatch";
import { evmPaymentAdapter } from "../payments/evm-adapter";
import { handlePaymentsApi } from "../payments/handler";
import { indexPaymentEvent } from "../payments/ledger";
import { storeVaultSnapshot } from "../payments/vault-snapshots";
import { handleSecurityApi } from "./handler";
import { securityPaymentDatabase } from "./payment-database";
import {
  securityLedgerPolicy,
  securityPaymentNotices,
  securitySettlementView,
} from "./payments";

const port = 18558;
const rpcUrl = `http://127.0.0.1:${port}`;
const chain = spawn(
  "anvil",
  ["--port", String(port), "--chain-id", "84532", "--silent"],
  { stdio: "ignore" },
);
const owner = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const authority = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const fee = "0x0000000000000000000000000000000000000fee";
const wallet = privateKeyToAccount(`0x${"0".repeat(63)}1`);
const technical = { githubId: "91001", githubLogin: "synthetic-security" };
const reporter = { githubId: "91002", githubLogin: "synthetic-reporter" };
const finance = { githubId: "91003", githubLogin: "synthetic-finance" };
const dispute = { githubId: "91004", githubLogin: "synthetic-dispute" };
const origin = "https://slop.test";
const { db: database, sqlite } = sqliteD1(
  readdirSync("migrations")
    .filter((p) => p.endsWith(".sql"))
    .sort(),
);
const privateDb = securityPaymentDatabase(database);
const digest = (s: string) => createHash("sha256").update(s).digest("hex");
async function rpc(method: string, params: unknown[]) {
  const r = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const b = await r.json();
  if (b.error) throw new Error(JSON.stringify(b.error));
  return b.result;
}
async function send(
  to: string,
  signature: string,
  args: string[] = [],
  from = owner,
) {
  const data = execFileSync("cast", ["calldata", signature, ...args], {
    encoding: "utf8",
  }).trim();
  const tx = await rpc("eth_sendTransaction", [
    { from, to, data, gas: "0x7a1200" },
  ]);
  await rpc("anvil_mine", ["0x1"]);
  return tx as string;
}
function deploy(contract: string, args: string[] = []) {
  if (contract === "src/ProjectEscrow.sol:EscrowFactory" && args.length)
    return deployUpgradeableFactory(deploy, args);

  return JSON.parse(
    execFileSync(
      "forge",
      [
        "create",
        "--root",
        "contracts/evm",
        contract,
        "--rpc-url",
        rpcUrl,
        "--unlocked",
        "--from",
        owner,
        "--broadcast",
        "--json",
        ...(args.length ? ["--constructor-args", ...args] : []),
      ],
      { encoding: "utf8" },
    ),
  ).deployedTo as string;
}
const codeDigest = async (address: string) =>
  createHash("sha256")
    .update(
      Buffer.from(
        (await rpc("eth_getCode", [address, "latest"])).slice(2),
        "hex",
      ),
    )
    .digest("hex");
let serial = 0;
const received = new Date(Date.now() - 60_000).toISOString();
async function call(
  actor: typeof reporter,
  method: string,
  path: string,
  body?: unknown,
) {
  const response = await handleSecurityApi(
    new Request(`${origin}/api/v1/${path}`, {
      method,
      headers: { origin, "content-type": "application/json" },
      ...(body ? { body: JSON.stringify(body) } : {}),
    }),
    {
      db: database,
      now: () => new Date(),
      randomId: () => crypto.randomUUID(),
      sessionActor: async () => actor,
      github: { fetch, apiOrigin: "https://api.github.invalid" },
      // The synthetic private report that GitHub received from the reporter.
      advisories: {
        privateReports: async () => ({
          state: "ok" as const,
          reports: [
            {
              ghsa: "GHSA-2345-6789-cfgh",
              createdAt: received,
              state: "triage",
              author: reporter,
              summary: "Synthetic report",
              description: "Synthetic local funds-loss example.",
              severity: null,
              cweIds: [],
              packages: [],
            },
          ],
        }),
        privateReport: async () => ({ state: "unavailable" as const }),
      },
    },
  );
  assert(response);
  return { status: response.status, body: await response.json() };
}
async function act(
  actor: typeof reporter,
  id: string,
  action: string,
  fields: Record<string, unknown> = {},
) {
  const current = await call(actor, "GET", `security-cases/${id}`);
  return call(actor, "POST", `security-cases/${id}/actions`, {
    action,
    expectedRevision: current.body.case.revision,
    idempotencyKey: `synthetic-action-${++serial}`,
    ...fields,
  });
}
try {
  for (let i = 0; i < 80; i++) {
    try {
      await rpc("eth_chainId", []);
      break;
    } catch {
      await Bun.sleep(50);
    }
  }
  const token = deploy("integration/TestDollar.sol:TestDollar");
  const factory = deploy("src/ProjectEscrow.sol:EscrowFactory", [
    owner,
    fee,
    authority,
    "3600",
  ]);
  const projectKey = `0x${"9".repeat(64)}`;
  // Private bounties use the owner's separate bounty-purpose vault (purpose 1).
  await send(factory, "create(bytes32,address,uint8)", [
    projectKey,
    token,
    "1",
  ]);
  const vault = execFileSync(
    "cast",
    [
      "call",
      factory,
      "vaults(bytes32)(address)",
      evmVaultKey({
        owner,
        projectId: projectKey,
        asset: token,
        payoutPolicy: "security-bounty",
      }),
      "--rpc-url",
      rpcUrl,
    ],
    { encoding: "utf8" },
  )
    .trim()
    .toLowerCase();
  const deployment = {
    evmUpgrade: await captureUpgrade(rpc, factory, vault),
    network: "base-sepolia",
    vault,
    asset: token,
    owner,
    identityAuthority: authority,
    feeRecipient: fee,
    codeSha256: await codeDigest(vault),
    factory,
    factoryCodeSha256: await codeDigest(factory),
    registrar: owner,
    bindingDelaySeconds: "3600",
    programId: null,
    projectPda: null,
    networkDomain: null,
    rotationDelaySeconds: null,
    upgradeAuthority: null,
    sourceCommit: "a".repeat(40),
    deploymentTransaction: `0x${"0".repeat(64)}`,
  };
  const program = {
    status: "open",
    intake: { repository: "synthetic/private" },
    amount: {
      currency: "USDC",
      decimals: 6,
      network: "base",
      grossMinor: "100000000",
    },
    sponsor: { name: "Synthetic sponsor", githubId: null },
    funding: {
      state: "verified-available",
      evidence: "synthetic-local-vault-funding",
      verifiedAt: received,
    },
    capacity: { awards: 1, closesAt: null },
    responseTargets: { acknowledgeHours: 24 },
    approvers: {
      technical: [technical],
      financial: [finance],
      dispute: [dispute],
    },
    settlement: {
      schemaVersion: "1",
      effectiveCycle: "2026-10",
      chain: "base",
      feeBasisPoints: 2500,
      withdrawalFeeBasisPoints: 200,
      feeMode: "deduct-from-gross",
      deployments: [deployment],
    },
  };
  const manifest = JSON.stringify({
    id: "synthetic-private",
    status: "active",
    securityBounty: program,
  });
  sqlite
    .query(
      "INSERT INTO project_revisions(project_id,revision,manifest,manifest_sha256,reason,created_at) VALUES(?,1,?,?,'synthetic',?)",
    )
    .run("synthetic-private", manifest, digest(manifest), received);
  sqlite
    .query(
      "INSERT INTO projects(id,status,revision,manifest,manifest_sha256,created_at,updated_at) VALUES(?,'active',1,?,?,?,?)",
    )
    .run("synthetic-private", manifest, digest(manifest), received, received);
  const imported = await call(technical, "POST", "security-cases", {
    mode: "import",
    projectId: "synthetic-private",
  });
  assert.deepEqual(imported.body, { state: "ok", received: 1 });
  const caseId = (
    sqlite
      .query("SELECT id FROM security_cases WHERE advisory_ghsa = ?")
      .get("GHSA-2345-6789-cfgh") as { id: string }
  ).id;
  assert.equal(
    (
      await act(technical, caseId, "decide", {
        outcome: "confirmed",
        severity: "critical",
        loss: "verified-potential",
        inScope: true,
        relatedParty: false,
        rootCauseKey: "synthetic-root",
        reason: "Synthetic local funds-loss example.",
        evidenceReference: "private-local-example",
        evidenceDigest: "d".repeat(64),
      })
    ).status,
    200,
  );
  const awardDecision = () =>
    act(technical, caseId, "award", {
      decision: "amount",
      grossMinor: "100000000",
      paymentDeadline: new Date(Date.now() + 86400000).toISOString(),
      confirmation: true,
      reason: "Synthetic owner award for the local example.",
    });
  // Owner decision D10: an empty vault without a finalized snapshot has no
  // funds to reserve, whatever the published terms say.
  assert.equal((await awardDecision()).body.error, "funds_unavailable");
  await send(token, "mint(address,uint256)", [owner, "100000000"]);
  await send(token, "approve(address,uint256)", [vault, "100000000"]);
  await send(vault, "deposit(uint128)", ["100000000"]);
  await rpc("anvil_mine", ["0x40"]);
  const config = {
    ...deployment,
    projectId: "synthetic-private",
    chain: "base" as const,
    chainId: "84532",
    payoutPolicy: "security-bounty" as const,
  };
  await storeVaultSnapshot(
    privateDb,
    { ...config, projectPda: undefined },
    await readDeploymentVaultTotals(
      config as unknown as PaymentDeployment,
      rpcUrl,
    ),
    new Date().toISOString(),
  );
  // The finalized free balance now covers it: the award reserves exactly
  // this gross amount.
  const awarded = await awardDecision();
  assert.equal(awarded.status, 200, JSON.stringify(awarded.body));
  const missingConsent = await act(finance, caseId, "prepare-payment", {
    network: "base-sepolia",
    confirmation: true,
  });
  assert.equal(missingConsent.body.error, "payment_consent_required");
  assert.equal(
    (
      await act(reporter, caseId, "consent-payment", {
        network: "base-sepolia",
        confirmation: true,
      })
    ).status,
    200,
  );
  const prepared = await act(technical, caseId, "prepare-payment", {
    network: "base-sepolia",
    confirmation: true,
  });
  assert.equal(prepared.status, 200, JSON.stringify(prepared.body));
  const plan = await securitySettlementView(database, caseId);
  assert(plan?.ownerRequest);
  assert.equal(plan.netBase, "75000000");
  assert.equal(plan.feeBase, "25000000");
  const tx = await rpc("eth_sendTransaction", [
    { ...plan.ownerRequest, network: undefined, gas: "0x7a1200" },
  ]);
  await rpc("anvil_mine", ["0x40"]);
  const adapter = evmPaymentAdapter(privateDb, {
    ...config,
    rpcUrl,
    chainId: 84532n,
  });
  const policy = securityLedgerPolicy(database);
  await indexPaymentEvent(
    privateDb,
    adapter,
    {
      transactionId: tx,
      eventIndex: 0,
      kind: "reserved",
      obligationId: plan.obligationId,
    },
    new Date().toISOString(),
    policy,
  );
  assert.equal(
    (await securitySettlementView(database, caseId))?.state,
    "needs-wallet",
  );
  assert.equal(
    sqlite
      .query<{ n: number }, []>("SELECT count(*) n FROM payment_obligations")
      .get()?.n,
    0,
  );
  // Register and prove the destination through the canonical account API,
  // then bind that same destination on chain with its EIP-712 signature.
  // Populate the canonical wallet through the account API below.
  const session = "s".repeat(43);
  const now = new Date().toISOString();
  sqlite
    .query(
      "INSERT INTO points_members(actor_id,github_id,login,joined_at,public) VALUES(?,?,?,?,0)",
    )
    .run("U_private", reporter.githubId, reporter.githubLogin, now);
  sqlite
    .query(
      "INSERT INTO points_sessions(token_hash,actor_id,expires_at) VALUES(?,?,?)",
    )
    .run(
      digest(session),
      "U_private",
      new Date(Date.now() + 3600000).toISOString(),
    );
  const accountCall = async (path: string, data?: unknown) => {
    const r = await handlePaymentsApi(
      new Request(`https://slop.cash/api/v1/payments/${path}`, {
        method: data ? "POST" : "GET",
        headers: {
          cookie: `__Host-slop_points=${session}`,
          origin: "https://slop.cash",
          "content-type": "application/json",
        },
        ...(data ? { body: JSON.stringify(data) } : {}),
      }),
      { db: database },
    );
    return { status: r.status, body: await r.json() };
  };
  const registration = await accountCall("wallets/register", {
    chain: "base",
    address: wallet.address.toLowerCase(),
  });
  assert.equal(registration.status, 200, JSON.stringify(registration.body));
  const claimId = registration.body.claimId;
  const challenge = await accountCall("wallets/challenge", { claimId });
  assert.equal(challenge.status, 200, JSON.stringify(challenge.body));
  const signature = await wallet.signMessage({
    message: challenge.body.message,
  });
  assert.equal(
    (
      await accountCall("wallets/authorize", {
        claimId,
        challengeId: challenge.body.challengeId,
        signature,
      })
    ).status,
    200,
  );
  const claimRow = sqlite
    .query("SELECT record_sha256 FROM wallet_claims WHERE id=?")
    .get(claimId) as { record_sha256: string };
  const binding = {
    githubUserId: reporter.githubId,
    destination: wallet.address,
    expectedVersion: "0",
    claimDigest: `0x${claimRow.record_sha256}`,
    expiresAt: String(Math.floor(Date.now() / 1000) + 86400),
  };
  const walletSignature = await wallet.signTypedData(
    evmBindingTypedData(84532n, vault, binding) as unknown as Parameters<
      typeof wallet.signTypedData
    >[0],
  );
  await rpc("eth_sendTransaction", [
    {
      from: authority,
      to: vault,
      gas: "0x7a1200",
      data: buildBindCalldata({ ...binding, walletSignature }),
    },
  ]);
  await rpc("evm_increaseTime", [3601]);
  await rpc("anvil_mine", ["0x40"]);
  await privateDb
    .prepare(
      "INSERT INTO payment_outbox(obligation_id,state,updated_at) VALUES(?,'ready',?)",
    )
    .bind(plan.obligationId, new Date().toISOString())
    .run();
  await rpc("anvil_setBalance", [wallet.address, "0x56bc75e2d63100000"]);
  sqlite.exec(
    "CREATE TABLE signer_journal(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
  );
  const journal: JournalStore = {
    async get<T>(key: string) {
      const row = sqlite
        .query<{ value: string }, [string]>(
          "SELECT value FROM signer_journal WHERE key=?",
        )
        .get(key);
      return row ? (JSON.parse(row.value) as T) : undefined;
    },
    async put<T>(key: string, value: T) {
      sqlite
        .query(
          "INSERT INTO signer_journal VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        )
        .run(key, JSON.stringify(value));
    },
    async transaction<T>(callback: (store: JournalStore) => Promise<T>) {
      sqlite.exec("BEGIN IMMEDIATE");
      try {
        const result = await callback(journal);
        sqlite.exec("COMMIT");
        return result;
      } catch (error) {
        sqlite.exec("ROLLBACK");
        throw error;
      }
    },
  };
  const makeExecutor = () =>
    createEvmExecutor({
      PAYMENTS_DB: privateDb,
      PAYMENT_DEPLOYMENTS: JSON.stringify([
        { ...config, gasCeiling: "500000" },
      ]),
      PAYMENT_RPC_URLS: JSON.stringify({ "base-sepolia": rpcUrl }),
      SIGNER: wallet,
      JOURNAL: journal,
    });
  let sent: string | undefined;
  let submittedInput:
    | (DispatchPayment & { idempotencyKey: string })
    | undefined;
  const execute = {
    submit: async (input: DispatchPayment & { idempotencyKey: string }) => {
      submittedInput = input;
      sent = (await makeExecutor().submit(input)).transactionId;
      throw new Error("Synthetic lost response after submission");
    },
  };
  await assert.rejects(
    dispatchPayment(
      privateDb,
      execute,
      plan.obligationId,
      new Date(),
      (id, at) => securityPaymentNotices(database, id, "held", at),
    ),
    /lost response/,
  );
  assert.equal(
    (await securitySettlementView(database, caseId))?.state,
    "uncertain",
  );
  assert(sent);
  assert(submittedInput);
  // Reconstruct the signer engine after a lost response. Its durable journal
  // returns the same signed transaction rather than paying a second time.
  assert.equal(
    (await makeExecutor().submit(submittedInput)).transactionId,
    sent,
  );
  assert.equal(
    sqlite
      .query<{ n: number }, []>(
        "SELECT count(*) n FROM signer_journal WHERE key LIKE 'pay:%'",
      )
      .get()?.n,
    1,
  );
  await rpc("anvil_mine", ["0x40"]);
  const paid = {
    transactionId: sent,
    eventIndex: 0,
    kind: "paid" as const,
    obligationId: plan.obligationId,
  };
  await indexPaymentEvent(
    privateDb,
    adapter,
    paid,
    new Date().toISOString(),
    policy,
  );
  await indexPaymentEvent(
    privateDb,
    adapter,
    paid,
    new Date().toISOString(),
    policy,
  );
  assert.equal((await securitySettlementView(database, caseId))?.state, "paid");
  assert.equal(
    sqlite
      .query<{ n: number }, []>(
        "SELECT count(*) n FROM security_payment_events WHERE kind='paid'",
      )
      .get()?.n,
    1,
  );
  assert.equal((await accountCall("me")).body.payments.length, 0);
  assert.equal(
    (await accountCall("projects/synthetic-private/totals")).status,
    503,
  );
  assert.equal(
    (await call(dispute, "GET", `security-cases/${caseId}`)).status,
    404,
  );
  assert.equal(
    sqlite
      .query<{ n: number }, []>(
        "SELECT count(*) n FROM notifications WHERE kind IN ('award_reserved','payment_paid','payout_held','payout_exception')",
      )
      .get()?.n,
    0,
  );
  const balance = execFileSync(
    "cast",
    [
      "call",
      token,
      "balanceOf(address)(uint256)",
      wallet.address,
      "--rpc-url",
      rpcUrl,
    ],
    { encoding: "utf8" },
  )
    .split(" ")[0]
    .trim();
  assert.equal(balance, "75000000");
  const backupRoot = mkdtempSync(join(tmpdir(), "slop-private-restore-"));
  const backup = join(backupRoot, "private.sqlite");
  sqlite.query("VACUUM INTO ?").run(backup);
  const restored = sqliteD1([], backup);
  try {
    assert.equal(
      (await securitySettlementView(restored.db, caseId))?.state,
      "paid",
    );
    await indexPaymentEvent(
      securityPaymentDatabase(restored.db),
      adapter,
      paid,
      new Date().toISOString(),
      securityLedgerPolicy(restored.db),
    );
    assert.equal(
      restored.sqlite
        .query<{ n: number }, []>(
          "SELECT count(*) n FROM security_payment_events WHERE kind='paid'",
        )
        .get()?.n,
      1,
    );
    assert.equal(
      restored.sqlite
        .query<{ n: number }, []>("SELECT count(*) n FROM payment_obligations")
        .get()?.n,
      0,
    );
    assert.equal(
      restored.sqlite
        .query<{ n: number }, []>(
          "SELECT count(*) n FROM security_payment_consents",
        )
        .get()?.n,
      1,
    );
    assert.throws(
      () =>
        restored.sqlite
          .query("DELETE FROM security_settlements WHERE case_id=?")
          .run(caseId),
      /immutable|permanent/,
    );
  } finally {
    restored.sqlite.close();
    rmSync(backupRoot, { recursive: true });
  }

  console.log(
    "Private bounty: real API approval and visibility consent, finalized vault funding, unsigned owner commitment, late wallet possession, 75/25 payment, lost-response recovery, replay rejection, private notices, backup restore, and public-output isolation passed.",
  );
} finally {
  chain.kill("SIGTERM");
  sqlite.close();
}
