import type { D1TransactionalDatabase as D1Database } from "../../backend/d1";
import {
  dispatchPayment,
  type PaymentExecutor,
} from "../../backend/payments/dispatch";
import { evmPaymentAdapter } from "../../backend/payments/evm-adapter";
import {
  indexPaymentEvent,
  type PaymentChainAdapter,
} from "../../backend/payments/ledger";
import { coordinateMonthlyPayments } from "../../backend/payments/monthly";
import {
  refreshVaultSnapshots,
  type VaultTotals,
} from "../../backend/payments/vault-snapshots";
import {
  CloudflareProjectPersistence,
  type ProjectD1Database,
} from "../../backend/projects/cloudflare-persistence";
import { publicRestrictionOf } from "../../backend/projects/enforcement";
import {
  securityLedgerPolicy,
  securityPaymentNotices,
} from "../../backend/security/payments";
import {
  readVaultTotals as readEvmVaultTotals,
  verifyEvmDeployment,
} from "../../contracts/evm/adapter";
import {
  readVaultTotals as readSolanaVaultTotals,
  solanaPaymentAdapter,
} from "../../contracts/solana/adapter";
import { chainFamily, type EscrowChain } from "../../src/lib/escrow-policy.mjs";
import type { PayoutPolicy } from "../../src/lib/payments/contracts";
import { parseMonthlySchedule } from "../../src/lib/payments/monthly-allocation";
import {
  loadRegistryPaymentDeployments,
  parsePaymentNetworks,
} from "./deployments";
import { reconcileFailedAttempts } from "./reconcile";
import { scanEvmPayments, scanSolanaPayments } from "./scanner";

export interface PaymentDeployment {
  evmUpgrade?: import("../../contracts/evm/adapter").EvmUpgrade;
  payoutPolicy?: PayoutPolicy;
  projectId: string;
  network: string;
  chain: EscrowChain;
  vault: string;
  programId?: string;
  projectPda?: string;
  asset: string;
  owner: string;
  identityAuthority: string;
  feeRecipient: string;
  rotationAuthority?: string;
  codeSha256: string;
  bindingDelaySeconds: string;
  rotationDelaySeconds?: string;
  factory?: string;
  factoryCodeSha256?: string;
  registrar?: string;
  upgradeAuthority: string | null;
  networkDomain?: string;
  chainId?: string;
  /** EVM only: executor gas ceiling, copied from the registry by prepare-payment-deployments. */
  gasCeiling?: string;
  /** EVM only: eth_getLogs page size, copied from the registry by prepare-payment-deployments. */
  scanPageBlocks?: string;
  deploymentTransaction?: string;
}
export interface PaymentsWorkerEnvironment {
  /** Private worker only. Its entrypoint binds the separate private ledger. */
  PAYMENT_SCOPE?: "security-bounty";
  PAYMENTS_DB: D1Database;
  /**
   * The D1 project registry (the Pages `SLOP_DB`, `slop-private`), bound
   * separately from PAYMENTS_DB. The Worker only reads it.
   */
  REGISTRY_DB: D1Database;
  /**
   * JSON array of the registry networks this Worker serves. Their vaults come
   * from REGISTRY_DB on every run; no deployment list is copied into the
   * Worker configuration.
   */
  PAYMENT_NETWORKS: string;
  /** Private JSON map of network name to a finalized-capable RPC endpoint. */
  PAYMENT_RPC_URLS: string;
  PAYMENT_SOLANA_GENESIS?: string;
  /** A separate restricted execution service; no signer secrets in this worker. */
  EVM_PAYMENT_EXECUTOR?: { fetch(request: Request): Promise<Response> };
  SOLANA_PAYMENT_EXECUTOR?: { fetch(request: Request): Promise<Response> };
  /**
   * The owner-decided automatic monthly cutoff (backend/payments/monthly.ts).
   * Unset, the coordinator freezes no month automatically.
   */
  MONTHLY_PAYMENT_SCHEDULE?: string;
}
/** The served networks' reviewed vaults, read from the D1 project registry. */
export function registryDeployments(env: PaymentsWorkerEnvironment) {
  return loadRegistryPaymentDeployments(
    env.REGISTRY_DB,
    parsePaymentNetworks(env.PAYMENT_NETWORKS),
    env.PAYMENT_SCOPE,
  );
}
export async function recoverUncertainAttempts(
  env: PaymentsWorkerEnvironment,
): Promise<void> {
  const row = await env.PAYMENTS_DB.prepare(
    "SELECT json_group_array(json_object('idempotencyKey',a.id,'obligationId',o.id,'network',o.network,'vault',o.vault,'chain',o.chain)) items FROM payment_attempts a JOIN payment_obligations o ON o.id=a.obligation_id WHERE a.state IN ('unknown','prepared') AND a.transaction_id IS NULL AND o.state='reserved'",
  ).first<{ items: string }>();
  const failures: unknown[] = [];
  for (const attempt of JSON.parse(row?.items ?? "[]") as {
    idempotencyKey: string;
    obligationId: string;
    network: string;
    vault: string;
    chain: string;
  }[]) {
    try {
      const service =
        chainFamily(attempt.chain) === "evm"
          ? env.EVM_PAYMENT_EXECUTOR
          : env.SOLANA_PAYMENT_EXECUTOR;
      if (!service) throw new Error("Attempt status service unavailable");
      const { chain: _chain, ...identity } = attempt;
      const response = await service.fetch(
        new Request("https://payments-executor.internal/v1/attempt-status", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(identity),
        }),
      );
      if (!response.ok) throw new Error("Attempt status reconciliation failed");
      const status = (await response.json()) as { transactionId: unknown };
      if (status.transactionId === null) {
        const successor = await env.PAYMENTS_DB.prepare(
          "SELECT w.id FROM payment_attempts a JOIN wallet_claims old ON old.id=a.claim_id JOIN wallet_claims w ON w.github_user_id=old.github_user_id AND w.chain=old.chain JOIN payment_wallet_authorizations consent ON consent.claim_id=w.id WHERE a.id=? AND w.id!=old.id AND NOT EXISTS(SELECT 1 FROM wallet_claims next WHERE next.supersedes_claim_id=w.id)",
        )
          .bind(attempt.idempotencyKey)
          .first<{ id: string }>();
        if (!successor) continue;
        const cancellation = await service.fetch(
          new Request(
            "https://payments-executor.internal/v1/cancel-unsubmitted",
            {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify(identity),
            },
          ),
        );
        if (!cancellation.ok)
          throw new Error("Unsigned attempt retirement failed");
        const outcome = (await cancellation.json()) as {
          retired: boolean;
          transactionId: unknown;
        };
        if (outcome.retired === true && outcome.transactionId === null) {
          await env.PAYMENTS_DB.batch([
            env.PAYMENTS_DB.prepare(
              "INSERT INTO payment_attempt_failures VALUES(?,NULL,?,?) ON CONFLICT(attempt_id) DO NOTHING",
            ).bind(
              attempt.idempotencyKey,
              new Date().toISOString(),
              JSON.stringify({
                kind: "unsigned-attempt-retired",
                successorClaimId: successor.id,
              }),
            ),
            env.PAYMENTS_DB.prepare(
              "UPDATE payment_attempts SET state='failed' WHERE id=? AND transaction_id IS NULL AND state IN ('prepared','unknown')",
            ).bind(attempt.idempotencyKey),
            env.PAYMENTS_DB.prepare(
              "UPDATE payment_outbox SET state='ready',lease_token=NULL,lease_until=NULL,updated_at=? WHERE obligation_id=? AND state!='paid'",
            ).bind(new Date().toISOString(), attempt.obligationId),
          ]);
          continue;
        }
        if (outcome.retired !== false)
          throw new Error("Invalid retirement result");
        status.transactionId = outcome.transactionId;
      }
      if (typeof status.transactionId !== "string" || !status.transactionId)
        throw new Error("Invalid attempt transaction identity");
      await env.PAYMENTS_DB.batch([
        env.PAYMENTS_DB.prepare(
          "UPDATE payment_attempts SET transaction_id=?,state='submitted' WHERE id=? AND transaction_id IS NULL AND state IN ('unknown','prepared')",
        ).bind(status.transactionId, attempt.idempotencyKey),
        env.PAYMENTS_DB.prepare(
          "UPDATE payment_outbox SET state='submitted',lease_token=NULL,lease_until=NULL,updated_at=? WHERE obligation_id=? AND state!='paid'",
        ).bind(new Date().toISOString(), attempt.obligationId),
      ]);
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length)
    throw new AggregateError(failures, "Payment attempt recovery failures");
}
function executor(env: PaymentsWorkerEnvironment): PaymentExecutor {
  return {
    async submit(input) {
      const { deployments } = await registryDeployments(env);
      const matched = deployments.filter(
        (d) => d.network === input.network && d.vault === input.vault,
      );
      if (matched.length !== 1)
        throw new Error("Reviewed execution deployment unavailable");
      const service =
        chainFamily(matched[0].chain) === "evm"
          ? env.EVM_PAYMENT_EXECUTOR
          : env.SOLANA_PAYMENT_EXECUTOR;
      if (!service) throw new Error("Chain execution service unavailable");
      const response = await service.fetch(
        new Request("https://payments-executor.internal/v1/pay", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "idempotency-key": input.idempotencyKey,
          },
          body: JSON.stringify(input),
        }),
      );
      if (!response.ok)
        throw new Error("Payment execution service rejected request");
      const result = (await response.json()) as { transactionId?: unknown };
      if (typeof result.transactionId !== "string" || !result.transactionId)
        throw new Error("Missing transaction identity");
      return { transactionId: result.transactionId };
    },
  };
}
export async function runPaymentDispatch(
  env: PaymentsWorkerEnvironment,
  now = new Date(),
): Promise<void> {
  if (!env.EVM_PAYMENT_EXECUTOR && !env.SOLANA_PAYMENT_EXECUTOR)
    throw new Error("Payment execution service unavailable");
  const rows = await env.PAYMENTS_DB.prepare(
    "SELECT json_group_array(obligation_id) ids FROM (SELECT obligation_id FROM payment_outbox WHERE state='ready' OR (state='processing' AND lease_until<?) ORDER BY updated_at LIMIT 50)",
  )
    .bind(now.toISOString())
    .first<{ ids: string }>();
  const failures: unknown[] = [];
  for (const id of JSON.parse(rows?.ids ?? "[]") as string[]) {
    try {
      await dispatchPayment(
        env.PAYMENTS_DB,
        executor(env),
        id,
        now,
        env.PAYMENT_SCOPE === "security-bounty"
          ? (id, at) => securityPaymentNotices(env.REGISTRY_DB, id, "held", at)
          : undefined,
      );
    } catch (error) {
      failures.push(error);
    }
  }
  if (failures.length)
    throw new AggregateError(failures, "Payment dispatch failures");
}
/**
 * The monthly coordinator for ordinary project vaults: freeze months due at
 * the configured cutoff, then create funded obligations once. Never runs for
 * private bounty programs. It reads the registry and enforcement records
 * from REGISTRY_DB and keeps its records in PAYMENTS_DB with the vault
 * snapshots and the chain projection it checks.
 */
export async function runMonthlyCoordinator(
  env: PaymentsWorkerEnvironment,
  now = new Date(),
) {
  if (env.PAYMENT_SCOPE === "security-bounty") return null;
  const registry = new CloudflareProjectPersistence(
    env.REGISTRY_DB as ProjectD1Database,
  );
  const report = await coordinateMonthlyPayments({
    db: env.PAYMENTS_DB,
    projects: {
      getProject: (id) => registry.getProject(id),
      restricted: async (project) =>
        publicRestrictionOf(project, await registry.listEnforcements())
          .state !== "clear",
    },
    networks: parsePaymentNetworks(env.PAYMENT_NETWORKS),
    schedule: parseMonthlySchedule(env.MONTHLY_PAYMENT_SCHEDULE),
    now,
  });
  if (report.failures.length)
    throw new AggregateError(report.failures, "Monthly coordinator failures");
  return report;
}
export interface PaymentEventMessage {
  projectId: string;
  network?: string;
  transactionId: string;
  eventIndex: number;
  kind: "reserved" | "paid";
  obligationId: string;
}
export async function ingestPaymentEvent(
  env: PaymentsWorkerEnvironment,
  message: PaymentEventMessage,
  now = new Date(),
  reviewed?: readonly PaymentDeployment[],
): Promise<void> {
  if (
    !message ||
    typeof message.projectId !== "string" ||
    typeof message.transactionId !== "string" ||
    typeof message.obligationId !== "string" ||
    !Number.isSafeInteger(message.eventIndex) ||
    message.eventIndex < 0 ||
    (message.kind !== "reserved" && message.kind !== "paid")
  )
    throw new Error("Invalid chain event request");
  const deployments = reviewed ?? (await registryDeployments(env)).deployments;
  const matches = deployments.filter(
    (d) =>
      d.projectId === message.projectId &&
      (message.network === undefined || d.network === message.network),
  );
  if (matches.length !== 1)
    throw new Error("Reviewed deployment unavailable or ambiguous");
  const deployment = matches[0];
  const family = chainFamily(deployment.chain);
  if (
    !(family === "evm" ? /^0x[0-9a-f]{64}$/ : /^[0-9a-f]{64}$/).test(
      message.obligationId,
    )
  )
    throw new Error("Noncanonical obligation identity");
  const rpcUrls = JSON.parse(env.PAYMENT_RPC_URLS) as Record<string, string>;
  const rpcUrl = rpcUrls[deployment.network];
  if (!rpcUrl) throw new Error("Private RPC configuration unavailable");
  let adapter: PaymentChainAdapter;
  if (
    family === "evm" &&
    deployment.chainId &&
    deployment.factory &&
    deployment.factoryCodeSha256 &&
    deployment.registrar
  ) {
    adapter = evmPaymentAdapter(env.PAYMENTS_DB, {
      ...deployment,
      rpcUrl,
      chainId: BigInt(deployment.chainId),
      factory: deployment.factory,
      factoryCodeSha256: deployment.factoryCodeSha256,
      registrar: deployment.registrar,
    });
  } else if (
    family === "solana" &&
    deployment.programId &&
    deployment.projectPda &&
    deployment.asset &&
    deployment.networkDomain &&
    deployment.rotationDelaySeconds &&
    deployment.rotationAuthority
  ) {
    const genesis = (
      JSON.parse(env.PAYMENT_SOLANA_GENESIS ?? "{}") as Record<string, string>
    )[deployment.network];
    if (!genesis) throw new Error("Solana genesis trust root unavailable");
    adapter = solanaPaymentAdapter({
      ...deployment,
      rpcUrl,
      genesisHash: genesis,
      programId: deployment.programId,
      projectPda: deployment.projectPda,
      mint: deployment.asset,
      networkDomain: deployment.networkDomain,
      rotationDelaySeconds: deployment.rotationDelaySeconds,
      rotationAuthority: deployment.rotationAuthority,
    });
  } else throw new Error("Reviewed chain deployment incomplete");
  await indexPaymentEvent(
    env.PAYMENTS_DB,
    adapter,
    message,
    now.toISOString(),
    env.PAYMENT_SCOPE === "security-bounty"
      ? securityLedgerPolicy(env.REGISTRY_DB)
      : undefined,
  );
}
/**
 * Reads the vault counters at the finalized block through the chain adapter
 * (EVM `finalized` tag, Solana `finalized` commitment). Pages never read the
 * chain; they read the vault_snapshots row that the cron writes from this.
 */
export async function readDeploymentVaultTotals(
  deployment: PaymentDeployment,
  rpcUrl: string,
): Promise<VaultTotals> {
  if (chainFamily(deployment.chain) === "evm") {
    if (
      !deployment.chainId ||
      !deployment.factory ||
      !deployment.factoryCodeSha256 ||
      !deployment.registrar
    )
      throw new Error("Reviewed chain deployment incomplete");
    const chainId = BigInt(deployment.chainId);
    // The counters mean what the reviewed code says only for that code.
    await verifyEvmDeployment({
      ...deployment,
      rpcUrl,
      chainId,
      factory: deployment.factory,
      factoryCodeSha256: deployment.factoryCodeSha256,
      registrar: deployment.registrar,
    });
    return readEvmVaultTotals({
      rpcUrl,
      network: deployment.network,
      vault: deployment.vault,
      chainId,
    });
  }
  if (!deployment.programId || !deployment.projectPda)
    throw new Error("Solana project deployment missing");
  return readSolanaVaultTotals({
    rpcUrl,
    network: deployment.network,
    programId: deployment.programId,
    projectPda: deployment.projectPda,
  });
}
/**
 * The cron's chain read: discover the served networks' vaults in the D1
 * registry, store each vault's finalized counters in vault_snapshots, then
 * scan its finalized payment events. Failures are returned, not thrown, so
 * one vault never stops the others or the payout steps.
 */
export async function syncRegistryVaults(env: PaymentsWorkerEnvironment) {
  const registry = await registryDeployments(env);
  const deployments = registry.deployments;
  const rpcUrls = JSON.parse(env.PAYMENT_RPC_URLS) as Record<string, string>;
  const failures: unknown[] = [...registry.failures];
  // The ledger takes each award's asset and decimals from this snapshot,
  // so it runs before the event scan.
  try {
    await refreshVaultSnapshots(
      env.PAYMENTS_DB,
      deployments,
      rpcUrls,
      readDeploymentVaultTotals,
    );
  } catch (error) {
    failures.push(error);
  }
  for (const deployment of deployments) {
    try {
      const index = (event: PaymentEventMessage) =>
        ingestPaymentEvent(env, event, new Date(), deployments);
      if (chainFamily(deployment.chain) === "evm")
        await scanEvmPayments(
          env.PAYMENTS_DB,
          deployment,
          rpcUrls[deployment.network],
          index,
        );
      else
        await scanSolanaPayments(
          env.PAYMENTS_DB,
          deployment,
          rpcUrls[deployment.network],
          index,
        );
    } catch (error) {
      failures.push(error);
    }
  }
  return { deployments, rpcUrls, failures };
}
export default {
  async scheduled(_controller: unknown, env: PaymentsWorkerEnvironment) {
    // One failing deployment or step must not stop scanning or payouts elsewhere.
    const { deployments, rpcUrls, failures } = await syncRegistryVaults(env);
    for (const step of [
      () => recoverUncertainAttempts(env),
      () =>
        reconcileFailedAttempts(
          env.PAYMENTS_DB,
          deployments,
          rpcUrls,
          JSON.parse(env.PAYMENT_SOLANA_GENESIS ?? "{}") as Record<
            string,
            string
          >,
        ),
      () => runMonthlyCoordinator(env),
      () => runPaymentDispatch(env),
    ]) {
      try {
        await step();
      } catch (error) {
        failures.push(error);
      }
    }
    if (failures.length)
      throw new AggregateError(failures, "Payment worker failures");
  },
  async queue(
    batch: {
      messages: { body: PaymentEventMessage; ack(): void; retry(): void }[];
    },
    env: PaymentsWorkerEnvironment,
  ) {
    for (const message of batch.messages) {
      try {
        await ingestPaymentEvent(env, message.body);
        message.ack();
      } catch {
        message.retry();
      }
    }
  },
};
