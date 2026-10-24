/**
 * slop-fee-converter: a cron Worker that converts project-token fees received
 * in each network fee wallet to that network's Circle USDC, inside the same
 * wallet (PRD section 6, TOK-07, MVP-07c). It has no HTTP route. On EVM it
 * calls only the permissionless claimFees() of reviewed vaults, which moves
 * accrued fees to their fixed fee recipient (issue #905). It never touches
 * obligations or payments, and no payout waits on it.
 *
 * The cron fires every minute. Most runs are `receipts` runs that convert
 * only tokens whose fee-wallet balance changed; every RECOVERY_SCAN_MINUTES
 * the run is a full `recovery` scan.
 */

import {
  type FeeConverterConfig,
  type FeeConverterEnv,
  isTokenAddress,
  type NetworkConfig,
  networkKey,
  normalizeToken,
  parseConfig,
} from "./config";
import {
  type ChainClient,
  message,
  type NetworkRunResult,
  type RunTrigger,
  runNetwork,
} from "./core";
import { createEvmClient } from "./evm";
import { createSolanaClient } from "./solana";
import {
  D1ConversionStore,
  type FeeD1Database,
  projectRewardTokens,
  projectVaults,
} from "./store";

export interface Env extends FeeConverterEnv {
  FEE_DB: FeeD1Database;
}

/** Minutes between full recovery scans; the other cron minutes check receipts. */
export const RECOVERY_SCAN_MINUTES = 15;

/** The run kind for a cron tick: a full scan on each recovery minute. */
export function triggerAt(scheduledTime: number): RunTrigger {
  return new Date(scheduledTime).getUTCMinutes() % RECOVERY_SCAN_MINUTES === 0
    ? "recovery"
    : "receipts";
}

export function chainClient(
  env: FeeConverterEnv,
  config: FeeConverterConfig,
  network: NetworkConfig,
  overrides: {
    fetch?: typeof fetch;
    chainIdOverride?: number;
    localBlockhash?: boolean;
    /** Local validator harness only; the hosted Worker never sets it. */
    allowSolanaLive?: boolean;
  } = {},
): ChainClient {
  // PRD TOK-07: the Solana fee recipient also confirms identity-attester
  // rotation (PAY-05), so a hot key for it may not sign until the owner
  // records how that role stays separate. Solana runs in dry_run only.
  if (
    config.mode === "live" &&
    network.network === "solana" &&
    !overrides.allowSolanaLive
  )
    throw new Error(
      "live Solana conversion is blocked until the owner separates the PAY-05 fee-recipient role from the hot key",
    );
  // dry_run never loads a key, so it cannot sign even when one is present.
  // A network without a verified USDC target never signs either: it only
  // reconciles recorded sends, which needs no key.
  const signs = config.mode === "live" && network.definition.usdc !== null;
  const secret = signs ? networkKey(env, network.network) : undefined;
  if (signs && secret === undefined)
    throw new Error(
      `live mode needs FEE_WALLET_KEY_${network.network.toUpperCase()}`,
    );
  return network.definition.family === "evm"
    ? createEvmClient({
        config: network,
        limits: config.limits,
        kyberClientId: config.kyberClientId,
        privateKey: secret,
        fetch: overrides.fetch,
        chainIdOverride: overrides.chainIdOverride,
      })
    : createSolanaClient({
        config: network,
        limits: config.limits,
        jupiterApiUrl: config.jupiterApiUrl,
        jupiterApiKey: config.jupiterApiKey,
        keypair: secret,
        fetch: overrides.fetch,
        localBlockhash: overrides.localBlockhash,
      });
}

export async function runOnce(
  env: Env,
  now: () => Date = () => new Date(),
  /** Local harnesses only; the scheduled handler never passes overrides. */
  overrides: Parameters<typeof chainClient>[3] = {},
  trigger: RunTrigger = "recovery",
): Promise<NetworkRunResult[]> {
  // Off is inert even when the rest of the configuration is incomplete.
  if ((env.FEE_CONVERTER_MODE ?? "off").trim() === "off") return [];
  const config = parseConfig(env);
  if (config.mode === "off") return [];
  const store = new D1ConversionStore(env.FEE_DB);
  const results: NetworkRunResult[] = [];
  const failures: Error[] = [];
  for (const network of config.networks) {
    try {
      results.push(
        await runNetwork(network, {
          mode: config.mode,
          trigger,
          limits: config.limits,
          store,
          now,
          randomId: () => crypto.randomUUID(),
          projectTokens: async (n) =>
            (
              await projectRewardTokens(
                env.FEE_DB,
                n.network,
                n.definition.escrowNetworks,
              )
            )
              .filter((token) => isTokenAddress(n.network, token))
              .map((token) => normalizeToken(n.network, token)),
          projectVaults: async (n) =>
            n.definition.family === "evm"
              ? (await projectVaults(env.FEE_DB, n.definition.escrowNetworks))
                  .filter((vault) => isTokenAddress(n.network, vault))
                  .map((vault) => normalizeToken(n.network, vault))
              : [],
          client: (n) => chainClient(env, config, n, overrides),
          log: (event) => console.log(JSON.stringify(event)),
        }),
      );
    } catch (error) {
      // Attempt the other networks, but do not report this run as successful.
      const reason = message(error);
      failures.push(new Error(`${network.network}: ${reason}`));
      console.error(
        JSON.stringify({
          event: "fee_converter_network_error",
          network: network.network,
          error: reason,
        }),
      );
    }
  }
  if (failures.length > 0)
    throw new AggregateError(
      failures,
      `fee conversion failed on ${failures.length} networks`,
    );
  return results;
}

export default {
  async scheduled(
    controller: { scheduledTime: number } | undefined,
    env: Env,
    ctx: { waitUntil(promise: Promise<unknown>): void },
  ) {
    const trigger = triggerAt(controller?.scheduledTime ?? Date.now());
    ctx.waitUntil(
      runOnce(env, undefined, undefined, trigger).then((results) =>
        console.log(
          JSON.stringify({ event: "fee_converter_run", trigger, results }),
        ),
      ),
    );
  },
  async fetch(): Promise<Response> {
    return new Response("Not found", { status: 404 });
  },
};
