import { afterEach, describe, expect, test } from "bun:test";
import {
  PROJECT_DISCRIMINATOR,
  PROJECT_SIZE,
  readVaultTotals,
  solanaBase58,
  solanaConfigAddress,
  solanaVaultAddress,
} from "./adapter";

const PROGRAM = "4hXeYxsTKbwVKRRn8P1emGNDmVUSx13VMykfUAsbPnnj";
const TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const PROJECT = solanaBase58(new Uint8Array(32).fill(7));
const MINT_BYTES = new Uint8Array(32).fill(9);
const MINT = solanaBase58(MINT_BYTES);
const VAULT = solanaVaultAddress(PROGRAM, PROJECT);
const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

interface Counters {
  reserved: bigint;
  deposited: bigint;
  paid: bigint;
  payoutFees: bigint;
  withdrawnGross: bigint;
  withdrawalFees: bigint;
}
const base: Counters = {
  reserved: 30n,
  deposited: 10n ** 19n,
  paid: 98n,
  payoutFees: 2n,
  withdrawnGross: 500n,
  withdrawalFees: 10n,
};
/** A Project account in the current 316-byte layout. */
function projectAccount(c: Counters, mint = MINT_BYTES): Uint8Array {
  const data = new Uint8Array(PROJECT_SIZE);
  const view = new DataView(data.buffer);
  data.set(
    Uint8Array.from(PROJECT_DISCRIMINATOR.match(/../g) ?? [], (h) =>
      Number.parseInt(h, 16),
    ),
  );
  data.set(mint, 168);
  view.setBigUint64(200, c.reserved, true);
  view.setBigUint64(208, c.deposited, true);
  view.setBigUint64(216, c.paid, true);
  view.setBigUint64(224, c.payoutFees, true);
  view.setBigUint64(232, c.withdrawnGross, true);
  view.setBigUint64(240, c.withdrawalFees, true);
  data[248] = 254;
  view.setBigInt64(249, 3600n, true);
  view.setBigInt64(298, 604800n, true);
  return data;
}
function mintAccount(decimals: number, initialized = 1): Uint8Array {
  const data = new Uint8Array(82);
  data[44] = decimals;
  data[45] = initialized;
  return data;
}
const encoded = (owner: string, data: Uint8Array) => ({
  owner,
  executable: false,
  lamports: 1,
  data: [Buffer.from(data).toString("base64"), "base64"],
});
function mockRpc(accounts: {
  project: Uint8Array;
  mint: Uint8Array;
  mintOwner?: string;
  slot?: number;
}) {
  const calls: { method: string; params: unknown[] }[] = [];
  const slot = accounts.slot ?? 123456;
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body));
    calls.push(body);
    const project = encoded(PROGRAM, accounts.project);
    let result: unknown;
    if (body.method === "getAccountInfo") {
      expect(body.params[0]).toBe(PROJECT);
      expect(body.params[1].commitment).toBe("finalized");
      result = { context: { slot: 1 }, value: project };
    } else if (body.method === "getMultipleAccounts") {
      expect(body.params[0]).toEqual([PROJECT, MINT]);
      expect(body.params[1].commitment).toBe("finalized");
      result = {
        context: { slot },
        value: [project, encoded(accounts.mintOwner ?? TOKEN, accounts.mint)],
      };
    } else if (body.method === "getBlockTime") {
      expect(body.params[0]).toBe(slot);
      result = 1_792_000_000;
    } else throw new Error(`Unexpected RPC ${body.method}`);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }));
  }) as typeof fetch;
  return calls;
}
const config = {
  rpcUrl: "https://rpc.invalid",
  network: "solana-localnet",
  projectPda: PROJECT,
  programId: PROGRAM,
};

describe("readVaultTotals", () => {
  test("reads counters and decimals from one finalized slot", async () => {
    const calls = mockRpc({
      project: projectAccount(base),
      mint: mintAccount(18),
    });
    expect(await readVaultTotals(config)).toEqual({
      network: "solana-localnet",
      vault: PROJECT,
      asset: MINT,
      decimals: 18,
      blockNumber: "123456",
      blockTime: new Date(1_792_000_000_000).toISOString(),
      totalDeposited: (10n ** 19n).toString(),
      totalPaid: "98",
      totalPayoutFees: "2",
      totalGrossWithdrawn: "500",
      totalWithdrawalFees: "10",
      freeBalance: (10n ** 19n - 98n - 2n - 500n - 30n).toString(),
      reservedPrincipal: null,
      reservedFees: null,
      accruedFees: null,
      reserved: "30",
    });
    expect(calls.map((c) => c.method)).toEqual([
      "getAccountInfo",
      "getMultipleAccounts",
      "getBlockTime",
    ]);
  });

  test("reads mint decimals 0, 6, 9 and 18", async () => {
    for (const decimals of [0, 6, 9, 18]) {
      mockRpc({
        project: projectAccount({ ...base, deposited: 1_000n }),
        mint: mintAccount(decimals),
      });
      const totals = await readVaultTotals(config);
      expect(totals.decimals).toBe(decimals);
      expect(totals.freeBalance).toBe("370");
    }
  });

  test("throws when the counters exceed deposits", async () => {
    mockRpc({
      project: projectAccount({ ...base, deposited: 629n }),
      mint: mintAccount(6),
    });
    await expect(readVaultTotals(config)).rejects.toThrow(
      "Project counters exceed deposits",
    );
  });

  test("refuses a Token-2022 mint and an uninitialized mint", async () => {
    mockRpc({
      project: projectAccount(base),
      mint: mintAccount(6),
      mintOwner: "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
    });
    await expect(readVaultTotals(config)).rejects.toThrow(
      "Not a classic SPL Token account",
    );
    mockRpc({ project: projectAccount(base), mint: mintAccount(6, 0) });
    await expect(readVaultTotals(config)).rejects.toThrow(
      "Mint is not initialized",
    );
  });

  test("refuses a legacy-size project account", async () => {
    mockRpc({
      project: projectAccount(base).slice(0, 265),
      mint: mintAccount(6),
    });
    await expect(readVaultTotals(config)).rejects.toThrow(
      "Account layout mismatch",
    );
  });
});

describe("program addresses", () => {
  // Expected values from @solana/web3.js PublicKey.findProgramAddressSync.
  test("derive the Config and vault PDAs", () => {
    expect(PROJECT).toBe("US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx");
    expect(solanaConfigAddress(PROGRAM)).toBe(
      "D1zzrMUJ5CyZZgwNkMHKp7n6WpV2MLev7i2P6j2BAxmC",
    );
    expect(VAULT).toBe("HKDSkf4p2xZ3frfngLQdS8QiE6Z9UazAqWxhEMJ63piw");
  });
});
