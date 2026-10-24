import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  PROJECT_SIZE,
  type SolanaEscrowConfig,
  solanaAccount,
  solanaAllocationProof,
  solanaAllocationRoot,
  solanaAllocationTotal,
  solanaAwardId,
  solanaBase58,
  solanaDigest,
  solanaMonthlyMessage,
  solanaPubkey,
  solanaRpc,
  solanaUint,
} from "../../contracts/solana/adapter";
import {
  bytes,
  concat,
  encoder,
  type Instruction,
  instructionData,
  le,
  message,
  pda,
  SYSTEM,
} from "../../contracts/solana/transactions";
import type { MonthlyAuthorization } from "./monthly";
import {
  broadcastSolanaTransaction,
  preflightSolanaDeployment,
  readSolanaAccount,
  type SolanaExecutorEnvironment,
  solanaTransactionStatus,
} from "./solana";

const hex = (value: Uint8Array) =>
  Array.from(value, (b) => b.toString(16).padStart(2, "0")).join("");
const discriminator = (name: string) =>
  hex(sha256(encoder.encode(`account:${name}`)).slice(0, 8));
function u32(value: number) {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, true);
  return result;
}
interface Attempt {
  fingerprint: string;
  transactionId: string;
  raw: string;
  lastValidBlockHeight: number;
  generation: number;
}

/** Stores signed bytes before broadcast; replaces only proven failed or expired attempts. */
async function submit(
  env: SolanaExecutorEnvironment,
  config: SolanaEscrowConfig,
  key: string,
  instructions: Instruction[],
) {
  const fingerprint = hex(
    sha256(
      encoder.encode(
        JSON.stringify([
          config.programId,
          config.projectPda,
          env.SOLANA_SIGNER.address,
          instructions,
        ]),
      ),
    ),
  );
  let attempt = await env.JOURNAL.get<Attempt>(key);
  let retired: Attempt | undefined;
  if (attempt) {
    if (attempt.fingerprint !== fingerprint)
      throw new Error("Monthly journal collision");
    const status = await solanaTransactionStatus({ config }, attempt);
    if (status && !status.failed)
      return { transactionId: attempt.transactionId, alreadyCommitted: false };
    if (status && !status.finalized)
      throw new Error("Monthly failure is not finalized");
    if (!status) {
      const height = await solanaRpc(config, "getBlockHeight", [
        { commitment: "finalized" },
      ]);
      if (typeof height !== "number" || !Number.isSafeInteger(height))
        throw new Error("Invalid finalized height");
      if (height <= attempt.lastValidBlockHeight) {
        return {
          ...(await broadcastSolanaTransaction({ config }, attempt)),
          alreadyCommitted: false,
        };
      }
    }
    retired = attempt;
  }
  const latest = (await solanaRpc(config, "getLatestBlockhash", [
    { commitment: "finalized" },
  ])) as {
    value: { blockhash: string; lastValidBlockHeight: number };
  };
  if (!Number.isSafeInteger(latest.value.lastValidBlockHeight))
    throw new Error("Invalid block height");
  const msg = message(
    env.SOLANA_SIGNER.address,
    latest.value.blockhash,
    instructions,
  );
  attempt = await env.JOURNAL.transaction(async (store) => {
    const existing = await store.get<Attempt>(key);
    if (
      existing?.fingerprint !== undefined &&
      existing.fingerprint !== fingerprint
    )
      throw new Error("Monthly journal collision");
    if (
      existing &&
      (!retired || existing.transactionId !== retired.transactionId)
    )
      return existing;
    if (retired && !existing) throw new Error("Monthly attempt disappeared");
    if (existing)
      await store.put(`${key}:retired:${existing.generation}`, existing);
    const signature = await env.SOLANA_SIGNER.signMessage(msg);
    if (
      signature.length !== 64 ||
      !ed25519.verify(signature, msg, bytes(env.SOLANA_SIGNER.address), {
        zip215: false,
      })
    )
      throw new Error("Invalid signer response");
    const raw = concat(Uint8Array.of(1), signature, msg);
    if (raw.length > 1232) throw new Error("Monthly transaction too large");
    const candidate: Attempt = {
      fingerprint,
      transactionId: solanaBase58(signature),
      raw: btoa(String.fromCharCode(...raw)),
      lastValidBlockHeight: latest.value.lastValidBlockHeight,
      generation: (existing?.generation ?? 0) + 1,
    };
    await store.put(key, candidate);
    return candidate;
  });
  return {
    ...(await broadcastSolanaTransaction({ config }, attempt)),
    alreadyCommitted: false,
  };
}

/** Advances one finalized monthly reservation by one bounded transaction. Never pays an award. */
export async function submitSolanaMonthly(
  env: SolanaExecutorEnvironment,
  authorization: MonthlyAuthorization,
  allowAdmission = true,
) {
  const { plan, signatureHex } = authorization;
  if (plan.family !== "solana") throw new Error("Wrong monthly family");
  const config = await preflightSolanaDeployment(env, {
    network: plan.request.network,
    vault: plan.deployment.vault,
  });
  if (
    config.projectId !== plan.request.projectId ||
    config.mint !== plan.deployment.asset
  )
    throw new Error("Wrong monthly deployment");
  const root = solanaAllocationRoot(plan.entries);
  const total = solanaAllocationTotal(plan.entries);
  const signed = solanaMonthlyMessage(
    config.programId,
    config.projectPda,
    plan.request.period,
    root,
    total,
    config.networkDomain,
  );
  if (
    root !== plan.allocationRoot ||
    total !== plan.totalGrossBase ||
    hex(signed) !== plan.messageHex
  )
    throw new Error("Monthly allocation mismatch");
  const period = u32(Number(plan.request.period.replace("-", "")));
  const month = pda(config.programId, [
    encoder.encode("month"),
    bytes(config.projectPda),
    period,
  ]);
  const record = await readSolanaAccount(
    config,
    month,
    100,
    discriminator("MonthlyAllocation"),
  );
  const payer = { key: env.SOLANA_SIGNER.address, write: true };
  const project = { key: config.projectPda, write: true };
  const system = { key: SYSTEM, write: false };
  const monthMeta = { key: month, write: true };
  const vault = { key: config.vault, write: false };
  const journal = `solana:monthly:${config.network}:${month}`;
  if (!record) {
    if (!allowAdmission)
      return {
        transactionId: null,
        alreadyCommitted: false,
        notAdmitted: true,
      };
    const state = await readSolanaAccount(
      config,
      config.projectPda,
      PROJECT_SIZE,
      discriminator("Project"),
    );
    if (!state) throw new Error("Project missing");
    const authority = solanaPubkey(state, 104);
    if (authority === env.SOLANA_SIGNER.address)
      throw new Error("Monthly gas signer must be separate from attester");
    if (!/^[0-9a-f]{128}$/.test(signatureHex))
      throw new Error("Invalid monthly signature");
    const signature = Uint8Array.from(signatureHex.match(/../g) ?? [], (s) =>
      Number.parseInt(s, 16),
    );
    if (!ed25519.verify(signature, signed, bytes(authority), { zip215: false }))
      throw new Error("Invalid monthly authority");
    // Ed25519 native instruction: key at 16, signature at 48, message at 112.
    const offsets = new Uint8Array(16);
    offsets[0] = 1;
    const view = new DataView(offsets.buffer);
    [48, 65535, 16, 65535, 112, signed.length, 65535].forEach((v, i) => {
      view.setUint16(2 + i * 2, v, true);
    });
    return submit(env, config, `${journal}:root`, [
      {
        program: "Ed25519SigVerify111111111111111111111111111",
        accounts: [],
        data: concat(offsets, bytes(authority), signature, signed),
      },
      {
        program: config.programId,
        accounts: [
          payer,
          project,
          vault,
          monthMeta,
          { key: "Sysvar1nstructions1111111111111111111111111", write: false },
          system,
        ],
        data: instructionData(
          "commit_monthly",
          period,
          solanaDigest(root),
          le(BigInt(total)),
        ),
      },
    ]);
  }
  if (
    solanaPubkey(record, 8) !== config.projectPda ||
    hex(record.slice(40, 44)) !== hex(period) ||
    hex(record.slice(44, 76)) !== root ||
    solanaUint(record, 84) !== BigInt(total)
  )
    throw new Error("Conflicting monthly reservation");
  if (solanaUint(record, 76) === BigInt(total))
    return { transactionId: null, alreadyCommitted: true };
  // Admission authenticated the whole root. Later authority rotation, opt-out and
  // period changes must not invalidate its already-funded, permissionless leaves.
  let markers: (Uint8Array | null)[] = [];
  for (let index = 0; index < plan.entries.length; index++) {
    if (index % 100 === 0) {
      const batch = plan.entries
        .slice(index, index + 100)
        .map((entry) =>
          pda(config.programId, [
            encoder.encode("settled"),
            bytes(month),
            solanaDigest(entry.sourceDigest),
          ]),
        );
      const response = (await solanaRpc(config, "getMultipleAccounts", [
        batch,
        { commitment: "finalized", encoding: "base64" },
      ])) as { value: unknown[] };
      if (
        !Array.isArray(response.value) ||
        response.value.length !== batch.length
      )
        throw new Error("Invalid monthly marker response");
      markers = response.value.map((value) =>
        value === null
          ? null
          : solanaAccount(
              value,
              config.programId,
              8,
              discriminator("BindingVeto"),
            ),
      );
    }
    const entry = plan.entries[index];
    const source = solanaDigest(entry.sourceDigest);
    const settled = pda(config.programId, [
      encoder.encode("settled"),
      bytes(month),
      source,
    ]);
    if (markers[index % 100]) continue;
    const origin = pda(config.programId, [
      encoder.encode("origin"),
      bytes(config.projectPda),
      source,
    ]);
    const consumed = await readSolanaAccount(
      config,
      origin,
      40,
      discriminator("Origin"),
    );
    const release = consumed !== null || BigInt(entry.githubUserId) === 0n;
    const proof = solanaAllocationProof(plan.entries, index);
    const award = solanaDigest(
      solanaAwardId(config.projectPda, entry.sourceDigest),
    );
    const args = [
      source,
      le(BigInt(entry.githubUserId)),
      le(BigInt(entry.grossMicro)),
      u32(index),
      u32(plan.entries.length),
      u32(proof.length),
      ...proof.map((n) => concat(solanaDigest(n.hash), le(BigInt(n.total)))),
    ];
    return submit(
      env,
      config,
      `${journal}:${index}:${release ? "release" : "commit"}`,
      [
        {
          program: config.programId,
          accounts: release
            ? [
                payer,
                project,
                monthMeta,
                { key: origin, write: false },
                { key: settled, write: true },
                system,
              ]
            : [
                payer,
                project,
                vault,
                monthMeta,
                { key: origin, write: true },
                {
                  key: pda(config.programId, [
                    encoder.encode("award"),
                    bytes(config.projectPda),
                    award,
                  ]),
                  write: true,
                },
                { key: settled, write: true },
                system,
              ],
          data: release
            ? instructionData("release_monthly_award", period, ...args)
            : instructionData("commit_monthly_award", period, award, ...args),
        },
      ],
    );
  }
  throw new Error("Monthly reservation counters disagree with settled leaves");
}
