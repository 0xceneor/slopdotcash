#!/usr/bin/env node
/**
 * Read-only Config planner for the program upgrade runbook. No key file,
 * signing or broadcasting.
 *
 *   node scripts/config-plan.mjs plan reviewed-config-input.json
 *     Builds the unsigned `initialize_config` transaction that the program's
 *     upgrade authority signs once, before the upgrade authority is revoked.
 *   node scripts/config-plan.mjs projects reviewed-config-input.json
 *     Lists every Project account of the program and whether the Config pins it.
 *
 * The input file holds `programId`, `upgradeAuthority`, `codeSha256`,
 * `identityAuthority` and `feeRecipient`. RPC URL, expected genesis and a fresh
 * blockhash come from SLOP_SOLANA_RPC_URL, SLOP_SOLANA_GENESIS and
 * SLOP_SOLANA_RECENT_BLOCKHASH. The output omits the RPC URL.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import anchor from "@coral-xyz/anchor";
import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
} from "@solana/web3.js";
import { verifyProgram } from "./owner-plan.mjs";

const PROJECT_DISCRIMINATOR = "cda8bdcab5f78e13";
const UPGRADEABLE_LOADER = new PublicKey(
  "BPFLoaderUpgradeab1e11111111111111111111111",
);
const base58 = (bytes) => new PublicKey(bytes).toBase58();
async function connect(input, runtime) {
  const connection = new Connection(runtime.rpcUrl, "finalized");
  if (
    typeof runtime.expectedGenesis !== "string" ||
    (await connection.getGenesisHash()) !== runtime.expectedGenesis
  )
    throw new Error("Wrong cluster genesis");
  const idl = JSON.parse(
    readFileSync(
      fileURLToPath(new URL("../idl/slop_escrow.json", import.meta.url)),
    ),
  );
  if (idl.address !== input.programId)
    throw new Error("IDL program identity mismatch");
  const program = new anchor.Program(idl, { connection });
  const config = PublicKey.findProgramAddressSync(
    [Buffer.from("config")],
    program.programId,
  )[0];
  return { connection, program, config };
}

/** The unsigned initialize_config transaction for the reviewed upgrade authority. */
export async function configPlan(input, runtime) {
  if (typeof input.upgradeAuthority !== "string")
    throw new Error("initialize_config needs the current upgrade authority");
  const { connection, program, config } = await connect(input, runtime);
  await verifyProgram(connection, program.programId, input);
  const authority = new PublicKey(input.upgradeAuthority),
    identity = new PublicKey(input.identityAuthority),
    fees = new PublicKey(input.feeRecipient);
  if (identity.equals(fees) || identity.equals(PublicKey.default))
    throw new Error("Identity authority and fee recipient must differ");
  if (await connection.getAccountInfo(config, "finalized"))
    throw new Error("Config already exists; it cannot change");
  const instruction = await program.methods
    .initializeConfig(identity, fees)
    .accountsStrict({
      authority,
      config,
      program: program.programId,
      programData: PublicKey.findProgramAddressSync(
        [program.programId.toBuffer()],
        UPGRADEABLE_LOADER,
      )[0],
      systemProgram: SystemProgram.programId,
    })
    .instruction();
  const blockhash = new PublicKey(runtime.recentBlockhash).toBase58();
  const transaction = new Transaction({
    feePayer: authority,
    recentBlockhash: blockhash,
  }).add(instruction);
  return {
    format: "solana-unsigned-legacy-transaction-v1",
    programId: input.programId,
    operation: "initialize-config",
    config: config.toBase58(),
    identityAuthority: identity.toBase58(),
    feeRecipient: fees.toBase58(),
    requiredSigner: authority.toBase58(),
    recentBlockhash: blockhash,
    transactionBase64: transaction
      .serialize({ requireAllSignatures: false, verifySignatures: false })
      .toString("base64"),
  };
}

/**
 * Every Project account of the program. A project is pinned only when it has the
 * current layout and its fee recipient equals the Config fee recipient; the
 * adapter refuses every other project.
 */
export async function listProjects(input, runtime) {
  const { connection, program, config } = await connect(input, runtime);
  const pinned = await program.account.config.fetchNullable(
    config,
    "finalized",
  );
  const accounts = await connection.getProgramAccounts(program.programId, {
    commitment: "finalized",
    filters: [
      {
        memcmp: {
          offset: 0,
          bytes: anchor.utils.bytes.bs58.encode(
            Buffer.from(PROJECT_DISCRIMINATOR, "hex"),
          ),
        },
      },
    ],
  });
  return {
    programId: input.programId,
    config: pinned
      ? {
          address: config.toBase58(),
          identityAuthority: pinned.identityAuthority.toBase58(),
          feeRecipient: pinned.feeRecipient.toBase58(),
        }
      : null,
    projects: accounts
      .map(({ pubkey, account }) => {
        const data = account.data,
          feeRecipient = base58(data.subarray(136, 168));
        return {
          address: pubkey.toBase58(),
          size: data.length,
          owner: base58(data.subarray(8, 40)),
          identityAuthority: base58(data.subarray(104, 136)),
          feeRecipient,
          mint: base58(data.subarray(168, 200)),
          pinned:
            pinned !== null &&
            data.length === 316 &&
            feeRecipient === pinned.feeRecipient.toBase58(),
        };
      })
      .sort((a, b) => a.address.localeCompare(b.address)),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, file] = process.argv.slice(2);
  if (!["plan", "projects"].includes(mode) || !file)
    throw new Error(
      "Usage: node config-plan.mjs plan|projects reviewed-config-input.json",
    );
  const input = JSON.parse(readFileSync(file, "utf8"));
  const runtime = {
    rpcUrl: process.env.SLOP_SOLANA_RPC_URL,
    expectedGenesis: process.env.SLOP_SOLANA_GENESIS,
    recentBlockhash: process.env.SLOP_SOLANA_RECENT_BLOCKHASH,
  };
  console.log(
    JSON.stringify(
      mode === "plan"
        ? await configPlan(input, runtime)
        : await listProjects(input, runtime),
      null,
      2,
    ),
  );
}
