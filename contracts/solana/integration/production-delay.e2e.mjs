import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import anchor from "@coral-xyz/anchor";
import { createMint, TOKEN_PROGRAM_ID } from "@solana/spl-token";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  sendAndConfirmTransaction,
  Transaction,
} from "@solana/web3.js";
import { configPlan } from "../scripts/config-plan.mjs";
import {
  configAddress,
  configFees,
  configIdentity,
  expectedDeployment,
  initializeConfig,
} from "./deployment.mjs";

// Runs only against the deployable build (no `short-delay-for-tests` feature).
const { AnchorProvider, Program, BN } = anchor;
const provider = AnchorProvider.env();
const payer = provider.wallet.payer;
const program = new Program(
  JSON.parse(readFileSync("target/idl/slop_escrow.json")),
  provider,
);
const hash = (s) => [...createHash("sha256").update(s).digest()];
const pda = (...seeds) =>
  PublicKey.findProgramAddressSync(seeds, program.programId)[0];

// This suite runs first on a fresh validator, before any Config exists.
test("only the upgrade authority initializes the Config, exactly once", async () => {
  const stranger = Keypair.generate();
  await sendAndConfirmTransaction(
    provider.connection,
    new Transaction().add(
      SystemProgram.transfer({
        fromPubkey: payer.publicKey,
        toPubkey: stranger.publicKey,
        lamports: 1_000_000_000,
      }),
    ),
    [payer],
  );
  await assert.rejects(
    initializeConfig(program, { authority: stranger }),
    /NotUpgradeAuthority/,
  );
  assert.equal(
    await provider.connection.getAccountInfo(configAddress(program.programId)),
    null,
  );
  // The identity authority and the fee recipient must be distinct, non-default keys.
  await assert.rejects(
    initializeConfig(program, { fees: configIdentity.publicKey }),
    /InvalidIdentity/,
  );
  // The human runbook path: config-plan builds the unsigned transaction and the
  // upgrade authority signs it.
  const reviewed = {
    programId: program.programId.toBase58(),
    ...expectedDeployment,
    identityAuthority: configIdentity.publicKey.toBase58(),
    feeRecipient: configFees.publicKey.toBase58(),
  };
  const runtime = async () => ({
    rpcUrl: provider.connection.rpcEndpoint,
    expectedGenesis: await provider.connection.getGenesisHash(),
    recentBlockhash: (await provider.connection.getLatestBlockhash()).blockhash,
  });
  const plan = await configPlan(reviewed, await runtime());
  assert.equal(plan.requiredSigner, payer.publicKey.toBase58());
  const transaction = Transaction.from(
    Buffer.from(plan.transactionBase64, "base64"),
  );
  assert.equal(
    transaction.signatures.every((s) => s.signature === null),
    true,
  );
  await provider.connection.confirmTransaction(
    await sendAndConfirmTransaction(provider.connection, transaction, [payer]),
    "finalized",
  );
  await assert.rejects(
    configPlan(reviewed, await runtime()),
    /Config already exists/,
  );
  const config = await program.account.config.fetch(
    configAddress(program.programId),
  );
  assert.equal(
    config.identityAuthority.toBase58(),
    configIdentity.publicKey.toBase58(),
  );
  assert.equal(config.feeRecipient.toBase58(), configFees.publicKey.toBase58());
  // No second initialization, and no update instruction exists.
  await assert.rejects(initializeConfig(program), /already in use|0x0/);
  await assert.rejects(
    initializeConfig(program, {
      identity: Keypair.generate().publicKey,
      fees: Keypair.generate().publicKey,
    }),
    /already in use|0x0/,
  );
});

test("the deployable build rejects a binding delay below one hour", async () => {
  const mint = await createMint(
    provider.connection,
    payer,
    payer.publicKey,
    null,
    6,
  );
  const initialize = (delay, rotationDelay = 3600) => {
    const id = hash(`production-delay:${delay}:${rotationDelay}`);
    const project = pda(
      Buffer.from("project"),
      payer.publicKey.toBuffer(),
      Buffer.from(id),
      Buffer.from([0]),
    );
    return program.methods
      .initialize(
        id,
        hash("solana:localnet:escrow-v2"),
        configIdentity.publicKey,
        configFees.publicKey,
        new BN(delay),
        new BN(rotationDelay),
        { ordinary: {} },
      )
      .accountsStrict({
        owner: payer.publicKey,
        project,
        mint,
        vault: pda(Buffer.from("vault"), project.toBuffer()),
        tokenProgram: TOKEN_PROGRAM_ID,
        systemProgram: SystemProgram.programId,
        config: configAddress(program.programId),
      })
      .rpc();
  };
  await assert.rejects(initialize(1), /InvalidDelay/);
  await assert.rejects(initialize(3599), /InvalidDelay/);
  // The identity authority rotation delay has the same one-hour floor.
  await assert.rejects(initialize(3600, 1), /InvalidDelay/);
  await assert.rejects(initialize(3600, 3599), /InvalidDelay/);
  await initialize(3600);
});
