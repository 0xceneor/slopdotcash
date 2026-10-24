/** Idempotent authorization for the ordinary monthly allocation, never a payment key. */
import { ed25519 } from "@noble/curves/ed25519.js";
import { recoverAddress } from "viem";
import {
  type MonthlyAttestationPlan,
  type MonthlyAttestationRequest,
  prepareMonthlyAttestation,
} from "../../backend/payments/monthly-attestation";
import { decodeBase58Bytes } from "../../src/lib/base58";
import type { JournalStore } from "./core";

export interface MonthlyAuthorization {
  plan: MonthlyAttestationPlan;
  /** Hex-encoded signature, without 0x. Public authorization; no private key. */
  signatureHex: string;
}
interface Intent {
  snapshotSha256: string;
  messageHex: string;
  authority: string;
  authorization?: MonthlyAuthorization;
}
const bytes = (hex: string) => {
  if (!/^(?:[a-f0-9]{2})+$/.test(hex))
    throw new Error("Invalid authorization encoding");
  return Uint8Array.from(hex.match(/../g) ?? [], (pair) =>
    Number.parseInt(pair, 16),
  );
};

/**
 * Called through the attester's serialized Durable Object. The intent is saved
 * before invoking its signer: interrupted requests may sign the same bytes but
 * can never replace a month's root. On-chain submission remains permissionless.
 */
export async function signMonthlyAllocation(
  deps: Omit<Parameters<typeof prepareMonthlyAttestation>[0], "now"> & {
    now(): Date;
    journal: JournalStore;
    /** Verify finalized chain identity, reviewed code and current authority. */
    verifyDeployment(plan: MonthlyAttestationPlan): Promise<void>;
    /** Sign the EVM digest directly (not personal_sign), or the Solana message. */
    sign(plan: MonthlyAttestationPlan): Promise<string>;
  },
  request: MonthlyAttestationRequest,
): Promise<MonthlyAuthorization> {
  const plan = await prepareMonthlyAttestation(
    { ...deps, now: deps.now() },
    request,
  );
  await deps.verifyDeployment(plan);
  const key = `monthly:${request.network}:${plan.deployment.vault}:${request.period}`;
  const expected: Intent = {
    snapshotSha256: request.snapshotSha256,
    messageHex: plan.messageHex,
    authority: plan.deployment.identityAuthority,
  };
  const intent = await deps.journal.transaction(async (tx) => {
    const previous = await tx.get<Intent>(key);
    if (previous) {
      if (
        previous.snapshotSha256 !== expected.snapshotSha256 ||
        previous.messageHex !== expected.messageHex ||
        previous.authority !== expected.authority
      )
        throw new Error(
          "Monthly authorization already bound to another allocation or authority",
        );
      return previous;
    }
    await tx.put(key, expected);
    return expected;
  });
  if (intent.authorization) return intent.authorization;
  const signatureHex = await deps.sign(plan);
  const signature = bytes(signatureHex);
  if (plan.family === "evm") {
    if (
      signature.length !== 65 ||
      (
        await recoverAddress({
          hash: `0x${plan.messageHex}`,
          signature: `0x${signatureHex}`,
        })
      ).toLowerCase() !== expected.authority.toLowerCase()
    )
      throw new Error(
        "Monthly signature does not match the reviewed authority",
      );
  } else if (
    signature.length !== 64 ||
    !ed25519.verify(
      signature,
      bytes(plan.messageHex),
      decodeBase58Bytes(expected.authority),
    )
  ) {
    throw new Error("Monthly signature does not match the reviewed authority");
  }
  // A slow signer must not publish after a restriction or opt-out was observed.
  const current = await prepareMonthlyAttestation(
    { ...deps, now: deps.now() },
    request,
  );
  if (
    current.messageHex !== plan.messageHex ||
    current.deployment.identityAuthority !== expected.authority
  )
    throw new Error("Monthly authorization changed during signing");
  const authorization = { plan, signatureHex };
  await deps.journal.put(key, { ...intent, authorization });
  return authorization;
}
