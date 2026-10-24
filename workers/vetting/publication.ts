/**
 * Trusted, operator-side reconciliation and one-attempt publication.
 * Never import this module into a guest or give a model its signing capability.
 */
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  dispositionProblems,
  MAX_VETTING_RESULT_BYTES,
  parseVettingResult,
  type VettingResult,
} from "../../backend/vetting/result";
import {
  parseRecordedVettingResult,
  recordedResultProblems,
} from "../../backend/vetting/scan-result";
import { REVIEW_AREAS, type ScannerEvidence } from "./scanners";
import { signedServiceHeaders, type VettingServiceSigner } from "./service";

const sha256 = (bytes: string | Uint8Array) =>
  createHash("sha256").update(bytes).digest("hex");

/** A separate trusted reviewer supplies this, never a scanner response. */
export type ConfirmedEvidence = {
  inputManifestSha256: string;
  traceSha256: string;
  reviewerId: string;
  confirmation: NonNullable<VettingResult["confirmation"]>;
};

export function reconcileResult(input: {
  /** Actual collector observation; its proposed disposition is ignored. */
  observation: unknown;
  inputManifest: Uint8Array;
  trace: Uint8Array;
  reviews: [ScannerEvidence, ScannerEvidence];
  confirmedEvidence?: ConfirmedEvidence;
}) {
  const observed = parseVettingResult(input.observation);
  if (
    sha256(input.inputManifest) !== observed.assessed.inputManifestSha256 ||
    sha256(input.trace) !== observed.traceSha256
  )
    throw new Error("Collected evidence does not match the observation");
  const inventory = JSON.parse(
    new TextDecoder("utf-8", { fatal: true }).decode(input.inputManifest),
  );
  if (!Array.isArray(inventory.visibilityGaps))
    throw new Error("Inventory coverage is missing");
  const result = parseVettingResult({
    ...observed,
    disposition: "incomplete",
    confirmation: null,
    modelReviews: input.reviews.map((review) => review.review),
    telemetry: {
      ...observed.telemetry,
      visibilityGaps: [
        ...observed.telemetry.visibilityGaps,
        ...inventory.visibilityGaps,
        ...input.reviews.flatMap((review) => review.visibilityGaps),
      ],
    },
  });
  // A completed response is not reconciliation. Any model finding needs
  // independent inspection; disagreement must never silently become clean.
  const reviewGaps: string[] = [];
  for (const scanner of input.reviews) {
    if (
      scanner.review.inputManifestSha256 !== result.assessed.inputManifestSha256
    )
      throw new Error("Scanner reviewed another inventory");
    if (
      scanner.review.findingCount !== scanner.findings.length ||
      scanner.review.status !== "completed" ||
      scanner.review.verdict !== "no-findings" ||
      scanner.coverage === null ||
      REVIEW_AREAS.some((area) => scanner.coverage?.[area] !== "complete")
    )
      reviewGaps.push(`${scanner.review.reviewer}:independent-review-required`);
  }
  if (input.reviews[0].review.verdict !== input.reviews[1].review.verdict)
    reviewGaps.push("independent-model-disagreement");
  result.telemetry.visibilityGaps = [
    ...new Set([...result.telemetry.visibilityGaps, ...reviewGaps]),
  ];
  let confirmationSha256: string | null = null;
  if (input.confirmedEvidence) {
    const decision = input.confirmedEvidence;
    if (
      !/^[A-Za-z0-9][A-Za-z0-9._:@/+-]{0,127}$/u.test(decision.reviewerId) ||
      decision.inputManifestSha256 !== result.assessed.inputManifestSha256 ||
      decision.traceSha256 !== result.traceSha256
    )
      throw new Error("Independent confirmation does not bind this evidence");
    result.confirmation = decision.confirmation;
    result.disposition = "malicious";
    confirmationSha256 = sha256(JSON.stringify(decision));
  } else {
    result.disposition = "clean";
    if (dispositionProblems(result).length > 0)
      result.disposition = "incomplete";
  }
  const checked = parseVettingResult(result);
  if (dispositionProblems(checked).length > 0)
    throw new Error("Reconciled disposition is not supported");
  const body = JSON.stringify(checked);
  if (Buffer.byteLength(body) > MAX_VETTING_RESULT_BYTES)
    throw new Error("Result exceeds the intake limit");
  return {
    body,
    resultSha256: sha256(body),
    confirmationSha256,
    disposition: checked.disposition,
    assessmentId: checked.assessmentId,
  };
}

/**
 * Explicitly publish reviewed bytes once. A private journal prevents a blind
 * retry after a lost response. An operator must reconcile uncertain outcomes.
 */
export async function publishResult(input: {
  origin: string;
  body: string;
  approvedSha256: string;
  signer: VettingServiceSigner;
  /** Existing operator-private directory outside all guest/shared mounts. */
  journalDirectory: string;
  at?: Date;
  fetch?: typeof fetch;
}) {
  const origin = new URL(input.origin);
  if (
    origin.protocol !== "https:" ||
    origin.origin !== input.origin ||
    origin.username ||
    origin.password
  )
    throw new Error("An exact reviewed HTTPS service origin is required");
  // Publishes either a bounded scan result or a historical v1 result.
  const result = parseRecordedVettingResult(JSON.parse(input.body));
  if (
    Buffer.byteLength(input.body) > MAX_VETTING_RESULT_BYTES ||
    sha256(input.body) !== input.approvedSha256 ||
    JSON.stringify(result) !== input.body ||
    recordedResultProblems(result).length > 0
  )
    throw new Error("Publication bytes do not match the approved result");
  const path = "/api/v1/vetting/results";
  const headers = await signedServiceHeaders({
    signer: input.signer,
    method: "POST",
    pathAndQuery: path,
    body: new TextEncoder().encode(input.body),
    at: input.at,
  });
  const directory = join(input.journalDirectory, result.assessmentId);
  // Atomic exclusive reservation across processes. Never remove it on failure.
  await mkdir(directory, { mode: 0o700 });
  const intent = {
    assessmentId: result.assessmentId,
    resultSha256: input.approvedSha256,
    origin: input.origin,
    disposition: result.disposition,
  };
  await writeFile(join(directory, "intent.json"), JSON.stringify(intent), {
    mode: 0o600,
    flag: "wx",
  });
  let outcome: "accepted" | "rejected" | "unknown" = "unknown";
  let httpStatus: number | null = null;
  try {
    const response = await (input.fetch ?? fetch)(`${input.origin}${path}`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: input.body,
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
    });
    httpStatus = response.status;
    if (response.status !== 200) {
      // A server failure or conflict can follow a committed write. Only the
      // intake's definite pre-write client rejections prove no acceptance.
      if ([400, 401, 403, 404, 413, 422].includes(response.status))
        outcome = "rejected";
      await response.body?.cancel();
    } else {
      // Check the committed assessment receipt, not only an HTTP success code.
      const reader = response.body?.getReader();
      if (!reader) throw new Error("Missing receipt");
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          size += value.byteLength;
          if (size > MAX_VETTING_RESULT_BYTES)
            throw new Error("Invalid receipt");
          chunks.push(value);
        }
      } finally {
        await reader.cancel();
      }
      const receipt = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (
        receipt.assessment?.id === result.assessmentId &&
        receipt.assessment?.revision === result.revision &&
        receipt.assessment?.state === result.disposition &&
        receipt.assessment?.commitSha === result.assessed.commitSha &&
        receipt.assessment?.templateSha256 === result.assessed.templateSha256 &&
        receipt.assessment?.policyVersion === result.policyVersion &&
        receipt.assessment?.resultSha256 === input.approvedSha256
      )
        outcome = "accepted";
    }
  } catch {
    // Do not leak transport errors, credentials or private result content.
  }
  const receipt = { ...intent, outcome, httpStatus };
  await writeFile(join(directory, "receipt.json"), JSON.stringify(receipt), {
    mode: 0o600,
    flag: "wx",
  });
  return receipt;
}
