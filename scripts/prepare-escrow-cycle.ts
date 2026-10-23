/**
 * Validates a historical escrow-v2 cycle directory. New monthly allocations
 * are private D1 records (scripts/prepare-monthly-rewards.ts); no new cycle
 * files are written, but earlier records stay verifiable.
 */
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { validateEscrowCycle as validateArchivedEscrowCycle } from "../src/lib/payments/escrow-cycle";
import { findProject } from "../src/lib/projects.mjs";

export async function validateEscrowCycle(
  directory: string,
  projectId: string,
  cycleId: string,
) {
  if (!findProject(projectId))
    throw new Error("Archived project is not canonical");
  return validateArchivedEscrowCycle(
    (name) => readFile(resolve(directory, name)),
    projectId,
    cycleId,
  );
}
