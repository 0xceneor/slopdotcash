/** Types the project registry generator for focused contract tests. */

export function renderProjectRegistry(
  values: unknown,
  syncedAt?: string | null,
): Promise<string>;
export function renderProjectRevisions(
  revisions: unknown,
  definitions: readonly unknown[],
): string;
export function fetchProjectRegistry(origin?: string): Promise<{
  projects: unknown[];
  revisions: unknown[];
  /** Restricted projects whose paused, retired revision is still pending; `projects` already shows them paused and retired. */
  withheld: string[];
}>;
export function syncProjectRegistry(checkOnly?: boolean): Promise<boolean>;
