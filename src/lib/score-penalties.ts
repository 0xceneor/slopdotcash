/**
 * Applies published Slopbot penalty debits (PRD section 7) to a set of score
 * events. A debit reduces only its actor's score for its own project and UTC
 * month, and never below zero: each (actor, project, month) group loses at
 * most the credit that the same events give it. Every caller passes exactly
 * the events it counts, so the rolling leaderboard, a project cycle and the
 * cumulative leaderboard each apply the same rule to their own scope.
 */
import type { ScoreEvent, ScorePenalty } from "./leaderboard-types";

const eventThirds = (event: ScoreEvent) =>
  event.scoreThirds ?? Math.round(event.points * 3);

/** Applied debit thirds by actor node ID; actors with no debit are absent. */
export function penaltyDebitThirds(
  events: readonly ScoreEvent[],
  penalties: readonly ScorePenalty[],
  projectOf: (repository: string) => string,
): Map<string, number> {
  if (penalties.length === 0) return new Map();
  const groups = new Map<
    string,
    { actorId: string; credit: number; debit: number }
  >();
  const group = (actorId: string, repository: string, period: string) => {
    const key = JSON.stringify([actorId, projectOf(repository), period]);
    const existing = groups.get(key);
    if (existing) return existing;
    const created = { actorId, credit: 0, debit: 0 };
    groups.set(key, created);
    return created;
  };
  for (const penalty of penalties)
    group(penalty.actor.id, penalty.repository, penalty.period).debit +=
      penalty.debitThirds;
  for (const event of events) {
    const key = JSON.stringify([
      event.actor.id,
      projectOf(event.repository),
      event.occurredAt.slice(0, 7),
    ]);
    const existing = groups.get(key);
    if (existing) existing.credit += eventThirds(event);
  }
  const applied = new Map<string, number>();
  for (const { actorId, credit, debit } of groups.values()) {
    const thirds = Math.min(credit, debit);
    if (thirds > 0) applied.set(actorId, (applied.get(actorId) ?? 0) + thirds);
  }
  return applied;
}

/** The project of each collected repository, from the snapshot inventory. */
export function snapshotProjectOf(snapshot: {
  repositories: readonly { id: string; projectId: string }[];
}): (repository: string) => string {
  const projects = new Map(
    snapshot.repositories.map((repository) => [
      repository.id,
      repository.projectId,
    ]),
  );
  return (repository) => {
    const project = projects.get(repository);
    if (project === undefined)
      throw new Error(`Repository ${repository} is outside the snapshot`);
    return project;
  };
}
