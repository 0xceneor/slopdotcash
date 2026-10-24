import type { PointAward } from "./points";

/** Group canonical point awards by occurrence date, independent of payout eligibility. */
export function dailyPoints(
  awards: readonly Pick<PointAward, "occurredAt" | "amount">[],
  today: Date,
  days: number,
): Array<{ day: string; points: number }> {
  const entries = Array.from({ length: days }, (_, index) => ({
    day: new Date(
      Date.UTC(
        today.getUTCFullYear(),
        today.getUTCMonth(),
        today.getUTCDate() - (days - 1 - index),
      ),
    )
      .toISOString()
      .slice(0, 10),
    points: 0,
  }));
  const byDay = new Map(entries.map((entry) => [entry.day, entry]));
  for (const award of awards) {
    const entry = byDay.get(award.occurredAt.slice(0, 10));
    if (entry) entry.points += award.amount;
  }
  return entries;
}
