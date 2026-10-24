import { expect, test } from "bun:test";
import { dailyPoints } from "../src/lib/profile-activity";

test("activity uses recorded points across reward-start dates and UTC boundaries", () => {
  // Historical awards still count as points even before a project starts paying.
  const chart = dailyPoints(
    [
      { occurredAt: "2026-07-05T23:59:59.999Z", amount: 750 },
      { occurredAt: "2026-07-06T23:59:59.999Z", amount: 10 },
      { occurredAt: "2026-07-07T00:00:00.000Z", amount: 30 },
      { occurredAt: "2026-07-07T12:00:00.000Z", amount: 90 },
      { occurredAt: "2026-07-08T00:00:00.000Z", amount: 240 },
    ],
    new Date("2026-07-07T23:59:59Z"),
    2,
  );
  expect(chart).toEqual([
    { day: "2026-07-06", points: 10 },
    { day: "2026-07-07", points: 120 },
  ]);
});
