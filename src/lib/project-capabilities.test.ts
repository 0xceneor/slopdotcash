import { describe, expect, test } from "bun:test";
import { evaluateProjectCapabilities } from "./project-capabilities.mjs";

const open = {
  registered: true,
  status: "active",
  listingTier: "standard",
  restriction: "clear",
  flagged: false,
  funding: "unfunded",
} as const;

describe("project capabilities", () => {
  test("an unfunded active project is open to contributor work and security review", () => {
    expect(evaluateProjectCapabilities(open)).toMatchObject({
      mayReviewForSecurity: true,
      mayOfferContributorWork: true,
      mayExecuteApprovedPayment: false,
    });
  });

  test("a retired project gets no review and keeps funded obligations", () => {
    expect(
      evaluateProjectCapabilities({
        ...open,
        listingTier: "retired",
        funding: "funded",
      }),
    ).toMatchObject({
      mayReviewForSecurity: false,
      mayOfferContributorWork: false,
      mayExecuteApprovedPayment: true,
    });
  });

  test.each([
    { status: "paused" as const },
    { restriction: "quarantined" as const },
    { restriction: "banned" as const },
    { restriction: "unknown" as const },
    { flagged: true },
  ])("a restricted project keeps security review only: %o", (change) => {
    const capabilities = evaluateProjectCapabilities({ ...open, ...change });
    expect(capabilities.mayReviewForSecurity).toBe(true);
    expect(capabilities.mayOfferContributorWork).toBe(false);
  });

  test("a funded obligation survives a pause or a ban", () => {
    for (const restriction of ["clear", "quarantined", "banned"] as const)
      expect(
        evaluateProjectCapabilities({
          ...open,
          status: "paused",
          restriction,
          funding: "funded",
        }).mayExecuteApprovedPayment,
      ).toBe(true);
  });

  test("unknown facts and unregistered repositories fail closed", () => {
    expect(
      evaluateProjectCapabilities({ registered: true, status: "active" }),
    ).toMatchObject({
      mayReviewForSecurity: true,
      mayOfferContributorWork: false,
      mayExecuteApprovedPayment: false,
    });
    expect(
      evaluateProjectCapabilities({
        ...open,
        registered: false,
        funding: "funded",
      }),
    ).toMatchObject({
      mayReviewForSecurity: false,
      mayOfferContributorWork: false,
      mayExecuteApprovedPayment: false,
    });
    expect(() =>
      evaluateProjectCapabilities({
        ...open,
        restriction: "paused" as "clear",
      }),
    ).toThrow("unknown project restriction state");
  });
});
