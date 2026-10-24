/** A monthly target must not look like an active payment offer. */
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { PROJECTS } from "../../src/lib/projects.mjs";

test("disabled payouts are visible from discovery through the project page", async ({
  page,
}, info) => {
  const original = PROJECTS.find((project) => project.id === "eliza");
  if (!original) throw new Error("Missing project fixture");
  const project = {
    ...original,
    status: "active",
    reward: { ...original.reward, paymentMode: "disabled" },
  };
  await page.route(
    /\/(?:api\/v1\/projects|data\/fixture-project-registry\.json)$/,
    (route) =>
      route.fulfill({ json: { schemaVersion: "1", projects: [project] } }),
  );
  await page.route("**/api/v1/projects/eliza", (route) =>
    route.fulfill({ json: { project, revision: 1 } }),
  );
  await page.route("**/.well-known/slop/projects.json", (route) =>
    route.fulfill({ json: { schemaVersion: "1", projects: [] } }),
  );
  await page.route("**/api/v1/project-session", (route) =>
    route.fulfill({ json: { session: null } }),
  );
  await page.goto("/", { waitUntil: "networkidle" });
  const card = page.locator('a.project-card[href="/projects/eliza"]');
  await expect(
    card.getByText("Payments not active", { exact: true }),
  ).toHaveCount(0);
  await expect(card).toContainText("/mo target");
  await page.screenshot({
    path: info.outputPath("home-payment-unavailable.png"),
    fullPage: true,
  });
  await card.click();
  await expect(
    page.getByRole("heading", { name: "Eliza", exact: true, level: 1 }),
  ).toBeVisible();
  await expect(page.locator(".project-reward-status")).toContainText(
    "payments not active",
  );
  await page.screenshot({
    path: info.outputPath("project-payment-unavailable.png"),
    fullPage: true,
  });
  await page.goto("/projects/eliza/funding", { waitUntil: "networkidle" });
  const status = page.locator(".funding-status-grid");
  const term = (name: string) =>
    status
      .locator("div")
      .filter({ has: page.locator("dt", { hasText: new RegExp(`^${name}$`) }) })
      .locator("dd");
  await expect(term("Payments")).toHaveText("Disabled");
  await expect(term("Project vault")).toHaveText("Not set up");
  await page.screenshot({
    path: info.outputPath("funding-payment-unavailable.png"),
    fullPage: true,
  });
  await page.goto("/sponsors", { waitUntil: "networkidle" });
  const pools = page.getByRole("table");
  const paymentsColumn = await pools
    .getByRole("columnheader")
    .allTextContents()
    .then((headers) => headers.indexOf("Payments"));
  expect(paymentsColumn).toBeGreaterThan(0);
  await expect(
    pools
      .getByRole("row")
      .filter({ has: page.getByRole("link", { name: "Eliza", exact: true }) })
      .getByRole("cell")
      .nth(paymentsColumn - 1),
  ).toHaveText("Disabled");
  expect(
    (
      await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21aa"])
        .analyze()
    ).violations,
  ).toEqual([]);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth - innerWidth,
    ),
  ).toBeLessThanOrEqual(1);
});
