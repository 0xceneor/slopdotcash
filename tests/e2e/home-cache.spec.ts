/**
 * First-visit discovery waits only for the project registry, which the site
 * reads from D1 at runtime; no other API or public data response may block it.
 */
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { homeProjects } from "../../src/lib/home-projects";

test.use({ video: "on" });

test("renders bundled projects with data stalled and GitHub blocked", async ({
  page,
}) => {
  const requests: string[] = [];
  const errors: string[] = [];
  page.on("request", (request) => requests.push(request.url()));
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  let release = () => {};
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.route(
    /\/(?:data|api)\/|\/\.well-known\/slop\/projects\.json$/,
    async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (
        path !== "/api/v1/projects" &&
        path !== "/data/fixture-project-registry.json"
      )
        await held;
      await route.fallback();
    },
  );
  await page.route(/https:\/\/[^/]*github[^/]*\//, (route) => route.abort());
  try {
    await page.goto("/", { waitUntil: "domcontentloaded" });
    const expected = homeProjects().filter(
      (project) => project.listingTier === "featured",
    );
    expect(expected.length).toBeGreaterThan(0);
    await expect(page.locator(".project-card")).toHaveCount(expected.length);
    for (const project of expected) {
      await expect(
        page.getByRole("heading", { name: project.name, exact: true }),
      ).toBeVisible();
    }
    await page.keyboard.press("Tab");
    await expect(page.locator(":focus")).toBeVisible();
    await page.screenshot({
      path: test.info().outputPath("cached-projects.png"),
      fullPage: true,
    });
    // Keep at least 320 CSS pixels for reflow. Doubling the 320px viewport
    // tests a 160px layout, below the site's supported minimum.
    if ((page.viewportSize()?.width ?? 0) >= 640) {
      await page.evaluate(() => {
        document.documentElement.style.zoom = "2";
      });
    }
    await expect
      .poll(() =>
        page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      )
      .toBe(true);
    const accessibility = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
      .analyze();
    expect(accessibility.violations).toEqual([]);
    // Project owner avatars are optional decoration: a blocked avatar falls
    // back to the bundled initial and never delays the project list.
    const avatar = /^https:\/\/avatars\.githubusercontent\.com\//u;
    expect(
      requests.filter((url) => !avatar.test(url) && /github/.test(url)),
    ).toEqual([]);
    await expect(page.locator("img.project-avatar")).toHaveCount(0);
    expect(
      errors.filter(
        (error) => !error.startsWith("Failed to load resource: net::"),
      ),
    ).toEqual([]);
  } finally {
    await test.info().attach("homepage-network-and-console", {
      body: JSON.stringify({ requests, errors }, null, 2),
      contentType: "application/json",
    });
    release();
  }
});

test("a failed registry read keeps the last good projects with a stale label", async ({
  page,
}) => {
  const errors: string[] = [];
  const published: number[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  page.on("response", (response) => {
    if (new URL(response.url()).pathname === "/data/project-registry.json")
      published.push(response.status());
  });
  // The fixture build reads its live registry from this file. The build
  // publishes its synced snapshot at /data/project-registry.json.
  await page.route("**/data/fixture-project-registry.json", (route) =>
    route.fulfill({ status: 503, json: { error: "unavailable" } }),
  );
  await page.goto("/", { waitUntil: "networkidle" });
  const notice = page
    .getByRole("complementary", { name: "Project registry status" })
    .getByRole("status");
  await expect(notice).toContainText("Projects may be outdated");
  await expect(notice).toContainText("Oct 16, 2026");
  await expect(notice).toContainText("HTTP 503");
  await expect(notice.getByRole("button", { name: "Try again" })).toBeVisible();
  expect(published).toEqual([200]);
  // The last good list is shown, never an outage page or an empty list.
  const expected = homeProjects().filter(
    (project) => project.listingTier === "featured",
  );
  expect(expected.length).toBeGreaterThan(0);
  await expect(page.locator(".project-card")).toHaveCount(expected.length);
  await expect(
    page.getByRole("heading", { name: "Projects are unavailable" }),
  ).toHaveCount(0);
  await page.screenshot({
    path: test.info().outputPath("stale-registry-home.png"),
    fullPage: true,
  });
  const home = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
  expect(home.violations).toEqual([]);
  // The retry control is reachable by keyboard, and the label reflows at
  // 200% zoom (only where that keeps at least 320 CSS pixels).
  const retry = notice.getByRole("button", { name: "Try again" });
  for (let step = 0; step < 12; step += 1) {
    if (await retry.evaluate((element) => element === document.activeElement))
      break;
    await page.keyboard.press("Tab");
  }
  await expect(retry).toBeFocused();
  if ((page.viewportSize()?.width ?? 0) >= 640) {
    await page.evaluate(() => {
      document.documentElement.style.zoom = "2";
    });
    await expect
      .poll(() =>
        page.evaluate(
          () => document.documentElement.scrollWidth <= window.innerWidth,
        ),
      )
      .toBe(true);
    await expect(notice).toBeVisible();
  }

  const project = expected[0];
  await page.goto(`/projects/${project.slug}`, { waitUntil: "networkidle" });
  await expect(
    page.getByRole("heading", { level: 1, name: project.name }),
  ).toBeVisible();
  await expect(notice).toContainText("Projects may be outdated");

  // Pages that act on the current manifest never use the last good copy.
  await page.goto(`/projects/${project.slug}/funding`, {
    waitUntil: "networkidle",
  });
  await expect(
    page.getByRole("heading", { name: "Projects are unavailable" }),
  ).toBeVisible();
  await expect(page.getByRole("alert")).toContainText(
    "This page needs the current project registry.",
  );
  await expect(notice).toHaveCount(0);

  // Account routes do not depend on the registry and show no label.
  await page.goto("/account", { waitUntil: "networkidle" });
  await expect(page.getByRole("heading", { level: 1 })).toContainText(
    "Account",
  );
  await expect(notice).toHaveCount(0);
  expect(
    errors.filter(
      (error) =>
        !error.startsWith("Failed to load resource: the server responded"),
    ),
  ).toEqual([]);
});
