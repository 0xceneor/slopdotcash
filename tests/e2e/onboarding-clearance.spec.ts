/** Exercises the start control's public discovery contract, not VM clearance. */
import { expect, test } from "@playwright/test";

test("agent setup retries unavailable discovery and only copies a cleared project prompt", async ({
  page,
  context,
}, info) => {
  let state: "unavailable" | "blocked" | "cleared" = "unavailable";
  await page.route("**/.well-known/slop/projects.json", (route) =>
    route.fulfill({
      // Invalid response bodies can occur when a static host substitutes index.html.
      ...(state === "unavailable"
        ? { contentType: "text/html", body: "<html>Unavailable</html>" }
        : {
            json: {
              schemaVersion: "1",
              projects: state === "blocked" ? [] : [{ project_id: "eliza" }],
            },
          }),
    }),
  );
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/projects/eliza", { waitUntil: "networkidle" });
  await expect(
    page.getByRole("heading", { name: "Agent setup unavailable", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Copy agent prompt" }),
  ).toHaveCount(0);
  state = "blocked";
  await page.getByRole("button", { name: "Check again", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Agent setup awaiting security review" }),
  ).toBeVisible();
  await page.screenshot({
    path: info.outputPath("blocked-agent-setup.png"),
    fullPage: true,
  });
  state = "cleared";
  await page.getByRole("button", { name: "Check again", exact: true }).click();
  await expect(
    page.getByRole("status", { name: "Agent prompt" }),
  ).toContainText("elizaOS/eliza");
  await page.getByRole("button", { name: "Copy agent prompt" }).click();
  await expect(page.getByRole("button", { name: /Copied/u })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain(
    "elizaOS/eliza",
  );
  state = "blocked";
  await page.goto("/", { waitUntil: "networkidle" });
  await expect(
    page.getByRole("heading", { name: "Projects", exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("heading", { name: /Agent setup/u })).toHaveCount(
    0,
  );
  await expect(
    page.getByRole("button", { name: "Copy agent prompt" }),
  ).toBeVisible();
  await page.screenshot({
    path: info.outputPath("home-no-cleared-projects.png"),
    fullPage: true,
  });
  state = "cleared";
  await page.reload({ waitUntil: "networkidle" });
  await expect(
    page.getByRole("status", { name: "Agent prompt" }),
  ).toContainText("/SKILL.md");
});

test("home agent setup stays usable when discovery is unavailable", async ({
  page,
  context,
}) => {
  await page.route("**/.well-known/slop/projects.json", (route) =>
    route.fulfill({ status: 503, body: "Unavailable" }),
  );
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await page.goto("/", { waitUntil: "networkidle" });
  await page.getByRole("button", { name: "Copy agent prompt" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toContain(
    "/SKILL.md",
  );
  await expect(
    page.getByRole("heading", { name: "Agent setup unavailable" }),
  ).toHaveCount(0);
});
