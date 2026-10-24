import { expect, test } from "@playwright/test";

test("hero types, deletes and cycles all original campaign phrases without moving the layout", async ({
  page,
}) => {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  test.setTimeout(45_000);
  await page.goto("/");
  const heading = page.getByRole("heading", { level: 1 });
  const text = heading.locator(".hero-typewriter");
  await expect(text).toHaveText("SHIPPING OPEN SOURCE.");
  await page.evaluate(() => document.fonts.ready);
  const before = await heading.boundingBox();
  for (const next of [
    "SECURING THE WEB.",
    "HACKING THE PLANET.",
    "BUILDING AGI.",
    "SHIPPING OPEN SOURCE.",
  ]) {
    await page.waitForFunction(() => {
      const value = document.querySelector(".hero-typewriter")?.textContent;
      return value === "";
    });
    await page.waitForFunction((target) => {
      const value =
        document.querySelector(".hero-typewriter")?.textContent ?? "";
      return (
        value.length > 0 &&
        value.length < target.length &&
        target.startsWith(value)
      );
    }, next);
    await expect(text).toHaveText(next);
    await expect(heading).toHaveAccessibleName(
      "MAKE MONEY SHIPPING OPEN SOURCE.",
    );
    expect((await heading.boundingBox())?.height).toBe(before?.height);
  }
});

test("reduced motion keeps the hero static", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await page.clock.install({ time: new Date("2026-10-24T00:00:00Z") });
  await page.clock.pauseAt(new Date("2026-10-24T00:00:01Z"));
  await page.goto("/");
  const text = page.locator(".hero-typewriter");
  await expect(text).toHaveText("SHIPPING OPEN SOURCE.");
  await page.clock.runFor(30_000);
  await expect(text).toHaveText("SHIPPING OPEN SOURCE.");
  await expect(
    page.locator(".hero-typewriter > .hero-typewriter-caret"),
  ).toBeHidden();
});
