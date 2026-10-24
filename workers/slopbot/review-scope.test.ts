// A paused project keeps security review only (PRD section 5): a non-security
// finding writes nothing to GitHub, while the same item on an active project
// is labeled. Local synthetic GitHub responses only; no model is called.
import { expect, test } from "bun:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import { readdirSync } from "node:fs";
import { findProject } from "../../src/lib/projects.mjs";
import { sqliteD1 } from "../../tests/sqlite-d1";
import type { Job } from "./contracts";
import type { D1Database } from "./persistence";
import { type ReviewEnv, reviewItem } from "./review";

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

async function reviewEmptyPull(status: "active" | "paused") {
  const { db, sqlite } = sqliteD1(
    readdirSync(new URL("../../migrations/", import.meta.url))
      .filter((p) => p.endsWith(".sql"))
      .sort(),
  );
  const project = findProject("asi");
  if (!project) throw new Error("fixture project missing");
  const manifest = JSON.stringify({ ...project, status });
  const digest = createHash("sha256").update(manifest).digest("hex");
  const at = "2026-10-21T00:00:00.000Z";
  sqlite.run(
    "INSERT INTO project_revisions(project_id,revision,manifest,manifest_sha256,reason,created_at) VALUES (?,1,?,?,?,?)",
    [project.id, manifest, digest, "local regression fixture", at],
  );
  sqlite.run(
    "INSERT INTO projects(id,status,revision,manifest,manifest_sha256,created_at,updated_at) VALUES (?,?,1,?,?,?,?)",
    [project.id, status, manifest, digest, at, at],
  );
  const [owner, repo] = new URL(project.repositories[0].githubUrl).pathname
    .slice(1)
    .split("/");
  sqlite.run(
    "INSERT INTO project_repositories(repository_key,project_id) VALUES (?,?)",
    [`${owner}/${repo}`.toLowerCase(), project.id],
  );
  sqlite.run(
    "INSERT INTO slopbot_installations(installation_id, account_id, account_login, account_type, created_at) VALUES (1,77,?,'Organization',?)",
    [owner, at],
  );
  const repositoryId = Number(project.authority.repositoryId);
  const writes: string[] = [];
  const server = Bun.serve({
    port: 0,
    fetch(request) {
      const path = new URL(request.url).pathname;
      if (request.method !== "GET") writes.push(`${request.method} ${path}`);
      if (path.endsWith("/access_tokens"))
        return Response.json({ token: "local-synthetic-token" });
      if (path === `/repos/${owner}/${repo}`)
        return Response.json({
          id: repositoryId,
          private: false,
          default_branch: "main",
          owner: { login: owner, id: 77, type: "Organization" },
        });
      if (path.endsWith("/issues/5") && request.method === "GET")
        return Response.json({
          node_id: "PR_local",
          number: 5,
          state: "open",
          title: "empty change",
          body: "Made via @slopdotcash",
          user: { login: "author", id: 42, type: "User" },
          assignees: [],
        });
      if (path.endsWith("/pulls/5"))
        return Response.json({
          draft: false,
          merged: false,
          head: { sha: "b".repeat(40) },
          base: { sha: "c".repeat(40) },
          additions: 0,
          deletions: 0,
          changed_files: 0,
        });
      if (path.endsWith("/branches/main"))
        return Response.json({ commit: { sha: "c".repeat(40) } });
      if (path.endsWith("/pulls/5/files")) return Response.json([]);
      if (path.endsWith("/permission"))
        return Response.json({ permission: "read" });
      if (path.endsWith("/issues/5/comments") && request.method === "GET")
        return Response.json([]);
      if (path.endsWith("/issues/5/comments"))
        return Response.json({ id: 900 }, { status: 201 });
      if (path.endsWith("/issues/5/labels"))
        return Response.json([{ name: "slopbot: empty" }]);
      return new Response(null, { status: 404 });
    },
  });
  const nativeFetch = globalThis.fetch;
  globalThis.fetch = ((
    url: Parameters<typeof fetch>[0],
    init: Parameters<typeof fetch>[1],
  ) => {
    const u = new URL(url instanceof Request ? url.url : String(url));
    if (u.hostname !== "api.github.com")
      throw new Error(`unexpected network request to ${u.hostname}`);
    return nativeFetch(new URL(u.pathname + u.search, server.url), init);
  }) as typeof fetch;
  const env = {
    SLOPBOT_DB: db as unknown as D1Database,
    SLOPBOT_APP_ID: "1",
    SLOPBOT_APP_PRIVATE_KEY: privateKey,
    SLOPBOT_APP_USER_ID: "999",
  } as ReviewEnv;
  const job: Extract<Job, { kind: "review" }> = {
    kind: "review",
    deliveryId: `scope-${status}`,
    installationId: 1,
    repositoryId,
    owner,
    repo,
    itemKind: "pull_request",
    number: 5,
  };
  try {
    const outcome = await reviewItem(env, job);
    const review = sqlite
      .query("SELECT status, action FROM slopbot_reviews")
      .get();
    return { outcome, writes, review };
  } finally {
    globalThis.fetch = nativeFetch;
    server.stop(true);
    sqlite.close();
  }
}

test("a paused project gets security review only and no contributor-work action", async () => {
  const paused = await reviewEmptyPull("paused");
  expect(paused.outcome).toBe("no action (empty; security review only)");
  expect(paused.review).toEqual({ status: "completed", action: "none" });
  expect(paused.writes.filter((w) => !w.endsWith("/access_tokens"))).toEqual(
    [],
  );

  const active = await reviewEmptyPull("active");
  expect(active.outcome).toBe("labeled (empty)");
  expect(active.review).toEqual({ status: "completed", action: "label" });
  expect(active.writes).toContain(
    "POST /repos/SlopDotCash/asi/issues/5/labels",
  );
});
