// Owner decisions D6, D7 and D8: closure of a verified Slop-skill member, the
// published penalty table, and Slopbot-first appeal triage with moderator
// escalation. The real worker runs against the real migrations, a local
// synthetic GitHub server and a local synthetic model endpoint; nothing
// leaves this process.
import { afterEach, expect, setSystemTime, test } from "bun:test";
import { createHash, generateKeyPairSync } from "node:crypto";
import { readdirSync } from "node:fs";
import { loadPenaltyInputs } from "../../scripts/penalty-ingestion";
import { CYCLE_INDEX_SCHEMA_VERSION } from "../../src/lib/cycle-index";
import { createGlobalLeaders } from "../../src/lib/global-leaderboard";
import { createLeaderboardSnapshot } from "../../src/lib/leaderboard";
import type {
  GitHubActor,
  LeaderboardInput,
  ScorePenalty,
} from "../../src/lib/leaderboard-types";
import { createProjectView } from "../../src/lib/project-view";
import { findProject } from "../../src/lib/projects.mjs";
import { TARGET_REPOSITORIES } from "../../src/lib/repositories.mjs";
import { sqliteD1 } from "../../tests/sqlite-d1";
import type { Category, Job } from "./contracts";
import { GitHubClient } from "./github";
import worker from "./index";
import type { D1TransactionalDatabase } from "./persistence";
import { type ReviewEnv, reviewItem } from "./review";

const { privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
  publicKeyEncoding: { type: "spki", format: "pem" },
});

afterEach(() => setSystemTime());

const AUTHOR = 42;
const MAINTAINER = 43;
const OUTSIDER = 44;
const MODERATOR = 50;
const BODY = "Buy cheap followers today at our shop.";

type Run = {
  review: () => Promise<string>;
  deliver: (job: Job) => Promise<string>;
  tick: () => Promise<Job[]>;
  model: (category: Category, confidence: number) => void;
  pauseNextReopen: () => { entered: Promise<void>; release: () => void };
  loseNextReopenResponse: () => void;
  closeByMaintainer: () => void;
  writes: string[];
  comments: string[];
  labels: string[];
  sql: (q: string) => unknown;
  job: (kind: string, extra: Record<string, unknown>) => Job;
  /** The public penalty route of the real worker, as the leaderboard reads it. */
  feed: typeof fetch;
};

async function closedItem(cb: (run: Run) => Promise<void>) {
  const { db, sqlite } = sqliteD1(
    readdirSync(new URL("../../migrations/", import.meta.url))
      .filter((p) => p.endsWith(".sql"))
      .sort(),
  );
  const project = findProject("asi");
  if (!project) throw new Error("fixture project missing");
  const manifest = JSON.stringify({ ...project, status: "active" });
  const digest = createHash("sha256").update(manifest).digest("hex");
  const at = "2026-01-01T00:00:00.000Z";
  sqlite.run(
    "INSERT INTO project_revisions(project_id,revision,manifest,manifest_sha256,reason,created_at) VALUES (?,1,?,?,?,?)",
    [project.id, manifest, digest, "local regression fixture", at],
  );
  sqlite.run(
    "INSERT INTO projects(id,status,revision,manifest,manifest_sha256,created_at,updated_at) VALUES (?,?,1,?,?,?,?)",
    [project.id, "active", manifest, digest, at, at],
  );
  const [owner, repo] = new URL(project.repositories[0].githubUrl).pathname
    .slice(1)
    .split("/");
  sqlite.run(
    "INSERT INTO project_repositories(repository_key,project_id) VALUES (?,?)",
    [`${owner}/${repo}`.toLowerCase(), project.id],
  );
  // An installation past its shadow period: 14 days and 50 completed reviews.
  sqlite.run(
    "INSERT INTO slopbot_installations(installation_id, account_id, account_login, account_type, created_at) VALUES (1,77,?,'Organization',?)",
    [owner, at],
  );
  const repositoryId = Number(project.authority.repositoryId);
  for (let i = 0; i < 50; i++)
    sqlite.run(
      `INSERT INTO slopbot_reviews(review_key,installation_id,repository_id,item_kind,item_number,item_node_id,
        author_id,revision,content_digest,policy_digest,status,created_at,completed_at)
       VALUES (?,1,?,'pull_request',?,?,1000,'r','d','p','completed',?,?)`,
      [`shadow-${i}`, repositoryId, 100 + i, `PR_shadow_${i}`, at, at],
    );
  // The verified Slop-skill member (D6): a member record and the author's own
  // authenticated run, whose pull_request_opened event names this node ID.
  sqlite.run(
    "INSERT INTO points_members(actor_id,github_id,login,joined_at,public) VALUES ('actor-42','42','author',?,0)",
    [at],
  );
  sqlite.run(
    `INSERT INTO trace_runs(id,client_run_id,github_user_id,github_login,project_id,repository,
      project_policy_revision,provider,model,client,client_version,state,created_at,create_idempotency_key)
     VALUES ('run-1','client-1','42','author',?,?,?,
      'surplus','claude-opus-5.5','claude-code','1.0.0','awaiting_trace',?,'idem-1')`,
    [project.id, `${owner}/${repo}`, "a".repeat(40), at],
  );
  sqlite.run(
    `INSERT INTO run_progress_events(id,run_id,github_user_id,kind,occurred_at,source,github_object_id,
      github_url,head_sha,created_at,idempotency_key)
     VALUES ('event-1','run-1','42','pull_request_opened',?,'agent','PR_local',NULL,NULL,?,'idem-event-1')`,
    [at, at],
  );

  const writes: string[] = [];
  const comments: string[] = [];
  const labels: string[] = [];
  let state = "open";
  let pauseReopen: (() => Promise<void>) | null = null;
  let loseReopenResponse = false;
  let verdict = { category: "spam" as Category, confidence: 0.97 };
  const config = Buffer.from(
    JSON.stringify({ version: 1, audience: "protection", closure: true }),
  ).toString("base64");
  const login = (id: number) =>
    ({
      [AUTHOR]: "author",
      [MAINTAINER]: "maintainer",
      [OUTSIDER]: "outsider",
      [MODERATOR]: "moderator",
    })[id];
  const server = Bun.serve({
    port: 0,
    async fetch(request) {
      const url = new URL(request.url);
      const path = url.pathname;
      if (request.method !== "GET" && !path.endsWith("/access_tokens"))
        writes.push(`${request.method} ${path}`);
      if (path === "/v1/messages")
        return Response.json({
          id: "msg_local",
          type: "message",
          role: "assistant",
          model: "claude-opus-5.5",
          stop_reason: "end_turn",
          content: [
            {
              type: "text",
              text: JSON.stringify({
                ...verdict,
                rule_refs: [
                  { source: "universal", quote: "Buy cheap followers" },
                ],
                evidence: ["Buy cheap followers"],
                summary: "This pull request advertises a service.",
                limitations: [],
                objective_defect: null,
              }),
            },
          ],
          usage: { input_tokens: 10, output_tokens: 10 },
        });
      if (path.endsWith("/access_tokens"))
        return Response.json({ token: "local-synthetic-token" });
      if (path === `/repos/${owner}/${repo}`)
        return Response.json({
          id: repositoryId,
          node_id: project.authority.repositoryNodeId,
          private: false,
          default_branch: "main",
          owner: { login: owner, id: 77, type: "Organization" },
        });
      if (path.endsWith("/contents/.github/slopbot.json"))
        return Response.json({
          type: "file",
          size: 64,
          content: config,
          encoding: "base64",
        });
      if (path.endsWith("/issues/5") && request.method === "GET")
        return Response.json({
          node_id: "PR_local",
          number: 5,
          state,
          title: "Followers",
          body: BODY,
          user: { login: "author", id: AUTHOR, type: "User" },
          assignees: [],
          labels: labels.map((name) => ({ name })),
          pull_request: {},
        });
      if (path.endsWith("/pulls/5") && request.method === "PATCH") {
        const next = ((await request.json()) as { state: string }).state;
        if (next === "open" && pauseReopen) {
          const pause = pauseReopen;
          pauseReopen = null;
          await pause();
        }
        state = next;
        if (next === "open" && loseReopenResponse) {
          loseReopenResponse = false;
          return Response.json(
            { error: "synthetic lost response" },
            { status: 503 },
          );
        }
        return Response.json({ state });
      }
      if (path.endsWith("/pulls/5"))
        return Response.json({
          draft: false,
          merged: false,
          head: { sha: "b".repeat(40) },
          base: { sha: "c".repeat(40) },
          additions: 1,
          deletions: 0,
          changed_files: 1,
        });
      if (path.endsWith("/branches/main"))
        return Response.json({ commit: { sha: "c".repeat(40) } });
      if (path.endsWith("/pulls/5/files"))
        return Response.json(
          url.searchParams.get("page") === "1" || !url.searchParams.has("page")
            ? [
                {
                  filename: "README.md",
                  status: "modified",
                  patch: `+${BODY}`,
                },
              ]
            : [],
        );
      const user = path.match(/^\/user\/(\d+)$/u);
      if (user && login(Number(user[1])))
        return Response.json({
          login: login(Number(user[1])),
          id: Number(user[1]),
          node_id: `U_${user[1]}`,
          avatar_url: `https://avatars.githubusercontent.com/u/${user[1]}?v=4`,
          html_url: `https://github.com/${login(Number(user[1]))}`,
          type: "User",
        });
      // The other collected repositories, for the leaderboard's identity read.
      const other = TARGET_REPOSITORIES.findIndex(
        (target) => path === `/repos/${target.owner}/${target.name}`,
      );
      if (other >= 0)
        return Response.json({
          id: 7000 + other,
          node_id: TARGET_REPOSITORIES[other].expectedNodeId,
        });
      if (path.endsWith("/permission"))
        return Response.json({
          permission: path.includes("/maintainer/") ? "write" : "read",
        });
      if (path.endsWith("/issues/5/comments") && request.method === "GET")
        return Response.json([
          {
            id: 1,
            body: "/slopbot appeal This is my real project page, not an advert.",
            user: { id: AUTHOR },
          },
        ]);
      if (path.endsWith("/issues/5/comments")) {
        comments.push(((await request.json()) as { body: string }).body);
        return Response.json({ id: 900 + comments.length }, { status: 201 });
      }
      if (/\/issues\/comments\/\d+$/u.test(path)) {
        comments.push(((await request.json()) as { body: string }).body);
        return Response.json({ id: Number(path.split("/").pop()) });
      }
      if (path.endsWith("/issues/5/labels")) {
        const body = (await request.json()) as { labels: string[] };
        for (const name of body.labels)
          if (!labels.includes(name)) labels.push(name);
        return Response.json(labels.map((name) => ({ name })));
      }
      const removed = path.match(/\/issues\/5\/labels\/(.+)$/u);
      if (removed && request.method === "DELETE") {
        const name = decodeURIComponent(removed[1]);
        labels.splice(labels.indexOf(name), 1);
        return Response.json([]);
      }
      return new Response(null, { status: 404 });
    },
  });
  const nativeFetch = globalThis.fetch;
  globalThis.fetch = ((
    url: Parameters<typeof fetch>[0],
    init: Parameters<typeof fetch>[1],
  ) => {
    const u = new URL(url instanceof Request ? url.url : String(url));
    if (u.origin === new URL(server.url).origin) return nativeFetch(url, init);
    if (u.hostname !== "api.github.com")
      throw new Error(`unexpected network request to ${u.hostname}`);
    return nativeFetch(new URL(u.pathname + u.search, server.url), init);
  }) as typeof fetch;
  const sent: Job[] = [];
  const env = {
    SLOPBOT_DB: db as unknown as D1TransactionalDatabase,
    SLOPBOT_APP_ID: "1",
    SLOPBOT_APP_PRIVATE_KEY: privateKey,
    SLOPBOT_APP_USER_ID: "999",
    SLOPBOT_CLOSURE_ENABLED: "true",
    PROJECT_MODERATOR_GITHUB_IDS: String(MODERATOR),
    SURPLUS_API_KEY: "local-synthetic-key",
    SURPLUS_BASE_URL: server.url.origin,
    SLOPBOT_QUEUE: { send: async (job: Job) => void sent.push(job) },
  };
  const base = {
    installationId: 1,
    repositoryId,
    owner,
    repo,
    itemKind: "pull_request" as const,
    number: 5,
  };
  type Worker = {
    fetch(request: Request, env: unknown): Promise<Response>;
    scheduled(event: unknown, env: unknown): Promise<void>;
    queue(batch: unknown, env: unknown): Promise<void>;
  };
  const outcomes: string[] = [];
  const log = console.log;
  console.log = (line: string) => {
    try {
      outcomes.push(JSON.parse(line).outcome);
    } catch {
      log(line);
    }
  };
  try {
    await cb({
      closeByMaintainer: () => {
        state = "closed";
      },
      loseNextReopenResponse: () => {
        loseReopenResponse = true;
      },
      pauseNextReopen: () => {
        let entered!: () => void;
        let release!: () => void;
        const arrival = new Promise<void>((resolve) => {
          entered = resolve;
        });
        const resumed = new Promise<void>((resolve) => {
          release = resolve;
        });
        pauseReopen = async () => {
          entered();
          await resumed;
        };
        return { entered: arrival, release };
      },
      writes,
      comments,
      labels,
      review: () =>
        reviewItem(env as unknown as ReviewEnv, {
          kind: "review",
          deliveryId: "close-review",
          ...base,
        }),
      job: (kind, extra) =>
        ({
          kind,
          deliveryId: `${kind}-${outcomes.length}`,
          ...base,
          ...extra,
        }) as Job,
      deliver: async (body) => {
        await (worker as unknown as Worker).queue(
          {
            messages: [
              {
                body,
                ack() {},
                retry() {
                  throw new Error("appeal job was retried");
                },
              },
            ],
          },
          env,
        );
        return outcomes.at(-1) ?? "";
      },
      tick: async () => {
        sent.length = 0;
        await (worker as unknown as Worker).scheduled({}, env);
        return [...sent];
      },
      model: (category, confidence) => {
        verdict = { category, confidence };
      },
      sql: (q) => sqlite.query(q).all(),
      feed: (async (url: Parameters<typeof fetch>[0]) =>
        (worker as unknown as Worker).fetch(
          new Request(url instanceof Request ? url.url : String(url)),
          env,
        )) as typeof fetch,
    });
  } finally {
    console.log = log;
    globalThis.fetch = nativeFetch;
    server.stop(true);
    sqlite.close();
  }
}

const PENALTY =
  "SELECT category, debit_thirds, moderator_review, reversal FROM slopbot_penalties";
const APPEAL =
  "SELECT draft, escalation IS NOT NULL AS escalated, resolution, resolved_by FROM slopbot_appeals";
const day = 24 * 60 * 60 * 1000;

test("a spam close debits 3 thirds once; an accepted uphold draft reopens the item and reverses the debit once", async () => {
  await closedItem(async (run) => {
    expect(await run.review()).toBe("closed (spam)");
    expect(run.writes).toContain("PATCH /repos/SlopDotCash/asi/pulls/5");
    expect(run.sql(PENALTY)).toEqual([
      {
        category: "spam",
        debit_thirds: 3,
        moderator_review: 0,
        reversal: null,
      },
    ]);
    expect(run.comments.at(-1)).toContain("removes 3 thirds of a point");
    // A replayed review records nothing new.
    expect(await run.review()).toBe(
      "already reviewed at this revision and policy",
    );
    expect(run.sql(PENALTY)).toHaveLength(1);

    // The independent appeal review no longer finds spam.
    run.model("none", 0.95);
    expect(await run.deliver(run.job("appeal", { senderId: AUTHOR }))).toBe(
      "appeal drafted (uphold)",
    );
    expect(run.sql(APPEAL)).toEqual([
      { draft: "uphold", escalated: 0, resolution: null, resolved_by: null },
    ]);
    expect(run.comments.at(-1)).toContain(
      "Slopbot drafted this resolution: uphold",
    );
    // Another person cannot answer the draft.
    expect(
      await run.deliver(
        run.job("appeal_command", { command: "accept", senderId: OUTSIDER }),
      ),
    ).toBe("only the appellant or a maintainer can answer the draft");

    expect(
      await run.deliver(
        run.job("appeal_command", { command: "accept", senderId: AUTHOR }),
      ),
    ).toBe("appeal upheld by the appellant");
    expect(
      run.writes.filter((w) => w === "PATCH /repos/SlopDotCash/asi/pulls/5"),
    ).toHaveLength(2);
    expect(run.labels).not.toContain("slopbot: spam");
    expect(run.sql(PENALTY)).toEqual([
      {
        category: "spam",
        debit_thirds: 3,
        moderator_review: 0,
        reversal: "appeal_upheld",
      },
    ]);

    // Replays, a later maintainer reopen and a re-review change nothing.
    const writes = run.writes.length;
    expect(
      await run.deliver(
        run.job("appeal_command", { command: "accept", senderId: AUTHOR }),
      ),
    ).toBe("appeal already resolved");
    expect(
      await run.deliver(run.job("human_reopen", { senderId: MAINTAINER })),
    ).toBe("human_reopen");
    // A maintainer closes the item again. A later command from anyone does
    // not resume the completed decision or reopen the item.
    run.closeByMaintainer();
    expect(
      await run.deliver(
        run.job("appeal_command", { command: "accept", senderId: OUTSIDER }),
      ),
    ).toBe("appeal already resolved");
    expect(run.writes).toHaveLength(writes);
    expect(run.sql(PENALTY)).toEqual([
      {
        category: "spam",
        debit_thirds: 3,
        moderator_review: 0,
        reversal: "appeal_upheld",
      },
    ]);
    expect(run.sql(APPEAL)).toEqual([
      {
        draft: "uphold",
        escalated: 0,
        resolution: "upheld",
        resolved_by: "appellant",
      },
    ]);
  });
});

test("a scam close escalates to a moderator; only a moderator decides, and a denial keeps the debit", async () => {
  await closedItem(async (run) => {
    run.model("scam", 0.97);
    expect(await run.review()).toBe("closed (scam)");
    expect(run.sql(PENALTY)).toEqual([
      {
        category: "scam",
        debit_thirds: 24,
        moderator_review: 1,
        reversal: null,
      },
    ]);
    expect(run.labels).toContain("slopbot: moderator");

    expect(await run.deliver(run.job("appeal", { senderId: AUTHOR }))).toBe(
      "appeal escalated: the finding is a confirmed-malicious result",
    );
    expect(
      await run.deliver(
        run.job("appeal_command", { command: "accept", senderId: AUTHOR }),
      ),
    ).toBe("a Slop moderator decides this appeal");
    expect(
      await run.deliver(
        run.job("appeal_command", { command: "uphold", senderId: MAINTAINER }),
      ),
    ).toBe("only a Slop moderator can decide an escalated appeal");
    expect(
      await run.deliver(
        run.job("appeal_command", { command: "deny", senderId: MODERATOR }),
      ),
    ).toBe("appeal denied by the moderator");
    expect(run.sql(PENALTY)).toEqual([
      {
        category: "scam",
        debit_thirds: 24,
        moderator_review: 1,
        reversal: null,
      },
    ]);
    // A maintainer reopen still wins and reverses the debit once.
    expect(
      await run.deliver(run.job("human_reopen", { senderId: MAINTAINER })),
    ).toBe("human_reopen");
    expect(run.sql(PENALTY)).toEqual([
      {
        category: "scam",
        debit_thirds: 24,
        moderator_review: 1,
        reversal: "maintainer_reopen",
      },
    ]);
  });
});

test("a rejected draft escalates, and an appeal unresolved for 7 days escalates once", async () => {
  await closedItem(async (run) => {
    expect(await run.review()).toBe("closed (spam)");
    // The appeal review confirms the finding: the draft denies the appeal.
    expect(await run.deliver(run.job("appeal", { senderId: AUTHOR }))).toBe(
      "appeal drafted (deny)",
    );
    const start = Date.now();
    setSystemTime(new Date(start + 6 * day));
    expect(await run.tick()).toEqual([]);
    setSystemTime(new Date(start + 7 * day + 60_000));
    const due = await run.tick();
    expect(due.map((j) => j.kind)).toEqual(["appeal_due"]);
    expect(await run.deliver(due[0])).toBe(
      "appeal escalated: the appeal is unresolved 7 days after it opened",
    );
    expect(await run.tick()).toEqual([]);
    expect(run.labels).toContain("slopbot: moderator");
    expect(
      await run.deliver(
        run.job("appeal_command", { command: "reject", senderId: MAINTAINER }),
      ),
    ).toBe("a Slop moderator decides this appeal");
  });
  await closedItem(async (run) => {
    expect(await run.review()).toBe("closed (spam)");
    await run.deliver(run.job("appeal", { senderId: AUTHOR }));
    expect(
      await run.deliver(
        run.job("appeal_command", { command: "reject", senderId: MAINTAINER }),
      ),
    ).toBe("appeal escalated: the maintainer rejected the draft");
    expect(run.sql(APPEAL)).toEqual([
      { draft: "deny", escalated: 1, resolution: null, resolved_by: null },
    ]);
  });
});

test("concurrent moderator decisions cannot deny an appeal after its uphold starts reopening the PR", async () => {
  await closedItem(async (run) => {
    run.model("scam", 0.97);
    await run.review();
    await run.deliver(run.job("appeal", { senderId: AUTHOR }));
    const pause = run.pauseNextReopen();
    const uphold = run.deliver(
      run.job("appeal_command", { command: "uphold", senderId: MODERATOR }),
    );
    await pause.entered;
    try {
      await run.deliver(
        run.job("appeal_command", { command: "deny", senderId: MODERATOR }),
      );
    } finally {
      pause.release();
      await uphold;
    }
    expect(run.sql("SELECT resolution FROM slopbot_appeals")).toEqual([
      { resolution: "upheld" },
    ]);
    expect(run.sql("SELECT reversal FROM slopbot_penalties")).toEqual([
      { reversal: "appeal_upheld" },
    ]);
    expect(
      run.comments.some((comment) => comment.includes("**Appeal denied**")),
    ).toBe(false);
  });
});

// The published score path: the leaderboard reads the worker's public penalty
// route, resolves the author on GitHub and builds the snapshot, the project
// cycle and the cumulative leaderboard from the same records.
const WINDOW = {
  from: "2026-09-15T00:01:00.000Z",
  to: "2026-10-20T00:01:00.000Z",
};
const AUTHOR_ACTOR: GitHubActor = {
  id: "U_42",
  login: "author",
  avatarUrl: "https://avatars.githubusercontent.com/u/42?v=4",
  url: "https://github.com/author",
  kind: "User",
};

function mergedInput(penalties: ScorePenalty[] | undefined): LeaderboardInput {
  const merges = [
    { number: 31, mergedAt: "2026-09-20T00:00:00.000Z", head: "1" },
    { number: 32, mergedAt: "2026-10-10T00:00:00.000Z", head: "2" },
    { number: 33, mergedAt: "2026-10-12T00:00:00.000Z", head: "3" },
  ].map(({ number, mergedAt, head }) => ({
    id: `PR_merged_${number}`,
    number,
    title: `fix: accepted outcome ${number}`,
    url: `https://github.com/SlopDotCash/asi/pull/${number}`,
    body: "Fixes a defect.",
    createdAt: mergedAt,
    updatedAt: mergedAt,
    mergedAt,
    author: AUTHOR_ACTOR,
    additions: 10,
    deletions: 2,
    head: head.repeat(40),
  }));
  return {
    generatedAt: WINDOW.to,
    windowFrom: WINDOW.from,
    windowTo: WINDOW.to,
    sourceUpdatedAt: merges[1].mergedAt,
    source: {
      provider: "github-graphql",
      fetchedAt: WINDOW.to,
      cutoffAt: WINDOW.to,
      repositoryId: "R_fixture_0",
      repositories: TARGET_REPOSITORIES.map((repository, index) => ({
        id: repository.id,
        repositoryId: `R_fixture_${index}`,
      })),
      requestCount: 1,
      searchSliceCount: 1,
      rateLimit: {
        cost: 1,
        limit: 5000,
        remaining: 4999,
        resetAt: WINDOW.to,
      },
      counts: {
        mergedPullRequests: merges.length,
        detailedMergedPullRequests: merges.length,
        closedIssues: 0,
        detailedClosedIssues: 0,
        resolvedIssues: 0,
        openIssues: 0,
        openPullRequests: 0,
      },
      verificationWindow: { days: 35, ...WINDOW },
      evidenceVerification: {
        status: "complete",
        sourceCount: 0,
        artifactCount: 0,
        maxSources: 64,
        maxArtifacts: 64,
      },
    },
    mergedPullRequestOutcomes: merges.map(({ head, ...merge }) => ({
      ...merge,
      baseRefName: "main",
      commits: [{ oid: head, author: AUTHOR_ACTOR }],
    })),
    mergedPullRequests: merges.map(({ head, ...merge }) => ({
      ...merge,
      lastEditedAt: null,
      editor: null,
      headRefOid: head,
      isDraft: false,
      reviewDecision: "APPROVED",
      activeReviewRequestCount: 0,
      assignees: [],
      labels: [],
      files: [{ path: "src/fix.py", additions: 10, deletions: 2 }],
      comments: [],
      reviews: [],
      closingIssueIds: [],
      changedFiles: 1,
      commitCount: 1,
    })),
    detailEligibleMergedPullRequestIds: merges.map((merge) => merge.id),
    closedIssueCount: 0,
    resolvedIssues: [],
    openIssues: [],
    openPullRequests: [],
    verificationWindowFrom: WINDOW.from,
    verifiedEvidence: [],
    penalties,
  };
}

async function publishedScore(run: Run) {
  const penalties = await loadPenaltyInputs(
    GitHubClient.forToken("local-synthetic-token"),
    WINDOW,
    run.feed,
  );
  const snapshot = createLeaderboardSnapshot(mergedInput(penalties));
  const leader = snapshot.leaders.find(
    (entry) => entry.actor.id === AUTHOR_ACTOR.id,
  );
  const cycle = (cycleId: string) =>
    createProjectView(snapshot, "asi", cycleId).leaders.find(
      (entry) => entry.actor.id === AUTHOR_ACTOR.id,
    );
  const global = createGlobalLeaders(snapshot, [], {
    schemaVersion: CYCLE_INDEX_SCHEMA_VERSION,
    generatedAt: WINDOW.to,
    cycles: [],
  }).find((entry) => entry.actor.id === AUTHOR_ACTOR.id);
  return {
    penalties: snapshot.penalties?.map(
      (penalty) => `${penalty.source.url}:${penalty.debitThirds}`,
    ),
    rolling: [leader?.scoreThirds, leader?.penaltyThirds ?? 0],
    september: [cycle("2026-09")?.scoreThirds, cycle("2026-09")?.penaltyThirds],
    october: [cycle("2026-10")?.scoreThirds, cycle("2026-10")?.penaltyThirds],
    global: global?.score,
  };
}

test("a recorded debit changes the published score of its month once, and an upheld appeal restores it once", async () => {
  setSystemTime(new Date("2026-10-20T00:00:00.000Z"));
  await closedItem(async (run) => {
    // Without a close, the author's merges score in their own months.
    const before = await publishedScore(run);
    expect(before.penalties).toEqual([]);
    const [september, october] = [before.september[0], before.october[0]];
    if (september === undefined || october === undefined)
      throw new Error("fixture merges did not score");
    expect(september).toBeGreaterThan(0);
    expect(october).toBeGreaterThan(3);
    expect(before.rolling).toEqual([september + october, 0]);
    expect(before.september).toEqual([september, 0]);
    expect(before.october).toEqual([october, 0]);

    // The confirmed spam close of 20 October debits 3 thirds from October
    // only. A replayed review records nothing new.
    expect(await run.review()).toBe("closed (spam)");
    expect(await run.review()).toBe(
      "already reviewed at this revision and policy",
    );
    const after = await publishedScore(run);
    expect(after).toEqual({
      penalties: ["https://github.com/SlopDotCash/asi/pull/5:3"],
      rolling: [september + october - 3, 3],
      september: [september, 0],
      october: [october - 3, 3],
      global: (september + october - 3) / 3,
    });

    // An upheld appeal reverses the debit once; the score returns.
    run.model("none", 0.95);
    await run.deliver(run.job("appeal", { senderId: AUTHOR }));
    expect(
      await run.deliver(
        run.job("appeal_command", { command: "accept", senderId: AUTHOR }),
      ),
    ).toBe("appeal upheld by the appellant");
    expect(await publishedScore(run)).toEqual(before);
  });
});

test("a scam debit never takes its month below zero, and the feed rejects an invalid month", async () => {
  setSystemTime(new Date("2026-10-20T00:00:00.000Z"));
  await closedItem(async (run) => {
    const before = await publishedScore(run);
    run.model("scam", 0.97);
    expect(await run.review()).toBe("closed (scam)");
    const after = await publishedScore(run);
    const [september, october] = [
      before.september[0] ?? 0,
      before.october[0] ?? 0,
    ];
    expect(october).toBeLessThan(24);
    expect(after).toMatchObject({
      penalties: ["https://github.com/SlopDotCash/asi/pull/5:24"],
      rolling: [september, october],
      september: [september, 0],
      october: [0, october],
    });
    for (const period of ["2026-13", "2026-1", ""])
      expect(
        (
          await run.feed(
            `https://slopbot.slop.cash/v1/penalties?period=${period}`,
          )
        ).status,
      ).toBe(400);
  });
});

test("a retry after an uncertain reopen completes the recorded appeal decision", async () => {
  await closedItem(async (run) => {
    run.model("scam", 0.97);
    await run.review();
    await run.deliver(run.job("appeal", { senderId: AUTHOR }));
    run.loseNextReopenResponse();
    await expect(
      run.deliver(
        run.job("appeal_command", { command: "uphold", senderId: MODERATOR }),
      ),
    ).rejects.toThrow("appeal job was retried");
    expect(run.sql("SELECT resolution FROM slopbot_appeals")).toEqual([
      { resolution: "upheld" },
    ]);
    expect(run.sql("SELECT reversal FROM slopbot_penalties")).toEqual([
      { reversal: null },
    ]);
    await run.deliver(
      run.job("appeal_command", { command: "deny", senderId: MODERATOR }),
    );
    expect(run.sql("SELECT resolution FROM slopbot_appeals")).toEqual([
      { resolution: "upheld" },
    ]);
    expect(run.sql("SELECT reversal FROM slopbot_penalties")).toEqual([
      { reversal: "appeal_upheld" },
    ]);
    expect(run.labels).not.toContain("slopbot: scam");
    expect(run.comments.at(-1)).toContain("**Appeal upheld**");
  });
});
