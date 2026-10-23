// The bounded malicious-code scan (audit finding 8) and two-contributor
// flags (audit finding 9) on the real migrations and handlers: a clean
// supported scan activates, reused scans bind identical content, changed
// content is rescanned automatically, two distinct flags pause atomically
// with one moderator notice, and a clean fresh scan reinstates a flag-only
// pause while a confirmed malicious result stays with a moderator.
import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import { CloudflareProjectPersistence } from "../backend/projects/cloudflare-persistence";
import { handleProjectApi } from "../backend/projects/handler";
import {
  handleProjectFlagsApi,
  ProjectFlagStore,
} from "../backend/vetting/flags";
import {
  handleVettingApi,
  queueAutomaticScan,
} from "../backend/vetting/handler";
import {
  CloudflareVettingPersistence,
  type VettingPin,
} from "../backend/vetting/persistence";
import {
  parseVettingScanResult,
  scanProblems,
  specialistRequired,
} from "../backend/vetting/scan-result";
import { applicationManifest } from "../tests/project-application-manifest";
import { sqliteD1 } from "../tests/sqlite-d1";
import { localVettingEvidence } from "../tests/vetting-evidence-fixture";
import {
  signedVettingHeaders,
  vettingKeyPair,
  vettingScanResult,
} from "../tests/vetting-fixtures";

const ORIGIN = "https://slop.cash";
const ADMIN = { githubId: "900000001", githubLogin: "e2e-admin" };
const APPLICANT = { githubId: "900000002", githubLogin: "e2e-applicant" };
const MODERATOR = { githubId: "900000004", githubLogin: "e2e-moderator" };
const ALICE = { githubId: "900000010", githubLogin: "alice" };
const BOB = { githubId: "900000011", githubLogin: "bob" };
const CAROL = { githubId: "900000012", githubLogin: "carol" };
const STEWARD = { githubId: "987654321", githubLogin: "example" };
const ACTORS: Record<string, { githubId: string; githubLogin: string }> = {
  admin: ADMIN,
  applicant: APPLICANT,
  alice: ALICE,
  bob: BOB,
  carol: CAROL,
  steward: STEWARD,
};
const NOW = new Date("2026-10-18T12:00:00.000Z");
const HEAD = "a".repeat(40);
const TEMPLATE = "b".repeat(64);

let retained: Awaited<ReturnType<typeof localVettingEvidence>>;
let sqlite: ReturnType<typeof sqliteD1>["sqlite"];
let projects: CloudflareProjectPersistence;
let vetting: CloudflareVettingPersistence;
let flags: ProjectFlagStore;
let keys: Awaited<ReturnType<typeof vettingKeyPair>>;
let livePin: VettingPin;
let clock: Date;
let ids = 0;

beforeEach(async () => {
  const database = sqliteD1(
    readdirSync(new URL("../migrations", import.meta.url))
      .filter((name) => name.endsWith(".sql"))
      .sort(),
  );
  sqlite = database.sqlite;
  projects = new CloudflareProjectPersistence(database.db);
  flags = new ProjectFlagStore(database.db);
  clock = NOW;
  retained = await localVettingEvidence(database.db, () => clock);
  vetting = new CloudflareVettingPersistence(
    database.db,
    async (a) => a.result !== null && retained.evidence.retained(a.result),
  );
  keys = await vettingKeyPair();
  livePin = { commitSha: HEAD, templateSha256: TEMPLATE };
});
afterEach(async () => {
  await retained?.dispose();
});

const actorOf = (request: Request) =>
  ACTORS[request.headers.get("x-test-actor") ?? ""] ?? null;
const readLivePin = async () => livePin;
const randomId = () =>
  `00000000-0000-4000-8000-${String(++ids).padStart(12, "0")}`;
const vettingDeps = () => ({
  evidence: retained.evidence,
  vetting,
  flags,
  projects,
  resultPublicKeys: keys.publicKey,
  operatorGithubIds: [ADMIN.githubId, MODERATOR.githubId],
  livePin: readLivePin,
  session: async (value: Request) => {
    const actor = actorOf(value);
    return actor && { ...actor, admin: actor === ADMIN };
  },
  now: () => clock,
  randomId,
});

function projectApi(request: Request) {
  return handleProjectApi(request, {
    persistence: projects,
    adminGithubIds: new Set([ADMIN.githubId]),
    moderatorGithubIds: new Set([MODERATOR.githubId]),
    now: () => clock,
    randomId,
    sessionActor: async (value) => actorOf(value),
    notifyAdmins: async () => true,
    repositoryControl: async () => ({ state: "proven", reason: "fixture" }),
    readTokenMetadata: async () => {
      throw new Error("no token reads in this suite");
    },
    github: { fetch: async () => new Response(null, { status: 404 }) },
    vettingClearance: (projectId, manifest, through, forReinstatement) =>
      vetting.manifestClearance(
        projectId,
        manifest,
        through,
        readLivePin,
        forReinstatement,
      ),
  }) as Promise<Response>;
}

const vettingApi = (request: Request) =>
  handleVettingApi(request, vettingDeps()) as Promise<Response>;

const flagApi = (request: Request) =>
  handleProjectFlagsApi(request, {
    flags,
    projects,
    sessionActor: async (value) => actorOf(value),
    moderatorGithubIds: [ADMIN.githubId, MODERATOR.githubId],
    queueFreshScan: (project) =>
      queueAutomaticScan(
        vettingDeps(),
        project,
        "Automatic fresh scan after two contributor flags paused the project",
      ),
    now: () => clock,
    randomId,
  }) as Promise<Response>;

function sessionRequest(
  method: string,
  path: string,
  actor: string,
  body?: unknown,
) {
  return new Request(`${ORIGIN}/api/v1/${path}`, {
    method,
    headers: {
      "x-test-actor": actor,
      ...(body === undefined
        ? {}
        : { "content-type": "application/json", origin: ORIGIN }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function signed(method: string, path: string, body = "") {
  return new Request(`${ORIGIN}/api/v1/${path}`, {
    method,
    headers: {
      "content-type": "application/json",
      ...(await signedVettingHeaders(
        keys.privateKey,
        keys.raw,
        method,
        `/api/v1/${path}`,
        body,
        clock,
      )),
    },
    body: method === "GET" ? undefined : body,
  });
}

async function listPausedProject() {
  const submitted = await projectApi(
    sessionRequest("POST", "project-applications", "applicant", {
      manifest: applicationManifest("open-registry", "example/open-registry"),
    }),
  );
  expect(submitted.status).toBe(201);
  const { application } = await submitted.json();
  const approved = await projectApi(
    sessionRequest(
      "POST",
      `admin/project-applications/${application.id}/approve`,
      "admin",
      {},
    ),
  );
  expect(approved.status).toBe(200);
}

/** The signed scanner service asks Slop to queue what changed. */
async function refresh() {
  const response = await vettingApi(
    await signed("POST", "vetting/refresh", "{}"),
  );
  expect(response.status).toBe(200);
  return (await response.json()) as { queued: string[] };
}

async function scanFixture(
  assessmentId: string,
  disposition: "clean" | "incomplete" | "malicious",
  options: Parameters<typeof vettingScanResult>[2] = {},
  retain = true,
) {
  const project = await projects.getProject("open-registry");
  const assessment = await vetting.getAssessment(assessmentId);
  if (project === null || assessment === null) throw new Error("not queued");
  const result = vettingScanResult(
    {
      assessmentId,
      projectId: project.id,
      revision: assessment.revision,
      manifestSha256: assessment.manifestSha256,
      repository: "example/open-registry",
      commitSha: assessment.commitSha,
      templateSha256: assessment.templateSha256,
    },
    disposition,
    options,
  );
  if (retain) await retained.retain(assessmentId, result.scan.runId);
  return result;
}

async function postResult(body: unknown) {
  return vettingApi(
    await signed("POST", "vetting/results", JSON.stringify(body)),
  );
}

async function activate() {
  const project = await projects.getProject("open-registry");
  return projectApi(
    sessionRequest("PUT", "admin/projects/open-registry/manifest", "admin", {
      manifest: { ...project?.manifest, status: "active" },
      expectedRevision: project?.revision,
      reason: "Activate the scanned revision",
    }),
  );
}

const publicProject = () =>
  projectApi(new Request(`${ORIGIN}/api/v1/projects/open-registry`));

function flag(actor: string, category = "credential-theft") {
  return flagApi(
    sessionRequest("POST", "project-flags/open-registry", actor, {
      category,
      evidence:
        "scripts/postinstall.js reads ~/.config/solana/id.json and posts it to a remote host",
      evidenceUrl:
        "https://github.com/example/open-registry/blob/main/scripts/postinstall.js",
    }),
  );
}

/** Lists, scans clean, and activates the project, as self-service setup does. */
async function activeProject() {
  await listPausedProject();
  const [id] = (await refresh()).queued;
  expect((await postResult(await scanFixture(id, "clean"))).status).toBe(200);
  expect((await activate()).status).toBe(200);
  return id;
}

describe("bounded malicious-code scan contract", () => {
  test("an ordinary clean scan needs no specialist; escalation does", async () => {
    const target = {
      assessmentId: `vet_${"1".repeat(32)}`,
      projectId: "open-registry",
      revision: 1,
      manifestSha256: "c".repeat(64),
      repository: "example/open-registry",
      commitSha: HEAD,
      templateSha256: TEMPLATE,
    };
    const clean = parseVettingScanResult(vettingScanResult(target, "clean"));
    expect(specialistRequired(clean)).toBe(false);
    expect(scanProblems(clean)).toEqual([]);

    const ambiguous = parseVettingScanResult(
      vettingScanResult(target, "clean", { ambiguous: true }),
    );
    expect(specialistRequired(ambiguous)).toBe(true);
    expect(scanProblems(ambiguous)).toContain(
      "An ambiguous or high-risk result needs a specialist review",
    );
    const cleared = parseVettingScanResult(
      vettingScanResult(target, "clean", { ambiguous: true, specialist: true }),
    );
    expect(scanProblems(cleared)).toEqual([]);

    // "Clean" means the defined checks passed on every defined surface.
    const partial = parseVettingScanResult({
      ...vettingScanResult(target, "incomplete"),
      disposition: "clean",
    });
    expect(scanProblems(partial)).toEqual(
      expect.arrayContaining([
        "The downloads surface was not read completely",
        "The scan reported visibility gaps",
      ]),
    );
    const skipped = vettingScanResult(target, "clean");
    expect(
      scanProblems(
        parseVettingScanResult({
          ...skipped,
          checks: { ...skipped.checks, "prompt-injection": "not-run" },
        }),
      ),
    ).toContain("The prompt-injection check did not run");

    // Untrusted execution never receives secrets, by contract.
    expect(() =>
      parseVettingScanResult({
        ...skipped,
        execution: {
          isolation: "sandbox",
          imageSha256: "e".repeat(64),
          runId: "exec-1",
          reason: "postinstall hook downloads a binary",
          startedAt: "2026-10-18T11:00:00.000Z",
          completedAt: "2026-10-18T11:01:00.000Z",
          secretsProvided: true,
          egress: "default-deny",
        },
      }),
    ).toThrow("execution.secretsProvided must be false");

    // A model label alone never confirms malice.
    expect(
      scanProblems(
        parseVettingScanResult({
          ...vettingScanResult(target, "malicious"),
          confirmation: null,
        }),
      ),
    ).toContain(
      "A malicious disposition needs reproducible behavior or verified source evidence",
    );
  });
});

describe("automatic scan and activation", () => {
  test("a clean supported scan lets activation proceed without an admin scan request", async () => {
    await listPausedProject();
    expect((await activate()).status).toBe(422);
    const { queued } = await refresh();
    expect(queued).toHaveLength(1);
    const assessment = await vetting.getAssessment(queued[0]);
    expect(assessment).toMatchObject({
      state: "pending",
      commitSha: HEAD,
      templateSha256: TEMPLATE,
      requestedBy: STEWARD,
      requestReason: "Automatic scan of new project content",
    });
    // A repeated refresh does not queue a duplicate.
    expect((await refresh()).queued).toEqual([]);

    // A clean claim without the retained report is refused.
    const unretained = await postResult(
      await scanFixture(queued[0], "clean", {}, false),
    );
    expect(unretained.status).toBe(422);
    expect((await unretained.json()).error).toBe("evidence_incomplete");

    const recorded = await postResult(await scanFixture(queued[0], "clean"));
    expect(recorded.status).toBe(200);
    expect((await recorded.json()).assessment).toMatchObject({
      state: "clean",
      modelRuns: [
        {
          reviewer: "primary",
          provider: "anthropic",
          model: "claude-opus-5-5",
        },
      ],
    });
    const detail = await (await publicProject()).json();
    expect(detail.vetting.state).toBe("cleared");
    expect((await activate()).status).toBe(200);
    expect((await projects.getProject("open-registry"))?.status).toBe("active");
  });

  test("changed executable content is rescanned; identical content reuses the cached scan", async () => {
    const first = await activeProject();
    // A new integration-branch commit makes the clearance stale.
    livePin = { commitSha: "e".repeat(40), templateSha256: TEMPLATE };
    expect((await (await publicProject()).json()).vetting.state).toBe("stale");
    const [rescan] = (await refresh()).queued;
    expect((await vetting.getAssessment(rescan))?.requestReason).toBe(
      "Automatic rescan: executable content or skill template changed",
    );
    const reuse = await scanFixture(
      rescan,
      "clean",
      { runId: "scan-run-1", reusedAssessmentId: first },
      false,
    );
    // A reuse must cite the same report and inventory as the original.
    const mismatched = await postResult({
      ...reuse,
      assessed: { ...reuse.assessed, inputManifestSha256: "f".repeat(64) },
      primaryReview: {
        ...reuse.primaryReview,
        inputManifestSha256: "f".repeat(64),
      },
    });
    expect(mismatched.status).toBe(422);
    expect((await mismatched.json()).error).toBe("reuse_mismatch");
    expect((await postResult(reuse)).status).toBe(200);
    expect((await (await publicProject()).json()).vetting.state).toBe(
      "cleared",
    );
  });

  test("an incomplete or legacy result never clears", async () => {
    await listPausedProject();
    const [id] = (await refresh()).queued;
    const incomplete = await scanFixture(id, "incomplete");
    const overclaimed = await postResult({
      ...incomplete,
      disposition: "clean",
    });
    expect(overclaimed.status).toBe(422);
    expect((await overclaimed.json()).message).toContain(
      "The downloads surface was not read completely",
    );
    expect((await postResult(incomplete)).status).toBe(200);
    expect((await (await publicProject()).json()).vetting.state).toBe(
      "quarantined",
    );
    expect((await activate()).status).toBe(422);
  });
});

describe("two-contributor flags", () => {
  test("two distinct flags pause atomically with one moderator notice; a clean fresh scan reinstates", async () => {
    await activeProject();
    const first = await flag("alice");
    expect(first.status).toBe(201);
    expect(await first.json()).toMatchObject({
      paused: false,
      restriction: "clear",
      flag: { category: "credential-theft", state: "active" },
    });
    // One active flag per contributor and project.
    const repeated = await flag("alice", "prompt-injection");
    expect(repeated.status).toBe(409);
    expect((await repeated.json()).error).toBe("flag_active");
    expect((await publicProject()).status).toBe(200);

    clock = new Date(NOW.getTime() + 60_000);
    const second = await flag("bob");
    expect(second.status).toBe(201);
    const paused = await second.json();
    expect(paused).toMatchObject({
      paused: true,
      restriction: "quarantined",
      pausedByFlags: true,
      freshScan: "queued",
    });
    // The pause closes the project's public routes and skills at once.
    const closed = await publicProject();
    expect(closed.status).toBe(410);
    expect((await closed.json()).restriction.state).toBe("quarantined");
    const [record] = (await projects.listEnforcements()).filter(
      (entry) => entry.projectId === "open-registry",
    );
    expect(record).toMatchObject({
      action: "quarantine",
      actorRole: "contributor-flags",
      decisionSource: "standing-rule",
      actor: null,
      systemIssuer: { kind: "contributor-flags", threshold: 2 },
    });
    expect((record.systemIssuer as { flagIds: string[] }).flagIds).toHaveLength(
      2,
    );
    // One notice per moderator, plus the project owner's notice.
    const notices = sqlite
      .query(
        "SELECT recipient_github_id AS recipient, kind, action_path AS path FROM notifications WHERE event_key = ? ORDER BY recipient_github_id",
      )
      .all(`project-enforcement:${record.id}`);
    expect(notices).toEqual([
      {
        recipient: ADMIN.githubId,
        kind: "project_quarantined",
        path: "/admin",
      },
      {
        recipient: APPLICANT.githubId,
        kind: "project_quarantined",
        path: "/projects/open-registry",
      },
      {
        recipient: MODERATOR.githubId,
        kind: "project_quarantined",
        path: "/admin",
      },
      {
        recipient: STEWARD.githubId,
        kind: "project_quarantined",
        path: "/projects/open-registry",
      },
    ]);
    // A third flag records evidence but never pauses twice.
    expect((await flag("carol")).status).toBe(201);
    expect(
      (await projects.listEnforcements()).filter(
        (entry) => entry.projectId === "open-registry",
      ),
    ).toHaveLength(1);
    // Moderators read the evidence; the pause needed no approval.
    const overview = await vettingApi(
      sessionRequest("GET", "admin/vetting", "admin"),
    );
    expect((await overview.json()).flags).toHaveLength(3);

    // The fresh scan queued with the pause reinstates on a clean result.
    const fresh = (await vetting.pendingAssessments()).at(-1);
    expect(fresh?.requestReason).toBe(
      "Automatic fresh scan after two contributor flags paused the project",
    );
    clock = new Date(NOW.getTime() + 120_000);
    if (!fresh) throw new Error("no fresh scan");
    expect(
      (
        await postResult(
          await scanFixture(fresh.id, "clean", { runId: "scan-run-2" }),
        )
      ).status,
    ).toBe(200);
    const records = (await projects.listEnforcements()).filter(
      (entry) => entry.projectId === "open-registry",
    );
    expect(records.at(-1)).toMatchObject({
      action: "reinstate",
      stateAfter: "clear",
      appealAfter: "none",
      actorRole: "vetting-service",
      systemIssuer: {
        rule: "clean-fresh-scan-after-flags",
        assessmentId: fresh.id,
      },
      result: "no_revision_needed",
    });
    expect((await publicProject()).status).toBe(200);
    expect((await projects.getProject("open-registry"))?.status).toBe("active");
    // Resolved flags stop counting, so the project does not pause again.
    expect(await flags.activeFlags()).toEqual([]);
    clock = new Date(NOW.getTime() + 180_000);
    expect(await (await flag("alice")).json()).toMatchObject({ paused: false });
    expect((await publicProject()).status).toBe(200);
  });

  test("withdrawn flags stop counting and owners cannot flag", async () => {
    await activeProject();
    const owner = await flag("steward");
    expect(owner.status).toBe(403);
    expect((await owner.json()).error).toBe("owner_cannot_flag");
    expect((await flag("alice")).status).toBe(201);
    const mine = await flagApi(
      sessionRequest("GET", "project-flags/open-registry", "alice"),
    );
    expect((await mine.json()).flag.state).toBe("active");
    const withdrawn = await flagApi(
      sessionRequest(
        "POST",
        "project-flags/open-registry/withdraw",
        "alice",
        {},
      ),
    );
    expect(withdrawn.status).toBe(200);
    expect(await (await flag("bob")).json()).toMatchObject({ paused: false });
    expect((await publicProject()).status).toBe(200);
    // Signed-out members and cross-site writes are refused.
    expect(
      (
        await flagApi(
          new Request(`${ORIGIN}/api/v1/project-flags/open-registry`),
        )
      ).status,
    ).toBe(401);
    const crossSite = await flagApi(
      new Request(`${ORIGIN}/api/v1/project-flags/open-registry`, {
        method: "POST",
        headers: {
          "x-test-actor": "carol",
          "content-type": "application/json",
          origin: "https://evil.example",
        },
        body: "{}",
      }),
    );
    expect(crossSite.status).toBe(403);
  });

  test("a confirmed malicious result after a flag pause stays with a moderator", async () => {
    await activeProject();
    expect((await flag("alice")).status).toBe(201);
    clock = new Date(NOW.getTime() + 60_000);
    expect(await (await flag("bob")).json()).toMatchObject({ paused: true });
    const fresh = (await vetting.pendingAssessments()).at(-1);
    if (!fresh) throw new Error("no fresh scan");
    clock = new Date(NOW.getTime() + 120_000);
    expect(
      (
        await postResult(
          await scanFixture(fresh.id, "malicious", { runId: "scan-run-2" }),
        )
      ).status,
    ).toBe(200);
    const records = (await projects.listEnforcements()).filter(
      (entry) => entry.projectId === "open-registry",
    );
    expect(records.at(-1)).toMatchObject({
      action: "ban",
      actorRole: "vetting-service",
    });
    // A later clean scan alone cannot lift a ban.
    clock = new Date(NOW.getTime() + 180_000);
    const banned = await projects.getProject("open-registry");
    if (banned === null) throw new Error("project vanished");
    const queued = await queueAutomaticScan(
      vettingDeps(),
      banned,
      "Automatic rescan",
    );
    expect(queued).toBe("queued");
    const next = (await vetting.pendingAssessments()).at(-1);
    if (!next) throw new Error("no rescan");
    expect(
      (
        await postResult(
          await scanFixture(next.id, "clean", { runId: "scan-run-3" }),
        )
      ).status,
    ).toBe(200);
    expect(
      (await projects.listEnforcements())
        .filter((entry) => entry.projectId === "open-registry")
        .at(-1)?.action,
    ).toBe("ban");
    expect((await publicProject()).status).toBe(410);
  });

  test("the database refuses a flag pause without two distinct active reporters", async () => {
    await activeProject();
    expect((await flag("alice")).status).toBe(201);
    const project = await projects.getProject("open-registry");
    if (project === null) throw new Error("project vanished");
    const [only] = await flags.activeFlags();
    expect(() =>
      sqlite
        .query(
          `INSERT INTO project_enforcements (id, project_id, sequence, action, state_after, appeal_after, reason, evidence_reference, repository_github_id, repository_keys, actor_role, decision_source, before_revision, before_manifest_sha256, result, created_at, system_issuer)
           VALUES ('enf_forged_flags', 'open-registry', 1, 'quarantine', 'quarantined', 'none', 'forged', 'forged', '123456789', '["example/open-registry"]', 'contributor-flags', 'standing-rule', ?, ?, 'revision_pending', ?, ?)`,
        )
        .run(
          project.revision,
          project.manifestSha256,
          NOW.toISOString(),
          JSON.stringify({
            kind: "contributor-flags",
            threshold: 2,
            flagIds: [only.id, only.id],
          }),
        ),
    ).toThrow("a flag pause needs two distinct active contributor flags");
  });
});
