// Runs the security case API against the real migrations. GitHub's private
// vulnerability reports and the analysis model are injected, and a
// concurrent writer can run between the case read and the write batch,
// which a browser test cannot schedule deterministically.
import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { readdirSync } from "node:fs";
import { sqliteD1 } from "../../tests/sqlite-d1";
import type { AdvisoryReader, GithubPrivateReport } from "./advisories";
import type { SecurityAnalysisInput, SecurityAnalyzer } from "./analysis";
import { handleSecurityApi, type SecurityD1Database } from "./handler";

const migrations = readdirSync("migrations")
  .filter((f) => f.endsWith(".sql"))
  .sort();
const ORIGIN = "https://slop.test";
const PROJECT = "bounty";
const REPOSITORY = "example/bounty";
const MAINTAINER = { githubId: "900000101", githubLogin: "maintainer" };
const REPORTER = { githubId: "900000102", githubLogin: "reporter" };
const TRIAGER = { githubId: "900000103", githubLogin: "triager" };
const FINANCE = { githubId: "900000104", githubLogin: "finance" };
const FINANCE_2 = { githubId: "900000107", githubLogin: "finance-two" };
const DISPUTE = { githubId: "900000105", githubLogin: "dispute" };
const DISPUTE_2 = { githubId: "900000106", githubLogin: "dispute-two" };
const DISPUTE_3 = { githubId: "900000108", githubLogin: "dispute-three" };
const DISPUTE_4 = { githubId: "900000109", githubLogin: "dispute-four" };
const DISPUTE_5 = { githubId: "900000110", githubLogin: "dispute-five" };
const OTHER = { githubId: "900000111", githubLogin: "other-reporter" };
const REVISION_AT = "2026-10-19T09:00:00.000Z";
const SECRET_DETAIL = "Synthetic exploit narrative that must stay private.";

type Account = typeof MAINTAINER;
type CaseReply = {
  id: string;
  revision: number;
  submissionState: string;
  receivedAt: string | null;
  receivedAtSource: string | null;
  awardState: string;
  receiptState: string;
  appealState: string;
  allowedActions: string[];
  nextStep: string;
  award: {
    grossMinor: string;
    researcherMinor: string;
    slopMinor: string;
  } | null;
  analysis?: {
    state: string;
    summary: string | null;
    duplicateCaseIds: string[];
    retryable: boolean;
  } | null;
  awardFunds?: { availableMinor: string } | null;
};
type Reply = {
  error?: string;
  replayed?: boolean;
  state?: string;
  received?: number;
  submission?: {
    id: string;
    state: string;
    lastCheck: string | null;
    caseId: string | null;
  };
  submissions?: { id: string }[];
  cases?: CaseReply[];
  case: CaseReply;
};

// An open paid program: 2 awards of 10,000.00 USD of verified funds.
const OPEN_PROGRAM = {
  status: "open",
  intake: { repository: REPOSITORY },
  amount: {
    currency: "USD",
    decimals: 2,
    network: null,
    grossMinor: "1000000",
  },
  funding: {
    state: "verified-available",
    evidence: "synthetic-funding-evidence",
    verifiedAt: REVISION_AT,
  },
  sponsor: { name: "Slop", githubId: null },
  approvers: {
    technical: [MAINTAINER],
    financial: [FINANCE, FINANCE_2],
    dispute: [DISPUTE, DISPUTE_2, DISPUTE_3, DISPUTE_4, DISPUTE_5],
  },
  capacity: { awards: 2, closesAt: null },
  responseTargets: {
    acknowledgeHours: 24,
    triageBusinessDays: 3,
    updateIntervalDays: 7,
  },
  scope: {
    includedAssets: ["Vault deposits"],
    severityRubric: "Critical means loss of covered funds.",
    lossDefinition: "Unauthorized loss of covered assets.",
  },
};

function programManifest(securityBounty: Record<string, unknown>): string {
  return JSON.stringify({ id: PROJECT, status: "active", securityBounty });
}

let ghsaCount = 0;
function report(
  author: Account,
  createdAt: string,
  ghsa = `GHSA-2c3f-4g5h-${"23456789cfghjmpqrvwx"[ghsaCount++ % 20]}j9m`,
): GithubPrivateReport {
  return {
    ghsa,
    createdAt,
    state: "triage",
    author: { githubId: author.githubId, githubLogin: author.githubLogin },
    summary: "Vault share rounding",
    description: SECRET_DETAIL,
    severity: "critical",
    cweIds: ["CWE-682"],
    packages: ["npm:vault"],
  };
}

function open(securityBounty: Record<string, unknown> = OPEN_PROGRAM) {
  const { db, sqlite } = sqliteD1(migrations);
  const manifest = programManifest(securityBounty);
  const digest = createHash("sha256").update(manifest).digest("hex");
  sqlite
    .query(
      "INSERT INTO project_revisions (project_id, revision, manifest, manifest_sha256, reason, created_at) VALUES (?, 1, ?, ?, 'test', ?)",
    )
    .run(PROJECT, manifest, digest, REVISION_AT);
  sqlite
    .query(
      "INSERT INTO projects (id, status, revision, manifest, manifest_sha256, created_at, updated_at) VALUES (?, 'active', 1, ?, ?, ?, ?)",
    )
    .run(PROJECT, manifest, digest, REVISION_AT, REVISION_AT);
  let actor = MAINTAINER;
  let ids = 0;
  let clock = Date.parse("2026-10-19T10:00:00.000Z");
  // Runs before the next write batch, after the handler read the case.
  let beforeBatch: (() => void) | null = null;
  const securityDb = db as unknown as SecurityD1Database;
  const wrapped: SecurityD1Database = {
    prepare: (sql) => securityDb.prepare(sql),
    batch: async (statements) => {
      const hook = beforeBatch;
      beforeBatch = null;
      hook?.();
      return securityDb.batch(statements);
    },
  };
  // GitHub: private reporting readiness and the repository's private reports.
  let intake: "enabled" | "disabled" | "forbidden" = "enabled";
  const reports: GithubPrivateReport[] = [];
  let reportsAvailable = true;
  const advisories: AdvisoryReader = {
    privateReports: async (repository) =>
      reportsAvailable && repository === REPOSITORY
        ? { state: "ok", reports: [...reports] }
        : { state: "unavailable" },
    privateReport: async (_repository, ghsa) => {
      const found = reports.find((entry) => entry.ghsa === ghsa);
      return found && reportsAvailable
        ? { state: "found", report: found }
        : { state: "unavailable" };
    },
  };
  const analyzed: SecurityAnalysisInput[] = [];
  let analyzerFails = false;
  let analyzerConfigured = true;
  const analyzer: SecurityAnalyzer = {
    provider: "fixture",
    model: "fixture-model",
    analyze: async (input) => {
      analyzed.push(input);
      if (analyzerFails) throw new Error("provider down");
      return {
        summary: "Rounding lets a depositor withdraw more than deposited.",
        severity: "critical",
        potentialLoss: "likely",
        duplicateCaseIds: input.priorCases.map((entry) => entry.id),
        rootCauseKey: "vault-share-rounding",
        remediation: "Round shares down on withdrawal.",
      };
    },
  };
  const call = async (
    as: Account,
    method: "GET" | "POST",
    path: string,
    body?: unknown,
  ) => {
    actor = as;
    const response = await handleSecurityApi(
      new Request(`${ORIGIN}/api/v1/${path}`, {
        method,
        headers:
          method === "POST"
            ? { origin: ORIGIN, "content-type": "application/json" }
            : {},
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      }),
      {
        db: wrapped,
        now: () => new Date(clock),
        randomId: () => {
          ids += 1;
          return `case${String(ids).padStart(8, "0")}`;
        },
        sessionActor: async () => actor,
        github: {
          fetch: async () =>
            intake === "forbidden"
              ? new Response("{}", { status: 403 })
              : Response.json({ enabled: intake === "enabled" }),
          apiOrigin: "https://api.github.invalid",
        },
        advisories,
        analyzer: analyzerConfigured ? analyzer : null,
      },
    );
    return {
      status: response?.status ?? 0,
      body: (await response?.json()) as Reply,
    };
  };
  let keys = 0;
  const key = () => {
    keys += 1;
    return `test-key-${String(keys).padStart(8, "0")}`;
  };
  // Inbox rows one account received for a case (NOT-01, SEC-09).
  const inbox = (account: Account, caseId: string) =>
    (
      sqlite
        .query(
          "SELECT event_key FROM notifications WHERE recipient_github_id = ? AND event_key LIKE ? ORDER BY event_key",
        )
        .all(account.githubId, `security-case:${caseId}:%`) as {
        event_key: string;
      }[]
    ).map((row) => row.event_key);
  const act = async (
    as: Account,
    id: string,
    fields: Record<string, unknown>,
  ) => {
    const current = await call(as, "GET", `security-cases/${id}`);
    return call(as, "POST", `security-cases/${id}/actions`, {
      expectedRevision: current.body.case.revision,
      idempotencyKey: key(),
      ...fields,
    });
  };
  /** GitHub received a report; the maintainer imports it into Slop. */
  const receive = async (author: Account, createdAt: string) => {
    const entry = report(author, createdAt);
    reports.push(entry);
    const imported = await call(MAINTAINER, "POST", "security-cases", {
      mode: "import",
      projectId: PROJECT,
    });
    expect(imported.body).toMatchObject({ state: "ok", received: 1 });
    const row = sqlite
      .query("SELECT id FROM security_cases WHERE advisory_ghsa = ?")
      .get(entry.ghsa) as { id: string };
    return row.id;
  };
  const decide = (
    id: string,
    rootCauseKey: string,
    fields: Record<string, unknown> = {},
  ) =>
    act(MAINTAINER, id, {
      action: "decide",
      outcome: "confirmed",
      severity: "critical",
      loss: "verified-potential",
      inScope: true,
      reason: "Reproduced on an isolated local fork.",
      relatedParty: false,
      rootCauseKey,
      ...fields,
    });
  const award = (id: string, grossMinor: string, as: Account = MAINTAINER) =>
    act(as, id, {
      action: "award",
      decision: "amount",
      grossMinor,
      paymentDeadline: "2026-11-30T00:00:00.000Z",
      confirmation: true,
      reason: "Owner award for a confirmed vault finding.",
    });
  const reservations = () =>
    sqlite
      .query(
        "SELECT case_id, gross_minor FROM security_award_reservations ORDER BY case_id",
      )
      .all() as { case_id: string; gross_minor: string }[];
  return {
    sqlite,
    call,
    key,
    act,
    receive,
    decide,
    award,
    inbox,
    reports,
    analyzed,
    reservations,
    setIntake: (state: typeof intake) => {
      intake = state;
    },
    setReportsAvailable: (available: boolean) => {
      reportsAvailable = available;
    },
    setAnalyzerFails: (fails: boolean) => {
      analyzerFails = fails;
    },
    setAnalyzerConfigured: (configured: boolean) => {
      analyzerConfigured = configured;
    },
    advance: (ms: number) => {
      clock += ms;
    },
    setBeforeBatch: (hook: () => void) => {
      beforeBatch = hook;
    },
  };
}

describe("automatic private intake", () => {
  test("a reporter's private report becomes a verified case from GitHub's own receipt", async () => {
    const env = open();
    const start = () =>
      env.call(REPORTER, "POST", "security-submissions", {
        projectId: PROJECT,
      });
    const started = await start();
    expect(started.status).toBe(201);
    const submission = started.body.submission as { id: string };
    expect(started.body.submission).toMatchObject({
      state: "awaiting-report",
      lastCheck: null,
      caseId: null,
    });
    // An interrupted submission is found again, never duplicated.
    const again = await start();
    expect(again.status).toBe(200);
    expect(again.body.submission?.id).toBe(submission.id);
    const check = () =>
      env.call(
        REPORTER,
        "POST",
        `security-submissions/${submission.id}/check`,
        {},
      );
    // GitHub cannot be read: that is not "no report".
    env.setReportsAvailable(false);
    expect((await check()).body.submission).toMatchObject({
      state: "awaiting-report",
      lastCheck: "unavailable",
    });
    env.setReportsAvailable(true);
    env.advance(11_000);
    expect((await check()).body.submission).toMatchObject({
      state: "awaiting-report",
      lastCheck: "none-found",
    });
    // Another researcher's report is not this reporter's receipt.
    env.reports.push(report(OTHER, "2026-10-19T10:00:05.000Z"));
    const mine = report(REPORTER, "2026-10-19T10:00:07.000Z");
    env.reports.push(mine);
    // A repeated check within the transport bound reuses the last answer.
    expect((await check()).body.submission?.lastCheck).toBe("none-found");
    env.advance(11_000);
    const found = await check();
    expect(found.body.submission).toMatchObject({
      state: "received",
      lastCheck: "received",
    });
    const caseId = found.body.submission?.caseId as string;
    const reporterView = await env.call(
      REPORTER,
      "GET",
      `security-cases/${caseId}`,
    );
    expect(reporterView.body.case).toMatchObject({
      submissionState: "verified",
      receivedAt: mine.createdAt,
      receivedAtSource: "github-advisory",
      awardState: "pending",
      receiptState: "received",
      nextStep: "Waiting for the project owner's response.",
    });
    // The reporter sees receipt, response and payout, never the analysis.
    expect(reporterView.body.case).not.toHaveProperty("analysis");
    expect(
      env.sqlite
        .query(
          "SELECT verified_by_github_id, reporter_github_login FROM security_cases WHERE id = ?",
        )
        .get(caseId),
    ).toEqual({
      verified_by_github_id: "github",
      reporter_github_login: "reporter",
    });
    // Only this reporter's report was recorded by their own check.
    expect(
      env.sqlite.query("SELECT COUNT(*) AS n FROM security_cases").get(),
    ).toEqual({ n: 1 });
    // The maintainer is notified of the receipt; the reporter acted.
    expect(env.inbox(MAINTAINER, caseId)).toEqual([
      `security-case:${caseId}:1`,
    ]);
    expect(env.inbox(REPORTER, caseId)).toEqual([]);
    // The private analysis read the report; D1 keeps only the proposal.
    expect(env.analyzed).toHaveLength(1);
    expect(env.analyzed[0].report.description).toBe(SECRET_DETAIL);
    const ownerView = await env.call(
      MAINTAINER,
      "GET",
      `security-cases/${caseId}`,
    );
    expect(ownerView.body.case.analysis).toMatchObject({
      state: "complete",
      summary: "Rounding lets a depositor withdraw more than deposited.",
      retryable: false,
    });
    expect(ownerView.body.case.allowedActions).toEqual(
      expect.arrayContaining(["request-information", "decide"]),
    );
    expect(ownerView.body.case.allowedActions).not.toContain("analyze");
    const stored = JSON.stringify(
      env.sqlite.query("SELECT * FROM security_case_analyses").all(),
    );
    expect(stored).not.toContain(SECRET_DETAIL);
    // A new report starts a new submission.
    expect((await start()).status).toBe(201);
  });

  test("starting a report needs private reporting on, with no public fallback", async () => {
    const env = open();
    for (const [state, code] of [
      ["disabled", "intake_disabled"],
      ["forbidden", "intake_forbidden"],
    ] as const) {
      env.setIntake(state);
      const refused = await env.call(REPORTER, "POST", "security-submissions", {
        projectId: PROJECT,
      });
      expect(refused.status).toBe(409);
      expect(refused.body.error).toBe(code);
    }
    expect(
      env.sqlite.query("SELECT COUNT(*) AS n FROM security_submissions").get(),
    ).toEqual({ n: 0 });
    // Signed out, nothing starts.
    const unknown = await env.call(REPORTER, "POST", "security-submissions", {
      projectId: "missing-project",
    });
    expect(unknown.status).toBe(404);
  });

  test("a maintainer imports direct GitHub reports and settles older links", async () => {
    const env = open();
    const linked = report(REPORTER, "2026-10-19T09:10:00.000Z");
    const wrongAuthor = report(REPORTER, "2026-10-19T09:20:00.000Z");
    const direct = report(OTHER, "2026-10-19T09:30:00.000Z");
    // Links from before automatic receipt, as the old claim flow stored them.
    const claim = (id: string, ghsa: string, account: Account) =>
      env.sqlite
        .query(
          "INSERT INTO security_cases (id, project_id, advisory_repository, advisory_ghsa, reporter_github_id, reporter_github_login, submission_state, receipt_state, remediation_state, award_state, payment_state, disclosure_state, recognition, appeal_state, revision, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 'claimed', 'received', 'not-started', 'not-applicable', 'not-applicable', 'embargoed', 'private', 'none', 1, ?, ?)",
        )
        .run(
          id,
          PROJECT,
          REPOSITORY,
          ghsa,
          account.githubId,
          account.githubLogin,
          REVISION_AT,
          REVISION_AT,
        );
    claim("sc_legacyclaim1", linked.ghsa, REPORTER);
    claim("sc_legacyclaim2", wrongAuthor.ghsa, OTHER);
    claim("sc_legacyclaim3", "GHSA-9c9f-9g9h-9j9m", REPORTER);
    env.reports.push(linked, wrongAuthor, direct);
    const notMaintainer = await env.call(TRIAGER, "POST", "security-cases", {
      mode: "import",
      projectId: PROJECT,
    });
    expect(notMaintainer.status).toBe(403);
    env.setReportsAvailable(false);
    expect(
      (
        await env.call(MAINTAINER, "POST", "security-cases", {
          mode: "import",
          projectId: PROJECT,
        })
      ).body,
    ).toMatchObject({ state: "unavailable", received: 0 });
    expect(
      env.sqlite
        .query(
          "SELECT COUNT(*) AS n FROM security_cases WHERE submission_state = 'claimed'",
        )
        .get(),
    ).toEqual({ n: 3 });
    env.setReportsAvailable(true);
    const imported = await env.call(MAINTAINER, "POST", "security-cases", {
      mode: "import",
      projectId: PROJECT,
    });
    expect(imported.body).toMatchObject({ state: "ok", received: 3 });
    const rows = env.sqlite
      .query(
        "SELECT id, advisory_ghsa, reporter_github_id, submission_state, received_at, received_at_source, revision FROM security_cases ORDER BY created_at, id",
      )
      .all() as Record<string, unknown>[];
    // The older link by the true author became that case.
    expect(rows.find((row) => row.id === "sc_legacyclaim1")).toMatchObject({
      submission_state: "verified",
      received_at: linked.createdAt,
      received_at_source: "github-advisory",
      revision: 2,
    });
    // GitHub names someone else, or no such private report exists.
    for (const id of ["sc_legacyclaim2", "sc_legacyclaim3"])
      expect(rows.find((row) => row.id === id)).toMatchObject({
        submission_state: "link-rejected",
        revision: 2,
      });
    for (const entry of [wrongAuthor, direct])
      expect(
        rows.find(
          (row) =>
            row.advisory_ghsa === entry.ghsa &&
            row.submission_state === "verified",
        ),
      ).toMatchObject({ reporter_github_id: entry.author.githubId });
    expect(
      env.sqlite
        .query(
          "SELECT kind FROM security_case_events WHERE case_id = 'sc_legacyclaim3'",
        )
        .all(),
    ).toEqual([{ kind: "receipt-mismatch" }]);
    // Importing again records nothing twice.
    expect(
      (
        await env.call(MAINTAINER, "POST", "security-cases", {
          mode: "import",
          projectId: PROJECT,
        })
      ).body,
    ).toMatchObject({ state: "ok", received: 0 });
    // Each new case got its private analysis; later ones compared earlier.
    expect(env.analyzed).toHaveLength(3);
    expect(env.analyzed[2].priorCases.map((entry) => entry.id)).toHaveLength(2);
  });

  test("listing cases records only the cases disclosed and refuses an unaudited response", async () => {
    const env = open();
    const first = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    const second = await env.receive(REPORTER, "2026-10-19T09:20:00.000Z");
    const reads = () =>
      env.sqlite
        .query(
          "SELECT case_id, actor_github_id, actor_role FROM security_case_access_log WHERE action = 'read' ORDER BY case_id",
        )
        .all();
    const listed = await env.call(REPORTER, "GET", "security-cases");
    expect(listed.status).toBe(200);
    expect(listed.body.submissions).toEqual([]);
    expect(reads()).toEqual(
      [first, second].sort().map((id) => ({
        case_id: id,
        actor_github_id: REPORTER.githubId,
        actor_role: "reporter",
      })),
    );
    const outsider = await env.call(TRIAGER, "GET", "security-cases");
    expect(outsider.status).toBe(200);
    expect(reads()).toHaveLength(2);
    env.sqlite.exec(
      "CREATE TRIGGER refuse_access_read BEFORE INSERT ON security_case_access_log BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END",
    );
    const unavailable = await env.call(REPORTER, "GET", "security-cases");
    expect(unavailable.status).toBe(500);
    expect(unavailable.body).not.toHaveProperty("cases");
    expect(reads()).toHaveLength(2);
  });

  test("a failed or missing analysis can be run again by the owner", async () => {
    const env = open();
    env.setAnalyzerConfigured(false);
    const id = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    const read = () => env.call(MAINTAINER, "GET", `security-cases/${id}`);
    expect((await read()).body.case.analysis).toMatchObject({
      state: "unavailable",
      retryable: true,
    });
    expect((await read()).body.case.allowedActions).toContain("analyze");
    // The reporter cannot run it.
    expect((await env.act(REPORTER, id, { action: "analyze" })).status).toBe(
      409,
    );
    env.setAnalyzerConfigured(true);
    env.setAnalyzerFails(true);
    const failed = await env.act(MAINTAINER, id, { action: "analyze" });
    expect(failed.status).toBe(200);
    expect(failed.body.case.analysis).toMatchObject({
      state: "failed",
      retryable: true,
    });
    env.setAnalyzerFails(false);
    const complete = await env.act(MAINTAINER, id, { action: "analyze" });
    expect(complete.body.case.analysis).toMatchObject({
      state: "complete",
      retryable: false,
    });
    const again = await env.act(MAINTAINER, id, { action: "analyze" });
    expect(again.status).toBe(409);
    expect(again.body.error).toBe("analysis_running");
  });

  test("a stale triager change grants or revokes nothing", async () => {
    const env = open();
    const { call, key, sqlite, setBeforeBatch, inbox } = env;
    const id = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    // Another maintainer moves the case two revisions ahead while this
    // request is in flight, so its event guard skips instead of colliding.
    const advance = (revisions: number[]) => () => {
      for (const revision of revisions) {
        sqlite
          .query(
            "UPDATE security_cases SET revision = ?, updated_at = ? WHERE id = ?",
          )
          .run(revision, REVISION_AT, id);
        sqlite
          .query(
            "INSERT INTO security_case_events (case_id, case_revision, kind, actor_github_id, actor_role, idempotency_key, detail, at) VALUES (?, ?, 'remediation', ?, 'security-maintainer', ?, '{}', ?)",
          )
          .run(id, revision, MAINTAINER.githubId, key(), REVISION_AT);
      }
    };
    const members = () =>
      sqlite
        .query(
          "SELECT github_id, revoked_at FROM security_case_members WHERE case_id = ?",
        )
        .all(id) as { github_id: string; revoked_at: string | null }[];
    setBeforeBatch(advance([2, 3]));
    const stale = await call(
      MAINTAINER,
      "POST",
      `security-cases/${id}/actions`,
      {
        action: "assign-triager",
        expectedRevision: 1,
        idempotencyKey: key(),
        ...TRIAGER,
      },
    );
    expect(stale.status).toBe(409);
    expect(stale.body.error).toBe("stale_revision");
    expect(members()).toEqual([]);
    expect(inbox(TRIAGER, id)).toEqual([]);
    expect((await call(TRIAGER, "GET", `security-cases/${id}`)).status).toBe(
      404,
    );
    const assigned = await call(
      MAINTAINER,
      "POST",
      `security-cases/${id}/actions`,
      {
        action: "assign-triager",
        expectedRevision: 3,
        idempotencyKey: key(),
        ...TRIAGER,
      },
    );
    expect(assigned.status).toBe(200);
    expect(members()).toEqual([
      { github_id: TRIAGER.githubId, revoked_at: null },
    ]);
    // Only the assignment that landed reaches the triager.
    expect(inbox(TRIAGER, id)).toEqual([`security-case:${id}:4`]);
    setBeforeBatch(advance([5, 6]));
    const staleRevoke = await call(
      MAINTAINER,
      "POST",
      `security-cases/${id}/actions`,
      {
        action: "revoke-triager",
        expectedRevision: 4,
        idempotencyKey: key(),
        githubId: TRIAGER.githubId,
      },
    );
    expect(staleRevoke.status).toBe(409);
    expect(members()).toEqual([
      { github_id: TRIAGER.githubId, revoked_at: null },
    ]);
  });
});

describe("discretionary awards", () => {
  test("the owner chooses the amount, and approval reserves exactly that amount", async () => {
    const env = open();
    const first = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    const second = await env.receive(REPORTER, "2026-10-19T09:20:00.000Z");
    // A high-severity finding with unverified loss is not barred: severity
    // and loss are priority guidance, not eligibility.
    const decided = await env.decide(first, "vault-drain", {
      severity: "high",
      loss: "not-verified",
    });
    expect(decided.status).toBe(200);
    expect(decided.body.case).toMatchObject({
      awardState: "pending",
      nextStep: "Choose an award amount or no award.",
    });
    expect(decided.body.case.allowedActions).toContain("award");
    // Nothing is reserved by a technical decision.
    expect(env.reservations()).toEqual([]);
    const inexact = await env.award(first, "1000002");
    expect(inexact.status).toBe(400);
    expect(inexact.body.error).toBe("invalid_amount");
    // Only the owner decides awards; finance cannot even see the case yet,
    // and the reporter cannot award their own report.
    expect(
      (
        await env.call(FINANCE, "POST", `security-cases/${first}/actions`, {
          action: "award",
          expectedRevision: 2,
          idempotencyKey: env.key(),
          decision: "amount",
          grossMinor: "1500000",
          paymentDeadline: "2026-11-30T00:00:00.000Z",
          confirmation: true,
          reason: "Finance trying to award directly.",
        })
      ).status,
    ).toBe(404);
    expect((await env.award(first, "1500000", REPORTER)).status).toBe(403);
    const approved = await env.award(first, "1500000");
    expect(approved.status).toBe(200);
    expect(approved.body.case).toMatchObject({
      awardState: "approved",
      award: {
        grossMinor: "1500000",
        researcherMinor: "1125000",
        slopMinor: "375000",
      },
    });
    expect(env.reservations()).toEqual([
      { case_id: first, gross_minor: "1500000" },
    ]);
    // Both finance approvers learn of the approved award.
    for (const payer of [FINANCE, FINANCE_2])
      expect(env.inbox(payer, first)).toEqual([`security-case:${first}:3`]);
    // The second finding decides and awards in one step; 500,000 remains.
    const tooMuch = await env.decide(second, "oracle-skew", {
      award: {
        decision: "amount",
        grossMinor: "600000",
        paymentDeadline: "2026-11-30T00:00:00.000Z",
        confirmation: true,
      },
    });
    expect(tooMuch.status).toBe(409);
    expect(tooMuch.body.error).toBe("insufficient_funds");
    const unchanged = await env.call(
      MAINTAINER,
      "GET",
      `security-cases/${second}`,
    );
    expect(unchanged.body.case).toMatchObject({
      revision: 1,
      receiptState: "received",
    });
    expect(unchanged.body.case.awardFunds).toMatchObject({
      availableMinor: "500000",
    });
    const fits = await env.decide(second, "oracle-skew", {
      award: {
        decision: "amount",
        grossMinor: "500000",
        paymentDeadline: "2026-11-30T00:00:00.000Z",
        confirmation: true,
      },
    });
    expect(fits.status).toBe(200);
    expect(fits.body.case.awardState).toBe("approved");
    // A reserved obligation cannot be redecided or withdrawn.
    expect(
      (
        await env.act(MAINTAINER, first, {
          action: "award",
          decision: "none",
          reason: "Changing my mind after approval.",
        })
      ).status,
    ).toBe(409);
  });

  test("no award is a decision the reporter can appeal", async () => {
    const env = open();
    const id = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    await env.decide(id, "vault-drain");
    const none = await env.act(MAINTAINER, id, {
      action: "award",
      decision: "none",
      reason: "Already known and mitigated before the report.",
    });
    expect(none.status).toBe(200);
    expect(none.body.case.awardState).toBe("ineligible");
    expect(env.reservations()).toEqual([]);
    const reporter = await env.call(REPORTER, "GET", `security-cases/${id}`);
    expect(reporter.body.case.allowedActions).toContain("appeal");
    const appealed = await env.act(REPORTER, id, {
      action: "appeal",
      reason: "The mitigation did not cover the path I reported.",
    });
    expect(appealed.body.case.appealState).toBe("open");
    for (const reviewer of [DISPUTE, DISPUTE_2])
      expect(env.inbox(reviewer, id)).toEqual([`security-case:${id}:4`]);
    // A returned appeal reopens the award decision.
    const returned = await env.act(DISPUTE, id, {
      action: "decide-appeal",
      outcome: "return",
      reason: "Decide the award again with the new evidence.",
    });
    expect(returned.body.case).toMatchObject({
      receiptState: "triaging",
      awardState: "pending",
    });
  });

  test("a concurrent reservation cannot overspend the program", async () => {
    const env = open();
    const first = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    const second = await env.receive(REPORTER, "2026-10-19T09:20:00.000Z");
    await env.decide(first, "vault-drain");
    await env.decide(second, "oracle-skew");
    // Another owner request reserves 1,500,000 after this request read the
    // available funds and before its batch commits.
    env.setBeforeBatch(() => {
      env.sqlite
        .query(
          "INSERT INTO security_award_reservations (case_id, project_id, root_cause_key, policy_revision, gross_minor, currency, reserved_at) VALUES (?, ?, 'oracle-skew', 1, '1500000', 'USD', ?)",
        )
        .run(second, PROJECT, REVISION_AT);
    });
    const raced = await env.award(first, "1000000");
    expect(raced.status).toBe(409);
    expect(raced.body.error).toBe("insufficient_funds");
    expect(env.reservations()).toEqual([
      { case_id: second, gross_minor: "1500000" },
    ]);
    expect(
      env.sqlite
        .query("SELECT award_state, revision FROM security_cases WHERE id = ?")
        .get(first),
    ).toEqual({ award_state: "pending", revision: 2 });
    // The same root cause never reserves twice.
    const third = await env.receive(REPORTER, "2026-10-19T09:30:00.000Z");
    const duplicate = await env.decide(third, "oracle-skew");
    expect(duplicate.status).toBe(409);
    expect(duplicate.body.error).toBe("root_cause_reserved");
    expect(
      (
        await env.decide(third, "oracle-skew", {
          outcome: "duplicate",
          duplicateOf: second,
        })
      ).body.case.awardState,
    ).toBe("ineligible");
  });

  test("a pledge reserves nothing", async () => {
    const env = open({ ...OPEN_PROGRAM, funding: { state: "pledged" } });
    const id = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    await env.decide(id, "vault-drain");
    const refused = await env.award(id, "1000000");
    expect(refused.status).toBe(409);
    expect(refused.body.error).toBe("funds_unavailable");
    expect(env.reservations()).toEqual([]);
  });

  test("an award reserved before discretionary awards is approved at its amount", async () => {
    const env = open();
    const id = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    await env.decide(id, "vault-drain");
    // The older flow reserved the program amount at the technical decision.
    env.sqlite
      .query(
        "INSERT INTO security_award_reservations (case_id, project_id, root_cause_key, policy_revision, gross_minor, currency, reserved_at) VALUES (?, ?, 'vault-drain', 1, '1000000', 'USD', ?)",
      )
      .run(id, PROJECT, REVISION_AT);
    env.sqlite
      .query("UPDATE security_cases SET award_state = 'reserved' WHERE id = ?")
      .run(id);
    expect((await env.award(id, "800000")).body.error).toBe(
      "award_obligation_exists",
    );
    const approved = await env.award(id, "1000000");
    expect(approved.status).toBe(200);
    expect(approved.body.case.awardState).toBe("approved");
    expect(env.reservations()).toEqual([
      { case_id: id, gross_minor: "1000000" },
    ]);
  });
});

describe("related-party awards", () => {
  test("a proposed related-party award reserves only after independent approval", async () => {
    const env = open();
    const related = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    const sameCause = await env.receive(OTHER, "2026-10-19T09:20:00.000Z");
    await env.decide(related, "shared-cause", { relatedParty: true });
    const proposed = await env.award(related, "800000");
    expect(proposed.status).toBe(200);
    expect(proposed.body.case).toMatchObject({
      awardState: "pending",
      award: { grossMinor: "800000" },
    });
    expect(env.reservations()).toEqual([]);
    // The dispute reviewers learn that a review waits; finance learns
    // nothing before an award is approved.
    for (const reviewer of [DISPUTE, DISPUTE_2])
      expect(env.inbox(reviewer, related)).toEqual([
        `security-case:${related}:3`,
      ]);
    expect(env.inbox(FINANCE, related)).toEqual([]);
    // The pending review holds its root cause.
    expect((await env.decide(sameCause, "shared-cause")).body.error).toBe(
      "root_cause_reserved",
    );
    const approved = await env.act(DISPUTE, related, {
      action: "decide-related-party",
      outcome: "approve",
      reason: "Approved after independent review.",
    });
    expect(approved.status).toBe(200);
    expect(approved.body.case.awardState).toBe("approved");
    expect(env.reservations()).toEqual([
      { case_id: related, gross_minor: "800000" },
    ]);
    expect(env.inbox(FINANCE, related)).toEqual([`security-case:${related}:4`]);
    // The reviewer is never notified of its own action.
    expect(env.inbox(DISPUTE, related)).toEqual([`security-case:${related}:3`]);
  });

  test("an appealed related-party refusal cannot be re-reviewed by the same reviewers", async () => {
    const env = open();
    const { act } = env;
    const related = await env.receive(REPORTER, "2026-10-19T09:10:00.000Z");
    const propose = async () => {
      expect(
        (await env.decide(related, "insider-cause", { relatedParty: false }))
          .status,
      ).toBe(200);
      return env.award(related, "800000");
    };
    await env.decide(related, "insider-cause", { relatedParty: true });
    expect((await env.award(related, "800000")).body.case.awardState).toBe(
      "pending",
    );
    const refuse = (reviewer: Account) =>
      act(reviewer, related, {
        action: "decide-related-party",
        outcome: "refuse",
        reason: "Refused after independent review.",
      });
    const appealAndReturn = async (reviewer: Account) => {
      expect(
        (
          await act(REPORTER, related, {
            action: "appeal",
            reason: "The related-party refusal used the wrong facts.",
          })
        ).status,
      ).toBe(200);
      expect(
        (
          await act(reviewer, related, {
            action: "decide-appeal",
            outcome: "return",
            reason: "Return for a new decision.",
          })
        ).status,
      ).toBe(200);
    };
    expect((await refuse(DISPUTE)).body.case.awardState).toBe("ineligible");
    await appealAndReturn(DISPUTE_2);
    // A redecision that declares no related party still needs a review.
    expect((await propose()).body.case.awardState).toBe("pending");
    expect(
      env.sqlite
        .query(
          "SELECT related_party, related_party_review, related_party_reviewer_github_id FROM security_cases WHERE id = ?",
        )
        .get(related),
    ).toEqual({
      related_party: "related",
      related_party_review: "pending",
      related_party_reviewer_github_id: DISPUTE.githubId,
    });
    for (const prior of [DISPUTE, DISPUTE_2]) {
      const reused = await act(prior, related, {
        action: "decide-related-party",
        outcome: "approve",
        reason: "Approved after independent review.",
      });
      expect(reused.status).toBe(403);
      expect(reused.body.error).toBe("conflicted");
    }
    expect((await refuse(DISPUTE_3)).body.case.awardState).toBe("ineligible");
    await appealAndReturn(DISPUTE_4);
    expect((await propose()).body.case.awardState).toBe("pending");
    for (const prior of [DISPUTE, DISPUTE_2, DISPUTE_3, DISPUTE_4]) {
      const reused = await act(prior, related, {
        action: "decide-related-party",
        outcome: "approve",
        reason: "Approved after independent review.",
      });
      expect(reused.status).toBe(403);
    }
    const approved = await act(DISPUTE_5, related, {
      action: "decide-related-party",
      outcome: "approve",
      reason: "Approved after independent review.",
    });
    expect(approved.status).toBe(200);
    expect(approved.body.case.awardState).toBe("approved");
  });
});
