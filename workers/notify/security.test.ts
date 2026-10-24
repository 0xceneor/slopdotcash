/** Actual case transitions and migrated SQLite D1, with only the mail transport substituted. */
import { expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import {
  handleNotificationsApi,
  type NotificationsDependencies,
} from "../../backend/notifications/handler";
import {
  FAKE_OAUTH,
  fakeGithub,
} from "../../backend/security/github-advisories.fake";
import {
  handleSecurityApi,
  type SecurityD1Database,
} from "../../backend/security/handler";
import { githubIntakeOAuth } from "../../backend/security/intake-grant";
import { deterministicAnalyzer } from "../../backend/security/report-analysis";
import { sqliteD1 } from "../../tests/sqlite-d1";
import {
  destinationDigest,
  dispatchSecurityMail,
  parseSecurityMailConfig,
  reconcileSecurityMail,
  type SecurityMailDependencies,
} from "./security";

const owner = { githubId: "101", githubLogin: "owner" };
const reporter = { githubId: "102", githubLogin: "reporter" };
const backup = { githubId: "103", githubLogin: "backup" };
const at = "2026-10-19T12:00:00.000Z";
const origin = "https://slop.test";
async function setup(beforeMailMigration = false) {
  const { db: source, sqlite } = sqliteD1(
    readdirSync("migrations")
      .filter(
        (p) =>
          p.endsWith(".sql") && (!beforeMailMigration || !p.startsWith("0030")),
      )
      .sort(),
  );
  const db = source as unknown as SecurityD1Database;
  const manifest = JSON.stringify({
    id: "bounty",
    status: "active",
    securityBounty: {
      status: "pending-approval",
      intake: { repository: "example/bounty" },
      approvers: { technical: [owner, backup], financial: [], dispute: [] },
      capacity: { awards: 1, closesAt: null },
      responseTargets: { acknowledgeHours: 1 },
    },
  });
  sqlite
    .query(
      "INSERT INTO project_revisions(project_id,revision,manifest,manifest_sha256,reason,created_at) VALUES ('bounty',1,?,?,'test',?)",
    )
    .run(manifest, "a".repeat(64), at);
  sqlite
    .query(
      "INSERT INTO projects(id,status,revision,manifest,manifest_sha256,created_at,updated_at) VALUES ('bounty','active',1,?,?,?,?)",
    )
    .run(manifest, "a".repeat(64), at, at);
  let current = new Date(at);
  let sequence = 0;
  const github = fakeGithub({ now: () => current });
  github.install("example/bounty");
  const cookies = new Map([
    ["__Host-slop_points", "fixture-session-" + "x".repeat(40)],
  ]);
  const absorb = (response: Response) => {
    for (const cookie of response.headers.getSetCookie()) {
      const pair = cookie.split(";")[0];
      cookies.set(
        pair.slice(0, pair.indexOf("=")),
        pair.slice(pair.indexOf("=") + 1),
      );
    }
  };
  const call = async (actor: typeof owner, path: string, body?: object) =>
    handleSecurityApi(
      new Request(origin + "/api/v1/" + path, {
        method: body === undefined ? "GET" : "POST",
        headers: {
          origin,
          "content-type": "application/json",
          cookie: [...cookies].map(([k, v]) => `${k}=${v}`).join("; "),
        },
        body: JSON.stringify(body),
      }),
      {
        db,
        now: () => current,
        randomId: () => `noticecase${++sequence}`,
        sessionActor: async () => actor,
        github: {
          fetch: async () => Response.json({ enabled: true }),
          apiOrigin: "https://github.invalid",
        },
        intake: {
          mode: "on",
          grantKey: Buffer.alloc(32, 7).toString("base64url"),
          clientId: "Iv1.intakeclient",
          authorizeOrigin: FAKE_OAUTH,
          oauth: githubIntakeOAuth({
            fetch: github.fetch,
            oauthOrigin: FAKE_OAUTH,
            clientId: "Iv1.intakeclient",
            clientSecret: "fixture-secret",
          }),
          advisories: github.client,
          installation: github.installation,
          analyzer: deterministicAnalyzer,
        },
      },
    );
  const advisory = github.seed(
    "example/bounty",
    { id: Number(reporter.githubId), login: reporter.githubLogin },
    { summary: "Synthetic report", description: "Synthetic report body" },
    at,
  );
  const started = await call(reporter, "security-submissions", {
    projectId: "bounty",
    origin: "direct",
    advisory: advisory.ghsa_id,
    idempotencyKey: "notify-intake-key-0001",
  });
  expect(started?.status).toBe(201);
  if (started === null) throw new Error("Submission route missing");
  absorb(started);
  const draft = (await started.json()) as {
    submission: { id: string };
    authorizeUrl: string;
  };
  const state = new URL(draft.authorizeUrl).searchParams.get("state");
  const code = github.issueCode({
    id: Number(reporter.githubId),
    login: reporter.githubLogin,
  });
  const authorized = await call(
    reporter,
    `security-submissions/authorize/callback?code=${code}&state=${state}`,
  );
  expect(authorized?.status).toBe(303);
  if (authorized === null) throw new Error("Authorization callback missing");
  absorb(authorized);
  const checked = await call(
    reporter,
    `security-submissions/${draft.submission.id}/verify`,
    { expectedRevision: 1 },
  );
  expect(checked?.status).toBe(200);
  if (checked === null) throw new Error("Submission verify route missing");
  const caseId = ((await checked.json()) as { submission: { caseId: string } })
    .submission.caseId;
  const recipients = Object.fromEntries(
    [
      [owner, backup],
      [backup, owner],
      [reporter, owner],
    ].map(([actor, spare]) => [
      actor.githubId,
      {
        email: `${actor.githubLogin}@example.com`,
        verifiedAt: at,
        evidenceReference: "private-operator-verification-1",
        backupGithubId: spare.githubId,
      },
    ]),
  );
  const config = parseSecurityMailConfig(
    JSON.stringify({
      inboxUrl: "https://staging.slop.cash/inbox",
      recipients,
    }),
  );
  expect(config).not.toBeNull();
  const sent: { to: string; mime: string }[] = [];
  const deps: SecurityMailDependencies = {
    db,
    config: config!,
    fromAddress: "notifications@slop.cash",
    now: () => current,
    sendEmail: async (_from, to, mime) => {
      sent.push({ to, mime });
    },
  };
  const rows = () =>
    sqlite
      .query(
        "SELECT * FROM security_notification_outbox ORDER BY recipient_github_id",
      )
      .all() as {
      id: string;
      event_key: string;
      recipient_github_id: string;
      state: string;
      attempts: number;
      acknowledged_at: string | null;
      escalation_of: string | null;
    }[];
  return {
    db,
    sqlite,
    deps,
    call,
    caseId,
    rows,
    sent,
    advance: (ms: number) => {
      current = new Date(current.getTime() + ms);
    },
  };
}

test("a case change queues once, sends generic per-role mail once, and needs explicit recipient acknowledgment", async () => {
  const h = await setup();
  expect(h.rows()).toHaveLength(2);
  await Promise.all([
    dispatchSecurityMail(h.deps),
    dispatchSecurityMail(h.deps),
  ]);
  expect(h.sent).toHaveLength(2);
  expect(h.rows().map((r) => r.state)).toEqual([
    "provider-accepted",
    "provider-accepted",
  ]);
  for (const send of h.sent) {
    expect(send.mime).toContain("https://staging.slop.cash/inbox");
    expect(send.mime).not.toContain(h.caseId);
    expect(send.mime).not.toContain("GHSA");
    expect(send.mime).not.toContain("bounty");
  }
  const notice = h
    .rows()
    .find((r) => r.recipient_github_id === owner.githubId)!;
  expect(
    (
      await h.call(reporter, `security-cases/${h.caseId}/acknowledge`, {
        eventKey: notice.event_key,
      })
    )?.status,
  ).toBe(404);
  expect(
    (
      await h.call(owner, `security-cases/${h.caseId}/acknowledge`, {
        eventKey: notice.event_key,
      })
    )?.status,
  ).toBe(200);
  expect(
    (
      await h.call(owner, `security-cases/${h.caseId}/acknowledge`, {
        eventKey: notice.event_key,
      })
    )?.status,
  ).toBe(200);
  expect(h.rows()[0].acknowledged_at).toBe(at);
  expect(
    h.sqlite
      .query(
        "SELECT count(*) AS n FROM security_notification_delivery_events WHERE state = 'acknowledged'",
      )
      .get(),
  ).toEqual({ n: 1 });
  await dispatchSecurityMail(h.deps);
  expect(h.sent).toHaveLength(2);
  expect(
    await reconcileSecurityMail(h.deps, {
      deliveryId: notice.id,
      attempt: notice.attempts,
      destinationDigest: await destinationDigest(
        h.deps.config.recipients[notice.recipient_github_id],
      ),
      outcome: "delivered",
      evidenceReference: "private-provider-delivery-receipt",
    }),
  ).toBe(true);
  expect(h.rows()[0].state).toBe("delivered");
  h.sqlite.close();
});

test("ambiguous transport never resends until independent non-acceptance evidence; failures reach only an authorized backup", async () => {
  const h = await setup();
  h.deps.sendEmail = async () => {
    throw new Error("transport interrupted after request");
  };
  await dispatchSecurityMail(h.deps);
  expect(
    h
      .rows()
      .filter((r) => !r.escalation_of)
      .map((r) => r.state),
  ).toEqual(["ambiguous", "ambiguous"]);
  expect(h.rows().filter((r) => r.escalation_of)).toHaveLength(2);
  await dispatchSecurityMail(h.deps);
  expect(h.rows()).toHaveLength(4); // no recursive escalation
  expect(
    h
      .rows()
      .filter((r) => !r.escalation_of)
      .every((r) => r.attempts === 1),
  ).toBe(true);
  const first = h.rows()[0];
  expect(
    await reconcileSecurityMail(h.deps, {
      deliveryId: first.id,
      attempt: first.attempts,
      destinationDigest: await destinationDigest(
        h.deps.config.recipients[first.recipient_github_id],
      ),
      outcome: "not-accepted",
      evidenceReference: "private-provider-negative-receipt",
    }),
  ).toBe(true);
  h.advance(60_000);
  h.deps.sendEmail = async (_from, to, mime) => {
    h.sent.push({ to, mime });
  };
  await dispatchSecurityMail(h.deps);
  expect(h.sent).toHaveLength(1);
  h.sqlite.close();
});

test("role revocation suppresses queued mail; missing verified destinations exhaust bounded retries without losing the case", async () => {
  const h = await setup();
  h.sqlite
    .query(
      "INSERT INTO project_revisions(project_id,revision,manifest,manifest_sha256,reason,created_at) SELECT id,2,json_set(manifest, '$.securityBounty.approvers.technical', json(?)),?, 'test role revocation',? FROM projects WHERE id='bounty'",
    )
    .run(JSON.stringify([owner]), "b".repeat(64), at);
  h.sqlite
    .query(
      "UPDATE projects SET revision=2, manifest_sha256='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', manifest = json_set(manifest, '$.securityBounty.approvers.technical', json(?)) WHERE id = 'bounty'",
    )
    .run(JSON.stringify([owner]));
  delete h.deps.config.recipients[owner.githubId];
  for (let i = 0; i < 5; i++) {
    await dispatchSecurityMail(h.deps);
    h.advance(3600_000);
  }
  expect(h.rows().map((r) => r.state)).toEqual(["exhausted", "suppressed"]);
  expect(h.rows().map((r) => r.attempts)).toEqual([5, 1]);
  expect(h.sent).toHaveLength(0);
  expect(
    h.sqlite
      .query("SELECT submission_state FROM security_cases WHERE id = ?")
      .get(h.caseId),
  ).toEqual({ submission_state: "verified" });
  h.sqlite.close();
});

test("backup notices have a durable inbox row and their own authenticated acknowledgment", async () => {
  const h = await setup();
  await dispatchSecurityMail(h.deps);
  h.advance(3600_000);
  await dispatchSecurityMail(h.deps);
  const escalation = h
    .rows()
    .find((r) => r.escalation_of && r.recipient_github_id === backup.githubId);
  if (!escalation) throw new Error("Backup notice missing");
  expect(
    h.sqlite
      .query(
        "SELECT kind, subject FROM notifications WHERE event_key = ? AND recipient_github_id = ?",
      )
      .get(escalation.event_key, backup.githubId),
  ).toEqual({ kind: "security_case", subject: h.caseId });
  expect(
    (
      await h.call(backup, `security-cases/${h.caseId}/acknowledge`, {
        eventKey: escalation.event_key,
      })
    )?.status,
  ).toBe(200);
  expect(
    h.rows().find((r) => r.id === escalation.id)?.acknowledged_at,
  ).not.toBeNull();
  h.sqlite.close();
});

test("already escalated history cannot starve a later overdue notice", async () => {
  const h = await setup();
  await dispatchSecurityMail(h.deps);
  h.advance(3600_000);
  // Persist the historical workload that caused the LIMIT 100 regression.
  for (let i = 0; i < 101; i++) {
    h.sqlite
      .query(
        "INSERT INTO notifications(event_key,recipient_github_id,kind,subject,action_path,source_at,created_at) VALUES (?,?,'security_case',?,'/security',?,?)",
      )
      .run(`security-case:historical-${i}`, owner.githubId, h.caseId, at, at);
  }
  h.sqlite
    .query(
      "UPDATE security_notification_outbox SET state='provider-accepted' WHERE event_key LIKE 'security-case:historical-%'",
    )
    .run();
  await dispatchSecurityMail(h.deps);
  h.advance(300_000);
  await dispatchSecurityMail(h.deps);
  const missing = h.sqlite
    .query(
      "SELECT count(*) AS n FROM security_notification_outbox o WHERE o.event_key LIKE 'security-case:historical-%' AND NOT EXISTS (SELECT 1 FROM security_notification_outbox b WHERE b.escalation_of=o.id)",
    )
    .get();
  expect(missing).toEqual({ n: 0 });
  h.sqlite.close();
});

test("pre-pilot inbox history is not mailed and does not expose a dead acknowledgment action", async () => {
  const h = await setup(true);
  h.sqlite.exec(
    readFileSync("migrations/0030_security_notification_outbox.sql", "utf8"),
  );
  expect(h.rows()).toEqual([]);
  const response = await handleNotificationsApi(
    new Request(origin + "/api/v1/notifications"),
    {
      db: h.db as unknown as NotificationsDependencies["db"],
      sessionActor: async () => owner,
      now: () => new Date(at),
    },
  );
  if (!response) throw new Error("Inbox route missing");
  const body = (await response.json()) as {
    notifications: Record<string, unknown>[];
  };
  expect(body.notifications).toHaveLength(1);
  expect(Object.hasOwn(body.notifications[0], "acknowledgedAt")).toBe(false);
  h.sqlite.close();
});

test("a negative receipt cannot reconcile a later attempt or append duplicate evidence", async () => {
  const h = await setup();
  h.deps.sendEmail = async () => {
    throw new Error("ambiguous send");
  };
  await dispatchSecurityMail(h.deps);
  const first = h
    .rows()
    .find((r) => !r.escalation_of && r.recipient_github_id === owner.githubId);
  if (!first) throw new Error("Original notice missing");
  const oldEvidence = {
    deliveryId: first.id,
    attempt: 1,
    destinationDigest: await destinationDigest(
      h.deps.config.recipients[owner.githubId],
    ),
    outcome: "not-accepted",
    evidenceReference: "provider-attempt-one-negative-receipt",
  };
  expect(await reconcileSecurityMail(h.deps, oldEvidence)).toBe(true);
  expect(await reconcileSecurityMail(h.deps, oldEvidence)).toBe(false);
  h.advance(60_000);
  h.deps.sendEmail = async () => {};
  await dispatchSecurityMail(h.deps);
  expect(h.rows().find((r) => r.id === first.id)?.state).toBe(
    "provider-accepted",
  );
  expect(await reconcileSecurityMail(h.deps, oldEvidence)).toBe(false);
  // Merely changing the asserted attempt cannot recycle evidence either.
  expect(
    await reconcileSecurityMail(h.deps, { ...oldEvidence, attempt: 2 }),
  ).toBe(false);
  expect(
    h.sqlite
      .query(
        "SELECT count(*) AS n FROM security_notification_delivery_events WHERE evidence_reference=?",
      )
      .get(oldEvidence.evidenceReference),
  ).toEqual({ n: 1 });
  expect(h.rows().find((r) => r.id === first.id)?.state).toBe(
    "provider-accepted",
  );
  h.sqlite.close();
});

test("concurrent copies of one provider receipt append one delivery event", async () => {
  const h = await setup();
  await dispatchSecurityMail(h.deps);
  const first = h.rows().find((r) => r.recipient_github_id === owner.githubId);
  if (!first) throw new Error("Original notice missing");
  const receipt = {
    deliveryId: first.id,
    attempt: 1,
    destinationDigest: await destinationDigest(
      h.deps.config.recipients[owner.githubId],
    ),
    outcome: "delivered",
    evidenceReference: "provider-delivery-receipt",
  };
  expect(
    (
      await Promise.all([
        reconcileSecurityMail(h.deps, receipt),
        reconcileSecurityMail(h.deps, receipt),
      ])
    ).sort(),
  ).toEqual([false, true]);
  expect(
    h.sqlite
      .query(
        "SELECT count(*) AS n FROM security_notification_delivery_events WHERE evidence_reference=?",
      )
      .get(receipt.evidenceReference),
  ).toEqual({ n: 1 });
  h.sqlite.close();
});
