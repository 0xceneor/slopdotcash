// Self-service account closure against the real migrations (PRD section 3,
// ACC-05): one confirmed request ends every session, removes the optional
// connections and activity email, and keeps the identity, claims, awards,
// obligations and inbox. Only an explicit reopen signs the account in again.
import { expect, test } from "bun:test";
import { readdirSync } from "node:fs";
import { handlePointsApi } from "../backend/points/handler";
import { sqliteD1 } from "../tests/sqlite-d1";
import { sha256Hex } from "../workers/identity/crypto";

const NOW = "2026-10-23T12:00:00.000Z";
const LATER = "2026-10-23T13:00:00.000Z";
const ME = { actor: "U_closing", github: "4100", login: "Closing-Member" };
const OTHER = { actor: "U_staying", github: "4200", login: "staying-member" };

async function harness() {
  const { db, sqlite } = sqliteD1(
    readdirSync(new URL("../migrations", import.meta.url))
      .filter((name) => name.endsWith(".sql"))
      .sort(),
  );
  const tokens = {
    me: "m".repeat(48),
    meOther: "n".repeat(48),
    other: "o".repeat(48),
  };
  for (const member of [ME, OTHER])
    sqlite
      .prepare(
        "INSERT INTO points_members(actor_id,github_id,login,joined_at,public) VALUES(?,?,?,?,1)",
      )
      .run(member.actor, member.github, member.login, NOW);
  for (const [token, actor] of [
    [tokens.me, ME.actor],
    [tokens.meOther, ME.actor],
    [tokens.other, OTHER.actor],
  ])
    sqlite
      .prepare(
        "INSERT INTO points_sessions(token_hash,actor_id,expires_at) VALUES(?,?,?)",
      )
      .run(await sha256Hex(token), actor, "2026-10-23T14:00:00.000Z");
  sqlite.exec(`
    INSERT INTO points_x_claims VALUES ('77','${ME.actor}','${NOW}');
    INSERT INTO points_x_awards VALUES ('${ME.actor}','77','${NOW}',10);
    INSERT INTO points_x_links VALUES ('${ME.actor}','77','closing_x','${NOW}',1);
    INSERT INTO points_x_flows VALUES ('state','browser','session','${ME.actor}','v','iv','2026-10-23T12:10:00.000Z',1,'pending');
    INSERT INTO points_telegram_claims VALUES ('88','${ME.actor}','${NOW}');
    INSERT INTO points_telegram_links VALUES ('${ME.actor}','88','closing_tg','${NOW}',1);
    INSERT INTO points_telegram_flows VALUES ('code','session','${ME.actor}','2026-10-23T12:10:00.000Z',1,'pending');
    INSERT INTO notification_email_preferences VALUES ('${ME.github}',1,'${"d".repeat(64)}','${NOW}');
    INSERT INTO notifications (event_key,recipient_github_id,kind,subject,action_path,source_at,created_at)
      VALUES ('payment-reserved:obligation-1','${ME.github}','award_reserved','alpha','/earnings','${NOW}','${NOW}');
    INSERT INTO wallet_claims (id,github_user_id,github_login,wallet_address,source,issue_repository,issue_number,source_body_sha256,observed_at,record_sha256,supersedes_claim_id,created_at,chain)
      VALUES ('claim-1','${ME.github}','${ME.login}','0x8f77c37d8650776bfe73c9b12b15209ee15d9b86','d1_registry',NULL,NULL,'${"a".repeat(64)}','${NOW}','${"b".repeat(64)}',NULL,'${NOW}','base');
    INSERT INTO payment_obligations VALUES ('obligation-1','alpha','${ME.github}','base-sepolia','base','0x2222222222222222222222222222222222222222','0x3333333333333333333333333333333333333333',6,'100000000','2000000','${"9".repeat(64)}','reserved','${NOW}',NULL);
    INSERT INTO project_revisions (project_id,revision,manifest,manifest_sha256,reason,created_at)
      VALUES ('alpha',1,'{"id":"alpha","status":"active"}','${"a".repeat(64)}','Listed','${NOW}');
    INSERT INTO projects (id,status,revision,manifest,manifest_sha256,created_at,updated_at)
      VALUES ('alpha','active',1,'{"id":"alpha","status":"active"}','${"a".repeat(64)}','${NOW}','${NOW}');
    INSERT INTO security_cases (id,project_id,advisory_repository,advisory_ghsa,reporter_github_id,reporter_github_login,submission_state,received_at,verified_at,verified_by_github_id,receipt_state,remediation_state,award_state,payment_state,disclosure_state,recognition,appeal_state,revision,created_at,updated_at)
      VALUES ('sc_closing0001','alpha','example/alpha','GHSA-aaaa-bbbb-cccc','${ME.github}','${ME.login}','verified','${NOW}','${NOW}','4200','received','not-started','not-applicable','not-applicable','embargoed','private','none',1,'${NOW}','${NOW}');
  `);
  let clock = NOW;
  const identity = { login: ME.login };
  const call = async (path: string, token: string | null, body?: unknown) => {
    const response = await handlePointsApi(
      new Request(`https://slop.cash/api/v1/points/${path}`, {
        method: body === undefined ? "GET" : "POST",
        headers: {
          ...(token ? { cookie: `__Host-slop_points=${token}` } : {}),
          ...(body === undefined
            ? {}
            : {
                origin: "https://slop.cash",
                "content-type": "application/json",
              }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
      {
        db,
        now: () => new Date(clock),
        rateLimitSecret: "test-only-rate-secret".repeat(4),
        identity: {
          fetch: async () =>
            Response.json({
              audience: "slop-points-web",
              githubActorId: ME.github,
              githubNodeId: ME.actor,
              githubLogin: identity.login,
            }),
        },
      },
    );
    return {
      status: response.status,
      cookie: response.headers.get("set-cookie"),
      body: await response.json(),
    };
  };
  const count = (sql: string, ...values: string[]) =>
    (sqlite.query(sql).get(...values) as { n: number }).n;
  return {
    sqlite,
    tokens,
    call,
    count,
    setClock: (at: string) => {
      clock = at;
    },
  };
}

test("closing an account ends every session, removes optional connections and keeps records", async () => {
  const { sqlite, tokens, call, count } = await harness();
  try {
    sqlite.exec(`INSERT INTO activity_notification_outbox
      (event_key,recipient_github_id,essential,destination_version,next_attempt_at,created_at,updated_at)
      VALUES ('payout-held:obligation-1:${NOW}','${ME.github}',0,'${"d".repeat(64)}','${NOW}','${NOW}','${NOW}'),
             ('wallet-claim:claim-1','${ME.github}',1,NULL,'${NOW}','${NOW}','${NOW}')`);
    // The confirmation must name this account; a mismatch changes nothing.
    const refused = await call("account/close", tokens.me, {
      login: OTHER.login,
    });
    expect(refused).toMatchObject({
      status: 400,
      body: { error: "confirmation_mismatch" },
    });
    expect(
      count(
        "SELECT count(*) n FROM points_sessions WHERE actor_id=?",
        ME.actor,
      ),
    ).toBe(2);
    // Closure changes only the membership, its optional connections, its
    // sessions, its email preference and the optional mail queue. The wallet,
    // the unpaid obligation, the private case and every other record stay
    // exactly as they were.
    const changed = new Set([
      "points_members",
      "points_sessions",
      "points_x_links",
      "points_x_flows",
      "points_telegram_links",
      "points_telegram_flows",
      "notification_email_preferences",
      "activity_notification_outbox",
      // The request limiter counts the closure request itself.
      "identity_rate_limits",
    ]);
    const snapshot = () =>
      Object.fromEntries(
        (
          sqlite
            .query(
              "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )
            .all() as { name: string }[]
        )
          .filter(({ name }) => !changed.has(name))
          .map(({ name }) => [
            name,
            sqlite.query(`SELECT * FROM "${name}" ORDER BY rowid`).all(),
          ]),
      );
    const before = snapshot();
    expect(before.wallet_claims).toHaveLength(1);
    expect(before.payment_obligations).toHaveLength(1);
    expect(before.security_cases).toHaveLength(1);

    const closed = await call("account/close", tokens.me, {
      login: "closing-member",
    });
    expect(closed.status).toBe(200);
    expect(closed.body).toEqual({ closed: true, closedAt: NOW });
    expect(closed.cookie).toContain("Max-Age=0");
    expect(snapshot()).toEqual(before);
    // A repeated attempt has no session left to act with.
    expect(
      (await call("account/close", tokens.me, { login: ME.login })).status,
    ).toBe(401);
    // Both of this account's sessions end; another account keeps its own.
    expect((await call("sessions", tokens.me)).status).toBe(401);
    expect((await call("sessions", tokens.meOther)).status).toBe(401);
    expect((await call("sessions", tokens.other)).status).toBe(200);
    expect(
      sqlite
        .query(
          "SELECT public, closed_at, welcome FROM points_members WHERE actor_id=?",
        )
        .get(ME.actor),
    ).toEqual({ public: 0, closed_at: NOW, welcome: 5 });
    for (const table of [
      "points_x_links",
      "points_x_flows",
      "points_telegram_links",
      "points_telegram_flows",
    ])
      expect(
        count(`SELECT count(*) n FROM ${table} WHERE actor_id=?`, ME.actor),
      ).toBe(0);
    // Claims keep each X and Telegram ID reserved; awards and inbox stay.
    for (const table of [
      "points_x_claims",
      "points_x_awards",
      "points_telegram_claims",
    ])
      expect(
        count(`SELECT count(*) n FROM ${table} WHERE actor_id=?`, ME.actor),
      ).toBe(1);
    expect(
      count(
        "SELECT count(*) n FROM notifications WHERE recipient_github_id=?",
        ME.github,
      ),
    ).toBe(1);
    // Activity mail is off and queued activity mail is suppressed; the
    // essential wallet-security notice is not.
    expect(
      sqlite
        .query(
          "SELECT enabled FROM notification_email_preferences WHERE github_id=?",
        )
        .get(ME.github),
    ).toEqual({ enabled: 0 });
    expect(
      sqlite
        .query(
          "SELECT essential, state, count(*) n FROM activity_notification_outbox GROUP BY essential, state ORDER BY essential",
        )
        .all(),
    ).toEqual([
      { essential: 0, state: "suppressed", n: 2 },
      { essential: 1, state: "queued", n: 1 },
    ]);
    // The closed membership leaves people lists and the public profile.
    const people = await call("people", null);
    expect(
      people.body.people.map((p: { actor: { id: string } }) => p.actor.id),
    ).toEqual([OTHER.actor]);
    expect((await call(`member?login=${ME.login}`, null)).body).toBeNull();
    // The database itself refuses a session or public visibility while closed.
    expect(() =>
      sqlite
        .prepare(
          "INSERT INTO points_sessions(token_hash,actor_id,expires_at) VALUES('x',?,?)",
        )
        .run(ME.actor, LATER),
    ).toThrow("a closed account has no sessions");
    expect(() =>
      sqlite
        .prepare("UPDATE points_members SET public=1 WHERE actor_id=?")
        .run(ME.actor),
    ).toThrow("a closed account is not public");
  } finally {
    sqlite.close();
  }
});

test("a closed account signs in again only through an explicit reopen", async () => {
  const { sqlite, tokens, call, count, setClock } = await harness();
  try {
    expect(
      (await call("account/close", tokens.me, { login: ME.login })).status,
    ).toBe(200);
    setClock(LATER);
    const assertion = `slop_assert_v1_${"a".repeat(48)}`;
    const ordinary = await call("join", null, { assertion, public: true });
    expect(ordinary).toMatchObject({
      status: 409,
      body: { error: "account_closed", closedAt: NOW },
    });
    expect(ordinary.cookie).toBeNull();
    expect(
      count(
        "SELECT count(*) n FROM points_sessions WHERE actor_id=?",
        ME.actor,
      ),
    ).toBe(0);
    // `reopen` accepts only true.
    expect(
      (await call("join", null, { assertion, public: false, reopen: false }))
        .status,
    ).toBe(400);
    const reopened = await call("join", null, {
      assertion,
      public: false,
      reopen: true,
    });
    expect(reopened.status).toBe(200);
    expect(reopened.body).toMatchObject({
      actor: { id: ME.actor, login: ME.login },
      public: false,
      socialPoints: 10,
    });
    expect(reopened.cookie).toContain("Max-Age=3600");
    expect(
      sqlite
        .query("SELECT public, closed_at FROM points_members WHERE actor_id=?")
        .get(ME.actor),
    ).toEqual({ public: 0, closed_at: null });
    // Removed connections stay removed until the person connects again.
    expect(
      count("SELECT count(*) n FROM points_x_links WHERE actor_id=?", ME.actor),
    ).toBe(0);
    // An open account ignores the reopen flag.
    expect(
      (await call("join", null, { assertion, public: false, reopen: true }))
        .status,
    ).toBe(200);
  } finally {
    sqlite.close();
  }
});

test("closure needs a signed-in session and a same-origin JSON request, and a repeat is safe", async () => {
  const { sqlite, tokens, call, count, setClock } = await harness();
  try {
    expect(
      (await call("account/close", null, { login: ME.login })).status,
    ).toBe(401);
    expect(
      (await call("account/close", "z".repeat(48), { login: ME.login })).status,
    ).toBe(401);
    const crossSite = await handlePointsApi(
      new Request("https://slop.cash/api/v1/points/account/close", {
        method: "POST",
        headers: {
          cookie: `__Host-slop_points=${tokens.me}`,
          origin: "https://attacker.example",
          "content-type": "application/json",
        },
        body: JSON.stringify({ login: ME.login }),
      }),
      {
        db: sqliteD1([]).db,
        rateLimitSecret: "test-only-rate-secret".repeat(4),
        identity: { fetch: async () => new Response(null, { status: 500 }) },
      },
    );
    expect(crossSite.status).toBe(403);
    // A second request that read its session before a concurrent closure
    // committed reports that same closure instead of failing.
    sqlite.exec(
      `UPDATE points_members SET closed_at='${NOW}', public=0 WHERE actor_id='${ME.actor}'`,
    );
    setClock(LATER);
    const raced = await call("account/close", tokens.meOther, {
      login: ME.login,
    });
    expect(raced).toMatchObject({
      status: 200,
      body: { closed: true, closedAt: NOW },
    });
    expect(
      count(
        "SELECT count(*) n FROM points_sessions WHERE actor_id=?",
        ME.actor,
      ),
    ).toBe(0);
  } finally {
    sqlite.close();
  }
});
