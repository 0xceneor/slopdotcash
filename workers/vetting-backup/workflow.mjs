import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { convertV4MiniflareOptions, Miniflare } from "miniflare";
import { unstable_splitSqlQuery as splitSqlQuery } from "wrangler";

const directory = await mkdtemp(join(tmpdir(), "slop-backup-workflow-"));
let runtime;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const options = (bytes) => ({
  customMetadata: { sha256: digest(bytes) },
  httpMetadata: { contentType: "application/octet-stream" },
});
try {
  const bundle = join(directory, "worker.mjs");
  const build = spawnSync(
    "bun",
    [
      "build",
      "workers/vetting-backup/core.ts",
      "--target=browser",
      `--outfile=${bundle}`,
    ],
    { encoding: "utf8" },
  );
  assert.equal(build.status, 0, build.stderr);
  const {
    default: worker,
    startDailyBackup,
    backupPage,
    restoreCheck,
    pruneAccessAudit,
  } = await import(pathToFileURL(bundle).href);
  const workerBundle = join(directory, "worker-entry.mjs");
  const workerBuild = spawnSync(
    "bun",
    [
      "build",
      "workers/vetting-backup/index.ts",
      "--target=browser",
      `--outfile=${workerBundle}`,
    ],
    { encoding: "utf8" },
  );
  assert.equal(workerBuild.status, 0, workerBuild.stderr);
  runtime = new Miniflare(
    convertV4MiniflareOptions({
      name: "backup-workflow",
      modules: true,
      script: await readFile(workerBundle, "utf8"),
      compatibilityDate: "2026-07-30",
      bindings: { EVIDENCE_BACKUP_MODE: "enabled" },
      r2Buckets: ["EVIDENCE_SOURCE", "EVIDENCE_BACKUPS", "RESTORED"],
      d1Databases: ["EVIDENCE_DATABASE"],
      queueProducers: {
        EVIDENCE_BACKUP_QUEUE: { queueName: "evidence-backup" },
      },
      queueConsumers: {
        "evidence-backup": {
          maxBatchSize: 1,
          maxBatchTimeout: 0,
          maxRetries: 1,
        },
      },
    }),
  );
  await runtime.ready;
  const source = await runtime.getR2Bucket("EVIDENCE_SOURCE");
  const backups = await runtime.getR2Bucket("EVIDENCE_BACKUPS");
  const restored = await runtime.getR2Bucket("RESTORED");
  const queue = await runtime.getQueueProducer("EVIDENCE_BACKUP_QUEUE");
  const db = await runtime.getD1Database("EVIDENCE_DATABASE");
  for (const migration of [
    "0034_vetting_private_evidence.sql",
    "0067_vetting_audit_retention.sql",
  ])
    for (const query of splitSqlQuery(
      await readFile(`migrations/${migration}`, "utf8"),
    ))
      await db.prepare(query).run();
  await db
    .prepare(
      "INSERT INTO vetting_evidence_audit(id,actor,action,assessment_id,created_at) VALUES('old','fixture','read','fixture',strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 year','-1 day')),('recent','fixture','read','fixture',strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
    )
    .run();
  await assert.rejects(
    db.prepare("DELETE FROM vetting_evidence_audit WHERE id='recent'").run(),
    /one year/,
  );
  const env = {
    EVIDENCE_DATABASE: db,
    EVIDENCE_SOURCE: source,
    EVIDENCE_BACKUPS: backups,
    EVIDENCE_BACKUP_QUEUE: queue,
    EVIDENCE_BACKUP_MODE: "enabled",
  };
  const fixtures = Array.from({ length: 65 }, (_, index) => ({
    key: `vetting/case-${String(index).padStart(3, "0")}/run/evidence`,
    bytes: Buffer.from(`harmless scanner fixture ${index}`),
  }));
  for (const object of fixtures)
    await source.put(object.key, object.bytes, options(object.bytes));
  await source.put("permanent-contributor-trace", "outside scanner scope");
  const now = Date.now();
  const day = new Date(now).toISOString().slice(0, 10);
  await startDailyBackup({ ...env, EVIDENCE_BACKUP_MODE: "off" }, now);
  assert.equal((await backups.list()).objects.length, 0);
  await pruneAccessAudit({ ...env, EVIDENCE_BACKUP_MODE: "off" });
  assert.equal(
    (
      await db
        .prepare("SELECT COUNT(*) AS count FROM vetting_evidence_audit")
        .first()
    ).count,
    2,
  );
  await worker.scheduled({ scheduledTime: now }, env);
  assert.deepEqual(
    (await db.prepare("SELECT id FROM vetting_evidence_audit").all()).results,
    [{ id: "recent" }],
  );
  const completionKey = `daily/${day}/complete.json`;
  const deadline = Date.now() + 30_000;
  let complete = await backups.get(completionKey);
  while (!complete) {
    assert.ok(
      Date.now() < deadline,
      "real queue worker did not finish the snapshot",
    );
    await new Promise((resolve) => setTimeout(resolve, 100));
    complete = await backups.get(completionKey);
  }
  const receipt = await complete.json();
  assert.equal(receipt.objects, fixtures.length);
  assert.equal(receipt.pages, 3);
  assert.equal(
    receipt.bytes,
    fixtures.reduce((sum, item) => sum + item.bytes.length, 0),
  );
  assert.equal(
    await backups.get(`daily/${day}/objects/permanent-contributor-trace`),
    null,
  );
  const completeDigest = complete.customMetadata.sha256;
  await startDailyBackup(env, now + 1000);
  assert.equal(
    (await backups.head(completionKey)).customMetadata.sha256,
    completeDigest,
  );

  const original = fixtures[37];
  const result = await restoreCheck(
    backups,
    restored,
    day,
    original.key,
    "before-activation",
  );
  assert.equal(result.sha256, digest(original.bytes));
  assert.deepEqual(
    Buffer.from(await (await restored.get(result.key)).arrayBuffer()),
    original.bytes,
  );
  assert.deepEqual(
    Buffer.from(await (await source.get(original.key)).arrayBuffer()),
    original.bytes,
  );
  assert.equal(
    (await runtime.dispatchFetch("https://backup.invalid/")).status,
    404,
  );

  // A corrupt copy cannot pass recovery, even with the original metadata.
  const corruptKey = `daily/${day}/objects/${original.key}`;
  await backups.put(
    corruptKey,
    Buffer.alloc(original.bytes.length),
    options(original.bytes),
  );
  await assert.rejects(
    restoreCheck(backups, restored, day, original.key, "corrupt-copy"),
    /changed/,
  );
  assert.equal(
    await restored.get(`restore-checks/corrupt-copy/${original.key}`),
    null,
  );

  // Storage corruption prevents completion; it is never a skipped object.
  const bad = Buffer.from("bad source");
  await source.put("vetting/000-corrupt/run/evidence", bad, {
    customMetadata: { sha256: "0".repeat(64) },
  });
  const jobs = [];
  const later = now + 86_400_000;
  const failureEnv = {
    ...env,
    EVIDENCE_BACKUP_QUEUE: {
      send: async (job) => {
        jobs.push(job);
      },
    },
  };
  await startDailyBackup(failureEnv, later);
  await assert.rejects(backupPage(failureEnv, jobs[0]), /changed/);
  assert.equal(
    await backups.get(
      `daily/${new Date(later).toISOString().slice(0, 10)}/complete.json`,
    ),
    null,
  );
  console.log(
    "PASS: real queue/R2 pagination, independent grant-free backup, verified restore, source preservation, scope isolation and corruption refusal",
  );
} finally {
  await runtime?.dispose();
  await rm(directory, { recursive: true, force: true });
}
