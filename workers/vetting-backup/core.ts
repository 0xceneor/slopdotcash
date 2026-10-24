/** Daily private copies of scanner bytes. No HTTP access or source deletion. */
import type { ProjectD1Database } from "../../backend/projects/cloudflare-persistence";
import type { R2Bucket } from "../../backend/trace/cloudflare-persistence";
import { sha256Hex } from "../../backend/trace/validation";
import {
  EVIDENCE_CHUNK_BYTES,
  verifiedPart,
} from "../../backend/vetting/evidence-chunks";

type ListedObject = { key: string; size: number; uploaded: Date };
export type ArchiveBucket = R2Bucket & {
  list(options: { prefix: string; limit: number; cursor?: string }): Promise<{
    objects: ListedObject[];
    truncated: boolean;
    cursor?: string;
  }>;
};
type BackupJob = {
  day: string;
  page: number;
  cursor?: string;
  previous: string | null;
  objects: number;
  bytes: number;
};
export type BackupEnvironment = {
  EVIDENCE_DATABASE: ProjectD1Database;
  EVIDENCE_SOURCE: ArchiveBucket;
  EVIDENCE_BACKUPS: ArchiveBucket;
  EVIDENCE_BACKUP_QUEUE: { send(job: BackupJob): Promise<void> };
  EVIDENCE_BACKUP_MODE?: string;
};
type Copy = {
  key: string;
  backupKey: string;
  sha256: string;
  sizeBytes: number;
};
type Page = {
  previous: string | null;
  cursor: string | null;
  next: string | null;
  objects: Copy[];
};
const encoder = new TextEncoder();
const root = (day: string) => {
  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(day) ||
    new Date(`${day}T00:00:00.000Z`).toISOString().slice(0, 10) !== day
  )
    throw new Error("Invalid backup day");
  return `daily/${day}`;
};
const pageKey = (day: string, page: number) =>
  `${root(day)}/pages/${page}.json`;

async function immutable(
  bucket: R2Bucket,
  key: string,
  bytes: Uint8Array,
  contentType: string,
) {
  const digest = await sha256Hex(bytes);
  await bucket.put(key, bytes, {
    onlyIf: { etagDoesNotMatch: "*" },
    customMetadata: { sha256: digest },
    httpMetadata: { contentType },
  });
  await verifiedPart(bucket, key, digest, bytes.byteLength);
  return digest;
}
async function jsonRecord<T>(
  bucket: R2Bucket,
  key: string,
): Promise<{ value: T; digest: string } | null> {
  const object = await bucket.head(key);
  if (!object) return null;
  const digest = object.customMetadata?.sha256;
  if (!digest || !/^[0-9a-f]{64}$/.test(digest))
    throw new Error("Invalid backup receipt");
  const bytes = await verifiedPart(bucket, key, digest, object.size);
  return { value: JSON.parse(new TextDecoder().decode(bytes)) as T, digest };
}

export async function startDailyBackup(
  env: BackupEnvironment,
  scheduledTime: number,
) {
  if (env.EVIDENCE_BACKUP_MODE !== "enabled") return;
  const day = new Date(scheduledTime).toISOString().slice(0, 10);
  const startKey = `${root(day)}/start.json`;
  if (!(await jsonRecord(env.EVIDENCE_BACKUPS, startKey))) {
    await immutable(
      env.EVIDENCE_BACKUPS,
      startKey,
      encoder.encode(
        JSON.stringify({
          day,
          startedAt: new Date(scheduledTime).toISOString(),
        }),
      ),
      "application/json",
    );
  }
  if (await jsonRecord(env.EVIDENCE_BACKUPS, `${root(day)}/complete.json`))
    return;
  await env.EVIDENCE_BACKUP_QUEUE.send({
    day,
    page: 0,
    previous: null,
    objects: 0,
    bytes: 0,
  });
}

export async function backupPage(env: BackupEnvironment, job: BackupJob) {
  if (env.EVIDENCE_BACKUP_MODE !== "enabled")
    throw new Error("Evidence backup is disabled");
  if (!Number.isSafeInteger(job.page) || job.page < 0)
    throw new Error("Invalid backup page");
  const start = await jsonRecord<{ day: string; startedAt: string }>(
    env.EVIDENCE_BACKUPS,
    `${root(job.day)}/start.json`,
  );
  if (
    !start ||
    start.value.day !== job.day ||
    !Number.isFinite(Date.parse(start.value.startedAt))
  )
    throw new Error("Missing backup start receipt");
  const key = pageKey(job.day, job.page);
  let receipt = await jsonRecord<Page>(env.EVIDENCE_BACKUPS, key);
  if (!receipt) {
    const listed = await env.EVIDENCE_SOURCE.list({
      prefix: "vetting/",
      limit: 32,
      cursor: job.cursor,
    });
    if (listed.truncated && (!listed.cursor || listed.cursor === job.cursor))
      throw new Error("Backup listing did not advance");
    const objects: Copy[] = [];
    for (const source of listed.objects) {
      if (source.uploaded.getTime() > Date.parse(start.value.startedAt))
        continue;
      if (
        !source.key.startsWith("vetting/") ||
        source.size > EVIDENCE_CHUNK_BYTES
      )
        throw new Error("Invalid scanner evidence object");
      const head = await env.EVIDENCE_SOURCE.head(source.key);
      const digest = head?.customMetadata?.sha256;
      if (
        !head ||
        head.size !== source.size ||
        !digest ||
        !/^[0-9a-f]{64}$/.test(digest)
      )
        throw new Error("Scanner evidence changed during backup");
      const bytes = await verifiedPart(
        env.EVIDENCE_SOURCE,
        source.key,
        digest,
        source.size,
      );
      const backupKey = `${root(job.day)}/objects/${source.key}`;
      await immutable(
        env.EVIDENCE_BACKUPS,
        backupKey,
        bytes,
        "application/octet-stream",
      );
      objects.push({
        key: source.key,
        backupKey,
        sha256: digest,
        sizeBytes: source.size,
      });
    }
    const value: Page = {
      previous: job.previous,
      cursor: job.cursor ?? null,
      next: listed.truncated ? (listed.cursor ?? null) : null,
      objects,
    };
    const digest = await immutable(
      env.EVIDENCE_BACKUPS,
      key,
      encoder.encode(JSON.stringify(value)),
      "application/json",
    );
    receipt = { value, digest };
  }
  if (
    receipt.value.previous !== job.previous ||
    receipt.value.cursor !== (job.cursor ?? null)
  )
    throw new Error("Backup receipt chain changed");
  const objects = job.objects + receipt.value.objects.length;
  const bytes =
    job.bytes +
    receipt.value.objects.reduce((sum, object) => sum + object.sizeBytes, 0);
  if (receipt.value.next !== null) {
    await env.EVIDENCE_BACKUP_QUEUE.send({
      day: job.day,
      page: job.page + 1,
      cursor: receipt.value.next,
      previous: receipt.digest,
      objects,
      bytes,
    });
    return;
  }
  await immutable(
    env.EVIDENCE_BACKUPS,
    `${root(job.day)}/complete.json`,
    encoder.encode(
      JSON.stringify({
        day: job.day,
        startedAt: start.value.startedAt,
        pages: job.page + 1,
        lastPageSha256: receipt.digest,
        objects,
        bytes,
      }),
    ),
    "application/json",
  );
}

/** Restore into a separate check prefix; never overwrite a live evidence object. */
export async function restoreCheck(
  backups: ArchiveBucket,
  destination: R2Bucket,
  day: string,
  sourceKey: string,
  checkId: string,
) {
  if (!/^[a-zA-Z0-9_-]{1,80}$/.test(checkId))
    throw new Error("Invalid restore check identity");
  const complete = await jsonRecord<{
    pages: number;
    lastPageSha256: string;
    objects: number;
    bytes: number;
  }>(backups, `${root(day)}/complete.json`);
  if (
    !complete ||
    !Number.isSafeInteger(complete.value.pages) ||
    complete.value.pages < 1
  )
    throw new Error("Backup is incomplete");
  let previous: string | null = null;
  let found: Copy | undefined;
  let objects = 0,
    bytes = 0;
  for (let page = 0; page < complete.value.pages; page++) {
    const record = await jsonRecord<Page>(backups, pageKey(day, page));
    if (!record || record.value.previous !== previous)
      throw new Error("Backup receipt chain is incomplete");
    previous = record.digest;
    for (const object of record.value.objects) {
      objects++;
      bytes += object.sizeBytes;
      if (object.key === sourceKey) {
        if (found) throw new Error("Backup contains a duplicate object");
        found = object;
      }
    }
  }
  if (
    previous !== complete.value.lastPageSha256 ||
    objects !== complete.value.objects ||
    bytes !== complete.value.bytes ||
    !found
  )
    throw new Error("Backup completion does not match its receipts");
  const data = await verifiedPart(
    backups,
    found.backupKey,
    found.sha256,
    found.sizeBytes,
  );
  const key = `restore-checks/${checkId}/${sourceKey}`;
  await immutable(destination, key, data, "application/octet-stream");
  return { key, sha256: found.sha256, sizeBytes: found.sizeBytes };
}

/** Calendar-year retention uses the database clock, not a caller-supplied date. */
export async function pruneAccessAudit(env: BackupEnvironment) {
  if (env.EVIDENCE_BACKUP_MODE !== "enabled") return;
  await env.EVIDENCE_DATABASE.prepare(
    "DELETE FROM vetting_evidence_audit WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 year')",
  ).run();
}

export default {
  fetch() {
    return new Response(null, { status: 404 });
  },
  async scheduled(event: { scheduledTime: number }, env: BackupEnvironment) {
    await startDailyBackup(env, event.scheduledTime);
    await pruneAccessAudit(env);
  },
  async queue(
    batch: { messages: { body: BackupJob; ack(): void; retry(): void }[] },
    env: BackupEnvironment,
  ) {
    for (const message of batch.messages) {
      try {
        await backupPage(env, message.body);
        message.ack();
      } catch {
        message.retry();
        console.error("Scanner evidence backup page failed");
      }
    }
  },
};
