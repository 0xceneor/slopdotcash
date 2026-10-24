/** NOT-01 optional activity delivery; essential wallet notices do not use the activity preference. */
import type { SecurityD1Database } from "../../backend/security/handler";
import { encodeQuotedPrintable } from "./handler";
import { destinationDigest, recordDelivery } from "./security";

type VerifiedDestination = {
  email: string;
  verifiedAt: string;
  evidenceReference: string;
};
export type ActivityMailConfig = {
  inboxUrl: string;
  recipients: Record<string, VerifiedDestination>;
};
export type ActivityMailDependencies = {
  db: SecurityD1Database;
  moderatorGithubIds?: ReadonlySet<string>;
  config: ActivityMailConfig;
  fromAddress: string;
  now(): Date;
  sendEmail(from: string, to: string, mime: string): Promise<void>;
};
const EMAIL =
  /^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/u;
export function parseActivityMailConfig(
  raw: string | undefined,
): ActivityMailConfig | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as ActivityMailConfig;
    if (Object.keys(value).sort().join() !== "inboxUrl,recipients") return null;
    const url = new URL(value.inboxUrl);
    if (
      url.protocol !== "https:" ||
      url.pathname !== "/inbox" ||
      url.username ||
      url.password ||
      url.search ||
      url.hash
    )
      return null;
    if (
      !value.recipients ||
      typeof value.recipients !== "object" ||
      Array.isArray(value.recipients)
    )
      return null;
    for (const [id, destination] of Object.entries(value.recipients)) {
      if (
        !/^[1-9]\d{0,19}$/u.test(id) ||
        !destination ||
        Object.keys(destination).sort().join() !==
          "email,evidenceReference,verifiedAt"
      )
        return null;
      if (
        typeof destination.email !== "string" ||
        !EMAIL.test(destination.email) ||
        typeof destination.verifiedAt !== "string" ||
        new Date(destination.verifiedAt).toISOString() !==
          destination.verifiedAt ||
        typeof destination.evidenceReference !== "string" ||
        !destination.evidenceReference.trim()
      )
        return null;
    }
    return value;
  } catch {
    return null;
  }
}
export async function activityMailEligibility(
  config: ActivityMailConfig,
  githubId: string,
  now: Date,
) {
  const destination = config.recipients[githubId];
  if (!destination || Date.parse(destination.verifiedAt) > now.getTime())
    return { available: false } as const;
  return {
    available: true,
    email: destination.email,
    destinationVersion: await destinationDigest(destination),
  } as const;
}

type Delivery = {
  id: string;
  event_key: string;
  recipient_github_id: string;
  essential: number;
  destination_version: string | null;
  attempts: number;
};
export async function dispatchActivityMail(
  deps: ActivityMailDependencies,
): Promise<void> {
  if (!/^[a-z0-9][a-z0-9._-]*@slop\.cash$/u.test(deps.fromAddress))
    throw new Error("Invalid mail sender");
  const now = deps.now();
  const at = now.toISOString();
  await deps.db
    .prepare(
      "UPDATE activity_notification_outbox SET state='ambiguous',updated_at=? WHERE state='sending' AND claimed_at < ?",
    )
    .bind(at, new Date(now.getTime() - 300_000).toISOString())
    .run();
  const pending = await deps.db
    .prepare(
      "SELECT * FROM activity_notification_outbox WHERE state IN ('queued','retrying') AND next_attempt_at<=? ORDER BY created_at,id LIMIT 25",
    )
    .bind(at)
    .all<Delivery>();
  for (const row of pending.results ?? []) {
    const claim = await deps.db
      .prepare(
        "UPDATE activity_notification_outbox SET state='sending',claimed_at=?,updated_at=?,attempts=attempts+1 WHERE id=? AND state IN ('queued','retrying') AND next_attempt_at<=?",
      )
      .bind(at, at, row.id, at)
      .run();
    if (claim.meta?.changes !== 1) continue;
    if (row.event_key.startsWith("slopbot-appeal:")) {
      const appeal = await deps.db
        .prepare(
          "SELECT appellant_github_id, resolved_at FROM slopbot_appeals WHERE appeal_key = ? AND escalated_at IS NOT NULL",
        )
        .bind(row.event_key.slice("slopbot-".length))
        .first<{ appellant_github_id: string; resolved_at: string | null }>();
      if (
        !deps.moderatorGithubIds?.has(row.recipient_github_id) ||
        !appeal ||
        appeal.resolved_at !== null ||
        appeal.appellant_github_id === row.recipient_github_id
      ) {
        await recordDelivery(deps, row, "suppressed", null, "activity");
        continue;
      }
    }
    const destination = await activityMailEligibility(
      deps.config,
      row.recipient_github_id,
      now,
    );
    const preference = await deps.db
      .prepare(
        "SELECT enabled,destination_version FROM notification_email_preferences WHERE github_id=?",
      )
      .bind(row.recipient_github_id)
      .first<{ enabled: number; destination_version: string | null }>();
    if (
      !destination.available ||
      (!row.essential &&
        (preference?.enabled !== 1 ||
          preference.destination_version !== destination.destinationVersion ||
          row.destination_version !== destination.destinationVersion))
    ) {
      await recordDelivery(deps, row, "suppressed", null, "activity");
      continue;
    }
    // Recipient and consent are resolved on the server immediately before this one-recipient send.
    await deps.db
      .prepare(
        "UPDATE activity_notification_outbox SET destination_digest=? WHERE id=?",
      )
      .bind(destination.destinationVersion, row.id)
      .run();
    const text = row.essential
      ? "Your Slop account has a security notice."
      : "Your Slop inbox has an activity update.";
    const mime = [
      `From: ${deps.fromAddress}`,
      `To: ${destination.email}`,
      "Subject: Slop inbox notice",
      `Date: ${now.toUTCString()}`,
      `Message-ID: <slop-notice-${row.id}-${row.attempts + 1}@slop.cash>`,
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: quoted-printable",
      "",
      encodeQuotedPrintable(
        `${text}\n\nSign in: ${deps.config.inboxUrl}\n\nDo not reply with approvals, evidence or payment details.\n`,
      ),
    ].join("\r\n");
    try {
      await deps.sendEmail(deps.fromAddress, destination.email, mime);
    } catch {
      await recordDelivery(deps, row, "ambiguous", null, "activity");
      continue;
    }
    await recordDelivery(deps, row, "provider-accepted", null, "activity");
  }
}
