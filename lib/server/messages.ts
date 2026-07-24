import { db, audit, notify, now } from "./db";

export interface MessageRow {
  id: string;
  sender_id: string;
  recipient_id: string;
  subject: string | null;
  body_cipher: string | null;
  priority: string;
  tags: string | null;
  security: string;
  created_at: number;
  expires_at: number | null;
  one_time: number;
  opened_at: number | null;
  revoked: number;
  purged: number;
  recipient_trashed: number;
  sender_trashed: number;
  sender_email?: string;
  recipient_email?: string;
}

export function isExpired(m: MessageRow): boolean {
  return m.expires_at !== null && m.expires_at < now();
}

/** Destroy ciphertext and all wrapped keys — the file becomes permanently unreadable. */
export function purgeMessage(messageId: string): void {
  db.prepare(
    `UPDATE attachments SET ciphertext = NULL, recipient_key = NULL, sender_key = NULL WHERE message_id = ?`
  ).run(messageId);
  db.prepare(`UPDATE messages SET purged = 1, body_cipher = NULL WHERE id = ?`).run(messageId);
}

/** Lazily purge anything past its expiry, with an audit trail. */
export function sweepExpired(userId: string): void {
  const expired = db
    .prepare(
      `SELECT id, sender_id, recipient_id FROM messages
       WHERE purged = 0 AND expires_at IS NOT NULL AND expires_at < ?
         AND (sender_id = ? OR recipient_id = ?)`
    )
    .all(now(), userId, userId) as { id: string; sender_id: string; recipient_id: string }[];
  for (const m of expired) {
    purgeMessage(m.id);
    audit({ userId: m.recipient_id, messageId: m.id, event: "expired" });
    notify(m.sender_id, "expired", "A file you sent has expired and was destroyed.", m.id);
    notify(m.recipient_id, "expired", "A file in your inbox expired and was destroyed.", m.id);
  }
}

export function messageStatus(m: MessageRow): string {
  if (m.revoked) return "revoked";
  if (isExpired(m)) return "expired";
  if (m.one_time && m.opened_at) return "consumed";
  if (m.purged) return "destroyed";
  return "active";
}

export function toClientMeta(m: MessageRow, attachments: unknown[]) {
  return {
    id: m.id,
    senderEmail: m.sender_email,
    recipientEmail: m.recipient_email,
    subject: m.subject,
    priority: m.priority,
    tags: JSON.parse(m.tags ?? "[]"),
    security: JSON.parse(m.security),
    createdAt: m.created_at,
    expiresAt: m.expires_at,
    oneTime: !!m.one_time,
    openedAt: m.opened_at,
    status: messageStatus(m),
    attachments,
  };
}
