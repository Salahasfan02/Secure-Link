import { NextResponse } from "next/server";
import { db, audit, notify, now } from "@/lib/server/db";
import { getSessionUser, requestMeta, randomToken } from "@/lib/server/session";
import { rateLimit } from "@/lib/server/ratelimit";
import { sweepExpired, toClientMeta, type MessageRow } from "@/lib/server/messages";

const MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024;

interface WrappedKey {
  ephPub: JsonWebKey;
  iv: string;
  wrapped: string;
}

interface AttachmentPayload {
  filename: string;
  mime: string;
  size: number;
  iv: string;
  ciphertext: string; // base64
  recipientKey: WrappedKey;
  senderKey: WrappedKey;
}

interface SendPayload {
  recipientEmail: string;
  subject?: string;
  bodyCipher?: { recipient: WrappedKey & { ct: string }; sender: WrappedKey & { ct: string } };
  priority?: string;
  tags?: string[];
  security: {
    oneTime?: boolean;
    downloadProtection?: boolean;
    watermark?: boolean;
    requireBiometric?: boolean;
    screenshotWarn?: boolean;
  };
  expiresAt?: number | null;
  attachments: AttachmentPayload[];
}

export async function POST(req: Request) {
  const me = await getSessionUser();
  if (!me) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const { ip, userAgent } = requestMeta(req);
  if (!rateLimit(`send:${me.id}`, 30, 60_000)) {
    return NextResponse.json({ error: "Sending too fast. Slow down." }, { status: 429 });
  }

  const p = (await req.json()) as SendPayload;
  const recipientEmail = p.recipientEmail?.trim().toLowerCase();
  if (!recipientEmail) {
    return NextResponse.json({ error: "Recipient email is required." }, { status: 400 });
  }
  const recipient = db.prepare(`SELECT id, email FROM users WHERE email = ?`).get(recipientEmail) as
    | { id: string; email: string }
    | undefined;
  if (!recipient) {
    return NextResponse.json({ error: "Recipient is not a BioVault user." }, { status: 404 });
  }
  if (!Array.isArray(p.attachments)) {
    return NextResponse.json({ error: "Attachments are required." }, { status: 400 });
  }
  for (const a of p.attachments) {
    if (!a.filename || !a.iv || !a.ciphertext || !a.recipientKey || !a.senderKey) {
      return NextResponse.json({ error: "Malformed encrypted attachment." }, { status: 400 });
    }
    if (a.size > MAX_ATTACHMENT_BYTES) {
      return NextResponse.json({ error: "Attachments are limited to 25 MB each." }, { status: 413 });
    }
  }
  if (p.expiresAt && p.expiresAt <= now()) {
    return NextResponse.json({ error: "Expiration must be in the future." }, { status: 400 });
  }

  const id = randomToken(12);
  const insertMessage = db.prepare(
    `INSERT INTO messages (id, sender_id, recipient_id, subject, body_cipher, priority, tags, security, created_at, expires_at, one_time)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  const insertAttachment = db.prepare(
    `INSERT INTO attachments (id, message_id, filename, mime, size, iv, ciphertext, recipient_key, sender_key)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  db.transaction(() => {
    insertMessage.run(
      id,
      me.id,
      recipient.id,
      p.subject ?? null,
      p.bodyCipher ? JSON.stringify(p.bodyCipher) : null,
      p.priority ?? "normal",
      JSON.stringify(p.tags ?? []),
      JSON.stringify(p.security ?? {}),
      now(),
      p.expiresAt ?? null,
      p.security?.oneTime ? 1 : 0
    );
    for (const a of p.attachments) {
      insertAttachment.run(
        randomToken(12),
        id,
        a.filename,
        a.mime || "application/octet-stream",
        a.size,
        a.iv,
        Buffer.from(a.ciphertext, "base64"),
        JSON.stringify(a.recipientKey),
        JSON.stringify(a.senderKey)
      );
    }
  })();

  audit({ userId: me.id, messageId: id, event: "sent", detail: `To ${recipient.email}`, ip, userAgent });
  if (recipient.id !== me.id) {
    notify(recipient.id, "delivered", `${me.email} sent you a secure file`, id);
  }
  return NextResponse.json({ id });
}

export async function GET(req: Request) {
  const me = await getSessionUser();
  if (!me) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  sweepExpired(me.id);

  const box = new URL(req.url).searchParams.get("box") ?? "inbox";
  let where: string;
  const params: (string | number)[] = [];
  switch (box) {
    case "inbox":
      where = `m.recipient_id = ? AND m.recipient_trashed = 0 AND m.revoked = 0 AND m.sender_id != m.recipient_id`;
      params.push(me.id);
      break;
    case "sent":
      where = `m.sender_id = ? AND m.sender_trashed = 0 AND m.sender_id != m.recipient_id`;
      params.push(me.id);
      break;
    case "vault":
      where = `m.sender_id = ? AND m.recipient_id = ? AND m.sender_trashed = 0`;
      params.push(me.id, me.id);
      break;
    case "trash":
      where = `((m.recipient_id = ? AND m.recipient_trashed = 1) OR (m.sender_id = ? AND m.sender_trashed = 1) OR (m.recipient_id = ? AND m.revoked = 1 AND m.recipient_trashed = 0))`;
      params.push(me.id, me.id, me.id);
      break;
    default:
      return NextResponse.json({ error: "Unknown box." }, { status: 400 });
  }

  const rows = db
    .prepare(
      `SELECT m.*, su.email as sender_email, ru.email as recipient_email
       FROM messages m
       JOIN users su ON su.id = m.sender_id
       JOIN users ru ON ru.id = m.recipient_id
       WHERE ${where}
       ORDER BY m.created_at DESC LIMIT 200`
    )
    .all(...params) as MessageRow[];

  const attachmentsFor = db.prepare(
    `SELECT id, filename, mime, size FROM attachments WHERE message_id = ?`
  );
  return NextResponse.json({
    messages: rows.map((m) => toClientMeta(m, attachmentsFor.all(m.id))),
  });
}
