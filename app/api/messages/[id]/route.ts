import { NextResponse } from "next/server";
import { db, audit, notify } from "@/lib/server/db";
import { getSessionUser, requestMeta } from "@/lib/server/session";
import { purgeMessage, toClientMeta, type MessageRow } from "@/lib/server/messages";

function loadMessage(id: string): MessageRow | undefined {
  return db
    .prepare(
      `SELECT m.*, su.email as sender_email, ru.email as recipient_email
       FROM messages m
       JOIN users su ON su.id = m.sender_id
       JOIN users ru ON ru.id = m.recipient_id
       WHERE m.id = ?`
    )
    .get(id) as MessageRow | undefined;
}

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getSessionUser();
  if (!me) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const { id } = await params;
  const m = loadMessage(id);
  if (!m || (m.sender_id !== me.id && m.recipient_id !== me.id)) {
    return NextResponse.json({ error: "Not found." }, { status: 404 });
  }
  const attachments = db
    .prepare(`SELECT id, filename, mime, size FROM attachments WHERE message_id = ?`)
    .all(id);
  return NextResponse.json({ message: toClientMeta(m, attachments) });
}

export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getSessionUser();
  if (!me) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const { id } = await params;
  const { ip, userAgent } = requestMeta(req);
  const m = loadMessage(id);
  if (!m || (m.sender_id !== me.id && m.recipient_id !== me.id)) {
    return NextResponse.json({ error: "Not found." }, { status: 404 });
  }

  const isSelf = m.sender_id === m.recipient_id;

  if (m.sender_id === me.id && !m.revoked && !isSelf) {
    // Sender delete = secure revoke: destroy keys + ciphertext everywhere.
    db.prepare(`UPDATE messages SET revoked = 1, sender_trashed = 1 WHERE id = ?`).run(id);
    purgeMessage(id);
    audit({ userId: me.id, messageId: id, event: "revoked", detail: "Sender revoked access", ip, userAgent });
    notify(m.recipient_id, "revoked", `${m.sender_email} revoked a file they sent you`, id);
    return NextResponse.json({ ok: true, revoked: true });
  }

  const trashedFlag = m.recipient_id === me.id ? "recipient_trashed" : "sender_trashed";
  const alreadyTrashed = m.recipient_id === me.id ? m.recipient_trashed : m.sender_trashed;

  if (!alreadyTrashed && !m.revoked) {
    db.prepare(`UPDATE messages SET ${trashedFlag} = 1 WHERE id = ?`).run(id);
    audit({ userId: me.id, messageId: id, event: "deleted", detail: "Moved to trash", ip, userAgent });
    return NextResponse.json({ ok: true, trashed: true });
  }

  // Delete from trash: destroy this party's key material permanently.
  const keyColumn = m.recipient_id === me.id ? "recipient_key" : "sender_key";
  db.prepare(`UPDATE attachments SET ${keyColumn} = NULL WHERE message_id = ?`).run(id);
  db.prepare(`UPDATE messages SET ${trashedFlag} = 2 WHERE id = ?`).run(id);
  const other = db
    .prepare(
      `SELECT COUNT(*) as n FROM attachments WHERE message_id = ? AND (recipient_key IS NOT NULL OR sender_key IS NOT NULL)`
    )
    .get(id) as { n: number };
  if (other.n === 0) purgeMessage(id);
  audit({ userId: me.id, messageId: id, event: "deleted", detail: "Permanently deleted", ip, userAgent });
  return NextResponse.json({ ok: true, purged: true });
}
