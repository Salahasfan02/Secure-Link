import { NextResponse } from "next/server";
import { db, audit, notify, now } from "@/lib/server/db";
import { getSessionUser, requestMeta } from "@/lib/server/session";
import { isExpired, purgeMessage, type MessageRow } from "@/lib/server/messages";

// Release the encrypted payload + the caller's wrapped key.
// Decryption happens ONLY on the client; this endpoint enforces
// access policy (expiry, one-time view, revocation, re-auth).
export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const me = await getSessionUser();
  if (!me) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const { id } = await params;
  const { ip, userAgent } = requestMeta(req);
  const body = (await req.json().catch(() => ({}))) as { reauthToken?: string };

  const m = db
    .prepare(
      `SELECT m.*, su.email as sender_email, ru.email as recipient_email
       FROM messages m JOIN users su ON su.id = m.sender_id JOIN users ru ON ru.id = m.recipient_id
       WHERE m.id = ?`
    )
    .get(id) as MessageRow | undefined;
  if (!m || (m.sender_id !== me.id && m.recipient_id !== me.id)) {
    return NextResponse.json({ error: "Not found." }, { status: 404 });
  }

  const isRecipient = m.recipient_id === me.id;
  const security = JSON.parse(m.security) as { requireBiometric?: boolean };

  if (m.revoked) {
    return NextResponse.json({ error: "The sender revoked access to this file." }, { status: 410 });
  }
  if (isExpired(m)) {
    if (!m.purged) {
      purgeMessage(id);
      notify(m.sender_id, "expired", "A file you sent has expired and was destroyed.", id);
      notify(m.recipient_id, "expired", "A file in your inbox expired and was destroyed.", id);
    }
    audit({ userId: me.id, messageId: id, event: "expired", detail: "Open attempt after expiry", ip, userAgent });
    return NextResponse.json({ error: "This file has expired and was destroyed." }, { status: 410 });
  }
  if (m.one_time && m.opened_at && isRecipient) {
    return NextResponse.json(
      { error: "One-time view already used. The file has been destroyed." },
      { status: 410 }
    );
  }
  if (m.purged) {
    return NextResponse.json({ error: "This file is no longer available." }, { status: 410 });
  }

  // "Require biometric on every open": demand a fresh assertion token.
  if (security.requireBiometric) {
    const valid =
      body.reauthToken &&
      db
        .prepare(`SELECT 1 FROM reauth_tokens WHERE token = ? AND user_id = ? AND expires_at > ?`)
        .get(body.reauthToken, me.id, now());
    if (!valid) {
      return NextResponse.json({ error: "reauth_required" }, { status: 403 });
    }
    db.prepare(`DELETE FROM reauth_tokens WHERE token = ?`).run(body.reauthToken!);
  }

  const rows = db
    .prepare(
      `SELECT id, filename, mime, size, iv, ciphertext, recipient_key, sender_key
       FROM attachments WHERE message_id = ?`
    )
    .all(id) as {
    id: string;
    filename: string;
    mime: string;
    size: number;
    iv: string;
    ciphertext: Buffer | null;
    recipient_key: string | null;
    sender_key: string | null;
  }[];

  const attachments = [];
  for (const a of rows) {
    const keyJson = isRecipient ? a.recipient_key : a.sender_key;
    if (!a.ciphertext || !keyJson) {
      return NextResponse.json({ error: "This file is no longer available." }, { status: 410 });
    }
    attachments.push({
      id: a.id,
      filename: a.filename,
      mime: a.mime,
      size: a.size,
      iv: a.iv,
      ciphertext: a.ciphertext.toString("base64"),
      wrappedKey: JSON.parse(keyJson),
    });
  }

  const bodyCipher = m.body_cipher ? JSON.parse(m.body_cipher) : null;

  if (isRecipient && m.sender_id !== m.recipient_id) {
    const firstOpen = !m.opened_at;
    db.prepare(`UPDATE messages SET opened_at = COALESCE(opened_at, ?) WHERE id = ?`).run(now(), id);
    audit({ userId: me.id, messageId: id, event: "opened", detail: `From ${m.sender_email}`, ip, userAgent });
    if (firstOpen) {
      notify(m.sender_id, "opened", `${m.recipient_email} opened your secure file`, id);
    }
    if (m.one_time) {
      // One-time view: destroy ciphertext + keys the moment it's served.
      purgeMessage(id);
      notify(m.sender_id, "one_time_done", `One-time view completed by ${m.recipient_email}`, id);
    }
  }

  return NextResponse.json({
    attachments,
    bodyCipher: bodyCipher ? (isRecipient ? bodyCipher.recipient : bodyCipher.sender) : null,
    role: isRecipient ? "recipient" : "sender",
  });
}
