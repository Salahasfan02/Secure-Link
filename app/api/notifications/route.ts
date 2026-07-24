import { NextResponse } from "next/server";
import { db } from "@/lib/server/db";
import { getSessionUser } from "@/lib/server/session";

export async function GET() {
  const me = await getSessionUser();
  if (!me) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const notifications = db
    .prepare(
      `SELECT id, type, text, message_id, read, created_at FROM notifications
       WHERE user_id = ? ORDER BY created_at DESC LIMIT 50`
    )
    .all(me.id);
  return NextResponse.json({ notifications });
}

export async function POST() {
  const me = await getSessionUser();
  if (!me) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  db.prepare(`UPDATE notifications SET read = 1 WHERE user_id = ?`).run(me.id);
  return NextResponse.json({ ok: true });
}
