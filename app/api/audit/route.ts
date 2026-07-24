import { NextResponse } from "next/server";
import { db } from "@/lib/server/db";
import { getSessionUser } from "@/lib/server/session";

export async function GET() {
  const me = await getSessionUser();
  if (!me) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const events = db
    .prepare(
      `SELECT a.event, a.detail, a.ip, a.user_agent, a.created_at, a.message_id, m.subject
       FROM audit a LEFT JOIN messages m ON m.id = a.message_id
       WHERE a.user_id = ? ORDER BY a.created_at DESC LIMIT 300`
    )
    .all(me.id);
  return NextResponse.json({ events });
}
