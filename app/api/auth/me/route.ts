import { NextResponse } from "next/server";
import { getSessionUser } from "@/lib/server/session";
import { db } from "@/lib/server/db";

export async function GET() {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ user: null }, { status: 401 });
  const key = db.prepare(`SELECT public_jwk FROM user_keys WHERE user_id = ?`).get(user.id) as
    | { public_jwk: string }
    | undefined;
  return NextResponse.json({
    user,
    publicJwk: key ? JSON.parse(key.public_jwk) : null,
  });
}
