import { NextResponse } from "next/server";
import { destroySession, getSessionUser, requestMeta } from "@/lib/server/session";
import { audit } from "@/lib/server/db";

export async function POST(req: Request) {
  const user = await getSessionUser();
  const { ip, userAgent } = requestMeta(req);
  if (user) audit({ userId: user.id, event: "logout", ip, userAgent });
  await destroySession();
  return NextResponse.json({ ok: true });
}
