import { NextResponse } from "next/server";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { db } from "@/lib/server/db";
import { rpFromRequest, requestMeta, storeChallenge } from "@/lib/server/session";
import { rateLimit, isLocked } from "@/lib/server/ratelimit";

export async function POST(req: Request) {
  const { ip } = requestMeta(req);
  if (!rateLimit(`login:${ip}`, 15, 60_000)) {
    return NextResponse.json({ error: "Too many attempts. Try again shortly." }, { status: 429 });
  }

  const { email } = (await req.json()) as { email?: string };
  const normalized = email?.trim().toLowerCase();
  if (!normalized) {
    return NextResponse.json({ error: "Email is required." }, { status: 400 });
  }
  if (isLocked(normalized)) {
    return NextResponse.json(
      { error: "Account temporarily locked after repeated failed attempts. Try again in 15 minutes." },
      { status: 423 }
    );
  }

  const user = db.prepare(`SELECT id FROM users WHERE email = ?`).get(normalized) as
    | { id: string }
    | undefined;
  const creds = user
    ? (db.prepare(`SELECT id, transports FROM credentials WHERE user_id = ?`).all(user.id) as {
        id: string;
        transports: string;
      }[])
    : [];
  if (!user || creds.length === 0) {
    return NextResponse.json({ error: "No account found for this email." }, { status: 404 });
  }

  const { rpID } = rpFromRequest(req);
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: "required",
    allowCredentials: creds.map((c) => ({
      id: c.id,
      transports: JSON.parse(c.transports ?? "[]"),
    })),
  });

  await storeChallenge("login", options.challenge, { email: normalized, userId: user.id });
  return NextResponse.json(options);
}
