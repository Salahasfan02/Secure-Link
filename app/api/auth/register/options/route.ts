import { NextResponse } from "next/server";
import { generateRegistrationOptions } from "@simplewebauthn/server";
import { db } from "@/lib/server/db";
import { rpFromRequest, requestMeta, storeChallenge } from "@/lib/server/session";
import { rateLimit } from "@/lib/server/ratelimit";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export async function POST(req: Request) {
  const { ip } = requestMeta(req);
  if (!rateLimit(`register:${ip}`, 10, 60_000)) {
    return NextResponse.json({ error: "Too many attempts. Try again shortly." }, { status: 429 });
  }

  const { email } = (await req.json()) as { email?: string };
  if (!email || !EMAIL_RE.test(email)) {
    return NextResponse.json({ error: "A valid email address is required." }, { status: 400 });
  }
  const normalized = email.trim().toLowerCase();

  const existing = db
    .prepare(
      `SELECT u.id, COUNT(c.id) as creds FROM users u
       LEFT JOIN credentials c ON c.user_id = u.id
       WHERE u.email = ? GROUP BY u.id`
    )
    .get(normalized) as { id: string; creds: number } | undefined;
  if (existing && existing.creds > 0) {
    return NextResponse.json(
      { error: "An account with this email already exists. Sign in instead." },
      { status: 409 }
    );
  }

  const { rpID } = rpFromRequest(req);
  const options = await generateRegistrationOptions({
    rpName: "BioVault",
    rpID,
    userName: normalized,
    attestationType: "none",
    authenticatorSelection: {
      // Platform authenticator = the device's own biometrics
      // (Touch ID / Face ID / Windows Hello / Android Biometrics).
      authenticatorAttachment: "platform",
      residentKey: "preferred",
      userVerification: "required",
    },
  });

  await storeChallenge("register", options.challenge, { email: normalized });
  return NextResponse.json(options);
}
