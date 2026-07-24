import { NextResponse } from "next/server";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { db, audit, notify, now } from "@/lib/server/db";
import {
  rpFromRequest,
  requestMeta,
  consumeChallenge,
  createSession,
} from "@/lib/server/session";
import { recordFailure, clearFailures, isLocked } from "@/lib/server/ratelimit";

export async function POST(req: Request) {
  const { ip, userAgent } = requestMeta(req);
  const { response } = (await req.json()) as { response: AuthenticationResponseJSON };

  const pending = await consumeChallenge("login");
  if (!pending?.userId || !pending.email) {
    return NextResponse.json({ error: "Login challenge expired. Try again." }, { status: 400 });
  }
  if (isLocked(pending.email)) {
    return NextResponse.json({ error: "Account temporarily locked." }, { status: 423 });
  }

  const cred = db
    .prepare(`SELECT * FROM credentials WHERE id = ? AND user_id = ?`)
    .get(response?.id, pending.userId) as
    | { id: string; user_id: string; public_key: Buffer; counter: number; transports: string }
    | undefined;

  const fail = (detail: string) => {
    recordFailure(pending.email!);
    audit({ userId: pending.userId, event: "login_failed", detail, ip, userAgent });
    return NextResponse.json({ error: "Biometric verification failed." }, { status: 401 });
  };

  if (!cred) return fail("Unknown credential");

  const { origin, rpID } = rpFromRequest(req);
  let verification;
  try {
    verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: pending.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
      credential: {
        id: cred.id,
        publicKey: new Uint8Array(cred.public_key),
        counter: cred.counter,
        transports: JSON.parse(cred.transports ?? "[]"),
      },
    });
  } catch (e) {
    return fail(String(e));
  }
  if (!verification.verified) return fail("Assertion rejected");

  // Replay protection: persist the authenticator's signature counter.
  db.prepare(`UPDATE credentials SET counter = ?, last_used_at = ? WHERE id = ?`).run(
    verification.authenticationInfo.newCounter,
    now(),
    cred.id
  );
  clearFailures(pending.email);

  // New-device heuristic: notify if this IP/UA pair hasn't been seen before.
  const seen = db
    .prepare(`SELECT 1 FROM sessions WHERE user_id = ? AND ip = ? AND user_agent = ? LIMIT 1`)
    .get(pending.userId, ip, userAgent);
  if (!seen) {
    notify(pending.userId, "new_device", `New sign-in from ${ip}`);
  }

  await createSession(pending.userId, req);
  audit({ userId: pending.userId, event: "login", detail: "Biometric sign-in", ip, userAgent });

  const user = db
    .prepare(`SELECT id, email, display_name FROM users WHERE id = ?`)
    .get(pending.userId);
  return NextResponse.json({ user });
}
