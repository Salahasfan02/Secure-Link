import { NextResponse } from "next/server";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { db, audit, now } from "@/lib/server/db";
import {
  rpFromRequest,
  requestMeta,
  getSessionUser,
  consumeChallenge,
  randomToken,
} from "@/lib/server/session";

const REAUTH_TTL_MS = 2 * 60 * 1000;

export async function POST(req: Request) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });
  const { ip, userAgent } = requestMeta(req);

  const { response } = (await req.json()) as { response: AuthenticationResponseJSON };
  const pending = await consumeChallenge("reauth");
  if (!pending || pending.userId !== user.id) {
    return NextResponse.json({ error: "Verification challenge expired." }, { status: 400 });
  }

  const cred = db
    .prepare(`SELECT * FROM credentials WHERE id = ? AND user_id = ?`)
    .get(response?.id, user.id) as
    | { id: string; public_key: Buffer; counter: number; transports: string }
    | undefined;
  if (!cred) {
    audit({ userId: user.id, event: "biometric_failed", detail: "Re-auth: unknown credential", ip, userAgent });
    return NextResponse.json({ error: "Biometric verification failed." }, { status: 401 });
  }

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
    audit({ userId: user.id, event: "biometric_failed", detail: `Re-auth: ${String(e)}`, ip, userAgent });
    return NextResponse.json({ error: "Biometric verification failed." }, { status: 401 });
  }
  if (!verification.verified) {
    audit({ userId: user.id, event: "biometric_failed", detail: "Re-auth rejected", ip, userAgent });
    return NextResponse.json({ error: "Biometric verification failed." }, { status: 401 });
  }

  db.prepare(`UPDATE credentials SET counter = ?, last_used_at = ? WHERE id = ?`).run(
    verification.authenticationInfo.newCounter,
    now(),
    cred.id
  );

  const token = randomToken();
  db.prepare(`DELETE FROM reauth_tokens WHERE expires_at < ?`).run(now());
  db.prepare(`INSERT INTO reauth_tokens (token, user_id, expires_at) VALUES (?, ?, ?)`).run(
    token,
    user.id,
    now() + REAUTH_TTL_MS
  );

  return NextResponse.json({ reauthToken: token });
}
