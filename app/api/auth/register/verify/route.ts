import { NextResponse } from "next/server";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { db, audit, now } from "@/lib/server/db";
import {
  rpFromRequest,
  requestMeta,
  consumeChallenge,
  createSession,
  randomToken,
} from "@/lib/server/session";

interface Body {
  response: RegistrationResponseJSON;
  publicJwk: JsonWebKey; // user's E2E ECDH public key, generated client-side
  deviceName?: string;
}

export async function POST(req: Request) {
  const { ip, userAgent } = requestMeta(req);
  const body = (await req.json()) as Body;
  if (!body?.response || !body?.publicJwk) {
    return NextResponse.json({ error: "Missing registration data." }, { status: 400 });
  }

  const pending = await consumeChallenge("register");
  if (!pending?.email) {
    return NextResponse.json({ error: "Registration challenge expired. Try again." }, { status: 400 });
  }

  const { origin, rpID } = rpFromRequest(req);
  let verification;
  try {
    verification = await verifyRegistrationResponse({
      response: body.response,
      expectedChallenge: pending.challenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (e) {
    audit({ event: "register_failed", detail: `${pending.email}: ${String(e)}`, ip, userAgent });
    return NextResponse.json({ error: "Biometric registration could not be verified." }, { status: 400 });
  }
  if (!verification.verified || !verification.registrationInfo) {
    return NextResponse.json({ error: "Biometric registration could not be verified." }, { status: 400 });
  }

  const { credential } = verification.registrationInfo;

  let user = db.prepare(`SELECT id FROM users WHERE email = ?`).get(pending.email) as
    | { id: string }
    | undefined;
  if (!user) {
    const id = randomToken(12);
    db.prepare(`INSERT INTO users (id, email, created_at) VALUES (?, ?, ?)`).run(
      id,
      pending.email,
      now()
    );
    user = { id };
  }

  db.prepare(
    `INSERT OR REPLACE INTO credentials (id, user_id, public_key, counter, transports, device_name, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    credential.id,
    user.id,
    Buffer.from(credential.publicKey),
    credential.counter,
    JSON.stringify(credential.transports ?? []),
    body.deviceName ?? userAgent.slice(0, 120),
    now()
  );

  // Publish the user's E2E *public* key. The private key never left their device.
  db.prepare(`INSERT OR REPLACE INTO user_keys (user_id, public_jwk) VALUES (?, ?)`).run(
    user.id,
    JSON.stringify(body.publicJwk)
  );

  await createSession(user.id, req);
  audit({ userId: user.id, event: "register", detail: "Account created with passkey", ip, userAgent });

  return NextResponse.json({ user: { id: user.id, email: pending.email } });
}
