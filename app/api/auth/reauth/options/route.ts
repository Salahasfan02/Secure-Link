import { NextResponse } from "next/server";
import { generateAuthenticationOptions } from "@simplewebauthn/server";
import { db } from "@/lib/server/db";
import { rpFromRequest, getSessionUser, storeChallenge } from "@/lib/server/session";

// Fresh biometric verification for an already-signed-in user —
// used by files sent with "require biometric on every open".
export async function POST(req: Request) {
  const user = await getSessionUser();
  if (!user) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const creds = db
    .prepare(`SELECT id, transports FROM credentials WHERE user_id = ?`)
    .all(user.id) as { id: string; transports: string }[];

  const { rpID } = rpFromRequest(req);
  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: "required",
    allowCredentials: creds.map((c) => ({
      id: c.id,
      transports: JSON.parse(c.transports ?? "[]"),
    })),
  });

  await storeChallenge("reauth", options.challenge, { userId: user.id });
  return NextResponse.json(options);
}
