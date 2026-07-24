import { NextResponse } from "next/server";
import { db } from "@/lib/server/db";
import { getSessionUser } from "@/lib/server/session";

// Directory lookup: find a recipient's E2E public key by email.
export async function GET(req: Request) {
  const me = await getSessionUser();
  if (!me) return NextResponse.json({ error: "Not signed in." }, { status: 401 });

  const email = new URL(req.url).searchParams.get("email")?.trim().toLowerCase();
  if (!email) return NextResponse.json({ error: "email query param required." }, { status: 400 });

  const row = db
    .prepare(
      `SELECT u.id, u.email, k.public_jwk FROM users u
       JOIN user_keys k ON k.user_id = u.id WHERE u.email = ?`
    )
    .get(email) as { id: string; email: string; public_jwk: string } | undefined;
  if (!row) {
    return NextResponse.json({ error: "No BioVault user found for this email." }, { status: 404 });
  }
  return NextResponse.json({ email: row.email, publicJwk: JSON.parse(row.public_jwk) });
}
