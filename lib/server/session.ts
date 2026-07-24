import { cookies } from "next/headers";
import crypto from "crypto";
import { db, now } from "./db";

export const SESSION_COOKIE = "bv_session";
export const CHALLENGE_COOKIE = "bv_challenge";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // automatic session timeout: 12h
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

export interface SessionUser {
  id: string;
  email: string;
  display_name: string | null;
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function requestMeta(req: Request) {
  return {
    ip:
      req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
      req.headers.get("x-real-ip") ??
      "127.0.0.1",
    userAgent: req.headers.get("user-agent") ?? "unknown",
  };
}

export function rpFromRequest(req: Request) {
  const origin =
    req.headers.get("origin") ??
    `http://${req.headers.get("host") ?? "localhost:3000"}`;
  return { origin, rpID: new URL(origin).hostname };
}

export async function createSession(userId: string, req: Request): Promise<void> {
  const token = randomToken();
  const { ip, userAgent } = requestMeta(req);
  db.prepare(
    `INSERT INTO sessions (token, user_id, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)`
  ).run(token, userId, now(), now() + SESSION_TTL_MS, ip, userAgent);
  const store = await cookies();
  store.set(SESSION_COOKIE, token, {
    httpOnly: true,
    sameSite: "strict",
    path: "/",
    maxAge: SESSION_TTL_MS / 1000,
  });
}

export async function destroySession(): Promise<void> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE)?.value;
  if (token) db.prepare(`DELETE FROM sessions WHERE token = ?`).run(token);
  store.delete(SESSION_COOKIE);
}

export async function getSessionUser(): Promise<SessionUser | null> {
  const store = await cookies();
  const token = store.get(SESSION_COOKIE)?.value;
  if (!token) return null;
  const row = db
    .prepare(
      `SELECT u.id, u.email, u.display_name FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token = ? AND s.expires_at > ?`
    )
    .get(token, now()) as SessionUser | undefined;
  return row ?? null;
}

/** Persist a WebAuthn challenge and point a short-lived cookie at it. */
export async function storeChallenge(
  type: "register" | "login" | "reauth",
  challenge: string,
  opts: { email?: string; userId?: string }
): Promise<void> {
  const id = randomToken(16);
  db.prepare(`DELETE FROM challenges WHERE created_at < ?`).run(now() - CHALLENGE_TTL_MS);
  db.prepare(
    `INSERT INTO challenges (id, email, user_id, challenge, type, created_at) VALUES (?, ?, ?, ?, ?, ?)`
  ).run(id, opts.email ?? null, opts.userId ?? null, challenge, type, now());
  const store = await cookies();
  store.set(CHALLENGE_COOKIE, id, {
    httpOnly: true,
    sameSite: "strict",
    path: "/",
    maxAge: CHALLENGE_TTL_MS / 1000,
  });
}

export async function consumeChallenge(
  type: "register" | "login" | "reauth"
): Promise<{ email: string | null; userId: string | null; challenge: string } | null> {
  const store = await cookies();
  const id = store.get(CHALLENGE_COOKIE)?.value;
  if (!id) return null;
  const row = db
    .prepare(
      `SELECT email, user_id as userId, challenge FROM challenges
       WHERE id = ? AND type = ? AND created_at > ?`
    )
    .get(id, type, now() - CHALLENGE_TTL_MS) as
    | { email: string | null; userId: string | null; challenge: string }
    | undefined;
  db.prepare(`DELETE FROM challenges WHERE id = ?`).run(id);
  store.delete(CHALLENGE_COOKIE);
  return row ?? null;
}
