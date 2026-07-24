import Database from "better-sqlite3";
import path from "path";
import fs from "fs";

function createDb(): Database.Database {
  const dataDir = path.join(process.cwd(), "data");
  fs.mkdirSync(dataDir, { recursive: true });
  const db = new Database(path.join(dataDir, "biovault.db"));
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      display_name TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,               -- base64url credential id
      user_id TEXT NOT NULL REFERENCES users(id),
      public_key BLOB NOT NULL,          -- COSE public key
      counter INTEGER NOT NULL DEFAULT 0,
      transports TEXT,                   -- JSON array
      device_name TEXT,
      created_at INTEGER NOT NULL,
      last_used_at INTEGER
    );

    -- E2E key directory: only PUBLIC keys ever reach the server.
    CREATE TABLE IF NOT EXISTS user_keys (
      user_id TEXT PRIMARY KEY REFERENCES users(id),
      public_jwk TEXT NOT NULL           -- ECDH P-256 public key (JWK)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      ip TEXT,
      user_agent TEXT
    );

    -- Pending WebAuthn challenges (registration / login / re-auth)
    CREATE TABLE IF NOT EXISTS challenges (
      id TEXT PRIMARY KEY,
      email TEXT,
      user_id TEXT,
      challenge TEXT NOT NULL,
      type TEXT NOT NULL,                -- 'register' | 'login' | 'reauth'
      created_at INTEGER NOT NULL
    );

    -- Short-lived tokens proving a fresh biometric assertion (for
    -- files sent with "require biometric verification on every open").
    CREATE TABLE IF NOT EXISTS reauth_tokens (
      token TEXT PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES users(id),
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      sender_id TEXT NOT NULL REFERENCES users(id),
      recipient_id TEXT NOT NULL REFERENCES users(id),
      subject TEXT,
      body_cipher TEXT,                  -- E2E encrypted message body (JSON envelope)
      priority TEXT DEFAULT 'normal',
      tags TEXT,                         -- JSON array
      security TEXT NOT NULL,            -- JSON: oneTime, downloadProtection, watermark, requireBiometric, screenshotWarn
      created_at INTEGER NOT NULL,
      expires_at INTEGER,
      one_time INTEGER NOT NULL DEFAULT 0,
      opened_at INTEGER,
      revoked INTEGER NOT NULL DEFAULT 0,
      purged INTEGER NOT NULL DEFAULT 0, -- ciphertext + keys destroyed
      recipient_trashed INTEGER NOT NULL DEFAULT 0,
      sender_trashed INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS attachments (
      id TEXT PRIMARY KEY,
      message_id TEXT NOT NULL REFERENCES messages(id),
      filename TEXT NOT NULL,
      mime TEXT NOT NULL,
      size INTEGER NOT NULL,
      iv TEXT,                           -- base64 AES-GCM IV for the file
      ciphertext BLOB,                   -- AES-256-GCM encrypted bytes (nulled on purge)
      recipient_key TEXT,                -- JSON: { ephPub, iv, wrapped } wrapped for recipient
      sender_key TEXT                    -- same, wrapped for sender (Sent-box access)
    );

    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      message_id TEXT,
      event TEXT NOT NULL,
      detail TEXT,
      ip TEXT,
      user_agent TEXT,
      created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL REFERENCES users(id),
      type TEXT NOT NULL,
      text TEXT NOT NULL,
      message_id TEXT,
      read INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id);
    CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(user_id);
    CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
  `);
  return db;
}

// Survive Next.js dev-server HMR without reopening the database.
const globalForDb = globalThis as unknown as { __biovaultDb?: Database.Database };
export const db: Database.Database = globalForDb.__biovaultDb ?? createDb();
globalForDb.__biovaultDb = db;

export function now(): number {
  return Date.now();
}

export function audit(entry: {
  userId?: string | null;
  messageId?: string | null;
  event: string;
  detail?: string;
  ip?: string | null;
  userAgent?: string | null;
}) {
  db.prepare(
    `INSERT INTO audit (user_id, message_id, event, detail, ip, user_agent, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    entry.userId ?? null,
    entry.messageId ?? null,
    entry.event,
    entry.detail ?? null,
    entry.ip ?? null,
    entry.userAgent ?? null,
    now()
  );
}

export function notify(userId: string, type: string, text: string, messageId?: string) {
  db.prepare(
    `INSERT INTO notifications (user_id, type, text, message_id, created_at) VALUES (?, ?, ?, ?, ?)`
  ).run(userId, type, text, messageId ?? null, now());
}
