// BioVault end-to-end test.
// Simulates a WebAuthn platform authenticator (real P-256 signatures,
// 'none' attestation) and replicates the client's Web Crypto E2E layer,
// then drives every server flow against a running dev server.
//
// Usage: node scripts/e2e-test.mjs [baseUrl]

import crypto from "crypto";

const BASE = process.argv[2] ?? "http://localhost:3100";
const RP_ID = new URL(BASE).hostname;
const subtle = globalThis.crypto.subtle;

// ---------- minimal CBOR encoder (enough for WebAuthn structures) ----------
function cborEncode(value) {
  const chunks = [];
  encodeItem(value, chunks);
  return Buffer.concat(chunks);
}
function head(major, len) {
  if (len < 24) return Buffer.from([(major << 5) | len]);
  if (len < 0x100) return Buffer.from([(major << 5) | 24, len]);
  if (len < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(len, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(len, 1);
  return b;
}
function encodeItem(v, out) {
  if (typeof v === "number" && Number.isInteger(v)) {
    if (v >= 0) out.push(head(0, v));
    else out.push(head(1, -v - 1));
  } else if (v instanceof Buffer || v instanceof Uint8Array) {
    const buf = Buffer.from(v);
    out.push(head(2, buf.length), buf);
  } else if (typeof v === "string") {
    const buf = Buffer.from(v, "utf8");
    out.push(head(3, buf.length), buf);
  } else if (v instanceof Map) {
    out.push(head(5, v.size));
    for (const [k, val] of v) {
      encodeItem(k, out);
      encodeItem(val, out);
    }
  } else if (v && typeof v === "object") {
    const keys = Object.keys(v);
    out.push(head(5, keys.length));
    for (const k of keys) {
      encodeItem(k, out);
      encodeItem(v[k], out);
    }
  } else {
    throw new Error(`cbor: unsupported ${typeof v}`);
  }
}

// ---------- fake platform authenticator ----------
function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

class FakeAuthenticator {
  constructor() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
      namedCurve: "P-256",
    });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    this.x = Buffer.from(jwk.x, "base64url");
    this.y = Buffer.from(jwk.y, "base64url");
    this.credId = crypto.randomBytes(32);
  }

  attestation(challenge, origin) {
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false })
    );
    const rpIdHash = crypto.createHash("sha256").update(RP_ID).digest();
    const cosePub = cborEncode(
      new Map([
        [1, 2], // kty EC2
        [3, -7], // alg ES256
        [-1, 1], // crv P-256
        [-2, this.x],
        [-3, this.y],
      ])
    );
    const authData = Buffer.concat([
      rpIdHash,
      Buffer.from([0x45]), // UP | UV | AT
      Buffer.alloc(4), // counter 0
      Buffer.alloc(16), // AAGUID
      Buffer.from([this.credId.length >> 8, this.credId.length & 0xff]),
      this.credId,
      cosePub,
    ]);
    const attestationObject = cborEncode({ fmt: "none", attStmt: {}, authData });
    return {
      id: b64url(this.credId),
      rawId: b64url(this.credId),
      type: "public-key",
      clientExtensionResults: {},
      authenticatorAttachment: "platform",
      response: {
        clientDataJSON: b64url(clientDataJSON),
        attestationObject: b64url(attestationObject),
        transports: ["internal"],
      },
    };
  }

  assertion(challenge, origin, { corrupt = false } = {}) {
    const clientDataJSON = Buffer.from(
      JSON.stringify({ type: "webauthn.get", challenge, origin, crossOrigin: false })
    );
    const rpIdHash = crypto.createHash("sha256").update(RP_ID).digest();
    const authData = Buffer.concat([rpIdHash, Buffer.from([0x05]), Buffer.alloc(4)]);
    const hash = crypto.createHash("sha256").update(clientDataJSON).digest();
    let signature = crypto
      .createSign("SHA256")
      .update(Buffer.concat([authData, hash]))
      .sign(this.privateKey);
    if (corrupt) signature[signature.length - 1] ^= 0xff;
    return {
      id: b64url(this.credId),
      rawId: b64url(this.credId),
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
        userHandle: null,
      },
    };
  }
}

// ---------- E2E crypto (mirrors lib/client/crypto.ts) ----------
async function generateIdentity() {
  const pair = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
    "deriveKey",
  ]);
  return { privateKey: pair.privateKey, publicJwk: await subtle.exportKey("jwk", pair.publicKey) };
}

async function deriveKek(privateKey, publicJwk) {
  const pub = await subtle.importKey(
    "jwk",
    publicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const shared = await subtle.deriveBits({ name: "ECDH", public: pub }, privateKey, 256);
  const hkdf = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode("biovault-file-key-wrap-v1"),
    },
    hkdf,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function wrapFor(rawKey, partyPubJwk) {
  const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
    "deriveKey",
  ]);
  const kek = await deriveKek(eph.privateKey, partyPubJwk);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await subtle.encrypt({ name: "AES-GCM", iv }, kek, rawKey);
  return {
    ephPub: await subtle.exportKey("jwk", eph.publicKey),
    iv: Buffer.from(iv).toString("base64"),
    wrapped: Buffer.from(wrapped).toString("base64"),
  };
}

async function encryptFile(data, recipientJwk, senderJwk) {
  const fileKey = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await subtle.encrypt({ name: "AES-GCM", iv }, fileKey, data);
  const raw = await subtle.exportKey("raw", fileKey);
  return {
    iv: Buffer.from(iv).toString("base64"),
    ciphertext: Buffer.from(ciphertext).toString("base64"),
    recipientKey: await wrapFor(raw, recipientJwk),
    senderKey: await wrapFor(raw, senderJwk),
  };
}

async function decryptFile(privateKey, { iv, ciphertext, wrappedKey }) {
  const kek = await deriveKek(privateKey, wrappedKey.ephPub);
  const raw = await subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(wrappedKey.iv, "base64") },
    kek,
    Buffer.from(wrappedKey.wrapped, "base64")
  );
  const fileKey = await subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
  const plain = await subtle.decrypt(
    { name: "AES-GCM", iv: Buffer.from(iv, "base64") },
    fileKey,
    Buffer.from(ciphertext, "base64")
  );
  return Buffer.from(plain);
}

// ---------- HTTP client with a cookie jar ----------
class Client {
  constructor() {
    this.cookies = new Map();
  }
  header() {
    return [...this.cookies.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }
  async call(path, { method = "GET", body } = {}) {
    const res = await fetch(`${BASE}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        Cookie: this.header(),
        Origin: BASE,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const sc of res.headers.getSetCookie?.() ?? []) {
      const [pair] = sc.split(";");
      const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      if (value) this.cookies.set(name, value);
      else this.cookies.delete(name);
    }
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
  }
}

// ---------- test harness ----------
let passed = 0;
let failed = 0;
function check(name, cond, extra = "") {
  if (cond) {
    passed++;
    console.log(`  ✓ ${name}`);
  } else {
    failed++;
    console.log(`  ✗ ${name} ${extra}`);
  }
}

async function registerUser(email) {
  const client = new Client();
  const auth = new FakeAuthenticator();
  const identity = await generateIdentity();

  const opts = await client.call("/api/auth/register/options", {
    method: "POST",
    body: { email },
  });
  if (opts.status !== 200) throw new Error(`register options: ${JSON.stringify(opts.data)}`);
  const verify = await client.call("/api/auth/register/verify", {
    method: "POST",
    body: {
      response: auth.attestation(opts.data.challenge, BASE),
      publicJwk: identity.publicJwk,
    },
  });
  if (verify.status !== 200) throw new Error(`register verify: ${JSON.stringify(verify.data)}`);
  return { email, client, auth, identity };
}

async function login(user) {
  const opts = await user.client.call("/api/auth/login/options", {
    method: "POST",
    body: { email: user.email },
  });
  if (opts.status !== 200) return opts;
  return user.client.call("/api/auth/login/verify", {
    method: "POST",
    body: { response: user.auth.assertion(opts.data.challenge, BASE) },
  });
}

async function sendFile(from, to, content, { subject, security = {}, expiresAt = null } = {}) {
  const dir = await from.client.call(`/api/users?email=${encodeURIComponent(to.email)}`);
  const enc = await encryptFile(Buffer.from(content), dir.data.publicJwk, from.identity.publicJwk);
  return from.client.call("/api/messages", {
    method: "POST",
    body: {
      recipientEmail: to.email,
      subject,
      security,
      expiresAt,
      attachments: [
        {
          filename: "secret.txt",
          mime: "text/plain",
          size: content.length,
          ...enc,
        },
      ],
    },
  });
}

const run = async () => {
  const suffix = Date.now().toString(36);
  console.log(`\nBioVault E2E test against ${BASE}\n`);

  console.log("Registration & login");
  const alice = await registerUser(`alice-${suffix}@test.dev`);
  const bob = await registerUser(`bob-${suffix}@test.dev`);
  check("register two users with simulated biometrics", true);

  const me = await alice.client.call("/api/auth/me");
  check("session established after registration", me.status === 200 && !!me.data.user);

  alice.client.cookies.delete("bv_session");
  const relogin = await login(alice);
  check("biometric re-login works", relogin.status === 200, JSON.stringify(relogin.data));

  // failed biometric: corrupt signature
  const badOpts = await alice.client.call("/api/auth/login/options", {
    method: "POST",
    body: { email: alice.email },
  });
  const badVerify = await alice.client.call("/api/auth/login/verify", {
    method: "POST",
    body: { response: alice.auth.assertion(badOpts.data.challenge, BASE, { corrupt: true }) },
  });
  check("corrupted biometric signature is rejected", badVerify.status === 401);
  await login(alice); // restore session

  console.log("\nBasic E2E file transfer");
  const secret = `TOP SECRET ${suffix} — for alice only`;
  const sent = await sendFile(bob, alice, secret, { subject: "Quarterly report" });
  check("bob sends encrypted file", sent.status === 200, JSON.stringify(sent.data));

  const inbox = await alice.client.call("/api/messages?box=inbox");
  const msg = inbox.data.messages?.find((m) => m.id === sent.data.id);
  check("file appears in alice's inbox", !!msg);

  const opened = await alice.client.call(`/api/messages/${sent.data.id}/open`, {
    method: "POST",
    body: {},
  });
  check("alice can open", opened.status === 200, JSON.stringify(opened.data));
  const plain = await decryptFile(alice.identity.privateKey, opened.data.attachments[0]);
  check("decrypted content matches original", plain.toString() === secret);

  const bobOpen = await bob.client.call(`/api/messages/${sent.data.id}/open`, {
    method: "POST",
    body: {},
  });
  const bobPlain = await decryptFile(bob.identity.privateKey, bobOpen.data.attachments[0]);
  check("sender can read own sent copy (sender-wrapped key)", bobPlain.toString() === secret);

  console.log("\nOne-time view");
  const once = await sendFile(bob, alice, "burn after reading", {
    subject: "One-time",
    security: { oneTime: true },
  });
  const firstOpen = await alice.client.call(`/api/messages/${once.data.id}/open`, {
    method: "POST",
    body: {},
  });
  check("first open succeeds", firstOpen.status === 200);
  const secondOpen = await alice.client.call(`/api/messages/${once.data.id}/open`, {
    method: "POST",
    body: {},
  });
  check("second open is refused (keys destroyed)", secondOpen.status === 410);

  console.log("\nSender revocation");
  const rev = await sendFile(bob, alice, "to be revoked", { subject: "Revocable" });
  const revoke = await bob.client.call(`/api/messages/${rev.data.id}`, { method: "DELETE" });
  check("sender revokes", revoke.status === 200 && revoke.data.revoked === true);
  const afterRevoke = await alice.client.call(`/api/messages/${rev.data.id}/open`, {
    method: "POST",
    body: {},
  });
  check("recipient locked out after revocation", afterRevoke.status === 410);

  console.log("\nRequire biometric on every open");
  const bio = await sendFile(bob, alice, "biometric-locked", {
    subject: "Bio-locked",
    security: { requireBiometric: true },
  });
  const noToken = await alice.client.call(`/api/messages/${bio.data.id}/open`, {
    method: "POST",
    body: {},
  });
  check("open without fresh biometric is refused", noToken.status === 403 && noToken.data.error === "reauth_required");

  const reOpts = await alice.client.call("/api/auth/reauth/options", { method: "POST", body: {} });
  const reVerify = await alice.client.call("/api/auth/reauth/verify", {
    method: "POST",
    body: { response: alice.auth.assertion(reOpts.data.challenge, BASE) },
  });
  check("fresh biometric assertion issues token", reVerify.status === 200 && !!reVerify.data.reauthToken);

  const withToken = await alice.client.call(`/api/messages/${bio.data.id}/open`, {
    method: "POST",
    body: { reauthToken: reVerify.data.reauthToken },
  });
  check("open succeeds with fresh biometric token", withToken.status === 200);

  const reuse = await alice.client.call(`/api/messages/${bio.data.id}/open`, {
    method: "POST",
    body: { reauthToken: reVerify.data.reauthToken },
  });
  check("reauth token is single-use (replay prevention)", reuse.status === 403);

  console.log("\nExpiration");
  const exp = await sendFile(bob, alice, "expires fast", {
    subject: "Expiring",
    expiresAt: Date.now() + 1200,
  });
  await new Promise((r) => setTimeout(r, 1600));
  const afterExpiry = await alice.client.call(`/api/messages/${exp.data.id}/open`, {
    method: "POST",
    body: {},
  });
  check("expired file is unreadable and destroyed", afterExpiry.status === 410);

  console.log("\nTrash & permanent delete");
  const del = await sendFile(bob, alice, "to be trashed", { subject: "Trash me" });
  const trash1 = await alice.client.call(`/api/messages/${del.data.id}`, { method: "DELETE" });
  check("recipient delete moves to trash", trash1.status === 200 && trash1.data.trashed === true);
  const trashBox = await alice.client.call("/api/messages?box=trash");
  check("message shows in trash", trashBox.data.messages?.some((m) => m.id === del.data.id));
  const trash2 = await alice.client.call(`/api/messages/${del.data.id}`, { method: "DELETE" });
  check("second delete purges recipient key", trash2.status === 200 && trash2.data.purged === true);

  console.log("\nZero-knowledge server check");
  const raw = await sendFile(bob, alice, "server should never see this plaintext", {
    subject: "ZK check",
  });
  // Read the server's database directly and make sure plaintext isn't there.
  const { default: Database } = await import("better-sqlite3");
  const dbRO = new Database("data/biovault.db", { readonly: true });
  const att = dbRO
    .prepare("SELECT ciphertext FROM attachments WHERE message_id = ?")
    .get(raw.data.id);
  const asText = att.ciphertext.toString("latin1");
  check(
    "stored blob does not contain plaintext",
    !asText.includes("server should never see this plaintext")
  );
  const keysOnServer = dbRO.prepare("SELECT public_jwk FROM user_keys").all();
  check(
    "server stores only public keys (no 'd' private component)",
    keysOnServer.every((k) => !("d" in JSON.parse(k.public_jwk)))
  );
  dbRO.close();

  console.log("\nAudit & notifications");
  const auditRes = await alice.client.call("/api/audit");
  const events = auditRes.data.events?.map((e) => e.event) ?? [];
  check(
    "audit trail covers login/open/delete/expiry/failures",
    ["login", "opened", "deleted", "expired", "login_failed"].every((e) => events.includes(e)),
    `got: ${[...new Set(events)].join(",")}`
  );
  const notif = await alice.client.call("/api/notifications");
  const types = notif.data.notifications?.map((n) => n.type) ?? [];
  check(
    "notifications: delivered/revoked/expired present",
    ["delivered", "revoked", "expired"].every((t) => types.includes(t)),
    `got: ${[...new Set(types)].join(",")}`
  );
  const bobNotif = await bob.client.call("/api/notifications");
  const bobTypes = bobNotif.data.notifications?.map((n) => n.type) ?? [];
  check(
    "sender notified on open & one-time completion",
    ["opened", "one_time_done"].every((t) => bobTypes.includes(t)),
    `got: ${[...new Set(bobTypes)].join(",")}`
  );

  console.log(`\n${passed} passed, ${failed} failed\n`);
  process.exit(failed > 0 ? 1 : 0);
};

run().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
