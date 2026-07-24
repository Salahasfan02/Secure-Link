// Seed a demo scenario for browser verification:
//  - registers the browser-side user (whose private key lives in the
//    browser's IndexedDB; its public JWK is passed as argv[2])
//  - registers a "colleague" sender and sends the demo user a few
//    messages exercising watermark / one-time / expiry / tags
//  - prints the demo user's session token for cookie injection
import crypto from "crypto";

const BASE = process.argv[3] ?? "http://localhost:3100";
const RP_ID = new URL(BASE).hostname;
const subtle = globalThis.crypto.subtle;
const browserPubJwk = JSON.parse(process.argv[2]);
const DEMO_EMAIL = "salah@demo.bio";
const SENDER_EMAIL = "colleague@demo.bio";

// --- minimal CBOR + fake authenticator (same as e2e-test.mjs) ---
function cborEncode(value) { const chunks = []; encodeItem(value, chunks); return Buffer.concat(chunks); }
function head(major, len) {
  if (len < 24) return Buffer.from([(major << 5) | len]);
  if (len < 0x100) return Buffer.from([(major << 5) | 24, len]);
  const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(len, 1); return b;
}
function encodeItem(v, out) {
  if (typeof v === "number" && Number.isInteger(v)) out.push(v >= 0 ? head(0, v) : head(1, -v - 1));
  else if (v instanceof Buffer || v instanceof Uint8Array) { const b = Buffer.from(v); out.push(head(2, b.length), b); }
  else if (typeof v === "string") { const b = Buffer.from(v, "utf8"); out.push(head(3, b.length), b); }
  else if (v instanceof Map) { out.push(head(5, v.size)); for (const [k, val] of v) { encodeItem(k, out); encodeItem(val, out); } }
  else if (v && typeof v === "object") { const ks = Object.keys(v); out.push(head(5, ks.length)); for (const k of ks) { encodeItem(k, out); encodeItem(v[k], out); } }
  else throw new Error("cbor");
}
const b64url = (b) => Buffer.from(b).toString("base64url");
class FakeAuthenticator {
  constructor() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    this.x = Buffer.from(jwk.x, "base64url");
    this.y = Buffer.from(jwk.y, "base64url");
    this.credId = crypto.randomBytes(32);
  }
  attestation(challenge, origin) {
    const cdj = Buffer.from(JSON.stringify({ type: "webauthn.create", challenge, origin, crossOrigin: false }));
    const rpIdHash = crypto.createHash("sha256").update(RP_ID).digest();
    const cose = cborEncode(new Map([[1, 2], [3, -7], [-1, 1], [-2, this.x], [-3, this.y]]));
    const authData = Buffer.concat([
      rpIdHash, Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16),
      Buffer.from([this.credId.length >> 8, this.credId.length & 0xff]), this.credId, cose,
    ]);
    return {
      id: b64url(this.credId), rawId: b64url(this.credId), type: "public-key",
      clientExtensionResults: {}, authenticatorAttachment: "platform",
      response: { clientDataJSON: b64url(cdj), attestationObject: b64url(cborEncode({ fmt: "none", attStmt: {}, authData })), transports: ["internal"] },
    };
  }
}
class Client {
  constructor() { this.cookies = new Map(); }
  async call(path, { method = "GET", body } = {}) {
    const res = await fetch(`${BASE}${path}`, {
      method,
      headers: { "Content-Type": "application/json", Cookie: [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; "), Origin: BASE },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const sc of res.headers.getSetCookie?.() ?? []) {
      const [pair] = sc.split(";"); const eq = pair.indexOf("=");
      const name = pair.slice(0, eq).trim(); const value = pair.slice(eq + 1).trim();
      if (value) this.cookies.set(name, value); else this.cookies.delete(name);
    }
    return { status: res.status, data: await res.json().catch(() => ({})) };
  }
}

async function deriveKek(privateKey, publicJwk) {
  const pub = await subtle.importKey("jwk", publicJwk, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const shared = await subtle.deriveBits({ name: "ECDH", public: pub }, privateKey, 256);
  const hkdf = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new TextEncoder().encode("biovault-file-key-wrap-v1") },
    hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function wrapFor(rawKey, jwk) {
  const eph = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits", "deriveKey"]);
  const kek = await deriveKek(eph.privateKey, jwk);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await subtle.encrypt({ name: "AES-GCM", iv }, kek, rawKey);
  return { ephPub: await subtle.exportKey("jwk", eph.publicKey), iv: Buffer.from(iv).toString("base64"), wrapped: Buffer.from(wrapped).toString("base64") };
}
async function encryptFile(data, recipientJwk, senderJwk) {
  const fk = await subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, fk, data);
  const raw = await subtle.exportKey("raw", fk);
  return {
    iv: Buffer.from(iv).toString("base64"), ciphertext: Buffer.from(ct).toString("base64"),
    recipientKey: await wrapFor(raw, recipientJwk), senderKey: await wrapFor(raw, senderJwk),
  };
}
async function encryptText(text, recipientJwk, senderJwk) {
  const enc = await encryptFile(Buffer.from(text), recipientJwk, senderJwk);
  const ct = `${enc.iv}.${enc.ciphertext}`;
  return { recipient: { ...enc.recipientKey, ct }, sender: { ...enc.senderKey, ct } };
}

async function register(email, publicJwk) {
  const client = new Client();
  const auth = new FakeAuthenticator();
  const opts = await client.call("/api/auth/register/options", { method: "POST", body: { email } });
  if (opts.status === 409) return { client: null }; // already exists
  const v = await client.call("/api/auth/register/verify", {
    method: "POST",
    body: { response: auth.attestation(opts.data.challenge, BASE), publicJwk },
  });
  if (v.status !== 200) throw new Error(JSON.stringify(v.data));
  return { client };
}

const run = async () => {
  const demo = await register(DEMO_EMAIL, browserPubJwk);
  if (!demo.client) throw new Error("demo user already exists — wipe data/biovault.db rows or use a new email");

  const senderIdentity = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits", "deriveKey"]);
  const senderPubJwk = await subtle.exportKey("jwk", senderIdentity.publicKey);
  const sender = await register(SENDER_EMAIL, senderPubJwk);

  const memo = `CONFIDENTIAL — Project Aurora term sheet

Valuation: $48M pre-money
Closing date: August 1, 2026
Lead investor: Meridian Capital

Do not forward. This memo is end-to-end encrypted;
only ${DEMO_EMAIL} can decrypt it.`;

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="640" height="400">
  <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#6366f1"/><stop offset="1" stop-color="#8b5cf6"/>
  </linearGradient></defs>
  <rect width="640" height="400" fill="url(#g)" rx="24"/>
  <text x="320" y="180" font-family="Helvetica" font-size="34" fill="white" text-anchor="middle" font-weight="bold">Aurora — Series B</text>
  <text x="320" y="225" font-family="Helvetica" font-size="18" fill="rgba(255,255,255,0.8)" text-anchor="middle">Cap table snapshot · Q3 2026</text>
</svg>`;

  // 1) Watermarked, download-protected memo with encrypted note
  const enc1 = await encryptFile(Buffer.from(memo), browserPubJwk, senderPubJwk);
  const enc1b = await encryptFile(Buffer.from(svg), browserPubJwk, senderPubJwk);
  const note = await encryptText(
    "Hi Salah — attaching the final term sheet and the cap table. Watermarked and view-only. Ping me on Signal if anything looks off. — J",
    browserPubJwk, senderPubJwk
  );
  await sender.client.call("/api/messages", {
    method: "POST",
    body: {
      recipientEmail: DEMO_EMAIL,
      subject: "Project Aurora — final term sheet",
      bodyCipher: note,
      priority: "high",
      tags: ["legal", "confidential"],
      security: { watermark: true, downloadProtection: true, screenshotWarn: true },
      expiresAt: Date.now() + 7 * 24 * 3600_000,
      attachments: [
        { filename: "term-sheet.txt", mime: "text/plain", size: memo.length, ...enc1 },
        { filename: "cap-table.svg", mime: "image/svg+xml", size: svg.length, ...enc1b },
      ],
    },
  });

  // 2) One-time view secret
  const secret = "Wire authorization code: 7741-AURORA-0817\nValid for a single view.";
  const enc2 = await encryptFile(Buffer.from(secret), browserPubJwk, senderPubJwk);
  await sender.client.call("/api/messages", {
    method: "POST",
    body: {
      recipientEmail: DEMO_EMAIL,
      subject: "Wire authorization — view once",
      security: { oneTime: true, watermark: true },
      attachments: [{ filename: "wire-auth.txt", mime: "text/plain", size: secret.length, ...enc2 }],
    },
  });

  // 3) Plain encrypted doc, 24h expiry
  const brief = "Board meeting brief — attendees, agenda, and vote items.";
  const enc3 = await encryptFile(Buffer.from(brief), browserPubJwk, senderPubJwk);
  await sender.client.call("/api/messages", {
    method: "POST",
    body: {
      recipientEmail: DEMO_EMAIL,
      subject: "Board brief (expires in 24h)",
      tags: ["board"],
      security: { watermark: false },
      expiresAt: Date.now() + 24 * 3600_000,
      attachments: [{ filename: "board-brief.txt", mime: "text/plain", size: brief.length, ...enc3 }],
    },
  });

  console.log("SESSION=" + demo.client.cookies.get("bv_session"));
};

run().catch((e) => { console.error(e); process.exit(1); });
