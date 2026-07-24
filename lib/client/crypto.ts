// BioVault client-side E2E cryptography (Web Crypto API).
//
// Design:
//  - Each user has an ECDH P-256 identity key pair. The private key is
//    generated non-extractable and lives only in this device's IndexedDB
//    (hardware keystore / secure enclave on native builds). It never
//    leaves the device; the server stores only the public JWK.
//  - Each file gets a fresh random AES-256-GCM key.
//  - The file key is wrapped per-party via ephemeral ECDH: an ephemeral
//    P-256 key agrees with the party's public key, HKDF-SHA256 derives a
//    KEK, and AES-GCM wraps the raw file key (ECIES-style).
//  - Biometrics never act as key material — a WebAuthn assertion (OS
//    biometric) gates *access* to the locally stored private key.

const DB_NAME = "biovault-keys";
const STORE = "identity";

export interface WrappedKey {
  ephPub: JsonWebKey;
  iv: string; // base64
  wrapped: string; // base64
}

function idb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function idbGet<T>(key: string): Promise<T | undefined> {
  return idb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
        tx.onsuccess = () => resolve(tx.result as T | undefined);
        tx.onerror = () => reject(tx.error);
      })
  );
}

function idbSet(key: string, value: unknown): Promise<void> {
  return idb().then(
    (db) =>
      new Promise((resolve, reject) => {
        const tx = db.transaction(STORE, "readwrite").objectStore(STORE).put(value, key);
        tx.onsuccess = () => resolve();
        tx.onerror = () => reject(tx.error);
      })
  );
}

export function b64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/** Create the device identity key pair. Private key is non-extractable. */
export async function generateIdentityKeys(
  email: string
): Promise<{ publicJwk: JsonWebKey }> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false, // non-extractable: the private key can be *used* but never exported
    ["deriveKey", "deriveBits"]
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  await idbSet(`priv:${email}`, pair.privateKey);
  await idbSet(`pub:${email}`, publicJwk);
  return { publicJwk };
}

export async function getPrivateKey(email: string): Promise<CryptoKey | null> {
  return (await idbGet<CryptoKey>(`priv:${email}`)) ?? null;
}

export async function hasIdentity(email: string): Promise<boolean> {
  return !!(await getPrivateKey(email));
}

async function deriveKek(
  privateKey: CryptoKey,
  publicJwk: JsonWebKey
): Promise<CryptoKey> {
  const pub = await crypto.subtle.importKey(
    "jwk",
    publicJwk,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: pub }, privateKey, 256);
  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32), // fresh ephemeral key per wrap → static salt is safe
      info: new TextEncoder().encode("biovault-file-key-wrap-v1"),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

/** Wrap a raw AES file key for one party (ECIES: ephemeral ECDH + HKDF + AES-GCM). */
async function wrapKeyFor(rawFileKey: ArrayBuffer, partyPubJwk: JsonWebKey): Promise<WrappedKey> {
  const eph = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveKey", "deriveBits"]
  );
  const kek = await deriveKek(eph.privateKey, partyPubJwk);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, kek, rawFileKey);
  return {
    ephPub: await crypto.subtle.exportKey("jwk", eph.publicKey),
    iv: b64(iv),
    wrapped: b64(wrapped),
  };
}

async function unwrapKey(myPrivateKey: CryptoKey, wk: WrappedKey): Promise<CryptoKey> {
  const kek = await deriveKek(myPrivateKey, wk.ephPub);
  const raw = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(wk.iv) as BufferSource },
    kek,
    unb64(wk.wrapped) as BufferSource
  );
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
}

export interface EncryptedFile {
  iv: string;
  ciphertext: string;
  recipientKey: WrappedKey;
  senderKey: WrappedKey;
}

/** Encrypt file bytes with a fresh AES-256-GCM key, wrapped for both parties. */
export async function encryptFile(
  data: ArrayBuffer,
  recipientPubJwk: JsonWebKey,
  senderPubJwk: JsonWebKey
): Promise<EncryptedFile> {
  const fileKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, fileKey, data);
  const rawKey = await crypto.subtle.exportKey("raw", fileKey);
  return {
    iv: b64(iv),
    ciphertext: b64(ciphertext),
    recipientKey: await wrapKeyFor(rawKey, recipientPubJwk),
    senderKey: await wrapKeyFor(rawKey, senderPubJwk),
  };
}

export async function decryptFile(
  myEmail: string,
  payload: { iv: string; ciphertext: string; wrappedKey: WrappedKey }
): Promise<ArrayBuffer> {
  const priv = await getPrivateKey(myEmail);
  if (!priv) {
    throw new Error(
      "Your private key isn't on this device. Files can only be decrypted on the device where your account was registered."
    );
  }
  const fileKey = await unwrapKey(priv, payload.wrappedKey);
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64(payload.iv) as BufferSource },
    fileKey,
    unb64(payload.ciphertext) as BufferSource
  );
}

/** Encrypt a short text (message body) for both parties. */
export async function encryptText(
  text: string,
  recipientPubJwk: JsonWebKey,
  senderPubJwk: JsonWebKey
): Promise<{ recipient: WrappedKey & { ct: string }; sender: WrappedKey & { ct: string } }> {
  const enc = await encryptFile(new TextEncoder().encode(text).buffer, recipientPubJwk, senderPubJwk);
  return {
    recipient: { ...enc.recipientKey, ct: `${enc.iv}.${enc.ciphertext}` },
    sender: { ...enc.senderKey, ct: `${enc.iv}.${enc.ciphertext}` },
  };
}

export async function decryptText(
  myEmail: string,
  envelope: WrappedKey & { ct: string }
): Promise<string> {
  const [iv, ciphertext] = envelope.ct.split(".");
  const buf = await decryptFile(myEmail, { iv, ciphertext, wrappedKey: envelope });
  return new TextDecoder().decode(buf);
}
