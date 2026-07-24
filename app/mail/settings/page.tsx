"use client";

import { useEffect, useState } from "react";
import { Fingerprint, KeyRound, ShieldCheck, Server, Loader2, Palette, Check } from "lucide-react";
import { api } from "@/lib/client/api";
import { hasIdentity } from "@/lib/client/crypto";

const ACCENTS = [
  { key: "sky", label: "Techy Blue", swatch: "#0ea5e9" },
  { key: "violet", label: "Violet", swatch: "#8b5cf6" },
  { key: "emerald", label: "Emerald", swatch: "#10b981" },
  { key: "slate", label: "Slate", swatch: "#64748b" },
] as const;

export default function SettingsPage() {
  const [me, setMe] = useState<{ email: string } | null>(null);
  const [publicJwk, setPublicJwk] = useState<JsonWebKey | null>(null);
  const [fingerprint, setFingerprint] = useState<string>("");
  const [keyOnDevice, setKeyOnDevice] = useState<boolean | null>(null);
  const [accent, setAccent] = useState<string>("sky");

  useEffect(() => {
    setAccent(localStorage.getItem("bv_accent") ?? "sky");
  }, []);

  function applyAccent(key: string) {
    document.documentElement.setAttribute("data-accent", key);
    localStorage.setItem("bv_accent", key);
    setAccent(key);
  }

  useEffect(() => {
    api<{ user: { email: string }; publicJwk: JsonWebKey | null }>("/api/auth/me").then(
      async (d) => {
        setMe(d.user);
        setPublicJwk(d.publicJwk);
        setKeyOnDevice(await hasIdentity(d.user.email));
        if (d.publicJwk) {
          const bytes = new TextEncoder().encode(JSON.stringify(d.publicJwk));
          const hash = await crypto.subtle.digest("SHA-256", bytes);
          const hex = Array.from(new Uint8Array(hash))
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");
          setFingerprint(hex.match(/.{4}/g)!.slice(0, 8).join(" ").toUpperCase());
        }
      }
    );
  }, []);

  if (!me) {
    return (
      <div className="flex justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-[var(--accent-500)]" />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-3xl px-6 py-8">
      <h1 className="mb-6 text-2xl font-bold tracking-tight">Settings</h1>

      <div className="space-y-4">
        <section className="glass rounded-3xl p-6">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-500">
            <Fingerprint className="h-4 w-4" /> Profile
          </h2>
          <div className="flex items-center gap-4">
            <div className="flex h-14 w-14 items-center justify-center rounded-full bg-gradient-to-br from-[var(--accent-900)] to-[var(--accent-400)] text-xl font-bold text-white">
              {me.email[0]?.toUpperCase()}
            </div>
            <div>
              <p className="font-semibold">{me.email}</p>
              <p className="text-sm text-slate-500">Passwordless account · biometric sign-in</p>
            </div>
          </div>
        </section>

        <section className="glass rounded-3xl p-6">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-500">
            <Palette className="h-4 w-4" /> Appearance
          </h2>
          <p className="mb-4 text-sm text-slate-500">
            Choose an accent color for buttons, links, and highlights across the app.
          </p>
          <div className="flex flex-wrap gap-3">
            {ACCENTS.map((a) => (
              <button
                key={a.key}
                onClick={() => applyAccent(a.key)}
                className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-sm font-medium transition ${
                  accent === a.key
                    ? "border-[var(--accent-400)] bg-[var(--accent-500-a10)]"
                    : "border-slate-200/70 hover:border-slate-300 dark:border-white/10 dark:hover:border-white/20"
                }`}
              >
                <span
                  className="h-4 w-4 rounded-full border border-black/10"
                  style={{ backgroundColor: a.swatch }}
                />
                {a.label}
                {accent === a.key && <Check className="h-3.5 w-3.5 text-[var(--accent-500)]" />}
              </button>
            ))}
          </div>
        </section>

        <section className="glass rounded-3xl p-6">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-500">
            <KeyRound className="h-4 w-4" /> Encryption keys
          </h2>
          <div className="space-y-3 text-sm">
            <div className="flex items-center justify-between rounded-xl bg-slate-500/5 px-4 py-3 dark:bg-white/5">
              <span>Private key on this device</span>
              {keyOnDevice === null ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : keyOnDevice ? (
                <span className="chip bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                  <ShieldCheck className="h-3 w-3" /> present · non-extractable
                </span>
              ) : (
                <span className="chip bg-amber-500/10 text-amber-600 dark:text-amber-400">
                  missing on this device
                </span>
              )}
            </div>
            <div className="rounded-xl bg-slate-500/5 px-4 py-3 dark:bg-white/5">
              <p className="mb-1 text-slate-500">Public key fingerprint (SHA-256)</p>
              <p className="font-mono text-xs">{fingerprint || "—"}</p>
            </div>
            <p className="text-xs leading-relaxed text-slate-500">
              Your private key was generated on your device and is stored non-extractable — it can
              be used to decrypt, but never exported, read, or transmitted. BioVault&apos;s server
              holds only the public key{publicJwk ? ` (${publicJwk.crv} curve)` : ""}. Losing this
              device means losing access to previously received files — by design, there is no
              recovery backdoor.
            </p>
          </div>
        </section>

        <section className="glass rounded-3xl p-6">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-500">
            <Server className="h-4 w-4" /> What the server knows
          </h2>
          <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
            <li>✓ Your email, public key, and message metadata (subjects, timestamps)</li>
            <li>✓ Encrypted file blobs it cannot read</li>
            <li>✗ Your biometrics — verified by your OS, never transmitted</li>
            <li>✗ Your private key — never leaves this device</li>
            <li>✗ File contents — encrypted with AES-256-GCM before upload</li>
          </ul>
        </section>
      </div>
    </div>
  );
}
