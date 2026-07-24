"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ScanFace, Loader2, ShieldAlert } from "lucide-react";
import { loginWithBiometrics } from "@/lib/client/api";
import { hasIdentity } from "@/lib/client/crypto";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [keyWarning, setKeyWarning] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("bv_email");
    if (saved) setEmail(saved);
  }, []);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const normalized = email.trim().toLowerCase();
      await loginWithBiometrics(normalized);
      localStorage.setItem("bv_email", normalized);
      if (!(await hasIdentity(normalized))) setKeyWarning(true);
      else router.push("/mail/inbox");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(
        msg.includes("NotAllowedError") || msg.toLowerCase().includes("timed out")
          ? "Biometric prompt was cancelled or timed out. Try again."
          : msg
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="relative flex flex-1 items-center justify-center overflow-hidden px-4">
      <div className="pointer-events-none absolute -top-32 left-1/4 h-96 w-96 rounded-full bg-[var(--accent-500-a20)] blur-3xl" />
      <div className="pointer-events-none absolute -bottom-32 right-1/4 h-96 w-96 rounded-full bg-[var(--accent-400-a20)] blur-3xl" />

      <div className="glass animate-rise relative w-full max-w-md rounded-3xl p-8 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-[var(--accent-900)] to-[var(--accent-400)] text-white">
            <ScanFace className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold">Welcome back</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Unlock your vault with biometrics
            </p>
          </div>
        </div>

        {keyWarning ? (
          <div className="space-y-4">
            <p className="flex gap-2 rounded-xl bg-amber-500/10 px-3 py-3 text-sm text-amber-700 dark:text-amber-400">
              <ShieldAlert className="h-5 w-5 shrink-0" />
              You&apos;re signed in, but this device doesn&apos;t hold your private decryption key.
              You can browse metadata, but files can only be decrypted on the device where you
              registered.
            </p>
            <button onClick={() => router.push("/mail/inbox")} className="btn-primary w-full py-3">
              Continue anyway
            </button>
          </div>
        ) : (
          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="mb-1.5 block text-sm font-medium">
                Email address
              </label>
              <input
                id="email"
                type="email"
                required
                autoFocus
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                className="input"
              />
            </div>

            <button type="submit" disabled={busy || !email} className="btn-primary w-full py-3">
              {busy ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : (
                <ScanFace className="h-5 w-5" />
              )}
              {busy ? "Waiting for biometrics…" : "Sign in with Face ID / Fingerprint"}
            </button>

            {error && (
              <p className="rounded-xl bg-rose-500/10 px-3 py-2 text-sm text-rose-600 dark:text-rose-400">
                {error}
              </p>
            )}
          </form>
        )}

        <p className="mt-6 text-center text-sm text-slate-500 dark:text-slate-400">
          New here?{" "}
          <Link href="/register" className="font-semibold text-[var(--accent-500)] hover:underline">
            Create your vault
          </Link>
        </p>
      </div>
    </main>
  );
}
