"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Fingerprint, ScanFace, ShieldCheck, Loader2, KeyRound } from "lucide-react";
import { registerWithBiometrics } from "@/lib/client/api";

export default function RegisterPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await registerWithBiometrics(email);
      localStorage.setItem("bv_email", email.trim().toLowerCase());
      router.push("/mail/inbox");
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
      <div className="pointer-events-none absolute -top-32 left-1/4 h-96 w-96 rounded-full bg-sky-500/20 blur-3xl" />
      <div className="pointer-events-none absolute -bottom-32 right-1/4 h-96 w-96 rounded-full bg-cyan-500/20 blur-3xl" />

      <div className="glass animate-rise relative w-full max-w-md rounded-3xl p-8 shadow-2xl">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-sky-900 to-cyan-500 text-white">
            <Fingerprint className="h-6 w-6" />
          </div>
          <div>
            <h1 className="text-xl font-bold">Create your vault</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">No password. Ever.</p>
          </div>
        </div>

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
            {busy ? <Loader2 className="h-5 w-5 animate-spin" /> : <ScanFace className="h-5 w-5" />}
            {busy ? "Waiting for biometrics…" : "Register with Face ID / Fingerprint"}
          </button>

          {error && (
            <p className="rounded-xl bg-rose-500/10 px-3 py-2 text-sm text-rose-600 dark:text-rose-400">
              {error}
            </p>
          )}
        </form>

        <div className="mt-6 space-y-2.5 border-t border-slate-200/70 pt-5 text-xs text-slate-500 dark:border-white/10 dark:text-slate-400">
          <p className="flex gap-2">
            <ShieldCheck className="h-4 w-4 shrink-0 text-emerald-500" />
            Your OS verifies your biometrics locally — they are never sent to or stored by BioVault.
          </p>
          <p className="flex gap-2">
            <KeyRound className="h-4 w-4 shrink-0 text-sky-500" />
            A private encryption key is generated on this device and never leaves it. The server
            receives only your public key.
          </p>
        </div>

        <p className="mt-6 text-center text-sm text-slate-500 dark:text-slate-400">
          Already have a vault?{" "}
          <Link href="/login" className="font-semibold text-sky-500 hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </main>
  );
}
