import Link from "next/link";
import { redirect } from "next/navigation";
import { Fingerprint, ScanFace, ShieldCheck, Lock, Flame, Eye } from "lucide-react";
import { getSessionUser } from "@/lib/server/session";

export default async function Landing() {
  const user = await getSessionUser();
  if (user) redirect("/mail/inbox");

  return (
    <main className="relative flex-1 overflow-hidden">
      {/* ambient gradient blobs */}
      <div className="pointer-events-none absolute -top-40 -left-40 h-[480px] w-[480px] rounded-full bg-[var(--accent-500-a20)] blur-3xl" />
      <div className="pointer-events-none absolute top-1/3 -right-40 h-[420px] w-[420px] rounded-full bg-[var(--accent-400-a20)] blur-3xl" />

      <div className="relative mx-auto flex max-w-5xl flex-col items-center px-6 pt-24 pb-20 text-center">
        <div className="glass animate-rise mb-8 flex items-center gap-2 rounded-full px-4 py-1.5 text-xs font-medium text-[var(--accent-600)] dark:text-[var(--accent-300)]">
          <ShieldCheck className="h-3.5 w-3.5" />
          End-to-end encrypted · Zero passwords
        </div>

        <h1 className="animate-rise max-w-3xl text-5xl font-bold tracking-tight sm:text-6xl">
          Send sensitive files,
          <span className="bg-gradient-to-r from-[var(--accent-900)] to-[var(--accent-400)] bg-clip-text text-transparent">
            {" "}
            unlocked by you.
          </span>
        </h1>
        <p className="animate-rise mt-6 max-w-xl text-lg text-slate-600 dark:text-slate-400">
          BioVault works like email — but every file is end-to-end encrypted and
          can only be opened with the recipient&apos;s fingerprint or face. The
          server never sees your data. There is nothing to phish.
        </p>

        <div className="animate-rise mt-10 flex gap-3">
          <Link href="/register" className="btn-primary px-6 py-3 text-base">
            <Fingerprint className="h-5 w-5" />
            Create your vault
          </Link>
          <Link href="/login" className="btn-ghost glass px-6 py-3 text-base">
            <ScanFace className="h-5 w-5" />
            Sign in
          </Link>
        </div>

        <div className="mt-20 grid w-full gap-4 sm:grid-cols-3">
          {[
            {
              icon: Lock,
              title: "True end-to-end encryption",
              body: "AES-256-GCM per file, keys wrapped with ECDH P-256. Encrypted before upload, decrypted only on the recipient's device.",
            },
            {
              icon: ScanFace,
              title: "Biometric everything",
              body: "Touch ID, Face ID, Windows Hello. Your biometrics never leave your device — they unlock a hardware-protected private key.",
            },
            {
              icon: Flame,
              title: "Self-destructing delivery",
              body: "One-time view, timed expiry, instant revocation. When access ends, the encryption keys are destroyed — permanently.",
            },
          ].map((f) => (
            <div key={f.title} className="glass animate-rise rounded-2xl p-6 text-left">
              <f.icon className="mb-3 h-6 w-6 text-[var(--accent-500)]" />
              <h3 className="mb-1.5 font-semibold">{f.title}</h3>
              <p className="text-sm leading-relaxed text-slate-600 dark:text-slate-400">{f.body}</p>
            </div>
          ))}
        </div>

        <p className="mt-16 flex items-center gap-2 text-xs text-slate-400 dark:text-slate-500">
          <Eye className="h-3.5 w-3.5" />
          Zero-knowledge by design — BioVault&apos;s servers store only ciphertext and public keys.
        </p>
      </div>
    </main>
  );
}
