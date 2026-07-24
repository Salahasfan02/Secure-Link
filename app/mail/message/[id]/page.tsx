"use client";

import { use, useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowLeft,
  Flame,
  Clock,
  ScanFace,
  Stamp,
  Download,
  Camera,
  Paperclip,
  Trash2,
  ShieldOff,
  Loader2,
  LockOpen,
  ShieldCheck,
} from "lucide-react";
import { api, ApiError, reauthWithBiometrics } from "@/lib/client/api";
import { decryptFile, decryptText, type WrappedKey } from "@/lib/client/crypto";
import SecureViewer, { type DecryptedFile } from "@/components/SecureViewer";

interface Meta {
  id: string;
  senderEmail: string;
  recipientEmail: string;
  subject: string | null;
  priority: string;
  tags: string[];
  security: {
    oneTime?: boolean;
    downloadProtection?: boolean;
    watermark?: boolean;
    requireBiometric?: boolean;
    screenshotWarn?: boolean;
  };
  createdAt: number;
  expiresAt: number | null;
  oneTime: boolean;
  openedAt: number | null;
  status: string;
  attachments: { id: string; filename: string; mime: string; size: number }[];
}

interface OpenResponse {
  attachments: {
    id: string;
    filename: string;
    mime: string;
    size: number;
    iv: string;
    ciphertext: string;
    wrappedKey: WrappedKey;
  }[];
  bodyCipher: (WrappedKey & { ct: string }) | null;
  role: "recipient" | "sender";
}

export default function MessagePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [meta, setMeta] = useState<Meta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState("");
  const [viewer, setViewer] = useState<{ files: DecryptedFile[]; body: string | null } | null>(
    null
  );
  const [myEmail, setMyEmail] = useState("");

  useEffect(() => {
    setMyEmail(localStorage.getItem("bv_email") ?? "");
    api<{ message: Meta }>(`/api/messages/${id}`)
      .then((d) => setMeta(d.message))
      .catch((e) => setError(e.message));
  }, [id]);

  const unlock = useCallback(async () => {
    if (!meta) return;
    setBusy(true);
    setError(null);
    try {
      let reauthToken: string | undefined;
      if (meta.security.requireBiometric) {
        setStage("Waiting for biometric verification…");
        reauthToken = await reauthWithBiometrics();
      }

      setStage("Fetching encrypted payload…");
      let opened: OpenResponse;
      try {
        opened = await api<OpenResponse>(`/api/messages/${id}/open`, {
          method: "POST",
          body: JSON.stringify({ reauthToken }),
        });
      } catch (e) {
        // Server may demand a fresh assertion even if the client didn't expect it.
        if (e instanceof ApiError && e.data?.error === "reauth_required") {
          setStage("Waiting for biometric verification…");
          const token = await reauthWithBiometrics();
          opened = await api<OpenResponse>(`/api/messages/${id}/open`, {
            method: "POST",
            body: JSON.stringify({ reauthToken: token }),
          });
        } else {
          throw e;
        }
      }

      setStage("Decrypting locally…");
      const files: DecryptedFile[] = [];
      for (const a of opened.attachments) {
        files.push({
          filename: a.filename,
          mime: a.mime,
          data: await decryptFile(myEmail, {
            iv: a.iv,
            ciphertext: a.ciphertext,
            wrappedKey: a.wrappedKey,
          }),
        });
      }
      const body = opened.bodyCipher ? await decryptText(myEmail, opened.bodyCipher) : null;

      setViewer({ files, body });
      // Refresh metadata (one-time flags, opened state) after viewing starts.
      api<{ message: Meta }>(`/api/messages/${id}`).then((d) => setMeta(d.message)).catch(() => {});
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      setError(
        msg.includes("NotAllowedError")
          ? "Biometric verification was cancelled."
          : msg
      );
    } finally {
      setBusy(false);
      setStage("");
    }
  }, [meta, id, myEmail]);

  async function remove() {
    const iAmSender = meta && myEmail === meta.senderEmail && myEmail !== meta.recipientEmail;
    const label = iAmSender
      ? "Revoke this file? The recipient immediately and permanently loses access."
      : "Delete this message?";
    if (!confirm(label)) return;
    try {
      await api(`/api/messages/${id}`, { method: "DELETE" });
      router.back();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  if (error && !meta) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-8">
        <p className="rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-600">{error}</p>
      </div>
    );
  }
  if (!meta) {
    return (
      <div className="flex justify-center py-20">
        <Loader2 className="h-6 w-6 animate-spin text-sky-500" />
      </div>
    );
  }

  const dead = meta.status !== "active";
  const iAmRecipient = myEmail === meta.recipientEmail;
  const consumedForMe = meta.status === "consumed" && iAmRecipient;

  const securityChips = [
    meta.oneTime && { icon: Flame, label: "One-time view", cls: "bg-orange-500/10 text-orange-500" },
    meta.expiresAt && {
      icon: Clock,
      label: `Expires ${new Date(meta.expiresAt).toLocaleString()}`,
      cls: "bg-amber-500/10 text-amber-600 dark:text-amber-400",
    },
    meta.security.requireBiometric && {
      icon: ScanFace,
      label: "Biometric required per open",
      cls: "bg-sky-500/10 text-sky-500",
    },
    meta.security.watermark && {
      icon: Stamp,
      label: "Watermarked",
      cls: "bg-teal-500/10 text-teal-600 dark:text-teal-400",
    },
    meta.security.downloadProtection && {
      icon: Download,
      label: "Download disabled",
      cls: "bg-slate-500/10 text-slate-500",
    },
    meta.security.screenshotWarn && {
      icon: Camera,
      label: "Screenshot warning",
      cls: "bg-rose-500/10 text-rose-500",
    },
  ].filter(Boolean) as { icon: typeof Flame; label: string; cls: string }[];

  return (
    <div className="mx-auto max-w-3xl px-6 py-8">
      <button onClick={() => router.back()} className="btn-ghost mb-4 -ml-2">
        <ArrowLeft className="h-4 w-4" />
        Back
      </button>

      <div className="glass animate-rise rounded-3xl p-7">
        <div className="mb-1 flex items-start justify-between gap-4">
          <h1 className="text-xl font-bold">{meta.subject || "(no subject)"}</h1>
          <button onClick={remove} className="btn-danger shrink-0 px-3 py-2">
            <Trash2 className="h-4 w-4" />
            {myEmail === meta.senderEmail && myEmail !== meta.recipientEmail
              ? "Revoke"
              : "Delete"}
          </button>
        </div>
        <p className="text-sm text-slate-500">
          <span className="font-medium text-slate-700 dark:text-slate-300">
            {meta.senderEmail}
          </span>{" "}
          → {meta.recipientEmail} · {new Date(meta.createdAt).toLocaleString()}
        </p>

        {securityChips.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-1.5">
            {securityChips.map((c) => (
              <span key={c.label} className={`chip ${c.cls}`}>
                <c.icon className="h-3 w-3" />
                {c.label}
              </span>
            ))}
            {meta.tags.map((t) => (
              <span key={t} className="chip bg-cyan-500/10 text-cyan-500">
                #{t}
              </span>
            ))}
          </div>
        )}

        <div className="mt-6 space-y-2">
          {meta.attachments.map((a) => (
            <div
              key={a.id}
              className="flex items-center gap-3 rounded-xl bg-slate-500/5 px-4 py-3 text-sm dark:bg-white/5"
            >
              <Paperclip className="h-4 w-4 shrink-0 text-sky-500" />
              <span className="min-w-0 flex-1 truncate font-medium">{a.filename}</span>
              <span className="text-xs text-slate-400">
                {(a.size / 1024 / 1024).toFixed(2)} MB · encrypted
              </span>
            </div>
          ))}
        </div>

        <div className="mt-6">
          {dead ? (
            <div className="flex items-center gap-3 rounded-2xl bg-slate-500/10 px-5 py-4 text-sm text-slate-500">
              <ShieldOff className="h-5 w-5 shrink-0" />
              {meta.status === "revoked" && "The sender revoked access. The keys were destroyed."}
              {meta.status === "expired" && "This file expired and was permanently destroyed."}
              {meta.status === "consumed" &&
                (consumedForMe
                  ? "One-time view already used. The file destroyed itself."
                  : `One-time view completed by ${meta.recipientEmail}. The file destroyed itself.`)}
              {meta.status === "destroyed" && "This file is no longer available."}
            </div>
          ) : (
            <button onClick={unlock} disabled={busy} className="btn-primary w-full py-3.5">
              {busy ? (
                <Loader2 className="h-5 w-5 animate-spin" />
              ) : meta.security.requireBiometric ? (
                <ScanFace className="h-5 w-5" />
              ) : (
                <LockOpen className="h-5 w-5" />
              )}
              {busy ? stage || "Working…" : "Unlock & view"}
              {meta.oneTime && iAmRecipient && !busy && (
                <span className="text-white/70">— destroys after viewing</span>
              )}
            </button>
          )}
          {error && (
            <p className="mt-3 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-600 dark:text-rose-400">
              {error}
            </p>
          )}
          <p className="mt-3 flex items-center justify-center gap-1.5 text-xs text-slate-400">
            <ShieldCheck className="h-3.5 w-3.5" />
            Files decrypt in your browser. The server only ever stores ciphertext.
          </p>
        </div>
      </div>

      {viewer && (
        <SecureViewer
          files={viewer.files}
          bodyText={viewer.body}
          watermarkText={
            meta.security.watermark ? `${myEmail} · ${new Date().toLocaleString()}` : null
          }
          downloadProtection={!!meta.security.downloadProtection}
          screenshotWarn={!!meta.security.screenshotWarn}
          onClose={() => setViewer(null)}
        />
      )}
    </div>
  );
}
