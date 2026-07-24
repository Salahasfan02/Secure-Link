"use client";

import { use, useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Flame,
  Clock,
  Paperclip,
  ScanFace,
  Stamp,
  Trash2,
  Upload,
  Loader2,
  ShieldOff,
  Inbox as InboxIcon,
} from "lucide-react";
import { api } from "@/lib/client/api";
import { encryptFile } from "@/lib/client/crypto";
import { loadDrafts, deleteDraft, type Draft } from "@/lib/client/drafts";

interface MessageMeta {
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
  };
  createdAt: number;
  expiresAt: number | null;
  oneTime: boolean;
  status: string;
  attachments: { id: string; filename: string; size: number }[];
}

const TITLES: Record<string, string> = {
  inbox: "Inbox",
  sent: "Sent",
  drafts: "Drafts",
  vault: "Secure Vault",
  trash: "Trash",
};

function timeLeft(expiresAt: number): string {
  const ms = expiresAt - Date.now();
  if (ms <= 0) return "expired";
  const h = Math.floor(ms / 3_600_000);
  if (h >= 24) return `${Math.floor(h / 24)}d left`;
  if (h >= 1) return `${h}h left`;
  return `${Math.max(1, Math.floor(ms / 60_000))}m left`;
}

export default function BoxPage({ params }: { params: Promise<{ box: string }> }) {
  const { box } = use(params);
  const router = useRouter();
  const [messages, setMessages] = useState<MessageMeta[] | null>(null);
  const [drafts, setDrafts] = useState<Draft[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [uploading, setUploading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const query = useSearchParams().get("q") ?? "";

  const refresh = useCallback(() => {
    if (box === "drafts") {
      setDrafts(loadDrafts());
      setMessages([]);
      return;
    }
    api<{ messages: MessageMeta[] }>(`/api/messages?box=${box}`)
      .then((d) => setMessages(d.messages))
      .catch((e) => setError(e.message));
  }, [box]);

  useEffect(refresh, [refresh]);

  async function vaultUpload(files: FileList | null) {
    if (!files?.length) return;
    setUploading(true);
    setError(null);
    try {
      const { publicJwk } = await api<{ publicJwk: JsonWebKey }>("/api/auth/me");
      const myEmail = localStorage.getItem("bv_email")!;
      const attachments = [];
      for (const file of Array.from(files)) {
        const enc = await encryptFile(await file.arrayBuffer(), publicJwk, publicJwk);
        attachments.push({
          filename: file.name,
          mime: file.type || "application/octet-stream",
          size: file.size,
          iv: enc.iv,
          ciphertext: enc.ciphertext,
          recipientKey: enc.recipientKey,
          senderKey: enc.senderKey,
        });
      }
      await api("/api/messages", {
        method: "POST",
        body: JSON.stringify({
          recipientEmail: myEmail,
          subject: files.length === 1 ? files[0].name : `${files.length} files`,
          security: { watermark: false },
          attachments,
        }),
      });
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  }

  const q = query.toLowerCase();
  const filtered = (messages ?? []).filter(
    (m) =>
      !q ||
      m.subject?.toLowerCase().includes(q) ||
      m.senderEmail.toLowerCase().includes(q) ||
      m.recipientEmail.toLowerCase().includes(q) ||
      m.tags.some((t) => t.toLowerCase().includes(q))
  );

  return (
    <div className="mx-auto max-w-4xl px-6 py-8">
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">{TITLES[box] ?? box}</h1>
        {box === "vault" && (
          <>
            <input
              ref={fileRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => vaultUpload(e.target.files)}
            />
            <button
              onClick={() => fileRef.current?.click()}
              disabled={uploading}
              className="btn-primary"
            >
              {uploading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Upload className="h-4 w-4" />
              )}
              {uploading ? "Encrypting…" : "Add to vault"}
            </button>
          </>
        )}
      </div>

      {error && (
        <p className="mb-4 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-600 dark:text-rose-400">
          {error}
        </p>
      )}

      {box === "drafts" ? (
        drafts.length === 0 ? (
          <EmptyState label="No drafts" sub="Drafts you save while composing appear here." />
        ) : (
          <div className="space-y-2">
            {drafts.map((d) => (
              <div
                key={d.id}
                className="glass flex cursor-pointer items-center gap-4 rounded-2xl px-5 py-4 transition hover:border-[var(--accent-400-a40)]"
                onClick={() => router.push(`/mail/compose?draft=${d.id}`)}
              >
                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium">{d.subject || "(no subject)"}</p>
                  <p className="truncate text-sm text-slate-500">
                    To: {d.to || "—"} · saved {new Date(d.savedAt).toLocaleString()}
                  </p>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    deleteDraft(d.id);
                    setDrafts(loadDrafts());
                  }}
                  className="btn-ghost p-2"
                  aria-label="Delete draft"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
        )
      ) : messages === null ? (
        <div className="flex justify-center py-20">
          <Loader2 className="h-6 w-6 animate-spin text-[var(--accent-500)]" />
        </div>
      ) : filtered.length === 0 ? (
        <EmptyState
          label={q ? "No matches" : "Nothing here yet"}
          sub={
            q
              ? "Try a different search."
              : box === "inbox"
                ? "Secure files sent to you will appear here."
                : box === "vault"
                  ? "Encrypt personal files to yourself for safe keeping."
                  : "—"
          }
        />
      ) : (
        <div className="space-y-2">
          {filtered.map((m) => {
            const dead = m.status !== "active";
            return (
              <Link
                key={m.id}
                href={`/mail/message/${m.id}`}
                className={`glass flex items-center gap-4 rounded-2xl px-5 py-4 transition hover:border-[var(--accent-400-a40)] ${
                  dead ? "opacity-55" : ""
                }`}
              >
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-[var(--accent-900-a80)] to-[var(--accent-400-a80)] text-sm font-bold text-white">
                  {(box === "sent" || box === "vault" ? m.recipientEmail : m.senderEmail)[0]?.toUpperCase()}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-2">
                    <p className="truncate text-sm font-semibold">
                      {box === "sent" || box === "vault"
                        ? `To: ${m.recipientEmail}`
                        : m.senderEmail}
                    </p>
                    {m.priority === "high" && (
                      <span className="chip bg-rose-500/10 text-rose-500">high</span>
                    )}
                  </div>
                  <p className="truncate font-medium">{m.subject || "(no subject)"}</p>
                  <div className="mt-1 flex flex-wrap items-center gap-1.5">
                    {m.attachments.length > 0 && (
                      <span className="chip bg-slate-500/10 text-slate-500">
                        <Paperclip className="h-3 w-3" />
                        {m.attachments.length}
                      </span>
                    )}
                    {m.oneTime && (
                      <span className="chip bg-orange-500/10 text-orange-500">
                        <Flame className="h-3 w-3" />
                        one-time
                      </span>
                    )}
                    {m.expiresAt && m.status === "active" && (
                      <span className="chip bg-amber-500/10 text-amber-600 dark:text-amber-400">
                        <Clock className="h-3 w-3" />
                        {timeLeft(m.expiresAt)}
                      </span>
                    )}
                    {m.security.requireBiometric && (
                      <span className="chip bg-[var(--accent-500-a10)] text-[var(--accent-500)]">
                        <ScanFace className="h-3 w-3" />
                        biometric lock
                      </span>
                    )}
                    {m.security.watermark && (
                      <span className="chip bg-teal-500/10 text-teal-600 dark:text-teal-400">
                        <Stamp className="h-3 w-3" />
                        watermark
                      </span>
                    )}
                    {dead && (
                      <span className="chip bg-slate-500/15 text-slate-500">
                        <ShieldOff className="h-3 w-3" />
                        {m.status}
                      </span>
                    )}
                    {m.tags.map((t) => (
                      <span key={t} className="chip bg-[var(--accent-400-a10)] text-[var(--accent-400)]">
                        #{t}
                      </span>
                    ))}
                  </div>
                </div>
                <span className="shrink-0 text-xs text-slate-400">
                  {new Date(m.createdAt).toLocaleDateString(undefined, {
                    month: "short",
                    day: "numeric",
                  })}{" "}
                  {new Date(m.createdAt).toLocaleTimeString(undefined, {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
              </Link>
            );
          })}
        </div>
      )}
    </div>
  );
}

function EmptyState({ label, sub }: { label: string; sub: string }) {
  return (
    <div className="glass flex flex-col items-center rounded-3xl py-20 text-center">
      <InboxIcon className="mb-3 h-10 w-10 text-slate-300 dark:text-slate-600" />
      <p className="font-semibold">{label}</p>
      <p className="mt-1 text-sm text-slate-500">{sub}</p>
    </div>
  );
}
