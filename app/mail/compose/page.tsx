"use client";

import { Suspense, useEffect, useRef, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Send,
  Paperclip,
  X,
  Flame,
  Clock,
  Download,
  Stamp,
  ScanFace,
  Camera,
  Loader2,
  Save,
  Lock,
} from "lucide-react";
import { api } from "@/lib/client/api";
import { encryptFile, encryptText } from "@/lib/client/crypto";
import { getDraft, saveDraft, deleteDraft, type Draft } from "@/lib/client/drafts";

const EXPIRY_CHOICES = [
  { value: "", label: "Never" },
  { value: "1h", label: "1 hour" },
  { value: "6h", label: "6 hours" },
  { value: "24h", label: "24 hours" },
  { value: "7d", label: "7 days" },
  { value: "30d", label: "30 days" },
  { value: "custom", label: "Custom…" },
];

function expiryToTimestamp(choice: string, custom: string): number | null {
  const h = 3_600_000;
  switch (choice) {
    case "1h": return Date.now() + h;
    case "6h": return Date.now() + 6 * h;
    case "24h": return Date.now() + 24 * h;
    case "7d": return Date.now() + 7 * 24 * h;
    case "30d": return Date.now() + 30 * 24 * h;
    case "custom": return custom ? new Date(custom).getTime() : null;
    default: return null;
  }
}

function ComposeInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const draftId = searchParams.get("draft");

  const [to, setTo] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [priority, setPriority] = useState("normal");
  const [tags, setTags] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [expiryChoice, setExpiryChoice] = useState("");
  const [customExpiry, setCustomExpiry] = useState("");
  const [security, setSecurity] = useState({
    oneTime: false,
    downloadProtection: false,
    watermark: true,
    requireBiometric: false,
    screenshotWarn: false,
  });
  const [busy, setBusy] = useState(false);
  const [stage, setStage] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    if (!draftId) return;
    const d = getDraft(draftId);
    if (d) {
      setTo(d.to);
      setSubject(d.subject);
      setBody(d.body);
      setPriority(d.priority);
      setTags(d.tags);
      setSecurity(d.security);
      setExpiryChoice(d.expiryChoice);
      setCustomExpiry(d.customExpiry);
    }
  }, [draftId]);

  function addFiles(list: FileList | File[] | null) {
    if (!list) return;
    setFiles((prev) => [...prev, ...Array.from(list)]);
  }

  function persistDraft() {
    const draft: Draft = {
      id: draftId ?? `d_${Date.now()}`,
      to,
      subject,
      body,
      priority,
      tags,
      security,
      expiryChoice,
      customExpiry,
      savedAt: Date.now(),
    };
    saveDraft(draft);
    setSaved(true);
    setTimeout(() => setSaved(false), 1500);
  }

  async function send(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (files.length === 0) {
      setError("Attach at least one file — BioVault is built for secure file delivery.");
      return;
    }
    setBusy(true);
    try {
      setStage("Looking up recipient…");
      const recipient = await api<{ publicJwk: JsonWebKey }>(
        `/api/users?email=${encodeURIComponent(to.trim().toLowerCase())}`
      );
      const meRes = await api<{ publicJwk: JsonWebKey }>("/api/auth/me");

      const attachments = [];
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        setStage(`Encrypting ${f.name} (${i + 1}/${files.length})…`);
        const enc = await encryptFile(await f.arrayBuffer(), recipient.publicJwk, meRes.publicJwk);
        attachments.push({
          filename: f.name,
          mime: f.type || "application/octet-stream",
          size: f.size,
          iv: enc.iv,
          ciphertext: enc.ciphertext,
          recipientKey: enc.recipientKey,
          senderKey: enc.senderKey,
        });
      }

      setStage("Encrypting message…");
      const bodyCipher = body.trim()
        ? await encryptText(body, recipient.publicJwk, meRes.publicJwk)
        : undefined;

      setStage("Uploading encrypted payload…");
      await api("/api/messages", {
        method: "POST",
        body: JSON.stringify({
          recipientEmail: to.trim().toLowerCase(),
          subject,
          bodyCipher,
          priority,
          tags: tags
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
          security,
          expiresAt: expiryToTimestamp(expiryChoice, customExpiry),
          attachments,
        }),
      });

      if (draftId) deleteDraft(draftId);
      router.push("/mail/sent");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
      setStage("");
    }
  }

  const toggles: {
    key: keyof typeof security;
    icon: typeof Flame;
    label: string;
    desc: string;
  }[] = [
    {
      key: "oneTime",
      icon: Flame,
      label: "One-time view",
      desc: "File self-destructs after the recipient opens it once. Keys are destroyed.",
    },
    {
      key: "downloadProtection",
      icon: Download,
      label: "Download protection",
      desc: "View-only inside the secure viewer. No download button.",
    },
    {
      key: "watermark",
      icon: Stamp,
      label: "Watermark",
      desc: "Overlays the viewer's email and timestamp on the document.",
    },
    {
      key: "requireBiometric",
      icon: ScanFace,
      label: "Biometric on every open",
      desc: "Requires a fresh Face ID / fingerprint check each time, even mid-session.",
    },
    {
      key: "screenshotWarn",
      icon: Camera,
      label: "Screenshot warning",
      desc: "Warns the viewer that screenshots can't be blocked in web browsers.",
    },
  ];

  return (
    <div className="mx-auto max-w-3xl px-6 py-8">
      <h1 className="mb-6 text-2xl font-bold tracking-tight">New secure send</h1>

      <form onSubmit={send} className="space-y-5">
        <div className="glass space-y-4 rounded-3xl p-6">
          <div>
            <label className="mb-1.5 block text-sm font-medium">To</label>
            <input
              type="email"
              required
              value={to}
              onChange={(e) => setTo(e.target.value)}
              placeholder="recipient@company.com"
              className="input"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium">Subject</label>
            <input
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="Q3 board documents"
              className="input"
            />
          </div>
          <div>
            <label className="mb-1.5 block text-sm font-medium">
              Message <span className="font-normal text-slate-400">(end-to-end encrypted)</span>
            </label>
            <textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              rows={4}
              placeholder="This note is encrypted along with your files."
              className="input resize-y"
            />
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="mb-1.5 block text-sm font-medium">Priority</label>
              <select
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                className="input"
              >
                <option value="low">Low</option>
                <option value="normal">Normal</option>
                <option value="high">High</option>
              </select>
            </div>
            <div>
              <label className="mb-1.5 block text-sm font-medium">Tags</label>
              <input
                value={tags}
                onChange={(e) => setTags(e.target.value)}
                placeholder="legal, confidential"
                className="input"
              />
            </div>
          </div>
        </div>

        {/* Files */}
        <div
          className={`glass rounded-3xl p-6 transition ${
            dragging ? "border-sky-400 ring-2 ring-sky-400/30" : ""
          }`}
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            addFiles(e.dataTransfer.files);
          }}
        >
          <div className="mb-3 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-sm font-semibold">
              <Paperclip className="h-4 w-4" />
              Files{" "}
              <span className="font-normal text-slate-400">
                — encrypted on this device before upload
              </span>
            </h2>
            <input
              ref={fileRef}
              type="file"
              multiple
              className="hidden"
              onChange={(e) => addFiles(e.target.files)}
            />
            <button type="button" onClick={() => fileRef.current?.click()} className="btn-ghost">
              Browse
            </button>
          </div>
          {files.length === 0 ? (
            <p className="rounded-xl border border-dashed border-slate-300 py-8 text-center text-sm text-slate-400 dark:border-white/15">
              Drop files here — PDFs, images, videos, documents, archives, anything.
            </p>
          ) : (
            <ul className="space-y-2">
              {files.map((f, i) => (
                <li
                  key={`${f.name}-${i}`}
                  className="flex items-center gap-3 rounded-xl bg-slate-500/5 px-3 py-2 text-sm dark:bg-white/5"
                >
                  <Lock className="h-4 w-4 shrink-0 text-sky-500" />
                  <span className="min-w-0 flex-1 truncate">{f.name}</span>
                  <span className="text-xs text-slate-400">
                    {(f.size / 1024 / 1024).toFixed(2)} MB
                  </span>
                  <button
                    type="button"
                    onClick={() => setFiles(files.filter((_, j) => j !== i))}
                    className="text-slate-400 hover:text-rose-500"
                    aria-label={`Remove ${f.name}`}
                  >
                    <X className="h-4 w-4" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Security options */}
        <div className="glass rounded-3xl p-6">
          <h2 className="mb-4 text-sm font-semibold">Security options</h2>
          <div className="grid gap-3 sm:grid-cols-2">
            {toggles.map((t) => (
              <label
                key={t.key}
                className={`flex cursor-pointer gap-3 rounded-2xl border p-3.5 transition ${
                  security[t.key]
                    ? "border-sky-400/60 bg-sky-500/5"
                    : "border-slate-200/70 hover:border-slate-300 dark:border-white/10 dark:hover:border-white/20"
                }`}
              >
                <input
                  type="checkbox"
                  checked={security[t.key]}
                  onChange={(e) => setSecurity({ ...security, [t.key]: e.target.checked })}
                  className="mt-0.5 h-4 w-4 accent-sky-500"
                />
                <div>
                  <p className="flex items-center gap-1.5 text-sm font-medium">
                    <t.icon className="h-3.5 w-3.5 text-sky-500" />
                    {t.label}
                  </p>
                  <p className="mt-0.5 text-xs leading-relaxed text-slate-500">{t.desc}</p>
                </div>
              </label>
            ))}

            <div className="rounded-2xl border border-slate-200/70 p-3.5 dark:border-white/10">
              <p className="flex items-center gap-1.5 text-sm font-medium">
                <Clock className="h-3.5 w-3.5 text-sky-500" />
                Expiration
              </p>
              <select
                value={expiryChoice}
                onChange={(e) => setExpiryChoice(e.target.value)}
                className="input mt-2"
              >
                {EXPIRY_CHOICES.map((c) => (
                  <option key={c.value} value={c.value}>
                    {c.label}
                  </option>
                ))}
              </select>
              {expiryChoice === "custom" && (
                <input
                  type="datetime-local"
                  value={customExpiry}
                  onChange={(e) => setCustomExpiry(e.target.value)}
                  className="input mt-2"
                />
              )}
            </div>
          </div>
        </div>

        {error && (
          <p className="rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-600 dark:text-rose-400">
            {error}
          </p>
        )}

        <div className="flex items-center gap-3">
          <button type="submit" disabled={busy} className="btn-primary px-6 py-3">
            {busy ? <Loader2 className="h-5 w-5 animate-spin" /> : <Send className="h-5 w-5" />}
            {busy ? stage || "Sending…" : "Encrypt & send"}
          </button>
          <button type="button" onClick={persistDraft} disabled={busy} className="btn-ghost">
            <Save className="h-4 w-4" />
            {saved ? "Saved!" : "Save draft"}
          </button>
        </div>
      </form>
    </div>
  );
}

export default function ComposePage() {
  return (
    <Suspense>
      <ComposeInner />
    </Suspense>
  );
}
