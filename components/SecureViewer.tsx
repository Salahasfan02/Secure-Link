"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { X, Download, Camera, FileText, ShieldCheck } from "lucide-react";

export interface DecryptedFile {
  filename: string;
  mime: string;
  data: ArrayBuffer;
}

interface Props {
  files: DecryptedFile[];
  bodyText?: string | null;
  watermarkText?: string | null;
  downloadProtection: boolean;
  screenshotWarn: boolean;
  onClose: () => void;
}

const IDLE_MS = 2 * 60 * 1000; // auto-close after 2 minutes of inactivity

export default function SecureViewer({
  files,
  bodyText,
  watermarkText,
  downloadProtection,
  screenshotWarn,
  onClose,
}: Props) {
  const [index, setIndex] = useState(0);
  const [urls, setUrls] = useState<string[]>([]);
  const idleTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Object URLs live only while the viewer is mounted — plaintext never
  // outlives the viewing session. (Created in an effect so StrictMode's
  // mount/cleanup replay always leaves valid URLs behind.)
  useEffect(() => {
    const created = files.map((f) => URL.createObjectURL(new Blob([f.data], { type: f.mime })));
    setUrls(created);
    return () => created.forEach((u) => URL.revokeObjectURL(u));
  }, [files]);

  const resetIdle = useCallback(() => {
    if (idleTimer.current) clearTimeout(idleTimer.current);
    idleTimer.current = setTimeout(onClose, IDLE_MS);
  }, [onClose]);

  useEffect(() => {
    resetIdle();
    const events = ["mousemove", "keydown", "scroll", "click"] as const;
    events.forEach((e) => window.addEventListener(e, resetIdle));
    return () => {
      if (idleTimer.current) clearTimeout(idleTimer.current);
      events.forEach((e) => window.removeEventListener(e, resetIdle));
    };
  }, [resetIdle]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const file = files[index];
  const url = urls[index];

  function download() {
    const a = document.createElement("a");
    a.href = url;
    a.download = file.filename;
    a.click();
  }

  const guard = downloadProtection
    ? {
        onContextMenu: (e: React.MouseEvent) => e.preventDefault(),
        onCopy: (e: React.ClipboardEvent) => e.preventDefault(),
        style: { userSelect: "none" as const },
      }
    : {};

  return (
    <div className="fixed inset-0 z-[100] flex flex-col bg-black/90 backdrop-blur-sm" {...guard}>
      {/* Toolbar */}
      <div className="flex items-center gap-3 px-5 py-3 text-white">
        <ShieldCheck className="h-5 w-5 text-emerald-400" />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold">{file?.filename}</p>
          <p className="text-xs text-white/50">
            Decrypted locally · auto-closes after 2 min idle
          </p>
        </div>
        {files.length > 1 && (
          <div className="flex items-center gap-1 text-sm">
            {files.map((f, i) => (
              <button
                key={i}
                onClick={() => setIndex(i)}
                className={`rounded-lg px-3 py-1.5 transition ${
                  i === index ? "bg-white/20" : "hover:bg-white/10 text-white/60"
                }`}
              >
                {i + 1}
              </button>
            ))}
          </div>
        )}
        {!downloadProtection && (
          <button
            onClick={download}
            className="flex items-center gap-2 rounded-xl bg-white/10 px-4 py-2 text-sm font-medium transition hover:bg-white/20"
          >
            <Download className="h-4 w-4" />
            Download
          </button>
        )}
        <button
          onClick={onClose}
          className="rounded-xl bg-white/10 p-2 transition hover:bg-white/20"
          aria-label="Close viewer"
        >
          <X className="h-5 w-5" />
        </button>
      </div>

      {screenshotWarn && (
        <div className="mx-5 mb-2 flex items-center gap-2 rounded-xl bg-amber-500/20 px-4 py-2 text-sm text-amber-200">
          <Camera className="h-4 w-4 shrink-0" />
          The sender asked for screenshot protection. Browsers can&apos;t block screenshots —
          this view is watermarked and every open is logged.
        </div>
      )}

      {/* Content */}
      <div className="relative m-5 mt-0 flex min-h-0 flex-1 items-center justify-center overflow-hidden rounded-2xl bg-black/40">
        {bodyText && index === 0 && files.length === 0 ? null : null}
        {file && url && <FileBody file={file} url={url} protectedView={downloadProtection} />}

        {/* Watermark overlay */}
        {watermarkText && (
          <div
            aria-hidden
            className="pointer-events-none absolute inset-0 z-10 overflow-hidden"
          >
            <div className="absolute -inset-1/2 flex rotate-[-30deg] flex-wrap content-start gap-x-16 gap-y-20 opacity-[0.14]">
              {Array.from({ length: 60 }).map((_, i) => (
                <span key={i} className="whitespace-nowrap text-lg font-semibold text-white">
                  {watermarkText}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Encrypted note */}
      {bodyText && (
        <div className="mx-5 mb-5 max-h-32 overflow-y-auto rounded-2xl bg-white/5 px-5 py-3 text-sm text-white/90">
          <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-white/40">
            <FileText className="h-3 w-3" /> Encrypted note
          </p>
          <p className="whitespace-pre-wrap">{bodyText}</p>
        </div>
      )}
    </div>
  );
}

function FileBody({
  file,
  url,
  protectedView,
}: {
  file: DecryptedFile;
  url: string;
  protectedView: boolean;
}) {
  const [text, setText] = useState<string | null>(null);
  const isText =
    file.mime.startsWith("text/") ||
    ["application/json", "application/xml"].includes(file.mime);

  useEffect(() => {
    if (isText) setText(new TextDecoder().decode(file.data));
    else setText(null);
  }, [file, isText]);

  if (file.mime.startsWith("image/")) {
    return (
      // eslint-disable-next-line @next/next/no-img-element
      <img
        src={url}
        alt={file.filename}
        className="max-h-full max-w-full object-contain"
        draggable={false}
      />
    );
  }
  if (file.mime === "application/pdf") {
    return (
      <iframe
        src={`${url}#toolbar=${protectedView ? 0 : 1}`}
        title={file.filename}
        className="h-full w-full"
      />
    );
  }
  if (file.mime.startsWith("video/")) {
    return (
      <video
        src={url}
        controls
        controlsList={protectedView ? "nodownload noremoteplayback" : undefined}
        className="max-h-full max-w-full"
      />
    );
  }
  if (file.mime.startsWith("audio/")) {
    return <audio src={url} controls controlsList={protectedView ? "nodownload" : undefined} />;
  }
  if (isText && text !== null) {
    return (
      <pre className="h-full w-full overflow-auto p-6 font-mono text-sm text-white/90">
        {text}
      </pre>
    );
  }
  return (
    <div className="text-center text-white/70">
      <FileText className="mx-auto mb-3 h-12 w-12 opacity-50" />
      <p className="font-medium">{file.filename}</p>
      <p className="mt-1 text-sm">
        No in-app preview for this format
        {protectedView ? " — and the sender disabled downloads." : ". Use Download to save it."}
      </p>
    </div>
  );
}
