"use client";

import { useEffect, useState } from "react";
import {
  LogIn,
  LogOut,
  Send,
  Eye,
  Trash2,
  ShieldOff,
  Clock,
  UserPlus,
  ShieldAlert,
  Activity as ActivityIcon,
  Loader2,
} from "lucide-react";
import { api } from "@/lib/client/api";

interface AuditEvent {
  event: string;
  detail: string | null;
  ip: string | null;
  user_agent: string | null;
  created_at: number;
  message_id: string | null;
  subject: string | null;
}

const EVENT_STYLE: Record<string, { icon: typeof LogIn; label: string; cls: string }> = {
  login: { icon: LogIn, label: "Signed in", cls: "text-emerald-500 bg-emerald-500/10" },
  logout: { icon: LogOut, label: "Signed out", cls: "text-slate-500 bg-slate-500/10" },
  register: { icon: UserPlus, label: "Account created", cls: "text-sky-500 bg-sky-500/10" },
  sent: { icon: Send, label: "File sent", cls: "text-sky-500 bg-sky-500/10" },
  opened: { icon: Eye, label: "File opened", cls: "text-cyan-500 bg-cyan-500/10" },
  deleted: { icon: Trash2, label: "Deleted", cls: "text-slate-500 bg-slate-500/10" },
  revoked: { icon: ShieldOff, label: "Access revoked", cls: "text-rose-500 bg-rose-500/10" },
  expired: { icon: Clock, label: "Expired", cls: "text-amber-500 bg-amber-500/10" },
  login_failed: {
    icon: ShieldAlert,
    label: "Failed sign-in",
    cls: "text-rose-500 bg-rose-500/10",
  },
  biometric_failed: {
    icon: ShieldAlert,
    label: "Failed biometric check",
    cls: "text-rose-500 bg-rose-500/10",
  },
  register_failed: {
    icon: ShieldAlert,
    label: "Failed registration",
    cls: "text-rose-500 bg-rose-500/10",
  },
};

export default function ActivityPage() {
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<{ events: AuditEvent[] }>("/api/audit")
      .then((d) => setEvents(d.events))
      .catch((e) => setError(e.message));
  }, []);

  return (
    <div className="mx-auto max-w-3xl px-6 py-8">
      <h1 className="mb-1 text-2xl font-bold tracking-tight">Activity</h1>
      <p className="mb-6 text-sm text-slate-500">
        Full audit trail for your account — sign-ins, opens, deletions, failed biometric
        attempts, devices and IPs.
      </p>

      {error && (
        <p className="mb-4 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-600">{error}</p>
      )}

      {events === null ? (
        <div className="flex justify-center py-20">
          <Loader2 className="h-6 w-6 animate-spin text-sky-500" />
        </div>
      ) : events.length === 0 ? (
        <div className="glass flex flex-col items-center rounded-3xl py-20">
          <ActivityIcon className="mb-3 h-10 w-10 text-slate-300 dark:text-slate-600" />
          <p className="font-semibold">No activity yet</p>
        </div>
      ) : (
        <div className="glass divide-y divide-slate-200/60 rounded-3xl dark:divide-white/5">
          {events.map((e, i) => {
            const style = EVENT_STYLE[e.event] ?? {
              icon: ActivityIcon,
              label: e.event,
              cls: "text-slate-500 bg-slate-500/10",
            };
            return (
              <div key={i} className="flex items-center gap-4 px-5 py-3.5">
                <div
                  className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${style.cls}`}
                >
                  <style.icon className="h-4 w-4" />
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium">
                    {style.label}
                    {e.subject && (
                      <span className="font-normal text-slate-500"> · “{e.subject}”</span>
                    )}
                  </p>
                  <p className="truncate text-xs text-slate-400">
                    {e.detail && `${e.detail} · `}
                    {e.ip} · {e.user_agent?.slice(0, 60)}
                  </p>
                </div>
                <span className="shrink-0 text-xs text-slate-400">
                  {new Date(e.created_at).toLocaleString()}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
