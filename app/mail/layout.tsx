"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Inbox,
  Send,
  PenLine,
  Lock,
  Trash2,
  Activity,
  Settings,
  Plus,
  Search,
  Bell,
  Moon,
  Sun,
  LogOut,
  Fingerprint,
} from "lucide-react";
import { api } from "@/lib/client/api";

interface Me {
  user: { id: string; email: string };
}

interface Notification {
  id: number;
  type: string;
  text: string;
  read: number;
  created_at: number;
}

const NAV = [
  { href: "/mail/inbox", label: "Inbox", icon: Inbox },
  { href: "/mail/sent", label: "Sent", icon: Send },
  { href: "/mail/drafts", label: "Drafts", icon: PenLine },
  { href: "/mail/vault", label: "Secure Vault", icon: Lock },
  { href: "/mail/trash", label: "Trash", icon: Trash2 },
];

const NAV_SECONDARY = [
  { href: "/mail/activity", label: "Activity", icon: Activity },
  { href: "/mail/settings", label: "Settings", icon: Settings },
];

export default function MailLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [me, setMe] = useState<Me["user"] | null>(null);
  const [dark, setDark] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [showNotifications, setShowNotifications] = useState(false);
  const [query, setQuery] = useState("");

  useEffect(() => {
    setQuery(new URLSearchParams(window.location.search).get("q") ?? "");
  }, []);
  const notifRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    api<Me>("/api/auth/me")
      .then((d) => setMe(d.user))
      .catch(() => router.replace("/login"));
  }, [router]);

  useEffect(() => {
    setDark(document.documentElement.classList.contains("dark"));
  }, []);

  const refreshNotifications = useCallback(() => {
    api<{ notifications: Notification[] }>("/api/notifications")
      .then((d) => setNotifications(d.notifications))
      .catch(() => {});
  }, []);

  useEffect(() => {
    refreshNotifications();
    const t = setInterval(refreshNotifications, 15_000);
    return () => clearInterval(t);
  }, [refreshNotifications]);

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
    }
    document.addEventListener("mousedown", onClick);
    return () => document.removeEventListener("mousedown", onClick);
  }, []);

  function toggleDark() {
    const next = !dark;
    setDark(next);
    document.documentElement.classList.toggle("dark", next);
    localStorage.setItem("bv_theme", next ? "dark" : "light");
  }

  async function logout() {
    await api("/api/auth/logout", { method: "POST" });
    router.replace("/login");
  }

  function onSearch(e: React.FormEvent) {
    e.preventDefault();
    const base = pathname.startsWith("/mail/") ? pathname : "/mail/inbox";
    router.replace(query ? `${base}?q=${encodeURIComponent(query)}` : base);
  }

  const unread = notifications.filter((n) => !n.read).length;

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="glass flex w-60 shrink-0 flex-col border-r p-4">
        <Link href="/mail/inbox" className="mb-6 flex items-center gap-2.5 px-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-sky-900 to-cyan-500 text-white">
            <Fingerprint className="h-5 w-5" />
          </div>
          <span className="text-lg font-bold tracking-tight">BioVault</span>
        </Link>

        <Link href="/mail/compose" className="btn-primary mb-6 w-full">
          <Plus className="h-4 w-4" />
          New secure send
        </Link>

        <nav className="space-y-1">
          {NAV.map((item) => {
            const active = pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition ${
                  active
                    ? "bg-sky-500/10 text-sky-600 dark:bg-sky-400/10 dark:text-sky-300"
                    : "text-slate-600 hover:bg-slate-200/60 dark:text-slate-400 dark:hover:bg-white/5"
                }`}
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="mt-auto space-y-1 border-t border-slate-200/70 pt-4 dark:border-white/10">
          {NAV_SECONDARY.map((item) => {
            const active = pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition ${
                  active
                    ? "bg-sky-500/10 text-sky-600 dark:bg-sky-400/10 dark:text-sky-300"
                    : "text-slate-600 hover:bg-slate-200/60 dark:text-slate-400 dark:hover:bg-white/5"
                }`}
              >
                <item.icon className="h-4 w-4" />
                {item.label}
              </Link>
            );
          })}
          <button
            onClick={logout}
            className="flex w-full items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-200/60 dark:text-slate-400 dark:hover:bg-white/5"
          >
            <LogOut className="h-4 w-4" />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main column */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Topbar */}
        <header className="glass flex items-center gap-3 border-b px-6 py-3">
          <form onSubmit={onSearch} className="relative max-w-md flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search subjects, senders, tags…"
              className="input pl-9"
            />
          </form>

          <div className="ml-auto flex items-center gap-2">
            <div className="relative" ref={notifRef}>
              <button
                onClick={() => {
                  setShowNotifications((v) => !v);
                  if (!showNotifications && unread > 0) {
                    api("/api/notifications", { method: "POST" }).then(refreshNotifications);
                  }
                }}
                className="btn-ghost relative p-2.5"
                aria-label="Notifications"
              >
                <Bell className="h-5 w-5" />
                {unread > 0 && (
                  <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-rose-500 px-1 text-[10px] font-bold text-white">
                    {unread}
                  </span>
                )}
              </button>
              {showNotifications && (
                <div className="glass animate-rise absolute right-0 top-12 z-50 max-h-96 w-80 overflow-y-auto rounded-2xl p-2 shadow-2xl">
                  {notifications.length === 0 ? (
                    <p className="px-3 py-6 text-center text-sm text-slate-500">
                      No notifications yet
                    </p>
                  ) : (
                    notifications.map((n) => (
                      <div
                        key={n.id}
                        className={`rounded-xl px-3 py-2.5 text-sm ${
                          n.read ? "opacity-60" : ""
                        }`}
                      >
                        <p>{n.text}</p>
                        <p className="mt-0.5 text-xs text-slate-400">
                          {new Date(n.created_at).toLocaleString()}
                        </p>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            <button onClick={toggleDark} className="btn-ghost p-2.5" aria-label="Toggle theme">
              {dark ? <Sun className="h-5 w-5" /> : <Moon className="h-5 w-5" />}
            </button>

            <div
              className="flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-sky-900 to-cyan-500 text-sm font-bold text-white"
              title={me?.email}
            >
              {me?.email?.[0]?.toUpperCase() ?? "?"}
            </div>
          </div>
        </header>

        <main className="min-h-0 flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}
