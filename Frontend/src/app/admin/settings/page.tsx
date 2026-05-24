"use client";

import { useCallback, useEffect, useState } from "react";
import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import {
  getAdminProfile,
  getAdminSessions,
  revokeAdminSession,
  changeAdminPassword,
  getMfaStatus,
} from "./actions";

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : "Something went wrong";
}

type Profile = Awaited<ReturnType<typeof getAdminProfile>>;
type SessionItem = {
  session_hash_prefix: string;
  created_at: string;
  last_used_at: string;
  expires_at: string;
  is_current: boolean;
};
type MfaStatus = { enrolled: boolean; verified: boolean };

export default function AdminSettingsPage() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <SettingsBody />
    </AdminRouteGuard>
  );
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function roleLabel(role: string): string {
  switch (role) {
    case "super-admin":
      return "Super Admin";
    case "admin":
      return "Admin";
    case "operator":
      return "Operator";
    default:
      return role;
  }
}

/* ─── Section shell ─────────────────────────────────────────────────── */

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-6">
      <h2 className="mb-4 text-lg font-medium text-[var(--text-primary)]">
        {title}
      </h2>
      {children}
    </div>
  );
}

function FieldRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-[var(--border)] py-3 last:border-b-0">
      <span className="text-sm text-[var(--text-secondary)]">{label}</span>
      <span className="text-sm font-medium text-[var(--text-primary)]">{value}</span>
    </div>
  );
}

/* ─── Profile section ──────────────────────────────────────────────── */

function ProfileSection() {
  const [profile, setProfile] = useState<Profile | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let cancelled = false;
    getAdminProfile()
      .then((p) => {
        if (!cancelled) setProfile(p);
      })
      .catch((e) => {
        if (!cancelled) setError(errMsg(e));
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return (
      <Section title="Profile">
        <div className="rounded bg-red-900/30 px-3 py-2 text-sm text-red-200">
          {error}
        </div>
      </Section>
    );
  }

  if (!profile) {
    return (
      <Section title="Profile">
        <div className="text-sm text-[var(--text-muted)]">Loading…</div>
      </Section>
    );
  }

  return (
    <Section title="Profile">
      <FieldRow label="Email / Subject" value={profile.subject} />
      <FieldRow label="Role" value={roleLabel(profile.role)} />
      {profile.tenant_id && (
        <FieldRow label="Tenant" value={profile.tenant_id} />
      )}
      <FieldRow label="Created" value={formatDate(profile.created_at)} />
      <FieldRow
        label="Account Status"
        value={
          profile.disabled_at ? (
            <span className="text-red-400">Disabled</span>
          ) : (
            <span className="text-green-400">Active</span>
          )
        }
      />
    </Section>
  );
}

/* ─── MFA status section ─────────────────────────────────────────────── */

function MfaSection() {
  const [mfa, setMfa] = useState<MfaStatus | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    setLoading(true);
    getMfaStatus()
      .then(setMfa)
      .catch((e) => setError(errMsg(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <Section title="Two-Factor Authentication">
      {error && (
        <div className="mb-4 rounded bg-red-900/30 px-3 py-2 text-sm text-red-200">
          {error}
        </div>
      )}
      <div className="flex items-center justify-between border-b border-[var(--border)] py-3">
        <div>
          <p className="text-sm text-[var(--text-primary)]">
            TOTP Authenticator
          </p>
          <p className="text-xs text-[var(--text-muted)]">
            {loading
              ? "Checking…"
              : mfa?.enrolled
                ? "Your account is protected with TOTP two-factor authentication."
                : "Enable TOTP for an extra layer of security on sign-in."}
          </p>
        </div>
        <span
          className={`rounded px-2.5 py-0.5 text-xs font-semibold ${
            mfa?.enrolled
              ? "bg-green-900/40 text-green-300"
              : "bg-yellow-900/40 text-yellow-300"
          }`}
        >
          {loading ? "…" : mfa?.enrolled ? "Enabled" : "Off"}
        </span>
      </div>
      {!mfa?.enrolled && (
        <p className="mt-3 text-xs text-[var(--text-muted)]">
          TOTP enrollment can be activated via the MFA setup flow in a future
          update.
        </p>
      )}
    </Section>
  );
}

/* ─── Password change section ────────────────────────────────────────── */

function PasswordSection() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setSuccess(false);

    if (newPassword !== confirmPassword) {
      setError("Passwords do not match / Пароли не совпадают");
      return;
    }
    if (newPassword.length < 8) {
      setError("Password must be at least 8 characters / Минимум 8 символов");
      return;
    }

    setLoading(true);
    try {
      await changeAdminPassword(currentPassword, newPassword);
      setSuccess(true);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
    } catch (err) {
      setError(errMsg(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Section title="Change Password / Смена пароля">
      {success && (
        <div className="mb-4 rounded bg-green-900/30 px-3 py-2 text-sm text-green-200">
          Password changed successfully / Пароль успешно изменён.
        </div>
      )}
      {error && (
        <div className="mb-4 rounded bg-red-900/30 px-3 py-2 text-sm text-red-200">
          {error}
        </div>
      )}
      <form onSubmit={handleSubmit} className="flex flex-col gap-4">
        <label className="flex flex-col gap-1">
          <span className="text-sm text-[var(--text-secondary)]">
            Current Password / Текущий пароль
          </span>
          <input
            type="password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
            required
            maxLength={1024}
            autoComplete="current-password"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-sm text-[var(--text-secondary)]">
            New Password / Новый пароль
          </span>
          <input
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
            required
            minLength={8}
            maxLength={1024}
            autoComplete="new-password"
          />
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-sm text-[var(--text-secondary)]">
            Confirm Password / Подтвердите пароль
          </span>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
            required
            minLength={8}
            maxLength={1024}
            autoComplete="new-password"
          />
        </label>
        <button
          type="submit"
          disabled={loading}
          className="rounded bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition hover:opacity-90 disabled:opacity-50"
        >
          {loading ? "Changing… / Изменение…" : "Change Password / Сменить пароль"}
        </button>
      </form>
    </Section>
  );
}

/* ─── Sessions section ────────────────────────────────────────────────── */

function SessionsSection() {
  const [sessions, setSessions] = useState<SessionItem[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [revoking, setRevoking] = useState<string | null>(null);

  const refresh = useCallback(() => {
    setLoading(true);
    getAdminSessions()
      .then((data) => setSessions(data.sessions))
      .catch((e) => setError(errMsg(e)))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function handleRevoke(prefix: string) {
    setRevoking(prefix);
    try {
      await revokeAdminSession(prefix);
      setSessions((prev) =>
        prev.filter((s) => s.session_hash_prefix !== prefix),
      );
    } catch (e) {
      setError(errMsg(e));
    } finally {
      setRevoking(null);
    }
  }

  return (
    <Section title="Active Sessions / Активные сессии">
      {error && (
        <div className="mb-4 rounded bg-red-900/30 px-3 py-2 text-sm text-red-200">
          {error}
        </div>
      )}
      {loading ? (
        <p className="text-sm text-[var(--text-muted)]">Loading…</p>
      ) : sessions.length === 0 ? (
        <p className="text-sm text-[var(--text-muted)]">No active sessions.</p>
      ) : (
        <div className="flex flex-col gap-3">
          {sessions.map((s) => (
            <div
              key={s.session_hash_prefix}
              className="flex flex-col gap-1 rounded border border-[var(--border)] bg-[var(--bg-primary)] p-3 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <code className="text-xs font-mono text-[var(--text-primary)]">
                    {s.session_hash_prefix}…
                  </code>
                  {s.is_current && (
                    <span className="rounded bg-green-900/40 px-1.5 py-0.5 text-[10px] font-semibold text-green-300">
                      Current
                    </span>
                  )}
                </div>
                <p className="mt-1 text-xs text-[var(--text-muted)]">
                  Created: {formatDate(s.created_at)}
                </p>
                <p className="text-xs text-[var(--text-muted)]">
                  Last used: {formatDate(s.last_used_at)}
                </p>
                <p className="text-xs text-[var(--text-muted)]">
                  Expires: {formatDate(s.expires_at)}
                </p>
              </div>
              {!s.is_current && (
                <button
                  type="button"
                  onClick={() => handleRevoke(s.session_hash_prefix)}
                  disabled={revoking === s.session_hash_prefix}
                  className="mt-2 sm:mt-0 rounded border border-red-800/60 px-3 py-1 text-xs font-medium text-red-300 transition hover:bg-red-900/30 disabled:opacity-50"
                >
                  {revoking === s.session_hash_prefix ? "Revoking…" : "Revoke"}
                </button>
              )}
            </div>
          ))}
        </div>
      )}
      <button
        type="button"
        onClick={refresh}
        className="mt-4 text-xs text-[var(--text-secondary)] transition hover:text-[var(--accent)]"
      >
        Refresh / Обновить
      </button>
    </Section>
  );
}

/* ─── Main settings body ─────────────────────────────────────────────── */

function SettingsBody() {
  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="mb-6 text-xl font-semibold text-[var(--text-primary)]">
        Settings / Настройки
      </h1>
      <div className="flex flex-col gap-6">
        <ProfileSection />
        <MfaSection />
        <PasswordSection />
        <SessionsSection />
      </div>
    </div>
  );
}