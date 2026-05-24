"use client";

import { useState } from "react";
import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { changeAdminPassword } from "./actions";

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : "Something went wrong";
}

export default function AdminSettingsPage() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <SettingsBody />
    </AdminRouteGuard>
  );
}

function SettingsBody() {
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
      setError("Пароли не совпадают / Passwords do not match");
      return;
    }
    if (newPassword.length < 8) {
      setError("Пароль должен быть не менее 8 символов / Password must be at least 8 characters");
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
    <div className="mx-auto max-w-lg">
      <h1 className="mb-6 text-xl font-semibold text-[var(--text-primary)]">
        Настройки / Settings
      </h1>

      <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-6">
        <h2 className="mb-4 text-lg font-medium text-[var(--text-primary)]">
          Смена пароля / Change Password
        </h2>

        {success && (
          <div className="mb-4 rounded bg-green-900/30 px-3 py-2 text-sm text-green-200">
            Пароль успешно изменён / Password changed successfully.
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
              Текущий пароль / Current Password
            </span>
            <input
              type="password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
              required
              maxLength={1024}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-sm text-[var(--text-secondary)]">
              Новый пароль / New Password
            </span>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
              required
              minLength={8}
              maxLength={1024}
            />
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-sm text-[var(--text-secondary)]">
              Подтвердите пароль / Confirm Password
            </span>
            <input
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
              required
              minLength={8}
              maxLength={1024}
            />
          </label>

          <button
            type="submit"
            disabled={loading}
            className="rounded bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition hover:opacity-90 disabled:opacity-50"
          >
            {loading ? "Изменение..." : "Сменить пароль / Change Password"}
          </button>
        </form>
      </div>
    </div>
  );
}