"use client";

import { useState } from "react";
import { requestPasswordReset } from "./actions";

export default function ResetPasswordPage() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await requestPasswordReset(email);
      setSent(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to request reset");
    } finally {
      setLoading(false);
    }
  }

  if (sent) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[var(--bg-primary)]">
        <div className="w-full max-w-md rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-8">
          <h1 className="mb-4 text-xl font-semibold text-[var(--text-primary)]">
            Check Your Email
          </h1>
          <p className="mb-4 text-sm text-[var(--text-secondary)]">
            If an account exists for <strong>{email}</strong>, you&apos;ll receive a password reset link
            with an OTP code. The link expires in 30 minutes.
          </p>
          <a
            href="/admin/login"
            className="inline-block rounded bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition hover:opacity-90"
          >
            Back to Login
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--bg-primary)]">
      <div className="w-full max-w-md rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-8">
        <h1 className="mb-2 text-xl font-semibold text-[var(--text-primary)]">
          Reset Password
        </h1>
        <p className="mb-6 text-sm text-[var(--text-muted)]">
          Enter your admin email address and we&apos;ll send you a reset link.
        </p>

        {error && (
          <div className="mb-4 rounded bg-red-900/30 px-3 py-2 text-sm text-red-200">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <label className="flex flex-col gap-1">
            <span className="text-sm text-[var(--text-secondary)]">Email</span>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)]"
              placeholder="admin@example.com"
              required
            />
          </label>

          <button
            type="submit"
            disabled={loading}
            className="rounded bg-[var(--accent)] px-4 py-2 text-sm font-medium text-white transition hover:opacity-90 disabled:opacity-50"
          >
            {loading ? "Sending..." : "Send Reset Link"}
          </button>
        </form>

        <p className="mt-4 text-center text-sm text-[var(--text-muted)]">
          <a href="/admin/login" className="text-[var(--accent)] underline">
            Back to Login
          </a>
        </p>
      </div>
    </div>
  );
}