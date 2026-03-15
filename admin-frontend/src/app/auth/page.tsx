"use client";

import { useEffect, useState } from "react";

export default function AuthPage() {
  const [key, setKey] = useState("");
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (typeof window !== "undefined") {
      setKey(localStorage.getItem("admin_key") ?? "");
    }
  }, []);

  const handleSave = (e: React.FormEvent) => {
    e.preventDefault();
    if (typeof window !== "undefined") {
      localStorage.setItem("admin_key", key);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    }
  };

  const handleClear = () => {
    if (typeof window !== "undefined") {
      localStorage.removeItem("admin_key");
      setKey("");
    }
  };

  return (
    <div className="mx-auto max-w-md">
      <h1 className="mb-4 text-xl font-semibold">Admin Auth</h1>
      <p className="mb-4 text-sm text-neutral-500">
        When backend ADMIN_API_KEY is set, admin endpoints require X-Admin-Key header.
        Store your key here (saved in localStorage). Leave empty for dev when ADMIN_API_KEY is not set.
      </p>
      <form onSubmit={handleSave} className="space-y-3">
        <input
          type="password"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="Admin API Key"
          className="w-full rounded border border-neutral-600 bg-neutral-900 px-3 py-2 text-white placeholder:text-neutral-500 focus:border-indigo-500 focus:outline-none"
        />
        <div className="flex gap-2">
          <button
            type="submit"
            className="rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-500"
          >
            {saved ? "Saved" : "Save Key"}
          </button>
          <button
            type="button"
            onClick={handleClear}
            className="rounded border border-neutral-600 px-4 py-2 text-neutral-400 hover:text-white"
          >
            Clear
          </button>
        </div>
      </form>
    </div>
  );
}
