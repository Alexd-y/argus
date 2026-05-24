import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadEnvConfig } from "@next/env";
import type { NextConfig } from "next";

/** Frontend app root (avoids picking repo-root package-lock when monorepo has multiple lockfiles). */
const turbopackRoot = path.dirname(fileURLToPath(import.meta.url));

// Ensure .env / .env.local are applied before reading NEXT_* here (Next can evaluate config
// before env is visible — then allowedDevOrigins misses EC2 origins and Turbopack blocks /_next/*).
loadEnvConfig(turbopackRoot);

/** Build allowedDevOrigins entries: full URL plus host:port (Next docs use hostname patterns). */
function expandAllowedDevOrigins(raw: string): string[] {
  const seen = new Set<string>();
  const push = (s: string) => {
    const t = s.trim();
    if (t && !seen.has(t)) seen.add(t);
  };
  for (const part of raw.split(",")) {
    const p = part.trim();
    if (!p) continue;
    push(p);
    try {
      const u = new URL(p);
      const hostPort = u.port ? `${u.hostname}:${u.port}` : u.hostname;
      push(hostPort);
      if (u.port === "" || u.port === "80" || u.port === "443") {
        push(u.hostname);
      }
    } catch {
      /* already host:port or bare host */
    }
  }
  return [...seen];
}

const backendUrl =
  process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  turbopack: {
    root: turbopackRoot,
  },
  reactStrictMode: true,
  // Prevent Next.js dev server from killing idle SSE connections (24h timeout).
  experimental: {
    proxyTimeout: 86_400_000,
  },
  // Next 16+ dev: allow Turbopack /_next/* when Origin is not localhost (e.g. EC2 public URL).
  // Set NEXT_ALLOWED_DEV_ORIGINS=http://YOUR_IP:6000 in .env.local (comma-separated for several).
  allowedDevOrigins: [
    "http://localhost:6000",
    "http://127.0.0.1:6000",
    "localhost:6000",
    "127.0.0.1:6000",
    ...expandAllowedDevOrigins(process.env.NEXT_ALLOWED_DEV_ORIGINS ?? ""),
  ],
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: `${backendUrl}/api/v1/:path*`,
      },
    ];
  },
};

export default nextConfig;
