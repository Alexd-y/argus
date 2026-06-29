import { networkInterfaces } from "node:os";
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

/** App ports served by `next dev` (public scan UI :5000, admin console :6100). */
const APP_PORTS = ["5000", "6100"] as const;

/**
 * Non-internal IPv4 addresses of this host, expanded to bare host + host:port
 * for every app port. Next 16 blocks cross-origin `/_next/*` in dev unless the
 * Origin is allow-listed; on a self-hosted box (e.g. EC2 private IP / LAN /
 * container bridge) this lets the dev server load its own assets without a
 * hardcoded address. The browser-facing public IP/domain still has no local
 * interface entry — set NEXT_ALLOWED_DEV_ORIGINS for it, or (recommended for a
 * public deployment) run the production build (`npm start`) which has no
 * dev-origin gate.
 */
function localInterfaceDevOrigins(): string[] {
  const out: string[] = [];
  let ifaces: ReturnType<typeof networkInterfaces> = {};
  try {
    ifaces = networkInterfaces();
  } catch {
    return out;
  }
  for (const addrs of Object.values(ifaces)) {
    for (const addr of addrs ?? []) {
      if (addr.family !== "IPv4" || addr.internal || !addr.address) continue;
      out.push(addr.address);
      for (const port of APP_PORTS) {
        out.push(`${addr.address}:${port}`);
        out.push(`http://${addr.address}:${port}`);
      }
    }
  }
  return out;
}

// Use `||` (not `??`) so an empty string from a misconfigured build arg never
// produces a hostless rewrite destination (`/api/v1/:path*` → self → 404).
const backendUrl =
  process.env.NEXT_PUBLIC_BACKEND_URL?.trim() ||
  process.env.BACKEND_URL?.trim() ||
  "http://localhost:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  turbopack: {
    root: turbopackRoot,
  },
  // Next 16+ dev: allow Turbopack /_next/* when Origin is not localhost (e.g. EC2 public URL).
  // Set NEXT_ALLOWED_DEV_ORIGINS=http://YOUR_IP:6100 in .env.local (comma-separated for several).
  allowedDevOrigins: [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    "localhost:5000",
    "127.0.0.1:5000",
    "http://localhost:6100",
    "http://127.0.0.1:6100",
    "localhost:6100",
    "127.0.0.1:6100",
    ...localInterfaceDevOrigins(),
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
