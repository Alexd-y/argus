import path from "node:path";
import { fileURLToPath } from "node:url";

import type { NextConfig } from "next";

/** Frontend app root (avoids picking repo-root package-lock when monorepo has multiple lockfiles). */
const turbopackRoot = path.dirname(fileURLToPath(import.meta.url));

const backendUrl =
  process.env.NEXT_PUBLIC_BACKEND_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  turbopack: {
    root: turbopackRoot,
  },
  // Next 16+ dev: allow Turbopack /_next/* when Origin is not localhost (e.g. EC2 public URL).
  // Set NEXT_ALLOWED_DEV_ORIGINS=http://YOUR_IP:5000 in .env.local (comma-separated for several).
  allowedDevOrigins: [
    "http://localhost:5000",
    "http://127.0.0.1:5000",
    ...(process.env.NEXT_ALLOWED_DEV_ORIGINS ?? "")
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean),
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
