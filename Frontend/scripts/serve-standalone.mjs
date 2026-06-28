/**
 * Production launcher for the Next.js standalone build (cross-platform).
 *
 * `next start` is NOT compatible with `output: "standalone"` (Next refuses and
 * the dev-origin gate / wrong port apply). The supported production runtime is
 * `node .next/standalone/server.js`, which serves `/_next/static` for ANY
 * origin — so the public scan UI renders correctly behind an EC2 public IP or
 * domain (no `allowedDevOrigins` gate, unlike `next dev`).
 *
 * The standalone bundle keeps static assets in `.next/static` and `public/`,
 * but `server.js` resolves them relative to its own directory. This launcher
 * colocates them into `.next/standalone/` (exactly what the Docker image does)
 * and then boots the server bound to 0.0.0.0 on the requested port.
 *
 * Usage:
 *   node scripts/serve-standalone.mjs        # PORT env or 5000
 *   node scripts/serve-standalone.mjs 6100   # explicit port (admin console)
 *   PORT=6100 node scripts/serve-standalone.mjs
 */
import { cpSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const appRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const standaloneDir = path.join(appRoot, ".next", "standalone");
const serverEntry = path.join(standaloneDir, "server.js");

if (!existsSync(serverEntry)) {
  console.error(
    "[serve-standalone] .next/standalone/server.js not found. Run `npm run build` first.",
  );
  process.exit(1);
}

// Colocate static assets next to server.js (mirrors infra Dockerfile COPY steps).
const copies = [
  [path.join(appRoot, ".next", "static"), path.join(standaloneDir, ".next", "static")],
  [path.join(appRoot, "public"), path.join(standaloneDir, "public")],
];
for (const [src, dest] of copies) {
  if (existsSync(src)) {
    cpSync(src, dest, { recursive: true });
  }
}

const portArg = process.argv[2]?.trim();
const port = (portArg && /^\d+$/.test(portArg) ? portArg : undefined) ?? process.env.PORT ?? "5000";

// Boot the standalone server in-process so signals (SIGINT/SIGTERM) propagate.
process.env.PORT = port;
process.env.HOSTNAME = process.env.HOSTNAME ?? "0.0.0.0";
process.env.NODE_ENV = "production";
// Production boot invariant (instrumentation.ts): admin auth must be `session`.
// The public scan UI does not use the admin surface, but the shared Next server
// still enforces this guard — default it so `npm start` boots out of the box.
process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE =
  process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE ?? "session";

process.chdir(standaloneDir);
// Dynamic import requires a file:// URL on Windows (bare drive paths are rejected).
await import(pathToFileURL(serverEntry).href);
