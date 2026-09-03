import path from "node:path";
import { fileURLToPath } from "node:url";
import type { NextConfig } from "next";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));

// Server-side proxy target for the `/api/v1/*` rewrite. This MUST be the
// INTERNAL backend URL (docker DNS `backend:8000`), never a public IP/domain:
//   - The browser only ever calls same-origin, relative `/api/v1/*`, so the
//     public UI works unchanged on `http://<ip>:5000` today and on
//     `https://ragnarok.svalbard.ca` later — nothing to reconfigure on IP
//     rotation or domain cutover.
//   - Next bakes this destination into the standalone bundle at BUILD time
//     (see Frontend/Dockerfile), so it must resolve inside the compose network
//     at request time — `backend:8000` always does; a public `x.x.x.x:PORT`
//     breaks the moment the EC2 IP changes.
// `NEXT_PUBLIC_BACKEND_URL` is intentionally NOT consulted here (it is a
// browser-facing value that operators sometimes point at a public gateway).
const backendUrl =
  process.env.BACKEND_URL?.trim() ||
  process.env.ARGUS_BACKEND_URL?.trim() ||
  "http://backend:8000";

const nextConfig: NextConfig = {
  output: "standalone",
  turbopack: {
    root: projectRoot,
  },
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
