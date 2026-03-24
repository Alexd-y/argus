#!/bin/sh
set -e
# Prefer TUNNEL_TOKEN (set by Compose from CLOUDFLARE_TUNNEL_TOKEN); fall back to .env in container.
tok="${TUNNEL_TOKEN:-}"
if [ -z "$tok" ]; then
  tok="${CLOUDFLARE_TUNNEL_TOKEN:-}"
fi
if [ -z "$tok" ] || [ "$tok" = "REPLACE_ME" ]; then
  echo "ERROR: CLOUDFLARE_TUNNEL_TOKEN is missing or placeholder REPLACE_ME." >&2
  echo "Set it in infra/.env: Zero Trust → Networks → Tunnels → your tunnel → Install connector / Docker —" >&2
  echo "paste the JWT from: cloudflared tunnel run --token <JWT>" >&2
  echo "Without a token, cloudflared fails with: \"cloudflared tunnel run\" requires the ID or name of the tunnel" >&2
  exit 1
fi
exec cloudflared tunnel --no-autoupdate run --token "$tok"
