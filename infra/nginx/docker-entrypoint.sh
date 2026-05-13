#!/bin/sh
set -e

# Build nginx CORS map entries from ARGUS_CORS_ALLOWED_ORIGINS (comma-separated).
#
# Two entry kinds are supported:
#   1. Exact match (default):
#         https://app.example.com
#      → "https://app.example.com" $http_origin;
#
#   2. PCRE regex match (entry starts with `~`, nginx map syntax):
#         ~^https://argus-frontend-[a-z0-9]+-alexds-projects-[a-z0-9]+\.vercel\.app$
#      → ~^https://argus-frontend-[a-z0-9]+-alexds-projects-[a-z0-9]+\.vercel\.app$ $http_origin;
#
# Regex entries are essential for Vercel preview URLs, which rotate on every
# deployment (e.g. argus-frontend-<HASH>-<org>-projects-<id>.vercel.app).
# Without regex support every preview redeploy would require a manual edit
# of .env + `docker compose up -d --force-recreate nginx`.
#
# Default (env var unset): localhost dev origins for local Frontend npm dev.

ORIGINS="${ARGUS_CORS_ALLOWED_ORIGINS:-http://localhost:3000,http://127.0.0.1:3000}"

# Build the entries with REAL newlines (not the literal "\n" escape sequence)
# so we can avoid `printf '%b'` later — that would interpret backslashes inside
# regex entries (e.g. `\.` becoming `.`, weakening the pattern).
MAP_ENTRIES=""
ENTRY_COUNT=0
NL='
'
IFS=','
for origin in $ORIGINS; do
    # Trim surrounding whitespace WITHOUT xargs/echo — both are POSIX-required
    # to interpret backslash escapes (`\.` → `.`), which silently weakens
    # regex entries. Pure parameter expansion preserves all characters.
    while [ "${origin# }" != "$origin" ] || [ "${origin#	}" != "$origin" ]; do
        origin="${origin# }"; origin="${origin#	}"
    done
    while [ "${origin% }" != "$origin" ] || [ "${origin%	}" != "$origin" ]; do
        origin="${origin% }"; origin="${origin%	}"
    done
    [ -z "$origin" ] && continue

    case "$origin" in
        '~'*)
            # nginx PCRE entry: NO quotes (nginx parses ~regex as a token).
            MAP_ENTRIES="${MAP_ENTRIES}    ${origin} \$http_origin;${NL}"
            ;;
        *)
            MAP_ENTRIES="${MAP_ENTRIES}    \"${origin}\" \$http_origin;${NL}"
            ;;
    esac
    ENTRY_COUNT=$((ENTRY_COUNT + 1))
done
unset IFS

# Direct assignment preserves backslashes inside regex patterns verbatim.
export ARGUS_CORS_MAP_ENTRIES="$MAP_ENTRIES"

# Optional backend auth header injection (gateway-side X-API-Key).
# This keeps API keys off the browser while allowing a public frontend to call
# protected backend endpoints through nginx.
GATEWAY_API_KEY="${ARGUS_GATEWAY_API_KEY:-}"
while [ "${GATEWAY_API_KEY# }" != "$GATEWAY_API_KEY" ] || [ "${GATEWAY_API_KEY#	}" != "$GATEWAY_API_KEY" ]; do
    GATEWAY_API_KEY="${GATEWAY_API_KEY# }"; GATEWAY_API_KEY="${GATEWAY_API_KEY#	}"
done
while [ "${GATEWAY_API_KEY% }" != "$GATEWAY_API_KEY" ] || [ "${GATEWAY_API_KEY%	}" != "$GATEWAY_API_KEY" ]; do
    GATEWAY_API_KEY="${GATEWAY_API_KEY% }"; GATEWAY_API_KEY="${GATEWAY_API_KEY%	}"
done
if [ -n "$GATEWAY_API_KEY" ]; then
    case "$GATEWAY_API_KEY" in
        *\"*|*\\*|*'$'*|*'`'*|*';'*)
            echo "[entrypoint] ARGUS_GATEWAY_API_KEY contains unsupported characters"
            exit 1
            ;;
    esac
    export ARGUS_PROXY_API_KEY_HEADER="        proxy_set_header   X-API-Key         \"${GATEWAY_API_KEY}\";"
    API_KEY_INJECTION_STATUS="enabled"
else
    export ARGUS_PROXY_API_KEY_HEADER=""
    API_KEY_INJECTION_STATUS="disabled"
fi

envsubst '${ARGUS_CORS_MAP_ENTRIES} ${ARGUS_PROXY_API_KEY_HEADER}' \
    < /etc/nginx/conf.d/api.conf.template \
    > /etc/nginx/conf.d/api.conf

# Validate the generated config before launching nginx — fail fast with a
# readable error in `docker logs argus-nginx` instead of a restart loop.
if ! nginx -t 2>/tmp/nginx-test.err; then
    echo "[entrypoint] nginx config invalid (likely a bad regex in ARGUS_CORS_ALLOWED_ORIGINS):"
    cat /tmp/nginx-test.err
    exit 1
fi

echo "[entrypoint] CORS origins configured (count: ${ENTRY_COUNT})"
echo "[entrypoint] Upstream API key header injection: ${API_KEY_INJECTION_STATUS}"
exec nginx -g 'daemon off;'
