# Thin wrapper: official cloudflared binary + Alpine sh for token validation and `run --token`.
# The upstream image has no shell, so we cannot avoid empty-token argv or print a clear error without this layer.
FROM cloudflare/cloudflared:latest AS upstream
FROM alpine:3.19
RUN apk add --no-cache ca-certificates
COPY --from=upstream /usr/local/bin/cloudflared /usr/local/bin/cloudflared
COPY docker-entrypoint.sh /docker-entrypoint.sh
# Strip Windows CRLF so `set -e` and shebang work when the repo is checked out on Windows.
RUN sed -i 's/\r$//' /docker-entrypoint.sh && chmod +x /docker-entrypoint.sh
ENTRYPOINT ["/docker-entrypoint.sh"]
