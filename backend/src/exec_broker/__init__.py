"""F-H01 Stage 4 — argus-exec-broker.

A tiny HTTP service that is the ONLY holder of the Docker socket. It accepts
"run tool X (argv) in container Y" requests, re-validates them server-side, and
performs the ``docker exec`` itself via the single gateway. It exposes no raw
Docker API, so the container-create escape that survives the Tecnativa proxy is
structurally unreachable through it.
"""
