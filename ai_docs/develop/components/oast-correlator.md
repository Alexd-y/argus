# OAST correlator and Redis Streams (T01)

## Role

`OASTCorrelator` (`backend/src/oast/correlator.py`) holds in-memory interaction state and unblocks async waiters when callbacks arrive. For **durable, replay-capable** fan-out across processes, enable **Redis Streams** via `OASTRedisStreamBridge` (`backend/src/oast/redis_stream.py`).

## Behaviour

- **Producer**: after a successful in-memory ingest, the bridge issues `XADD` to a single stream with one field, `payload` (JSON of `OASTInteraction`). Approximate trim uses `MAXLEN ~` from settings.
- **Consumer**: one consumer group (`oast_stream_group`) and `XREADGROUP` on that stream; each message is re-applied with `OASTCorrelator.ingest` (idempotent via `(token_id, interaction.id)` dedup), then `XACK`.
- **Redis unavailable**: `XADD` is skipped; structured warning logs (`oast.redis_stream.*`) without secrets or raw stack traces in API responses. In-process correlation still works for the local process (degraded multi-instance fan-out).

## Configuration

Uses the existing **`redis_url`** (TLS: `rediss://`). Keys:

| Env | Purpose |
|-----|---------|
| `OAST_REDIS_STREAMS_ENABLED` | `true` to enable bridge |
| `OAST_STREAM_KEY` | Stream name (default `argus:oast:interactions`) |
| `OAST_STREAM_GROUP` | Consumer group (default `argus-oast-correlators`) |
| `OAST_STREAM_CONSUMER_NAME` | Optional fixed consumer id; default `hostname-pid` |
| `OAST_STREAM_MAXLEN` | Approximate max stream length |
| `OAST_STREAM_BLOCK_MS` | `XREADGROUP` block timeout |

## Wiring

```python
from src.core.config import settings
from src.oast import OASTRedisStreamBridge, OASTCorrelator

bridge = OASTRedisStreamBridge(settings)
correlator = OASTCorrelator(
    provisioner,
    on_interaction_stored=bridge.publish_after_store,
)
# asyncio.create_task(bridge.run_consumer(correlator))  # when a singleton exists
```

## Follow-ups

See `.cursor/workspace/active/orch-argus-20260420-1430/notes/T01-followups.md` for pending backlog (e.g. `XAUTOCLAIM`, app lifespan wiring).
