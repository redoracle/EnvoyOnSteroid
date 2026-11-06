# Streaming protocol security boundary

**Not implemented.** The Envoy + Coraza reference deployment uses two
128 KiB buffering stages to inspect finite HTTP bodies and prevent a
WAF-denied request from being forwarded upstream. It is not a
WebSocket, streaming gRPC, or unlimited-upload gateway.

## Why a generic streaming switch would be unsafe

Streaming messages have no guaranteed end-of-request inspection point.
Removing the buffers or bypassing Coraza for upgraded traffic can forward
uninspected data to the backend. The test audit demonstrated this exact
type of failure for a JSON POST that received HTTP 403 but still reached
the upstream. Inspecting an HTTP upgrade handshake does **not** validate
subsequent WebSocket frames or gRPC messages.

## Requirements for a separate streaming implementation

1. Define the concrete application protocol, message schemas, allowed
   paths and methods, authentication and authorization rules.
2. Provide a separate, strictly allowlisted listener or virtual host,
   not a wildcard upgrade or WAF bypass on the existing HTTP listener.
3. Require authenticated ingress as appropriate (mTLS/origin/host
   checks), stream quotas, timeouts and bounded memory/backpressure.
4. Inspect and authorize **each message** at a protocol-aware boundary,
   not merely at connection handshake. Ensure business side effects
   happen only after required per-message validation.
5. Test fragmented frames, interleaving, oversize messages, slow
   senders, cancellations, reconnects, backend failures and mixed
   concurrent streams against a real streaming backend.
6. Require measured memory/latency and negative bypass tests before
   any production release.

No streaming backend or message contract currently exists in this
repository, so opening an unguarded upgrade path is not justified.
