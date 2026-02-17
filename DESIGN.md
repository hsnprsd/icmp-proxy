# ICMP Proxy Design

## Purpose
This document describes the current design and behavior of this repository (`icmp-proxy`) as implemented in code.

This is an implementation document, not a compatibility promise.

## Non-Goals
- Guaranteeing backward wire compatibility across commits.
- Claiming production-grade hardening for hostile networks.
- Replacing code-level behavior as the source of truth.

## System Overview
`icmp-proxy` tunnels application traffic over ICMP between two roles:
- `client`: accepts local proxy traffic (HTTP proxy and SOCKS5 proxy), encapsulates it into ICMP frames, and sends to server.
- `server`: decapsulates ICMP frames, opens outbound TCP/UDP sockets, and relays data back.

The tunnel uses raw ICMP sockets (`socket.AF_INET`, `socket.SOCK_RAW`, `socket.IPPROTO_ICMP`) and therefore typically requires elevated privileges (root or equivalent capability).

## High-Level Architecture

### Module Responsibilities
- `icmp_proxy/client.py`: client session auth, stream open/close/data, HTTP proxy frontend, SOCKS5 frontend.
- `icmp_proxy/server.py`: server auth handling, stream lifecycle, outbound TCP/UDP relay.
- `icmp_proxy/transport.py`: reliable frame transport over ICMP (ACKs, retransmit, duplicate suppression, adaptive inflight window).
- `icmp_proxy/protocol.py`: wire format constants, frame header, message payload encoders/decoders.
- `icmp_proxy/auth.py`: PSK-based HMAC signing/verification, nonce generation, replay cache, timestamp checks.
- `icmp_proxy/icmp.py`: ICMP packet encode/decode and checksum validation.
- `icmp_proxy/config.py`: defaults + INI + env resolution and typed config structures.
- `icmp_proxy/metrics.py`: generic counters/gauges utility (currently not central to transport path).

### Data Paths

#### TCP proxy flow
1. Local app connects to client HTTP proxy or SOCKS5 proxy (`CONNECT`).
2. Client authenticates session (HELLO/HELLO_ACK) if not already done.
3. Client sends `OPEN_STREAM` (reliable) with target host/port.
4. Server dials upstream TCP target and responds `OPEN_OK` or `OPEN_ERR`.
5. Both sides exchange `DATA` frames (reliable), chunked by `session.mtu_payload`.
6. Either side sends `CLOSE`; peer responds `CLOSE_ACK`; stream state is cleared.

#### UDP proxy flow (SOCKS5 `UDP ASSOCIATE`)
1. Local app performs SOCKS5 auth/method negotiation (no-auth only).
2. Client sends `OPEN_DATAGRAM` (reliable).
3. Server allocates datagram stream state and returns `OPEN_OK`.
4. UDP payloads are wrapped as `DatagramPacket` inside `DATA` frames.
5. SOCKS5 UDP fragmentation is not supported (`FRAG` must be `0`).

## Wire Protocol

### Frame Header
All tunnel messages are sent in `Frame`:
- `flags` (`u8`)
- `msg_type` (`u8`)
- `reserved` (`u8`)
- `session_id` (`u32`)
- `stream_id` (`u32`)
- `seq_num` (`u32`)
- `ack_num` (`u32`)
- `payload_len` (`u16`)
- `payload` (`payload_len` bytes)

Maximum frame payload is `65535` bytes (`MAX_PAYLOAD_LEN`), but practical data chunking is additionally bounded by configured `mtu_payload`.

### Message Types
- `HELLO`
- `HELLO_ACK`
- `OPEN_STREAM`
- `OPEN_OK`
- `OPEN_ERR`
- `DATA`
- `CLOSE`
- `CLOSE_ACK`
- `KEEPALIVE`
- `OPEN_DATAGRAM`

### Flags
- `FLAG_RELIABLE (0x01)`: frame participates in reliable delivery.
- `FLAG_FRAGMENTED (0x02)`: defined constant, not currently implemented by transport logic.

### Payload Structures
- `HELLO`: `client_id`, `client_nonce`, `timestamp_ms`, HMAC.
- `HELLO_ACK`: `server_nonce`, `timestamp_ms`, HMAC.
- `OPEN_STREAM`: destination host + port.
- `OPEN_DATAGRAM`: empty payload.
- `OPEN_OK`: assigned `stream_id`.
- `OPEN_ERR`: `error_code` + `reason`.
- `DATA`: opaque bytes (TCP bytes or encoded `DatagramPacket`).
- `CLOSE`, `CLOSE_ACK`, `KEEPALIVE`: empty payload.
- `DatagramPacket`: address type + remote host + remote port + UDP payload (IPv4/IPv6/domain).

## Authentication and Session Establishment

### Handshake
- Client sends `HELLO` (reliable) with:
  - configured `client_id`
  - random 16-byte nonce
  - timestamp
  - `HMAC-SHA256(psk, client_id || 0x00 || nonce || timestamp)`
- Server validates:
  - `client_id` matches configured expected value
  - timestamp is within `auth_skew_ms`
  - nonce is fresh in replay cache (`ReplayCache` with TTL and max entries)
  - HMAC signature is valid
- Server returns `HELLO_ACK` with:
  - random server nonce
  - timestamp
  - `HMAC-SHA256(psk, session_id || client_nonce || server_nonce || timestamp)`
- Client validates timestamp and signature, then adopts returned `session_id`.

### Session behavior
- Server supports multiple authenticated sessions concurrently.
- Session IDs are bound to the source host observed during handshake.
- Server caches recent successful HELLO nonces to re-send the same `HELLO_ACK` for retransmitted HELLO frames within replay TTL.
- Idle authenticated sessions are evicted after `session_idle_timeout_ms`.

## Reliable Transport Behavior (`ReliableICMPSession`)

### Reliability model
- `send_reliable(...)` assigns per-stream sequence numbers (`seq_num`) and marks frames with `FLAG_RELIABLE`.
- Receiver sends `KEEPALIVE` with `ack_num = received seq_num`.
- Sender removes pending frame when matching ACK is observed.
- Duplicate reliable inbound frames are detected per stream (`seen_limit_per_stream`) and dropped after ACKing.

### Retransmission
- Pending reliable frames are scanned every `retx_scan_interval_ms`.
- If not ACKed by `retx_timeout_ms`, frame is resent.
- After `retx_max_retries`, frame is dropped and optional `on_retry_exhausted(session_id, stream_id, msg_type)` callback fires.

### Inflight control
- Limits:
  - per-stream inflight cap (`max_inflight_per_stream`)
  - global inflight cap (`max_global_inflight`)
  - minimum per-stream window (`min_inflight_per_stream`)
- `send_reliable` blocks up to ~2 seconds waiting for inflight capacity before raising `TimeoutError`.

### Adaptive flow control
When enabled (`flowcontrol_enable`), transport adjusts stream window sizes using retry pressure and saturation:
- Increase when stream is saturated and global headroom exists.
- Decrease when retry ratio exceeds `flowcontrol_loss_threshold`.
- Behavior tuned by `flowcontrol_*` parameters.

### Performance logging
- Transport periodically takes stats snapshots (`stats_interval_ms`).
- Flow stats are logged only if `performance_metrics_enable` is enabled.

## Client-Side Proxy Frontends

### HTTP proxy behavior
- Supports:
  - `CONNECT host:port` (for HTTPS tunneling)
  - origin-form requests with `Host` header
  - absolute-form `http://...` requests (rewritten to origin-form upstream)
- Does not support absolute-form `https://...` requests for direct HTTP proxying.
- Rewrites/filters proxy hop headers and forces `Connection: close`.

### SOCKS5 behavior
- SOCKS version 5 only.
- Authentication methods: no-auth only.
- Commands:
  - `CONNECT` (TCP stream tunneling)
  - `UDP ASSOCIATE` (UDP relay through datagram stream)
- UDP associate:
  - accepts only unfragmented SOCKS5 UDP datagrams (`FRAG=0`)
  - tracks first client UDP source address unless request provides a concrete client addr/port

## Server Relay Behavior

### TCP streams
- On `OPEN_STREAM`, server opens outbound TCP connection with `target_connect_timeout_ms`.
- On success, server creates a tunnel stream ID, sends `OPEN_OK`, and starts relay thread.
- On upstream connect failure, returns `OPEN_ERR` (`503 upstream connect failed`).

### Datagram streams
- On `OPEN_DATAGRAM`, server creates datagram stream state and relay thread.
- UDP sockets are maintained per address family (IPv4/IPv6) and opened lazily on first send.
- Oversized inbound UDP packets (encoded size > `mtu_payload`) are dropped rather than fragmented.

## Configuration Model

### Source precedence
1. Built-in defaults.
2. `config.ini` in current directory (or explicit path via `ICMP_PROXY_CONFIG_FILE`).
3. Environment variables (`ICMP_PROXY_*`) override INI/defaults.

### Validation behavior
- If `ICMP_PROXY_CONFIG_FILE` is set and path does not exist, startup fails.
- Unknown INI sections or keys fail config load.
- Numeric/boolean fields are parsed and clamped where applicable.

### Key config groups
- Auth and identity: `ICMP_PROXY_PSK`, `ICMP_PROXY_CLIENT_ID`, replay/skew settings.
- Transport reliability: retransmit timers, retries, seen cache, inflight limits.
- Flow control: `ICMP_PROXY_FLOWCONTROL_*`.
- Endpoints/listeners:
  - server: `ICMP_PROXY_BIND_HOST`, `ICMP_PROXY_CLIENT_HOST`
  - client: `ICMP_PROXY_REMOTE_HOST`, HTTP/SOCKS bind vars
- Session lifecycle: `ICMP_PROXY_SESSION_IDLE_TIMEOUT_MS`

## Operational Notes
- Entry points:
  - server: `python3 -m icmp_proxy.server`
  - client: `python3 -m icmp_proxy.client`
- Both sides use raw ICMP sockets and require appropriate privileges.
- Local E2E tests may require disabling kernel ICMP echo replies (`net.ipv4.icmp_echo_ignore_all=1`) to avoid collisions.
- Graceful close paths attempt stream cleanup and transport state cleanup on both sides.

## Security Considerations
- The built-in default PSK (`change-me`) is insecure and intended only for development.
- Handshake authenticity is PSK-backed (HMAC), with timestamp window and nonce replay defenses.
- Post-handshake tunnel frames are not individually HMAC-authenticated or encrypted; payload confidentiality is not provided by this protocol.
- Deploy with network controls (ACLs/firewall segmentation) and strong PSK management.
- Limit exposure of local proxy listeners to trusted interfaces.

## Known Limitations
- Compatibility is intentionally unstable during active development.
- No implemented use of `FLAG_FRAGMENTED`; oversized tunnel payloads are dropped or must be pre-chunked by sender.
- SOCKS5 UDP fragmentation unsupported (`FRAG=0` only).
- TCP upstream dial path is IPv4 socket based (`AF_INET`), while datagram path supports IPv4/IPv6 via `getaddrinfo`.
- ICMP may be filtered, rate-limited, or deprioritized by networks/middleboxes.

## Future Work (Potential)
- Per-frame authenticated encryption for confidentiality/integrity.
- Full fragmentation/reassembly support.
- Stronger observability and exported metrics endpoints.

## Glossary
- Session: authenticated client-server tunnel identified by `session_id`.
- Stream: logical channel within a session (`stream_id`) for TCP or datagram relay.
- Inflight: reliable frames sent but not yet ACKed.
- ACK: acknowledgment represented by `ack_num` on inbound frame.
- Retransmit: resend of pending reliable frame after timeout.
- Goodput: acknowledged payload bytes per second (logged flow metric).
