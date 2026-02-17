# ICMP Proxy

Production-oriented ICMP tunnel prototype with:
- Versioned wire protocol (`PROTOCOL_VERSION=1`)
- PSK-authenticated `HELLO`/`HELLO_ACK` handshake
- Reliable delivery (retransmit + duplicate suppression + ACK via `ack_num`)
- Stream lifecycle messages: `OPEN_STREAM`, `DATA`, `CLOSE`

## Compatibility Policy

During active development, backward compatibility is intentionally not preserved.
Wire protocol, message formats, and module/CLI interfaces may break between commits.

## Configuration

The runtime is configured through environment variables:

- `ICMP_PROXY_PSK_FILE` (default: `./psk.txt`)
- `ICMP_PROXY_CLIENT_ID` (default: `default-client`)
- `ICMP_PROXY_REMOTE_HOST` (client-side, default: `127.0.0.1`)
- `ICMP_PROXY_BIND_HOST` (server-side, default: `0.0.0.0`)
- `ICMP_PROXY_CLIENT_HOST` (server-side destination for replies, default: `127.0.0.1`)
- `ICMP_PROXY_MAX_STREAMS` (default: `512`)
- `ICMP_PROXY_MAX_INFLIGHT_PER_STREAM` (default: `32`)
- `ICMP_PROXY_MTU_PAYLOAD` (default: `1200`)
- `ICMP_PROXY_RETX_TIMEOUT_MS` (default: `100`)
- `ICMP_PROXY_RETX_MAX_RETRIES` (default: `5`)
- `ICMP_PROXY_RETX_SCAN_INTERVAL_MS` (default: `20`)
- `ICMP_PROXY_LOG_LEVEL` (default: `INFO`)

## Local Development

Create a PSK file:

```bash
printf "dev-secret\n" > psk.txt
```

Run syntax checks:

```bash
python3 -m py_compile icmp_proxy/*.py tests/*.py
```

Run non-root tests:

```bash
python3 -m pytest -m "not requires_root"
```

Run root E2E tests:

```bash
./run_e2e_tests.sh local
./run_e2e_tests.sh external
```

## Running

Disable kernel echo replies for local end-to-end testing:

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

Start server:

```bash
sudo -E ICMP_PROXY_PSK_FILE=./psk.txt ICMP_PROXY_CLIENT_ID=default-client python3 -m icmp_proxy.server
```

Start client:

```bash
sudo -E ICMP_PROXY_PSK_FILE=./psk.txt ICMP_PROXY_CLIENT_ID=default-client ICMP_PROXY_REMOTE_HOST=127.0.0.1 python3 -m icmp_proxy.client
```

Restore host default:

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
