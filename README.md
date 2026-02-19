# ICMP Proxy
[![Tests](https://github.com/hsnprsd/icmp-proxy/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/hsnprsd/icmp-proxy/actions/workflows/tests.yml)

Production-oriented ICMP tunnel prototype with:
- Binary wire protocol
- PSK-authenticated `HELLO`/`HELLO_ACK` handshake
- Reliable delivery (retransmit + duplicate suppression + ACK via `ack_num`)
- Stream lifecycle messages: `OPEN_STREAM`, `DATA`, `CLOSE`

Runtime support:
- Linux and macOS are supported for manual server/client execution.
- Raw ICMP sockets require elevated privileges (`root`/`sudo` on macOS, or `root`/`CAP_NET_RAW` on Linux).

## Debian Packages

Installable Debian packages are published on GitHub Releases for:

- Debian 12 (`amd64`)
- Ubuntu 24.04 (`amd64`)

Package matrix:

- `icmp-proxy-common_<version>_all.deb`: shared Python runtime and both CLI entry points
- `icmp-proxy-server_<version>_amd64.deb`: server systemd unit + `/etc/icmp-proxy/server.env`
- `icmp-proxy-client_<version>_amd64.deb`: client systemd unit + `/etc/icmp-proxy/client.env`

Quick install examples:

```bash
# Server host
sudo apt install ./icmp-proxy-common_<version>_all.deb ./icmp-proxy-server_<version>_amd64.deb

# Client host
sudo apt install ./icmp-proxy-common_<version>_all.deb ./icmp-proxy-client_<version>_amd64.deb
```

Post-install:

- Edit `/etc/icmp-proxy/server.env` and/or `/etc/icmp-proxy/client.env`
- Services are installed but not auto-enabled and not auto-started
- Start explicitly when config is ready:

```bash
sudo systemctl enable --now icmp-proxy-server
sudo systemctl enable --now icmp-proxy-client
```

## Documentation

- Design document: [`DESIGN.md`](DESIGN.md)
- Usage guide (server/client runbook): [`USAGE.md`](USAGE.md)
- Contributing guide (setup, local run, test policy): [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Agent-facing contribution pointer: [`AGENTS.md`](AGENTS.md)

## Configuration

Configuration is loaded with this precedence (lowest to highest):

1. Built-in defaults
2. `config.ini` in the current working directory
3. Environment variables (`ICMP_PROXY_*`)

Set `ICMP_PROXY_CONFIG_FILE` to load a specific INI path instead of `./config.ini`.
If `ICMP_PROXY_CONFIG_FILE` is set and the file does not exist, startup fails.

Example `config.ini`:

```ini
[common]
log_level = info
psk = change-me
client_id = default-client

[session]
max_inflight_per_stream = 1024
min_inflight_per_stream = 32
max_global_inflight = 2048
mtu_payload = 1200
heartbeat_interval_ms = 15000

[server]
bind_host = 0.0.0.0
client_host = 127.0.0.1
session_idle_timeout_ms = 60000
prometheus_enable = 1
prometheus_bind_host = 0.0.0.0
prometheus_port = 2112

[client]
server_host = 127.0.0.1
http_proxy_bind_host = 127.0.0.1
http_proxy_bind_port = 8080
socks_proxy_enable = 1
socks_proxy_bind_host = 127.0.0.1
socks_proxy_bind_port = 1080
```

Boolean parsing for all `*_ENABLE` settings: values `0`, `false`, `no`, `off` (case-insensitive) are treated as `false`; any other non-empty value is `true`.

### Parameter Reference

| Environment variable | INI key | Default | Description |
| --- | --- | --- | --- |
| `ICMP_PROXY_CONFIG_FILE` | n/a | `./config.ini` | Optional config file path override. If set but empty or missing, startup fails. |
| `ICMP_PROXY_LOG_LEVEL` | `[common].log_level` | `INFO` | Logging level; normalized to uppercase (for example `debug` -> `DEBUG`). |
| `ICMP_PROXY_PSK` | `[common].psk` | `change-me` | Shared pre-shared key for client/server authentication. |
| `ICMP_PROXY_CLIENT_ID` | `[common].client_id` | `default-client` | Client identity expected during authenticated handshake. |
| `ICMP_PROXY_AUTH_SKEW_MS` | `[common].auth_skew_ms` | `30000` | Allowed request timestamp skew window during authentication. |
| `ICMP_PROXY_AUTH_REPLAY_TTL_MS` | `[common].auth_replay_ttl_ms` | `30000` | Replay protection cache retention time for handshake attempts. |
| `ICMP_PROXY_AUTH_REPLAY_MAX_ENTRIES` | `[common].auth_replay_max_entries` | `8192` | Maximum replay cache size before old entries are evicted. |
| `ICMP_PROXY_RETX_TIMEOUT_MS` | `[session].retx_timeout_ms` | `100` | Initial retransmission timeout per reliable frame. |
| `ICMP_PROXY_RETX_MAX_RETRIES` | `[session].retx_max_retries` | `5` | Maximum retransmission attempts before giving up. |
| `ICMP_PROXY_RETX_SCAN_INTERVAL_MS` | `[session].retx_scan_interval_ms` | `20` | Interval for retransmission scan/timeout checks. |
| `ICMP_PROXY_SEEN_LIMIT_PER_STREAM` | `[session].seen_limit_per_stream` | `1024` | Duplicate-suppression cache size per stream. |
| `ICMP_PROXY_MAX_INFLIGHT_PER_STREAM` | `[session].max_inflight_per_stream` | `1024` | Max unacked reliable frames per stream; clamped to at least `1`. |
| `ICMP_PROXY_MIN_INFLIGHT_PER_STREAM` | `[session].min_inflight_per_stream` | `32` | Lower bound for adaptive inflight window; clamped to at least `1` and capped at `max_inflight_per_stream`. |
| `ICMP_PROXY_MAX_GLOBAL_INFLIGHT` | `[session].max_global_inflight` | `2048` | Global cap for unacked reliable frames across streams; clamped to at least `1`. |
| `ICMP_PROXY_MTU_PAYLOAD` | `[session].mtu_payload` | `1200` | Max payload bytes per tunneled DATA frame chunk. |
| `ICMP_PROXY_FLOWCONTROL_ENABLE` | `[session].flowcontrol_enable` | `1` | Enables adaptive flow control window tuning. |
| `ICMP_PROXY_FLOWCONTROL_ALPHA` | `[session].flowcontrol_alpha` | `0.125` | Smoothed RTT factor; clamped to `[0.01, 1.0]`. |
| `ICMP_PROXY_FLOWCONTROL_BETA` | `[session].flowcontrol_beta` | `0.25` | Smoothed loss factor; clamped to `[0.01, 1.0]`. |
| `ICMP_PROXY_FLOWCONTROL_INCREASE_STEP` | `[session].flowcontrol_increase_step` | `8` | Additive increase step for inflight window growth; clamped to at least `1`. |
| `ICMP_PROXY_FLOWCONTROL_DECREASE_FACTOR` | `[session].flowcontrol_decrease_factor` | `0.7` | Multiplicative decrease factor on loss; clamped to `[0.1, 0.99]`. |
| `ICMP_PROXY_FLOWCONTROL_LOSS_THRESHOLD` | `[session].flowcontrol_loss_threshold` | `0.02` | Loss ratio threshold that triggers window decrease; clamped to at least `0.0`. |
| `ICMP_PROXY_STATS_INTERVAL_MS` | `[session].stats_interval_ms` | `1000` | Interval for flow-control/performance stat updates; clamped to at least `100`. |
| `ICMP_PROXY_PERFORMANCE_METRICS_ENABLE` | `[session].performance_metrics_enable` | `0` | Emits periodic performance logs when enabled. |
| `ICMP_PROXY_HEARTBEAT_INTERVAL_MS` | `[session].heartbeat_interval_ms` | `15000` | Client heartbeat cadence used to keep authenticated sessions active on idle links (`0` disables heartbeats). |
| `ICMP_PROXY_BIND_HOST` | `[server].bind_host` | `0.0.0.0` | Local source IP used by server raw ICMP socket. |
| `ICMP_PROXY_CLIENT_HOST` | `[server].client_host` | `127.0.0.1` | Destination host for ICMP replies sent by server. |
| `ICMP_PROXY_TARGET_CONNECT_TIMEOUT_MS` | `[server].target_connect_timeout_ms` | `3000` | Timeout for outbound target TCP connects initiated by server streams. |
| `ICMP_PROXY_SESSION_IDLE_TIMEOUT_MS` | `[server].session_idle_timeout_ms` | `60000` | Server-side authenticated session idle timeout. |
| `ICMP_PROXY_PROMETHEUS_ENABLE` | `[server].prometheus_enable` | `1` | Enables Prometheus endpoint export on server. |
| `ICMP_PROXY_PROMETHEUS_BIND_HOST` | `[server].prometheus_bind_host` | `0.0.0.0` | Bind host for Prometheus metrics HTTP listener. |
| `ICMP_PROXY_PROMETHEUS_PORT` | `[server].prometheus_port` | `2112` | Bind port for Prometheus metrics HTTP listener. |
| `ICMP_PROXY_REMOTE_HOST` | `[client].server_host` | `127.0.0.1` | Remote ICMP server host used by client (env name differs from INI key). |
| `ICMP_PROXY_HTTP_PROXY_BIND_HOST` | `[client].http_proxy_bind_host` | `127.0.0.1` | Local bind host for HTTP proxy listener. |
| `ICMP_PROXY_HTTP_PROXY_BIND_PORT` | `[client].http_proxy_bind_port` | `8080` | Local bind port for HTTP proxy listener. |
| `ICMP_PROXY_SOCKS_PROXY_ENABLE` | `[client].socks_proxy_enable` | `1` | Enables local SOCKS5 listener on client. |
| `ICMP_PROXY_SOCKS_PROXY_BIND_HOST` | `[client].socks_proxy_bind_host` | `127.0.0.1` | Local bind host for SOCKS5 proxy listener. |
| `ICMP_PROXY_SOCKS_PROXY_BIND_PORT` | `[client].socks_proxy_bind_port` | `1080` | Local bind port for SOCKS5 proxy listener. |

Server exports Prometheus metrics at `/metrics` when enabled (default), for example:

```bash
curl http://127.0.0.1:2112/metrics
```
