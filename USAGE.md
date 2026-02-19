# ICMP Proxy Usage Guide

This guide is the canonical runtime reference for operating ICMP Proxy as a server/client pair.
It covers both manual execution and systemd-based deployment.

## Prerequisites

- Linux or macOS host(s) with Python 3 available.
- Privilege to open raw ICMP sockets:
  - Linux: run as `root`, or run with `CAP_NET_RAW` capability.
  - macOS: run as `root`/`sudo` (no `CAP_NET_RAW` equivalent).
- Network path must allow ICMP Echo Request/Reply between client and server hosts.
- A shared PSK must be configured on both sides.
- Do not use the default PSK `change-me` outside local testing.

For local loopback testing on one Linux machine, disable kernel ICMP echo replies first:

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

Restore when done (Linux):

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
```

## Configuration

Configuration precedence (low to high):

1. Built-in defaults
2. `./config.ini` in current working directory
3. Environment variables (`ICMP_PROXY_*`)

Optional config file override:

- `ICMP_PROXY_CONFIG_FILE=/path/to/config.ini`
- If this variable is set and the file is missing, startup fails.

INI/env naming note:

- INI key: `[client].server_host`
- Environment key: `ICMP_PROXY_REMOTE_HOST`
- Both refer to the remote ICMP server host used by the client.

Minimal server environment:

```bash
export ICMP_PROXY_PSK='replace-with-strong-secret'
export ICMP_PROXY_CLIENT_ID='edge-a'
export ICMP_PROXY_BIND_HOST='0.0.0.0'
export ICMP_PROXY_CLIENT_HOST='127.0.0.1'
```

Minimal client environment:

```bash
export ICMP_PROXY_PSK='replace-with-strong-secret'
export ICMP_PROXY_CLIENT_ID='edge-a'
export ICMP_PROXY_REMOTE_HOST='SERVER_PUBLIC_IP_OR_DNS'
export ICMP_PROXY_HTTP_PROXY_BIND_HOST='127.0.0.1'
export ICMP_PROXY_HTTP_PROXY_BIND_PORT='8080'
export ICMP_PROXY_SOCKS_PROXY_ENABLE='1'
export ICMP_PROXY_SOCKS_PROXY_BIND_HOST='127.0.0.1'
export ICMP_PROXY_SOCKS_PROXY_BIND_PORT='1080'
```

## Manual Run

### Run Server

```bash
sudo -E icmp-proxy-server
```

Expected behavior:

- Process stays in foreground and logs startup.
- If enabled (default), Prometheus endpoint listens on `http://<bind_host>:2112/metrics`.

Prometheus quick check:

```bash
curl http://127.0.0.1:2112/metrics
```

### Run Client

```bash
sudo -E icmp-proxy-client
```

Expected behavior:

- Authenticates with server (PSK + client ID).
- Starts local listeners:
  - HTTP proxy on `127.0.0.1:8080` (default)
  - SOCKS5 proxy on `127.0.0.1:1080` (default, no auth)

Source checkout fallback:

- `sudo -E python3 -m icmp_proxy.server`
- `sudo -E python3 -m icmp_proxy.client`

## End-to-End Verification

After server and client are running:

HTTP proxy check:

```bash
curl -v -x http://127.0.0.1:8080 http://example.com/
```

SOCKS5 check:

```bash
curl -v --socks5-hostname 127.0.0.1:1080 http://example.com/
```

If both commands return expected content/status, the tunnel and proxy paths are functioning.

## Troubleshooting

`authentication failed` or handshake loops:

- Verify `ICMP_PROXY_PSK` matches on both sides.
- Verify `ICMP_PROXY_CLIENT_ID` matches expected identity.

No traffic / timeouts:

- Verify ICMP is allowed by network/firewall/security groups.
- Verify client `ICMP_PROXY_REMOTE_HOST` points to the server ICMP-reachable address.
- Confirm the server is running with raw socket privileges.

Client starts but app cannot connect to proxy:

- Verify bind host/port values (`ICMP_PROXY_HTTP_PROXY_BIND_*`, `ICMP_PROXY_SOCKS_PROXY_*`).
- Confirm local firewall rules allow loopback/client access.

Prometheus unavailable:

- Verify `ICMP_PROXY_PROMETHEUS_ENABLE=1`.
- Verify `ICMP_PROXY_PROMETHEUS_BIND_HOST` and `ICMP_PROXY_PROMETHEUS_PORT`.

## Systemd Deployment (Production)

Install role-specific `.deb` artifacts from GitHub Releases:

- `icmp-proxy-common_<version>_all.deb`
- `icmp-proxy-server_<version>_amd64.deb`
- `icmp-proxy-client_<version>_amd64.deb`

Server host install:

```bash
sudo apt install ./icmp-proxy-common_<version>_all.deb ./icmp-proxy-server_<version>_amd64.deb
```

Client host install:

```bash
sudo apt install ./icmp-proxy-common_<version>_all.deb ./icmp-proxy-client_<version>_amd64.deb
```

Services are installed to `/lib/systemd/system`, but package install does not enable or start them.

### 1. Configure Environment Files

Edit the package-installed role file(s):

- `/etc/icmp-proxy/server.env` on the server host
- `/etc/icmp-proxy/client.env` on the client host

At minimum set:

- `ICMP_PROXY_PSK` to a strong shared secret (both sides)
- `ICMP_PROXY_CLIENT_ID` consistently
- `ICMP_PROXY_REMOTE_HOST` on the client to the server address

Optional:

- Set `ICMP_PROXY_CONFIG_FILE=/etc/icmp-proxy/config.ini` if you manage an INI file centrally.

### 2. Enable and Start Services

Server host:

```bash
sudo systemctl enable --now icmp-proxy-server
sudo systemctl status icmp-proxy-server --no-pager
```

Client host:

```bash
sudo systemctl enable --now icmp-proxy-client
sudo systemctl status icmp-proxy-client --no-pager
```

### 3. Logs

Server logs:

```bash
sudo journalctl -u icmp-proxy-server -f
```

Client logs:

```bash
sudo journalctl -u icmp-proxy-client -f
```

### 4. Post-Deploy Validation

- Run the HTTP and SOCKS5 `curl` checks from the client host.
- If enabled, check server metrics endpoint.

## Security and Operations Notes

- Restrict local proxy listeners to loopback unless remote access is explicitly required.
- Keep `ICMP_PROXY_HTTP_PROXY_BIND_HOST=127.0.0.1` and `ICMP_PROXY_SOCKS_PROXY_BIND_HOST=127.0.0.1` for local-only access.
- Rotate PSKs regularly; do not commit secrets to source control.
- Review/re-tune reliability and flow-control parameters (`ICMP_PROXY_RETX_*`, `ICMP_PROXY_MAX_INFLIGHT_*`, `ICMP_PROXY_FLOWCONTROL_*`) for high latency/loss environments.
- Keep `ICMP_PROXY_HEARTBEAT_INTERVAL_MS` below `ICMP_PROXY_SESSION_IDLE_TIMEOUT_MS` so idle authenticated sessions stay alive.
- Keep an eye on session behavior (`ICMP_PROXY_SESSION_IDLE_TIMEOUT_MS`) and Prometheus metrics for operational health.
