# Contributing

This repository uses Python 3 and `pytest` for tests.

## Prerequisites

- Linux or macOS host with Python 3.
- Permission to run raw ICMP sockets:
  - Linux: run as `root`, or run with `CAP_NET_RAW`.
  - macOS: run as `root`/`sudo` (no `CAP_NET_RAW` equivalent).

## Setup

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
```

For Debian package builds (Debian 12 / Ubuntu 24.04):

```bash
sudo apt-get update
sudo apt-get install -y debhelper dh-python devscripts lintian pybuild-plugin-pyproject python3-all python3-setuptools python3-wheel
```

## Coding Style

The project uses `isort` + `black` for Python formatting.

Format imports and code:

```bash
python3 -m isort icmp_proxy tests
python3 -m black icmp_proxy tests
```

Check formatting without changing files:

```bash
python3 -m isort --check-only icmp_proxy tests
python3 -m black --check icmp_proxy tests
```

## Run Locally

For complete runtime details, see `USAGE.md`.

For single-machine loopback testing on Linux, disable kernel ICMP echo replies:

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

Restore after testing (Linux):

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
```

Set minimum shared env vars (same values on both client and server):

```bash
export ICMP_PROXY_PSK='dev-secret'
export ICMP_PROXY_CLIENT_ID='dev-client'
```

Run server:

```bash
sudo -E python3 -m icmp_proxy.server
```

Run client (separate terminal):

```bash
export ICMP_PROXY_REMOTE_HOST='127.0.0.1'
sudo -E python3 -m icmp_proxy.client
```

Quick checks:

```bash
curl -v -x http://127.0.0.1:8080 http://example.com/
curl -v --socks5-hostname 127.0.0.1:1080 http://example.com/
```

## Tests

Run these before opening a PR.

Syntax check:

```bash
python3 -m py_compile icmp_proxy/*.py tests/*.py
```

Unit/integration tests that do not require root:

```bash
python3 -m pytest -m "not requires_root"
```

Root-required E2E tests (local path only):

```bash
./run_e2e_tests.sh local
```

Root-required E2E tests (external path):

```bash
./run_e2e_tests.sh external
```

Run full E2E set:

```bash
./run_e2e_tests.sh all
```

## Debian Package Validation

Build `.deb` artifacts:

```bash
dpkg-buildpackage -us -uc -b
```

Run lintian on generated packages:

```bash
lintian ../icmp-proxy-common_*_all.deb ../icmp-proxy-server_*_amd64.deb ../icmp-proxy-client_*_amd64.deb
```
