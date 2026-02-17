# ICMP Proxy Test Workflow

## Install test dependency

```bash
python3 -m pip install pytest
```

## Fast developer tests (no root)

Run protocol and reliability tests only:

```bash
python3 -m pytest -m "not requires_root"
```

## End-to-end ICMP tests (raw sockets)

Raw ICMP tests require root and disabling kernel echo replies:

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

Or use the helper script (handles sysctl setup/restore automatically):

```bash
./run_e2e_tests.sh
```

Run deterministic local E2E:

```bash
sudo -E python3 -m pytest -m "e2e_local and requires_root"
```

Equivalent with script:

```bash
./run_e2e_tests.sh local
```

Run external connectivity E2E (`google.com:80`):

```bash
sudo -E python3 -m pytest -m "e2e_external and requires_root"
```

Equivalent with script:

```bash
./run_e2e_tests.sh external
```

Run the complete suite:

```bash
sudo -E python3 -m pytest
```

Restore system default after testing:

```bash
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
