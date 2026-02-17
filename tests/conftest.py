import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SYSCTL_ICMP_IGNORE_PATH = Path("/proc/sys/net/ipv4/icmp_echo_ignore_all")


def _read_icmp_echo_ignore_all() -> int | None:
    try:
        return int(SYSCTL_ICMP_IGNORE_PATH.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


@pytest.fixture
def require_root() -> None:
    if not hasattr(os, "geteuid"):
        pytest.skip("requires POSIX geteuid support")
    if os.geteuid() != 0:
        pytest.skip("requires root privileges for raw ICMP sockets")


@pytest.fixture
def require_icmp_echo_ignored() -> None:
    value = _read_icmp_echo_ignore_all()
    if value != 1:
        pytest.skip(
            "requires net.ipv4.icmp_echo_ignore_all=1; "
            "run: sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1"
        )


@pytest.fixture
def icmp_server_process(require_root: None, require_icmp_echo_ignored: None):
    psk_file = PROJECT_ROOT / ".test-psk"
    psk_file.write_text("test-secret\n", encoding="utf-8")
    env = os.environ.copy()
    env.setdefault("ICMP_PROXY_LOG_LEVEL", "WARNING")
    env.setdefault("ICMP_PROXY_PSK_FILE", str(psk_file))
    env.setdefault("ICMP_PROXY_CLIENT_ID", "test-client")

    process = subprocess.Popen(
        [sys.executable, "-m", "icmp_proxy.server"],
        cwd=PROJECT_ROOT,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = ""
            if process.stderr is not None:
                stderr = process.stderr.read()
            raise RuntimeError(
                f"icmp_proxy.server exited early with code {process.returncode}: {stderr}"
            )
        time.sleep(0.05)

    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2.0)
        try:
            psk_file.unlink()
        except OSError:
            pass


@pytest.fixture
def local_http_backend():
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: 11\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        b"hello world"
    )
    requests: list[bytes] = []
    ready = threading.Event()
    stop = threading.Event()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(0.2)

        host, port = listener.getsockname()

        def serve_one() -> None:
            ready.set()
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(1.0)
                    data = bytearray()
                    while True:
                        try:
                            chunk = conn.recv(4096)
                        except socket.timeout:
                            break
                        if not chunk:
                            break
                        data.extend(chunk)
                        if b"\r\n\r\n" in data:
                            break
                    requests.append(bytes(data))
                    conn.sendall(response)
                break

        server_thread = threading.Thread(target=serve_one, daemon=True)
        server_thread.start()
        ready.wait(timeout=1.0)

        try:
            yield {
                "host": host,
                "port": port,
                "response": response,
                "requests": requests,
            }
        finally:
            stop.set()
            server_thread.join(timeout=1.0)
