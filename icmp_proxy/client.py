from __future__ import annotations

from dataclasses import dataclass
import logging
import socket
from threading import Event, Lock, Thread
from urllib.parse import urlsplit

from .auth import (
    generate_nonce,
    load_psk,
    now_ms,
    sign_client_hello,
    sign_server_hello_ack,
    timestamp_within_window,
    verify_signature,
)
from .config import ClientConfig, load_client_config
from .icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REQUEST, ICMP_ECHO_REQUEST_CODE
from .protocol import (
    Close,
    CloseAck,
    Data,
    Hello,
    HelloAck,
    MessageType,
    OpenErr,
    OpenOk,
    OpenStream,
)
from .transport import ReliableICMPSession

LOGGER = logging.getLogger("icmp_proxy.client")

HTTP_HEADER_TERMINATOR = b"\r\n\r\n"
MAX_HTTP_HEADER_BYTES = 64 * 1024
PROXY_SOCKET_POLL_TIMEOUT_S = 0.5


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


@dataclass(frozen=True)
class ProxyRequest:
    method: str
    remote_host: str
    remote_port: int
    rewritten_head: bytes | None


def _parse_authority(authority: str, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if not authority:
        raise ValueError("missing target host")

    if authority.startswith("["):
        close_idx = authority.find("]")
        if close_idx < 0:
            raise ValueError("invalid IPv6 authority")
        host = authority[1:close_idx]
        remainder = authority[close_idx + 1 :]
        if not remainder:
            return host, default_port
        if not remainder.startswith(":"):
            raise ValueError("invalid authority suffix")
        port_raw = remainder[1:]
    else:
        if authority.count(":") == 1:
            host, port_raw = authority.rsplit(":", 1)
            if not host:
                raise ValueError("missing target host")
        elif ":" in authority:
            return authority, default_port
        else:
            return authority, default_port

    if not port_raw.isdigit():
        raise ValueError("invalid target port")
    port = int(port_raw)
    if not (1 <= port <= 65535):
        raise ValueError("target port out of range")
    return host, port


def _format_host_header(host: str, port: int, default_port: int) -> str:
    host_value = host
    if ":" in host_value and not host_value.startswith("["):
        host_value = f"[{host_value}]"
    if port == default_port:
        return host_value
    return f"{host_value}:{port}"


def _extract_host_header(header_lines: list[bytes]) -> str | None:
    for line in header_lines:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        if name.strip().lower() == b"host":
            host_value = value.strip()
            if not host_value:
                return None
            return host_value.decode("latin-1")
    return None


def parse_proxy_request_head(head: bytes) -> ProxyRequest:
    if not head.endswith(HTTP_HEADER_TERMINATOR):
        raise ValueError("incomplete HTTP request headers")
    header_lines = head[: -len(HTTP_HEADER_TERMINATOR)].split(b"\r\n")
    if not header_lines or not header_lines[0]:
        raise ValueError("missing HTTP request line")
    try:
        method, target, version = header_lines[0].decode("latin-1").split(" ", 2)
    except ValueError as exc:
        raise ValueError("invalid HTTP request line") from exc
    if not version.startswith("HTTP/"):
        raise ValueError("invalid HTTP version")

    method_upper = method.upper()
    if method_upper == "CONNECT":
        remote_host, remote_port = _parse_authority(target, default_port=443)
        return ProxyRequest(
            method=method_upper,
            remote_host=remote_host,
            remote_port=remote_port,
            rewritten_head=None,
        )

    upstream_target = target
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlsplit(target)
        if parsed.scheme.lower() != "http":
            raise ValueError("only http:// absolute-form requests are supported")
        if parsed.hostname is None:
            raise ValueError("missing target host")
        remote_host = parsed.hostname
        remote_port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        upstream_target = path
    elif target.startswith("/") or target == "*":
        host_header = _extract_host_header(header_lines[1:])
        if host_header is None:
            raise ValueError("missing Host header")
        remote_host, remote_port = _parse_authority(host_header, default_port=80)
    else:
        raise ValueError("unsupported request target")

    rewritten_lines = [f"{method} {upstream_target} {version}".encode("latin-1")]
    has_host = False
    for line in header_lines[1:]:
        if not line:
            continue
        if b":" not in line:
            raise ValueError("invalid HTTP header")
        name_raw, value_raw = line.split(b":", 1)
        name = name_raw.strip()
        value = value_raw.strip()
        name_lower = name.lower()
        if name_lower in (b"connection", b"proxy-connection", b"proxy-authorization"):
            continue
        if name_lower == b"host":
            has_host = True
        rewritten_lines.append(name + b": " + value)
    if not has_host:
        rewritten_lines.append(
            b"Host: " + _format_host_header(remote_host, remote_port, default_port=80).encode("latin-1")
        )
    rewritten_lines.append(b"Connection: close")
    rewritten_head = b"\r\n".join(rewritten_lines) + HTTP_HEADER_TERMINATOR
    return ProxyRequest(
        method=method_upper,
        remote_host=remote_host,
        remote_port=remote_port,
        rewritten_head=rewritten_head,
    )


def read_http_request_head(connection: socket.socket) -> tuple[bytes, bytes]:
    buffer = bytearray()
    while len(buffer) <= MAX_HTTP_HEADER_BYTES:
        marker_index = buffer.find(HTTP_HEADER_TERMINATOR)
        if marker_index >= 0:
            marker_end = marker_index + len(HTTP_HEADER_TERMINATOR)
            return bytes(buffer[:marker_end]), bytes(buffer[marker_end:])
        chunk = connection.recv(4096)
        if not chunk:
            break
        buffer.extend(chunk)
    raise ValueError("HTTP request headers too large or truncated")


def _send_http_error(
    connection: socket.socket, *, status: int, reason: str, message: str
) -> None:
    body = f"{status} {reason}\n{message}\n".encode("utf-8")
    response = (
        f"HTTP/1.1 {status} {reason}\r\n"
        "Connection: close\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "\r\n"
    ).encode("latin-1") + body
    try:
        connection.sendall(response)
    except OSError:
        pass


class Client:
    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        self.psk = load_psk(config.common.psk_file)
        self.session_id = 0
        self.client_nonce = b""
        self._open_lock = Lock()

    def __enter__(self) -> "Client":
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.socket.bind(("0.0.0.0", 0))
        session = self.config.session
        self.reliable = ReliableICMPSession(
            connection=self.socket,
            remote_host=self.config.server_host,
            outbound_icmp_type=ICMP_ECHO_REQUEST,
            outbound_icmp_code=ICMP_ECHO_REQUEST_CODE,
            inbound_icmp_type=ICMP_ECHO_REPLY,
            inbound_icmp_code=ICMP_ECHO_REPLY_CODE,
            retx_timeout_ms=session.retx_timeout_ms,
            retx_max_retries=session.retx_max_retries,
            retx_scan_interval_ms=session.retx_scan_interval_ms,
            seen_limit_per_stream=session.seen_limit_per_stream,
            max_inflight_per_stream=session.max_inflight_per_stream,
        )
        self.reliable.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.reliable.stop()
        self.socket.close()

    def authenticate(self) -> int:
        self.client_nonce = generate_nonce()
        timestamp_ms = now_ms()
        hello = Hello(
            client_id=self.config.common.client_id,
            nonce=self.client_nonce,
            timestamp_ms=timestamp_ms,
            hmac_sha256=sign_client_hello(
                psk=self.psk,
                client_id=self.config.common.client_id,
                nonce=self.client_nonce,
                timestamp_ms=timestamp_ms,
            ),
        )

        hello_seq = self.reliable.send_reliable(
            msg_type=MessageType.HELLO,
            session_id=0,
            stream_id=0,
            payload=hello.encode(),
        )
        frame = self.reliable.wait_for_frame(
            lambda f: f.msg_type == MessageType.HELLO_ACK,
            timeout_s=5.0,
        )
        if frame is None:
            raise TimeoutError("timed out waiting for HELLO_ACK")
        hello_ack = HelloAck.decode(frame.payload)
        if not timestamp_within_window(
            timestamp_ms=hello_ack.timestamp_ms,
            now_timestamp_ms=now_ms(),
            allowed_skew_ms=self.config.common.auth_skew_ms,
        ):
            raise ValueError("stale HELLO_ACK timestamp")
        expected_sig = sign_server_hello_ack(
            psk=self.psk,
            session_id=frame.session_id,
            client_nonce=self.client_nonce,
            server_nonce=hello_ack.server_nonce,
            timestamp_ms=hello_ack.timestamp_ms,
        )
        if not verify_signature(expected_sig, hello_ack.hmac_sha256):
            raise ValueError("HELLO_ACK signature verification failed")
        self.session_id = frame.session_id
        if not self.reliable.wait_for_ack(stream_id=0, seq_num=hello_seq, timeout_s=1.0):
            LOGGER.warning("HELLO ack was not confirmed by retransmit state in time")
        return self.session_id

    def open_stream(self, remote_host: str, remote_port: int) -> int:
        with self._open_lock:
            self.reliable.send_reliable(
                msg_type=MessageType.OPEN_STREAM,
                session_id=self.session_id,
                stream_id=0,
                payload=OpenStream(remote_host=remote_host, remote_port=remote_port).encode(),
            )
            frame = self.reliable.wait_for_frame(
                lambda f: f.msg_type in (MessageType.OPEN_OK, MessageType.OPEN_ERR),
                timeout_s=5.0,
            )
        if frame is None:
            raise TimeoutError("timed out waiting for OPEN response")
        if frame.msg_type == MessageType.OPEN_ERR:
            open_err = OpenErr.decode(frame.payload)
            raise RuntimeError(f"open stream failed: {open_err.error_code} {open_err.reason}")
        open_ok = OpenOk.decode(frame.payload)
        return open_ok.assigned_stream_id

    def recv_stream_chunk(
        self, stream_id: int, timeout_s: float = 2.0
    ) -> tuple[bytes | None, bool]:
        frame = self.reliable.wait_for_frame(
            lambda f: f.stream_id == stream_id
            and f.msg_type in (MessageType.DATA, MessageType.CLOSE, MessageType.CLOSE_ACK),
            timeout_s=timeout_s,
        )
        if frame is None:
            return None, False
        if frame.msg_type in (MessageType.CLOSE, MessageType.CLOSE_ACK):
            return b"", True
        return Data.decode(frame.payload).payload, False

    def send_stream_data(self, stream_id: int, payload: bytes) -> None:
        mtu_payload = max(1, self.config.session.mtu_payload)
        for offset in range(0, len(payload), mtu_payload):
            chunk = payload[offset : offset + mtu_payload]
            self.reliable.send_reliable(
                msg_type=MessageType.DATA,
                session_id=self.session_id,
                stream_id=stream_id,
                payload=Data(payload=chunk).encode(),
            )

    def recv_stream_data(self, stream_id: int, timeout_s: float = 2.0) -> bytes:
        parts: list[bytes] = []
        while True:
            chunk, closed = self.recv_stream_chunk(stream_id=stream_id, timeout_s=timeout_s)
            if chunk is None:
                break
            if closed:
                break
            parts.append(chunk)
        return b"".join(parts)

    def close_stream(self, stream_id: int) -> None:
        close_seq = self.reliable.send_reliable(
            msg_type=MessageType.CLOSE,
            session_id=self.session_id,
            stream_id=stream_id,
            payload=Close().encode(),
        )
        frame = self.reliable.wait_for_frame(
            lambda f: f.stream_id == stream_id and f.msg_type == MessageType.CLOSE_ACK,
            timeout_s=2.0,
        )
        if frame is not None:
            CloseAck.decode(frame.payload)
        self.reliable.wait_for_ack(stream_id=stream_id, seq_num=close_seq, timeout_s=1.0)
        self.reliable.clear_stream_state(stream_id)


class HTTPProxyServer:
    def __init__(self, client: Client, bind_host: str, bind_port: int) -> None:
        self.client = client
        self.bind_host = bind_host
        self.bind_port = bind_port

    def serve_forever(self) -> None:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.bind_host, self.bind_port))
        server_socket.listen(128)
        LOGGER.info("HTTP proxy listening on %s:%d", self.bind_host, self.bind_port)

        with server_socket:
            while True:
                connection, address = server_socket.accept()
                Thread(
                    target=self._handle_connection,
                    args=(connection, address),
                    daemon=True,
                ).start()

    def _handle_connection(self, connection: socket.socket, address: tuple[str, int]) -> None:
        stream_id: int | None = None
        with connection:
            connection.settimeout(10.0)
            try:
                request_head, remainder = read_http_request_head(connection)
                parsed = parse_proxy_request_head(request_head)
                stream_id = self.client.open_stream(parsed.remote_host, parsed.remote_port)
                connection.settimeout(PROXY_SOCKET_POLL_TIMEOUT_S)

                if parsed.method == "CONNECT":
                    connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    initial_upstream = remainder
                else:
                    if parsed.rewritten_head is None:
                        raise ValueError("failed to build upstream HTTP request")
                    initial_upstream = parsed.rewritten_head + remainder

                self._relay_stream(connection, stream_id, initial_upstream)
            except ValueError as exc:
                LOGGER.warning(
                    "invalid proxy request from %s:%d: %s",
                    address[0],
                    address[1],
                    exc,
                )
                _send_http_error(
                    connection,
                    status=400,
                    reason="Bad Request",
                    message=str(exc),
                )
            except TimeoutError as exc:
                LOGGER.warning(
                    "timeout while proxying request from %s:%d: %s",
                    address[0],
                    address[1],
                    exc,
                )
                _send_http_error(
                    connection,
                    status=504,
                    reason="Gateway Timeout",
                    message=str(exc),
                )
            except RuntimeError as exc:
                LOGGER.warning(
                    "upstream open failed for %s:%d: %s",
                    address[0],
                    address[1],
                    exc,
                )
                _send_http_error(
                    connection,
                    status=502,
                    reason="Bad Gateway",
                    message=str(exc),
                )
            except OSError:
                pass
            finally:
                if stream_id is not None:
                    try:
                        self.client.close_stream(stream_id)
                    except Exception:
                        self.client.reliable.clear_stream_state(stream_id)

    def _relay_stream(
        self, connection: socket.socket, stream_id: int, initial_upstream: bytes
    ) -> None:
        stop_event = Event()
        relay_error: list[Exception] = []

        def _client_to_upstream() -> None:
            try:
                if initial_upstream:
                    self.client.send_stream_data(stream_id, initial_upstream)
                while not stop_event.is_set():
                    try:
                        chunk = connection.recv(4096)
                    except socket.timeout:
                        continue
                    if not chunk:
                        break
                    self.client.send_stream_data(stream_id, chunk)
            except Exception as exc:
                relay_error.append(exc)
            finally:
                stop_event.set()

        upload_thread = Thread(target=_client_to_upstream, daemon=True)
        upload_thread.start()
        try:
            while not stop_event.is_set():
                chunk, closed = self.client.recv_stream_chunk(
                    stream_id=stream_id,
                    timeout_s=PROXY_SOCKET_POLL_TIMEOUT_S,
                )
                if chunk is None:
                    continue
                if closed:
                    break
                if chunk:
                    connection.sendall(chunk)
        finally:
            stop_event.set()
            upload_thread.join(timeout=1.0)

        if relay_error:
            error = relay_error[0]
            if isinstance(error, (TimeoutError, RuntimeError, OSError)):
                raise error
            raise RuntimeError("proxy relay failed") from error


def main() -> None:
    config = load_client_config()
    configure_logging(config.common.log_level)
    with Client(config) as client:
        client.authenticate()
        proxy_server = HTTPProxyServer(
            client=client,
            bind_host=config.http_proxy_bind_host,
            bind_port=config.http_proxy_bind_port,
        )
        proxy_server.serve_forever()


if __name__ == "__main__":
    main()
