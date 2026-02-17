from __future__ import annotations

from dataclasses import dataclass
import ipaddress
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
from .config import DEFAULT_PSK, ClientConfig, load_client_config
from .icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REQUEST, ICMP_ECHO_REQUEST_CODE
from .protocol import (
    Close,
    CloseAck,
    Data,
    DatagramPacket,
    Hello,
    HelloAck,
    MessageType,
    OpenDatagram,
    OpenErr,
    OpenOk,
    OpenStream,
)
from .transport import ReliableICMPSession

LOGGER = logging.getLogger("icmp_proxy.client")

HTTP_HEADER_TERMINATOR = b"\r\n\r\n"
MAX_HTTP_HEADER_BYTES = 64 * 1024
PROXY_SOCKET_POLL_TIMEOUT_S = 0.5
SOCKS_VERSION = 0x05
SOCKS5_METHOD_NO_AUTH = 0x00
SOCKS5_METHOD_NO_ACCEPTABLE = 0xFF
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_UDP_ASSOCIATE = 0x03
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPV6 = 0x04
SOCKS5_REPLY_SUCCEEDED = 0x00
SOCKS5_REPLY_GENERAL_FAILURE = 0x01
SOCKS5_REPLY_HOST_UNREACHABLE = 0x04
SOCKS5_REPLY_TTL_EXPIRED = 0x06
SOCKS5_REPLY_COMMAND_NOT_SUPPORTED = 0x07
SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


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


@dataclass(frozen=True)
class SOCKS5ConnectRequest:
    remote_host: str
    remote_port: int


@dataclass(frozen=True)
class SOCKS5Request:
    command: int
    remote_host: str
    remote_port: int


@dataclass(frozen=True)
class SOCKS5UDPDatagram:
    fragment: int
    remote_host: str
    remote_port: int
    payload: bytes


class SOCKS5ProtocolError(ValueError):
    def __init__(self, message: str, *, reply_code: int = SOCKS5_REPLY_GENERAL_FAILURE) -> None:
        super().__init__(message)
        self.reply_code = reply_code


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


def _recv_exact(connection: socket.socket, size: int) -> bytes:
    if size <= 0:
        return b""
    buffer = bytearray()
    while len(buffer) < size:
        chunk = connection.recv(size - len(buffer))
        if not chunk:
            raise SOCKS5ProtocolError("truncated SOCKS payload")
        buffer.extend(chunk)
    return bytes(buffer)


def read_socks5_greeting(connection: socket.socket) -> bytes:
    header = _recv_exact(connection, 2)
    version, methods_len = header[0], header[1]
    if version != SOCKS_VERSION:
        raise SOCKS5ProtocolError("unsupported SOCKS version")
    methods = _recv_exact(connection, methods_len)
    return methods


def _parse_socks5_address(payload: bytes, cursor: int) -> tuple[str, int, int]:
    if len(payload) <= cursor:
        raise SOCKS5ProtocolError("truncated SOCKS request")
    address_type = payload[cursor]
    cursor += 1
    if address_type == SOCKS5_ATYP_IPV4:
        if len(payload) < cursor + 4 + 2:
            raise SOCKS5ProtocolError("truncated IPv4 SOCKS request")
        remote_host = socket.inet_ntoa(payload[cursor : cursor + 4])
        cursor += 4
    elif address_type == SOCKS5_ATYP_DOMAIN:
        if len(payload) < cursor + 1:
            raise SOCKS5ProtocolError("truncated domain SOCKS request")
        domain_length = payload[cursor]
        cursor += 1
        if domain_length == 0:
            raise SOCKS5ProtocolError("empty SOCKS domain")
        if len(payload) < cursor + domain_length + 2:
            raise SOCKS5ProtocolError("truncated domain SOCKS request")
        remote_host = payload[cursor : cursor + domain_length].decode("idna")
        cursor += domain_length
    elif address_type == SOCKS5_ATYP_IPV6:
        if len(payload) < cursor + 16 + 2:
            raise SOCKS5ProtocolError("truncated IPv6 SOCKS request")
        remote_host = socket.inet_ntop(socket.AF_INET6, payload[cursor : cursor + 16])
        cursor += 16
    else:
        raise SOCKS5ProtocolError(
            "unsupported SOCKS address type",
            reply_code=SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
        )
    remote_port = int.from_bytes(payload[cursor : cursor + 2], byteorder="big")
    cursor += 2
    return remote_host, remote_port, cursor


def parse_socks5_request(payload: bytes) -> SOCKS5Request:
    if len(payload) < 4:
        raise SOCKS5ProtocolError("truncated SOCKS request")

    version, command, reserved = payload[0], payload[1], payload[2]
    if version != SOCKS_VERSION:
        raise SOCKS5ProtocolError("unsupported SOCKS version")
    if reserved != 0:
        raise SOCKS5ProtocolError("invalid SOCKS reserved byte")
    if command not in (SOCKS5_CMD_CONNECT, SOCKS5_CMD_UDP_ASSOCIATE):
        raise SOCKS5ProtocolError(
            "unsupported SOCKS command",
            reply_code=SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
        )

    remote_host, remote_port, cursor = _parse_socks5_address(payload, 3)
    if command == SOCKS5_CMD_CONNECT and remote_port == 0:
        raise SOCKS5ProtocolError("invalid SOCKS destination port")
    if cursor != len(payload):
        raise SOCKS5ProtocolError("invalid trailing bytes in SOCKS request")
    return SOCKS5Request(command=command, remote_host=remote_host, remote_port=remote_port)


def parse_socks5_connect_request(payload: bytes) -> SOCKS5ConnectRequest:
    request = parse_socks5_request(payload)
    if request.command != SOCKS5_CMD_CONNECT:
        raise SOCKS5ProtocolError(
            "unsupported SOCKS command",
            reply_code=SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
        )
    return SOCKS5ConnectRequest(remote_host=request.remote_host, remote_port=request.remote_port)


def read_socks5_request(connection: socket.socket) -> SOCKS5Request:
    header = _recv_exact(connection, 4)
    address_type = header[3]
    payload = bytearray(header)
    if address_type == SOCKS5_ATYP_IPV4:
        payload.extend(_recv_exact(connection, 4))
    elif address_type == SOCKS5_ATYP_DOMAIN:
        domain_length_raw = _recv_exact(connection, 1)
        payload.extend(domain_length_raw)
        payload.extend(_recv_exact(connection, domain_length_raw[0]))
    elif address_type == SOCKS5_ATYP_IPV6:
        payload.extend(_recv_exact(connection, 16))
    else:
        raise SOCKS5ProtocolError(
            "unsupported SOCKS address type",
            reply_code=SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
        )
    payload.extend(_recv_exact(connection, 2))
    return parse_socks5_request(bytes(payload))


def read_socks5_connect_request(connection: socket.socket) -> SOCKS5ConnectRequest:
    request = read_socks5_request(connection)
    if request.command != SOCKS5_CMD_CONNECT:
        raise SOCKS5ProtocolError(
            "unsupported SOCKS command",
            reply_code=SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
        )
    return SOCKS5ConnectRequest(remote_host=request.remote_host, remote_port=request.remote_port)


def build_socks5_method_selection(method: int) -> bytes:
    return bytes([SOCKS_VERSION, method])


def _encode_socks5_address(remote_host: str, remote_port: int) -> bytes:
    if not (0 <= remote_port <= 65535):
        raise SOCKS5ProtocolError("invalid SOCKS destination port")
    try:
        ip_addr = ipaddress.ip_address(remote_host)
    except ValueError:
        host_bytes = remote_host.encode("idna")
        if not host_bytes:
            raise SOCKS5ProtocolError("empty SOCKS domain")
        if len(host_bytes) > 255:
            raise SOCKS5ProtocolError("SOCKS domain too long")
        return bytes([SOCKS5_ATYP_DOMAIN, len(host_bytes)]) + host_bytes + remote_port.to_bytes(2, "big")
    if isinstance(ip_addr, ipaddress.IPv4Address):
        return bytes([SOCKS5_ATYP_IPV4]) + ip_addr.packed + remote_port.to_bytes(2, "big")
    return bytes([SOCKS5_ATYP_IPV6]) + ip_addr.packed + remote_port.to_bytes(2, "big")


def build_socks5_reply(reply_code: int, *, bind_host: str = "0.0.0.0", bind_port: int = 0) -> bytes:
    return bytes([SOCKS_VERSION, reply_code, 0x00]) + _encode_socks5_address(bind_host, bind_port)


def parse_socks5_udp_datagram(payload: bytes) -> SOCKS5UDPDatagram:
    if len(payload) < 4:
        raise SOCKS5ProtocolError("truncated SOCKS5 UDP datagram")
    if payload[0] != 0 or payload[1] != 0:
        raise SOCKS5ProtocolError("invalid SOCKS5 UDP reserved bytes")
    fragment = payload[2]
    remote_host, remote_port, cursor = _parse_socks5_address(payload, 3)
    return SOCKS5UDPDatagram(
        fragment=fragment,
        remote_host=remote_host,
        remote_port=remote_port,
        payload=payload[cursor:],
    )


def build_socks5_udp_datagram(remote_host: str, remote_port: int, payload: bytes) -> bytes:
    return b"\x00\x00\x00" + _encode_socks5_address(remote_host, remote_port) + payload


def _is_unspecified_address(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_unspecified
    except ValueError:
        return True


def _listener_family_for_host(bind_host: str) -> int:
    try:
        addr = ipaddress.ip_address(bind_host)
    except ValueError:
        try:
            addr_info = socket.getaddrinfo(
                bind_host,
                0,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                flags=socket.AI_PASSIVE,
            )
        except OSError:
            return socket.AF_INET
        return addr_info[0][0]
    if isinstance(addr, ipaddress.IPv6Address):
        return socket.AF_INET6
    return socket.AF_INET


def _sockaddr_host_port(sockaddr: tuple[object, ...]) -> tuple[str, int]:
    if len(sockaddr) < 2:
        raise ValueError("invalid socket address")
    return str(sockaddr[0]), int(sockaddr[1])


def _sockaddr_for_send(family: int, host: str, port: int) -> tuple[str, int] | tuple[str, int, int, int]:
    if family == socket.AF_INET6:
        return (host, port, 0, 0)
    return (host, port)


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


def _relay_stream(client: Client, connection: socket.socket, stream_id: int, initial_upstream: bytes) -> None:
    stop_event = Event()
    relay_error: list[Exception] = []

    def _client_to_upstream() -> None:
        try:
            if initial_upstream:
                client.send_stream_data(stream_id, initial_upstream)
            while not stop_event.is_set():
                try:
                    chunk = connection.recv(4096)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                client.send_stream_data(stream_id, chunk)
        except Exception as exc:
            relay_error.append(exc)
        finally:
            stop_event.set()

    upload_thread = Thread(target=_client_to_upstream, daemon=True)
    upload_thread.start()
    try:
        while not stop_event.is_set():
            chunk, closed = client.recv_stream_chunk(
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


class Client:
    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        self.psk = load_psk(config.common.psk)
        if config.common.psk.strip() == DEFAULT_PSK:
            LOGGER.warning(
                "using default PSK; set [common].psk in config.ini or ICMP_PROXY_PSK in the environment"
            )
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
            max_global_inflight=session.max_global_inflight,
            min_inflight_per_stream=session.min_inflight_per_stream,
            flowcontrol_enable=session.flowcontrol_enable,
            flowcontrol_alpha=session.flowcontrol_alpha,
            flowcontrol_beta=session.flowcontrol_beta,
            flowcontrol_increase_step=session.flowcontrol_increase_step,
            flowcontrol_decrease_factor=session.flowcontrol_decrease_factor,
            flowcontrol_loss_threshold=session.flowcontrol_loss_threshold,
            stats_interval_ms=session.stats_interval_ms,
            performance_metrics_enable=session.performance_metrics_enable,
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
        if not self.reliable.wait_for_ack(
            session_id=0,
            stream_id=0,
            seq_num=hello_seq,
            timeout_s=1.0,
        ):
            LOGGER.warning("HELLO ack was not confirmed by retransmit state in time")
        return self.session_id

    def _open(self, msg_type: MessageType, payload: bytes) -> int:
        with self._open_lock:
            self.reliable.send_reliable(
                msg_type=msg_type,
                session_id=self.session_id,
                stream_id=0,
                payload=payload,
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

    def open_stream(self, remote_host: str, remote_port: int) -> int:
        return self._open(
            MessageType.OPEN_STREAM,
            OpenStream(remote_host=remote_host, remote_port=remote_port).encode(),
        )

    def open_datagram(self) -> int:
        return self._open(MessageType.OPEN_DATAGRAM, OpenDatagram().encode())

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

    def send_datagram(self, stream_id: int, remote_host: str, remote_port: int, payload: bytes) -> None:
        encoded = DatagramPacket(
            remote_host=remote_host,
            remote_port=remote_port,
            payload=payload,
        ).encode()
        mtu_payload = max(1, self.config.session.mtu_payload)
        if len(encoded) > mtu_payload:
            raise ValueError("datagram exceeds session mtu_payload")
        self.reliable.send_reliable(
            msg_type=MessageType.DATA,
            session_id=self.session_id,
            stream_id=stream_id,
            payload=Data(payload=encoded).encode(),
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

    def recv_datagram(self, stream_id: int, timeout_s: float = 2.0) -> tuple[DatagramPacket | None, bool]:
        frame = self.reliable.wait_for_frame(
            lambda f: f.stream_id == stream_id
            and f.msg_type in (MessageType.DATA, MessageType.CLOSE, MessageType.CLOSE_ACK),
            timeout_s=timeout_s,
        )
        if frame is None:
            return None, False
        if frame.msg_type in (MessageType.CLOSE, MessageType.CLOSE_ACK):
            return None, True
        payload = Data.decode(frame.payload).payload
        return DatagramPacket.decode(payload), False

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
        self.reliable.wait_for_ack(
            session_id=self.session_id,
            stream_id=stream_id,
            seq_num=close_seq,
            timeout_s=1.0,
        )
        self.reliable.clear_stream_state(self.session_id, stream_id)


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

                _relay_stream(self.client, connection, stream_id, initial_upstream)
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
                        self.client.reliable.clear_stream_state(self.client.session_id, stream_id)


class SOCKS5ProxyServer:
    def __init__(self, client: Client, bind_host: str, bind_port: int) -> None:
        self.client = client
        self.bind_host = bind_host
        self.bind_port = bind_port

    def serve_forever(self) -> None:
        family = _listener_family_for_host(self.bind_host)
        server_socket = socket.socket(family, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.bind_host, self.bind_port))
        server_socket.listen(128)
        LOGGER.info("SOCKS5 proxy listening on %s:%d", self.bind_host, self.bind_port)

        with server_socket:
            while True:
                connection, address = server_socket.accept()
                Thread(
                    target=self._handle_connection,
                    args=(connection, address),
                    daemon=True,
                ).start()

    def _relay_udp_associate(
        self,
        connection: socket.socket,
        udp_socket: socket.socket,
        stream_id: int,
        request: SOCKS5Request,
    ) -> None:
        stop_event = Event()
        relay_error: list[Exception] = []
        expected_client_addr: tuple[str, int] | tuple[str, int, int, int] | None = None
        expected_client_host_port: tuple[str, int] | None = None
        udp_family = getattr(udp_socket, "family", socket.AF_INET)
        if request.remote_port != 0 and not _is_unspecified_address(request.remote_host):
            expected_client_host_port = (request.remote_host, request.remote_port)
            expected_client_addr = _sockaddr_for_send(
                udp_family, request.remote_host, request.remote_port
            )

        def _udp_to_tunnel() -> None:
            nonlocal expected_client_addr
            nonlocal expected_client_host_port
            try:
                while not stop_event.is_set():
                    try:
                        payload, sender = udp_socket.recvfrom(65535)
                    except socket.timeout:
                        continue
                    sender_addr = (str(sender[0]), int(sender[1]))
                    if expected_client_host_port is None:
                        expected_client_host_port = sender_addr
                        expected_client_addr = sender
                    elif sender_addr != expected_client_host_port:
                        continue
                    try:
                        datagram = parse_socks5_udp_datagram(payload)
                    except SOCKS5ProtocolError:
                        continue
                    if datagram.fragment != 0:
                        continue
                    self.client.send_datagram(
                        stream_id=stream_id,
                        remote_host=datagram.remote_host,
                        remote_port=datagram.remote_port,
                        payload=datagram.payload,
                    )
            except Exception as exc:
                relay_error.append(exc)
            finally:
                stop_event.set()

        def _tunnel_to_udp() -> None:
            while not stop_event.is_set():
                try:
                    packet, closed = self.client.recv_datagram(
                        stream_id=stream_id,
                        timeout_s=PROXY_SOCKET_POLL_TIMEOUT_S,
                    )
                except ValueError:
                    continue
                except Exception as exc:
                    relay_error.append(exc)
                    stop_event.set()
                    break
                if packet is None:
                    continue
                if closed:
                    stop_event.set()
                    break
                if expected_client_addr is None:
                    continue
                response = build_socks5_udp_datagram(
                    remote_host=packet.remote_host,
                    remote_port=packet.remote_port,
                    payload=packet.payload,
                )
                try:
                    udp_socket.sendto(response, expected_client_addr)
                except OSError:
                    continue

        upload_thread = Thread(target=_udp_to_tunnel, daemon=True)
        download_thread = Thread(target=_tunnel_to_udp, daemon=True)
        upload_thread.start()
        download_thread.start()
        try:
            while not stop_event.is_set():
                try:
                    chunk = connection.recv(1)
                except socket.timeout:
                    continue
                if not chunk:
                    break
        finally:
            stop_event.set()
            upload_thread.join(timeout=1.0)
            download_thread.join(timeout=1.0)

        if relay_error:
            error = relay_error[0]
            if isinstance(error, (TimeoutError, RuntimeError, OSError)):
                raise error
            raise RuntimeError("udp associate relay failed") from error

    def _handle_connection(self, connection: socket.socket, address: tuple[str, int]) -> None:
        stream_id: int | None = None
        with connection:
            connection.settimeout(10.0)
            try:
                try:
                    local_host, _local_port = _sockaddr_host_port(connection.getsockname())
                except (OSError, ValueError, TypeError):
                    local_host = self.bind_host

                methods = read_socks5_greeting(connection)
                if SOCKS5_METHOD_NO_AUTH not in methods:
                    connection.sendall(build_socks5_method_selection(SOCKS5_METHOD_NO_ACCEPTABLE))
                    return
                connection.sendall(build_socks5_method_selection(SOCKS5_METHOD_NO_AUTH))

                request = read_socks5_request(connection)
                if request.command == SOCKS5_CMD_CONNECT:
                    stream_id = self.client.open_stream(request.remote_host, request.remote_port)
                    connection.sendall(build_socks5_reply(SOCKS5_REPLY_SUCCEEDED, bind_host=local_host))
                    connection.settimeout(PROXY_SOCKET_POLL_TIMEOUT_S)
                    _relay_stream(self.client, connection, stream_id, b"")
                elif request.command == SOCKS5_CMD_UDP_ASSOCIATE:
                    stream_id = self.client.open_datagram()
                    udp_bind_host = local_host
                    udp_family = _listener_family_for_host(udp_bind_host)
                    with socket.socket(udp_family, socket.SOCK_DGRAM) as udp_socket:
                        udp_socket.bind((udp_bind_host, 0))
                        bind_host, bind_port = _sockaddr_host_port(udp_socket.getsockname())
                        connection.sendall(
                            build_socks5_reply(
                                SOCKS5_REPLY_SUCCEEDED,
                                bind_host=bind_host,
                                bind_port=bind_port,
                            )
                        )
                        connection.settimeout(PROXY_SOCKET_POLL_TIMEOUT_S)
                        udp_socket.settimeout(PROXY_SOCKET_POLL_TIMEOUT_S)
                        self._relay_udp_associate(connection, udp_socket, stream_id, request)
                else:
                    raise SOCKS5ProtocolError(
                        "unsupported SOCKS command",
                        reply_code=SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
                    )
            except SOCKS5ProtocolError as exc:
                LOGGER.warning(
                    "invalid SOCKS5 request from %s:%d: %s",
                    address[0],
                    address[1],
                    exc,
                )
                try:
                    connection.sendall(build_socks5_reply(exc.reply_code, bind_host=local_host))
                except OSError:
                    pass
            except TimeoutError as exc:
                LOGGER.warning(
                    "timeout while proxying SOCKS5 request from %s:%d: %s",
                    address[0],
                    address[1],
                    exc,
                )
                try:
                    connection.sendall(build_socks5_reply(SOCKS5_REPLY_TTL_EXPIRED, bind_host=local_host))
                except OSError:
                    pass
            except RuntimeError as exc:
                LOGGER.warning(
                    "SOCKS5 upstream open failed for %s:%d: %s",
                    address[0],
                    address[1],
                    exc,
                )
                try:
                    connection.sendall(
                        build_socks5_reply(SOCKS5_REPLY_HOST_UNREACHABLE, bind_host=local_host)
                    )
                except OSError:
                    pass
            except OSError:
                pass
            finally:
                if stream_id is not None:
                    try:
                        self.client.close_stream(stream_id)
                    except Exception:
                        self.client.reliable.clear_stream_state(self.client.session_id, stream_id)


def _run_proxy_servers(client: Client, config: ClientConfig) -> None:
    listeners = [
        (
            "http",
            HTTPProxyServer(
                client=client,
                bind_host=config.http_proxy_bind_host,
                bind_port=config.http_proxy_bind_port,
            ),
        ),
    ]
    if config.socks_proxy_enable:
        listeners.append(
            (
                "socks5",
                SOCKS5ProxyServer(
                    client=client,
                    bind_host=config.socks_proxy_bind_host,
                    bind_port=config.socks_proxy_bind_port,
                ),
            )
        )
    else:
        LOGGER.info("SOCKS5 proxy listener disabled")

    listener_threads: list[Thread] = []
    for name, listener in listeners:
        thread = Thread(target=listener.serve_forever, daemon=True, name=f"{name}-proxy-listener")
        thread.start()
        listener_threads.append(thread)

    while True:
        for thread in listener_threads:
            thread.join(timeout=1.0)
            if not thread.is_alive():
                raise RuntimeError(f"{thread.name} stopped unexpectedly")


def main() -> None:
    config = load_client_config()
    configure_logging(config.common.log_level)
    with Client(config) as client:
        client.authenticate()
        _run_proxy_servers(client, config)


if __name__ == "__main__":
    main()
