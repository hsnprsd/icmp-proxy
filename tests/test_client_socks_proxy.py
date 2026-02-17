import socket

from icmp_proxy.client import (
    SOCKS5_CMD_CONNECT,
    SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
    SOCKS5_REPLY_HOST_UNREACHABLE,
    SOCKS5_REPLY_SUCCEEDED,
    SOCKS5ProtocolError,
    SOCKS5ProxyServer,
    build_socks5_method_selection,
    build_socks5_reply,
    parse_socks5_connect_request,
    read_socks5_connect_request,
    read_socks5_greeting,
)


class FakeConnection:
    def __init__(self, chunks: list[bytes]) -> None:
        self._buffer = bytearray().join(chunks)
        self.sent = bytearray()
        self.timeout: float | None = None

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        _ = exc_type
        _ = exc_value
        _ = traceback
        return

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        if size <= 0:
            return b""
        if not self._buffer:
            return b""
        chunk = bytes(self._buffer[:size])
        del self._buffer[:size]
        return chunk

    def sendall(self, payload: bytes) -> None:
        self.sent.extend(payload)


class FakeClient:
    def __init__(self, *, open_error: Exception | None = None) -> None:
        self.open_error = open_error
        self.opened: list[tuple[str, int]] = []
        self.closed: list[int] = []
        self.reliable = type("Reliable", (), {"clear_stream_state": lambda *_args, **_kwargs: None})()

    def open_stream(self, remote_host: str, remote_port: int) -> int:
        self.opened.append((remote_host, remote_port))
        if self.open_error is not None:
            raise self.open_error
        return 77

    def close_stream(self, stream_id: int) -> None:
        self.closed.append(stream_id)

    def send_stream_data(self, _stream_id: int, _payload: bytes) -> None:  # pragma: no cover
        return

    def recv_stream_chunk(self, _stream_id: int, timeout_s: float = 2.0) -> tuple[bytes | None, bool]:  # pragma: no cover
        _ = timeout_s
        return b"", True


def _build_domain_connect_request(host: str, port: int) -> bytes:
    host_bytes = host.encode("idna")
    return bytes([0x05, SOCKS5_CMD_CONNECT, 0x00, 0x03, len(host_bytes)]) + host_bytes + port.to_bytes(2, "big")


def test_parse_socks5_connect_request_domain() -> None:
    request = _build_domain_connect_request("example.com", 443)
    parsed = parse_socks5_connect_request(request)
    assert parsed.remote_host == "example.com"
    assert parsed.remote_port == 443


def test_parse_socks5_connect_request_ipv4() -> None:
    request = bytes([0x05, SOCKS5_CMD_CONNECT, 0x00, 0x01]) + socket.inet_aton("203.0.113.5") + (8080).to_bytes(2, "big")
    parsed = parse_socks5_connect_request(request)
    assert parsed.remote_host == "203.0.113.5"
    assert parsed.remote_port == 8080


def test_parse_socks5_connect_request_ipv6() -> None:
    request = bytes([0x05, SOCKS5_CMD_CONNECT, 0x00, 0x04]) + socket.inet_pton(socket.AF_INET6, "2001:db8::1") + (53).to_bytes(2, "big")
    parsed = parse_socks5_connect_request(request)
    assert parsed.remote_host == "2001:db8::1"
    assert parsed.remote_port == 53


def test_parse_socks5_connect_rejects_unsupported_command() -> None:
    request = bytes([0x05, 0x02, 0x00, 0x01]) + socket.inet_aton("127.0.0.1") + (80).to_bytes(2, "big")
    try:
        parse_socks5_connect_request(request)
    except SOCKS5ProtocolError as exc:
        assert exc.reply_code == SOCKS5_REPLY_COMMAND_NOT_SUPPORTED
    else:
        raise AssertionError("expected SOCKS5ProtocolError")


def test_parse_socks5_connect_rejects_unsupported_atyp() -> None:
    request = bytes([0x05, 0x01, 0x00, 0x09, 0x00, 0x50])
    try:
        parse_socks5_connect_request(request)
    except SOCKS5ProtocolError as exc:
        assert exc.reply_code == SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED
    else:
        raise AssertionError("expected SOCKS5ProtocolError")


def test_read_socks5_greeting_reads_methods() -> None:
    connection = FakeConnection([b"\x05\x02", b"\x00\x02"])
    methods = read_socks5_greeting(connection)  # type: ignore[arg-type]
    assert methods == b"\x00\x02"


def test_read_socks5_connect_request_from_connection() -> None:
    request = _build_domain_connect_request("api.test", 8443)
    connection = FakeConnection([request[:4], request[4:5], request[5:8], request[8:]])
    parsed = read_socks5_connect_request(connection)  # type: ignore[arg-type]
    assert parsed.remote_host == "api.test"
    assert parsed.remote_port == 8443


def test_socks_reply_builders() -> None:
    assert build_socks5_method_selection(0x00) == b"\x05\x00"
    assert build_socks5_reply(SOCKS5_REPLY_SUCCEEDED) == b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"


def test_socks5_proxy_server_success_handshake(monkeypatch) -> None:
    fake_client = FakeClient()
    server = SOCKS5ProxyServer(fake_client, bind_host="127.0.0.1", bind_port=1080)
    relay_calls: list[tuple[int, bytes]] = []

    def _fake_relay(client, connection, stream_id: int, initial_upstream: bytes) -> None:
        _ = client
        _ = connection
        relay_calls.append((stream_id, initial_upstream))

    monkeypatch.setattr("icmp_proxy.client._relay_stream", _fake_relay)
    connection = FakeConnection(
        [
            b"\x05\x01\x00",
            _build_domain_connect_request("example.com", 443),
        ]
    )
    server._handle_connection(connection, ("127.0.0.1", 5555))  # type: ignore[arg-type]

    assert bytes(connection.sent) == b"\x05\x00\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    assert fake_client.opened == [("example.com", 443)]
    assert fake_client.closed == [77]
    assert relay_calls == [(77, b"")]


def test_socks5_proxy_server_open_failure_returns_reply() -> None:
    fake_client = FakeClient(open_error=RuntimeError("upstream connect failed"))
    server = SOCKS5ProxyServer(fake_client, bind_host="127.0.0.1", bind_port=1080)
    connection = FakeConnection(
        [
            b"\x05\x01\x00",
            _build_domain_connect_request("example.com", 443),
        ]
    )
    server._handle_connection(connection, ("127.0.0.1", 5556))  # type: ignore[arg-type]

    assert bytes(connection.sent) == b"\x05\x00" + build_socks5_reply(SOCKS5_REPLY_HOST_UNREACHABLE)
    assert fake_client.closed == []
