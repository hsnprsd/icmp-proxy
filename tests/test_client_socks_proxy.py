import socket
from time import sleep

from icmp_proxy.client import (
    SOCKS5_CMD_CONNECT,
    SOCKS5_CMD_UDP_ASSOCIATE,
    SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED,
    SOCKS5_REPLY_COMMAND_NOT_SUPPORTED,
    SOCKS5_REPLY_HOST_UNREACHABLE,
    SOCKS5_REPLY_SUCCEEDED,
    SOCKS5ProtocolError,
    SOCKS5ProxyServer,
    SOCKS5Request,
    build_socks5_method_selection,
    build_socks5_reply,
    build_socks5_udp_datagram,
    parse_socks5_connect_request,
    parse_socks5_request,
    parse_socks5_udp_datagram,
    read_socks5_connect_request,
    read_socks5_greeting,
    read_socks5_request,
)
from icmp_proxy.protocol import DatagramPacket


class FakeConnection:
    def __init__(self, chunks: list[bytes], *, sockname: tuple[str, int] = ("127.0.0.1", 1080)) -> None:
        self._buffer = bytearray().join(chunks)
        self.sent = bytearray()
        self.timeout: float | None = None
        self._sockname = sockname

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        _ = exc_type
        _ = exc_value
        _ = traceback
        return

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def getsockname(self) -> tuple[str, int]:
        return self._sockname

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
        self.opened_datagram = 0
        self.closed: list[int] = []
        self.sent_datagrams: list[tuple[int, str, int, bytes]] = []
        self.recv_datagrams: list[tuple[DatagramPacket | None, bool]] = []
        self.reliable = type("Reliable", (), {"clear_stream_state": lambda *_args, **_kwargs: None})()

    def open_stream(self, remote_host: str, remote_port: int) -> int:
        self.opened.append((remote_host, remote_port))
        if self.open_error is not None:
            raise self.open_error
        return 77

    def open_datagram(self) -> int:
        self.opened_datagram += 1
        if self.open_error is not None:
            raise self.open_error
        return 88

    def close_stream(self, stream_id: int) -> None:
        self.closed.append(stream_id)

    def send_stream_data(self, _stream_id: int, _payload: bytes) -> None:  # pragma: no cover
        return

    def recv_stream_chunk(self, _stream_id: int, timeout_s: float = 2.0) -> tuple[bytes | None, bool]:  # pragma: no cover
        _ = timeout_s
        return b"", True

    def send_datagram(self, stream_id: int, remote_host: str, remote_port: int, payload: bytes) -> None:
        self.sent_datagrams.append((stream_id, remote_host, remote_port, payload))

    def recv_datagram(self, stream_id: int, timeout_s: float = 2.0) -> tuple[DatagramPacket | None, bool]:
        _ = stream_id
        _ = timeout_s
        if self.recv_datagrams:
            return self.recv_datagrams.pop(0)
        return None, False


class FakeUDPBindSocket:
    def __init__(self) -> None:
        self.timeout: float | None = None
        self.bound = ("0.0.0.0", 0)

    def __enter__(self) -> "FakeUDPBindSocket":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        _ = exc_type
        _ = exc_value
        _ = traceback
        return

    def bind(self, address: tuple[str, int]) -> None:
        self.bound = address

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", 53000)

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout


class FakeRelayUDPSocket:
    def __init__(self, recv_packets: list[tuple[bytes, tuple[str, int]]]) -> None:
        self.recv_packets = list(recv_packets)
        self.sent_packets: list[tuple[bytes, tuple[str, int]]] = []
        self.timeout: float | None = None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        if self.recv_packets:
            return self.recv_packets.pop(0)
        raise socket.timeout

    def sendto(self, payload: bytes, address: tuple[str, int]) -> None:
        self.sent_packets.append((payload, address))


class FakeControlConnectionForRelay:
    def __init__(self, timeout_cycles: int = 20) -> None:
        self.timeout_cycles = timeout_cycles
        self.timeout: float | None = None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, _size: int) -> bytes:
        if self.timeout_cycles > 0:
            self.timeout_cycles -= 1
            sleep(0.01)
            raise socket.timeout
        return b""


def _build_domain_request(command: int, host: str, port: int) -> bytes:
    host_bytes = host.encode("idna")
    return bytes([0x05, command, 0x00, 0x03, len(host_bytes)]) + host_bytes + port.to_bytes(2, "big")


def _build_domain_connect_request(host: str, port: int) -> bytes:
    return _build_domain_request(SOCKS5_CMD_CONNECT, host, port)


def _build_domain_udp_associate_request(host: str, port: int) -> bytes:
    return _build_domain_request(SOCKS5_CMD_UDP_ASSOCIATE, host, port)


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


def test_parse_socks5_request_udp_associate() -> None:
    request = _build_domain_udp_associate_request("0.0.0.0", 0)
    parsed = parse_socks5_request(request)
    assert parsed.command == SOCKS5_CMD_UDP_ASSOCIATE
    assert parsed.remote_host == "0.0.0.0"
    assert parsed.remote_port == 0


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


def test_read_socks5_request_udp_associate_from_connection() -> None:
    request = _build_domain_udp_associate_request("127.0.0.1", 0)
    connection = FakeConnection([request[:4], request[4:5], request[5:8], request[8:]])
    parsed = read_socks5_request(connection)  # type: ignore[arg-type]
    assert parsed == SOCKS5Request(command=SOCKS5_CMD_UDP_ASSOCIATE, remote_host="127.0.0.1", remote_port=0)


def test_socks_reply_builders() -> None:
    assert build_socks5_method_selection(0x00) == b"\x05\x00"
    assert build_socks5_reply(SOCKS5_REPLY_SUCCEEDED) == b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    assert build_socks5_reply(SOCKS5_REPLY_SUCCEEDED, bind_host="127.0.0.1", bind_port=5353) == (
        b"\x05\x00\x00\x01\x7f\x00\x00\x01\x14\xe9"
    )


def test_socks_udp_datagram_round_trip() -> None:
    payload = build_socks5_udp_datagram("example.com", 53, b"abc")
    parsed = parse_socks5_udp_datagram(payload)
    assert parsed.fragment == 0
    assert parsed.remote_host == "example.com"
    assert parsed.remote_port == 53
    assert parsed.payload == b"abc"


def test_socks_udp_datagram_rejects_reserved_bytes() -> None:
    try:
        parse_socks5_udp_datagram(b"\x00\x01\x00\x01\x7f\x00\x00\x01\x00\x35")
    except SOCKS5ProtocolError as exc:
        assert "reserved" in str(exc)
    else:
        raise AssertionError("expected SOCKS5ProtocolError")


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


def test_socks5_proxy_server_udp_associate_handshake(monkeypatch) -> None:
    fake_client = FakeClient()
    server = SOCKS5ProxyServer(fake_client, bind_host="127.0.0.1", bind_port=1080)
    udp_socket = FakeUDPBindSocket()
    relay_calls: list[int] = []

    def _fake_socket(family: int, socktype: int, proto: int = 0):
        _ = proto
        if family == socket.AF_INET and socktype == socket.SOCK_DGRAM:
            return udp_socket
        raise AssertionError("unexpected socket constructor call")

    def _fake_relay(connection, local_udp_socket, stream_id: int, request: SOCKS5Request) -> None:
        _ = connection
        _ = local_udp_socket
        _ = request
        relay_calls.append(stream_id)

    monkeypatch.setattr("icmp_proxy.client.socket.socket", _fake_socket)
    monkeypatch.setattr(server, "_relay_udp_associate", _fake_relay)

    connection = FakeConnection(
        [
            b"\x05\x01\x00",
            _build_domain_udp_associate_request("0.0.0.0", 0),
        ],
        sockname=("127.0.0.1", 1080),
    )
    server._handle_connection(connection, ("127.0.0.1", 5557))  # type: ignore[arg-type]

    assert bytes(connection.sent) == b"\x05\x00" + build_socks5_reply(
        SOCKS5_REPLY_SUCCEEDED,
        bind_host="127.0.0.1",
        bind_port=53000,
    )
    assert fake_client.opened_datagram == 1
    assert fake_client.closed == [88]
    assert relay_calls == [88]


def test_socks5_udp_associate_relay_forwards_both_directions() -> None:
    fake_client = FakeClient()
    server = SOCKS5ProxyServer(fake_client, bind_host="127.0.0.1", bind_port=1080)
    sender_port = 53001
    udp_socket = FakeRelayUDPSocket(
        recv_packets=[
            (
                build_socks5_udp_datagram("1.1.1.1", 53, b"query"),
                ("127.0.0.1", sender_port),
            )
        ]
    )

    fake_client.recv_datagrams.append(
        (
            DatagramPacket(remote_host="198.51.100.9", remote_port=5300, payload=b"resp"),
            False,
        )
    )
    request = SOCKS5Request(
        command=SOCKS5_CMD_UDP_ASSOCIATE,
        remote_host="127.0.0.1",
        remote_port=sender_port,
    )
    control = FakeControlConnectionForRelay(timeout_cycles=20)
    control.settimeout(0.05)
    udp_socket.settimeout(0.05)

    server._relay_udp_associate(control, udp_socket, 88, request)  # type: ignore[arg-type]

    assert fake_client.sent_datagrams == [(88, "1.1.1.1", 53, b"query")]
    assert udp_socket.sent_packets == [
        (
            build_socks5_udp_datagram("198.51.100.9", 5300, b"resp"),
            ("127.0.0.1", sender_port),
        )
    ]
