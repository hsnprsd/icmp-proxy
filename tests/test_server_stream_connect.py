from icmp_proxy.config import CommonConfig, ServerConfig, SessionConfig
from icmp_proxy.protocol import Frame, MessageType, OpenErr, OpenStream
from icmp_proxy.server import Server, SessionState


class FakeReliable:
    def __init__(self) -> None:
        self.sent_reliable: list[dict[str, object]] = []
        self.sent_untracked: list[dict[str, object]] = []

    def send_reliable(self, **kwargs) -> int:  # type: ignore[no-untyped-def]
        self.sent_reliable.append(kwargs)
        return 1

    def send_untracked(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        self.sent_untracked.append(kwargs)

    def clear_stream_state(self, session_id: int, stream_id: int) -> None:
        _ = (session_id, stream_id)


class FakeTCPSocket:
    def __init__(self) -> None:
        self.timeout: float | None = None
        self.closed = False

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def close(self) -> None:
        self.closed = True


def _server_config() -> ServerConfig:
    return ServerConfig(
        bind_host="0.0.0.0",
        client_host="127.0.0.1",
        target_connect_timeout_ms=1000,
        session_idle_timeout_ms=30_000,
        prometheus_enable=False,
        prometheus_bind_host="0.0.0.0",
        prometheus_port=2112,
        common=CommonConfig(
            log_level="WARNING",
            psk="test-secret",
            client_id="test-client",
            auth_skew_ms=30_000,
            auth_replay_ttl_ms=30_000,
            auth_replay_max_entries=128,
        ),
        session=SessionConfig(
            retx_timeout_ms=100,
            retx_max_retries=3,
            retx_scan_interval_ms=20,
            seen_limit_per_stream=1024,
            max_inflight_per_stream=32,
            mtu_payload=1200,
        ),
    )


def test_process_open_stream_uses_create_connection_for_ipv6(monkeypatch) -> None:
    server = Server(_server_config())
    server.reliable = FakeReliable()  # type: ignore[assignment]
    server.sessions[100] = SessionState(
        remote_host="198.51.100.10",
        client_nonce=b"x" * 16,
        last_activity_ms=1,
    )
    fake_socket = FakeTCPSocket()
    create_calls: list[tuple[tuple[str, int], float]] = []

    def _fake_create_connection(address, timeout=None, source_address=None):  # type: ignore[no-untyped-def]
        _ = source_address
        create_calls.append((address, timeout))
        return fake_socket

    monkeypatch.setattr("icmp_proxy.server.socket.create_connection", _fake_create_connection)
    monkeypatch.setattr(server, "relay_tcp", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(server, "_allocate_stream_id", lambda _session_id: 77)

    frame = Frame.make(
        msg_type=MessageType.OPEN_STREAM,
        session_id=100,
        stream_id=0,
        payload=OpenStream(remote_host="2001:db8::20", remote_port=443).encode(),
    )
    server.process_open_stream(frame)

    assert create_calls == [(("2001:db8::20", 443), 1.0)]
    assert fake_socket.timeout is None
    assert server.outbound_streams[(100, 77)].socket is fake_socket  # type: ignore[index]
    assert len(server.reliable.sent_reliable) == 1  # type: ignore[attr-defined]
    sent = server.reliable.sent_reliable[0]  # type: ignore[attr-defined]
    assert sent["msg_type"] == MessageType.OPEN_OK
    assert sent["session_id"] == 100
    assert sent["stream_id"] == 77
    assert sent["remote_host"] == "198.51.100.10"


def test_process_open_stream_connect_failure_returns_open_err(monkeypatch) -> None:
    server = Server(_server_config())
    server.reliable = FakeReliable()  # type: ignore[assignment]
    server.sessions[100] = SessionState(
        remote_host="198.51.100.10",
        client_nonce=b"x" * 16,
        last_activity_ms=1,
    )

    def _fake_create_connection(address, timeout=None, source_address=None):  # type: ignore[no-untyped-def]
        _ = (address, timeout, source_address)
        raise OSError("connect failed")

    monkeypatch.setattr("icmp_proxy.server.socket.create_connection", _fake_create_connection)

    frame = Frame.make(
        msg_type=MessageType.OPEN_STREAM,
        session_id=100,
        stream_id=0,
        payload=OpenStream(remote_host="2001:db8::20", remote_port=443).encode(),
    )
    server.process_open_stream(frame)

    assert len(server.reliable.sent_reliable) == 0  # type: ignore[attr-defined]
    assert len(server.reliable.sent_untracked) == 1  # type: ignore[attr-defined]
    open_err_payload = server.reliable.sent_untracked[0]["payload"]  # type: ignore[attr-defined]
    open_err = OpenErr.decode(open_err_payload)  # type: ignore[arg-type]
    assert open_err.error_code == 503
    assert "upstream connect failed" in open_err.reason
