from icmp_proxy.auth import now_ms, sign_client_hello
from icmp_proxy.config import CommonConfig, ServerConfig, SessionConfig
from icmp_proxy.protocol import Frame, Hello, MessageType
from icmp_proxy.server import Server


class FakeReliable:
    def __init__(self) -> None:
        self.sent: list[dict[str, int | bytes | str | None | MessageType]] = []

    def send_reliable(
        self,
        *,
        msg_type: MessageType,
        session_id: int,
        stream_id: int,
        payload: bytes,
        flags: int = 0,
        remote_host: str | None = None,
    ) -> int:
        self.sent.append(
            {
                "msg_type": msg_type,
                "session_id": session_id,
                "stream_id": stream_id,
                "payload": payload,
                "flags": flags,
                "remote_host": remote_host,
            }
        )
        return 1

    def send_untracked(
        self,
        *,
        msg_type: MessageType,
        session_id: int,
        stream_id: int,
        payload: bytes,
        ack_num: int = 0,
        flags: int = 0,
        remote_host: str | None = None,
    ) -> None:
        _ = remote_host
        self.sent.append(
            {
                "msg_type": msg_type,
                "session_id": session_id,
                "stream_id": stream_id,
                "payload": payload,
                "ack_num": ack_num,
                "flags": flags,
                "remote_host": remote_host,
            }
        )

    def clear_stream_state(self, session_id: int, stream_id: int) -> None:  # pragma: no cover - no-op in this test
        _ = (session_id, stream_id)


class FakeSocket:
    def bind(self, addr) -> None:  # type: ignore[no-untyped-def]
        _ = addr

    def close(self) -> None:
        return


class FakeRuntimeReliable:
    def __init__(self, **kwargs) -> None:  # type: ignore[no-untyped-def]
        _ = kwargs

    def start(self) -> None:
        return

    def stop(self) -> None:
        return

    def wait(self) -> None:
        return

    def clear_stream_state(self, session_id: int, stream_id: int) -> None:
        _ = (session_id, stream_id)


def _server_config() -> ServerConfig:
    return ServerConfig(
        bind_host="0.0.0.0",
        client_host="127.0.0.1",
        target_connect_timeout_ms=1000,
        session_idle_timeout_ms=30_000,
        prometheus_enable=True,
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


def test_process_hello_duplicate_nonce_resends_same_session() -> None:
    server = Server(_server_config())
    server.reliable = FakeReliable()  # type: ignore[assignment]

    nonce = b"x" * 16
    timestamp_ms = now_ms()
    hello = Hello(
        client_id="test-client",
        nonce=nonce,
        timestamp_ms=timestamp_ms,
        hmac_sha256=sign_client_hello(
            psk=b"test-secret",
            client_id="test-client",
            nonce=nonce,
            timestamp_ms=timestamp_ms,
        ),
    )
    frame1 = Frame.make(
        msg_type=MessageType.HELLO,
        payload=hello.encode(),
        session_id=0,
        stream_id=0,
        seq_num=11,
    )
    frame2 = Frame.make(
        msg_type=MessageType.HELLO,
        payload=hello.encode(),
        session_id=0,
        stream_id=0,
        seq_num=12,
    )

    server.process_hello(frame1, "127.0.0.1")
    server.process_hello(frame2, "127.0.0.1")

    assert len(server.reliable.sent) == 2  # type: ignore[attr-defined]
    first = server.reliable.sent[0]  # type: ignore[attr-defined]
    second = server.reliable.sent[1]  # type: ignore[attr-defined]
    assert first["msg_type"] == MessageType.HELLO_ACK
    assert second["msg_type"] == MessageType.HELLO_ACK
    assert first["session_id"] == second["session_id"]


def test_process_hello_allows_multiple_active_sessions() -> None:
    server = Server(_server_config())
    server.reliable = FakeReliable()  # type: ignore[assignment]

    timestamp_ms = now_ms()
    hello1 = Hello(
        client_id="test-client",
        nonce=b"a" * 16,
        timestamp_ms=timestamp_ms,
        hmac_sha256=sign_client_hello(
            psk=b"test-secret",
            client_id="test-client",
            nonce=b"a" * 16,
            timestamp_ms=timestamp_ms,
        ),
    )
    hello2 = Hello(
        client_id="test-client",
        nonce=b"b" * 16,
        timestamp_ms=timestamp_ms,
        hmac_sha256=sign_client_hello(
            psk=b"test-secret",
            client_id="test-client",
            nonce=b"b" * 16,
            timestamp_ms=timestamp_ms,
        ),
    )
    frame1 = Frame.make(msg_type=MessageType.HELLO, payload=hello1.encode(), session_id=0, stream_id=0, seq_num=1)
    frame2 = Frame.make(msg_type=MessageType.HELLO, payload=hello2.encode(), session_id=0, stream_id=0, seq_num=2)

    server.process_hello(frame1, "10.0.0.1")
    server.process_hello(frame2, "10.0.0.2")

    assert len(server.sessions) == 2
    ack1 = server.reliable.sent[0]  # type: ignore[attr-defined]
    ack2 = server.reliable.sent[1]  # type: ignore[attr-defined]
    assert ack1["session_id"] != ack2["session_id"]
    assert server.sessions[ack1["session_id"]].remote_host == "10.0.0.1"  # type: ignore[index]
    assert server.sessions[ack2["session_id"]].remote_host == "10.0.0.2"  # type: ignore[index]


def test_process_frame_rejects_mismatched_source_host() -> None:
    server = Server(_server_config())
    server.reliable = FakeReliable()  # type: ignore[assignment]

    timestamp_ms = now_ms()
    hello = Hello(
        client_id="test-client",
        nonce=b"z" * 16,
        timestamp_ms=timestamp_ms,
        hmac_sha256=sign_client_hello(
            psk=b"test-secret",
            client_id="test-client",
            nonce=b"z" * 16,
            timestamp_ms=timestamp_ms,
        ),
    )
    hello_frame = Frame.make(msg_type=MessageType.HELLO, payload=hello.encode(), session_id=0, stream_id=0, seq_num=7)
    server.process_hello(hello_frame, "10.1.1.1")

    session_id = int(server.reliable.sent[0]["session_id"])  # type: ignore[attr-defined]
    before = len(server.reliable.sent)  # type: ignore[attr-defined]

    open_datagram_frame = Frame.make(
        msg_type=MessageType.OPEN_DATAGRAM,
        payload=b"",
        session_id=session_id,
        stream_id=0,
        seq_num=9,
    )
    server.process_frame(open_datagram_frame, "10.1.1.2")

    assert len(server.reliable.sent) == before  # type: ignore[attr-defined]


def test_server_context_starts_prometheus_when_enabled(monkeypatch) -> None:
    config = _server_config()
    stop_called = {"value": False}
    start_called = {"value": False}

    class FakeMetricsServer:
        def stop(self) -> None:
            stop_called["value"] = True

    def _fake_start(host: str, port: int, metrics) -> FakeMetricsServer:  # type: ignore[no-untyped-def]
        _ = metrics
        start_called["value"] = True
        assert host == "0.0.0.0"
        assert port == 2112
        return FakeMetricsServer()

    monkeypatch.setattr("icmp_proxy.server.start_prometheus_http_server", _fake_start)
    monkeypatch.setattr("icmp_proxy.server.ReliableICMPSession", FakeRuntimeReliable)
    monkeypatch.setattr("icmp_proxy.server.socket.socket", lambda *args, **kwargs: FakeSocket())

    with Server(config):
        assert start_called["value"] is True

    assert stop_called["value"] is True


def test_server_context_skips_prometheus_when_disabled(monkeypatch) -> None:
    config = _server_config()
    config = ServerConfig(
        bind_host=config.bind_host,
        client_host=config.client_host,
        target_connect_timeout_ms=config.target_connect_timeout_ms,
        session_idle_timeout_ms=config.session_idle_timeout_ms,
        prometheus_enable=False,
        prometheus_bind_host=config.prometheus_bind_host,
        prometheus_port=config.prometheus_port,
        common=config.common,
        session=config.session,
    )
    start_called = {"value": False}

    def _fake_start(host: str, port: int, metrics) -> None:  # type: ignore[no-untyped-def]
        _ = (host, port, metrics)
        start_called["value"] = True

    monkeypatch.setattr("icmp_proxy.server.start_prometheus_http_server", _fake_start)
    monkeypatch.setattr("icmp_proxy.server.ReliableICMPSession", FakeRuntimeReliable)
    monkeypatch.setattr("icmp_proxy.server.socket.socket", lambda *args, **kwargs: FakeSocket())

    with Server(config):
        pass

    assert start_called["value"] is False
