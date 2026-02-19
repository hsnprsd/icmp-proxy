import time

from icmp_proxy.client import Client
from icmp_proxy.config import ClientConfig, CommonConfig, SessionConfig
from icmp_proxy.protocol import MessageType


class FakeReliable:
    def __init__(self) -> None:
        self.sent: list[dict[str, int | bytes | MessageType]] = []

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
        _ = (ack_num, flags, remote_host)
        self.sent.append(
            {
                "msg_type": msg_type,
                "session_id": session_id,
                "stream_id": stream_id,
                "payload": payload,
            }
        )


def _wait_until(predicate, timeout_s: float = 0.6, interval_s: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return False


def _client_config(*, heartbeat_interval_ms: int) -> ClientConfig:
    return ClientConfig(
        server_host="127.0.0.1",
        http_proxy_bind_host="127.0.0.1",
        http_proxy_bind_port=8080,
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
            heartbeat_interval_ms=heartbeat_interval_ms,
        ),
    )


def test_heartbeat_sender_emits_periodic_frames() -> None:
    client = Client(_client_config(heartbeat_interval_ms=20))
    fake_reliable = FakeReliable()
    client.reliable = fake_reliable  # type: ignore[assignment]
    client.session_id = 77
    client._start_heartbeat()
    try:
        assert _wait_until(lambda: len(fake_reliable.sent) >= 2)
    finally:
        client._stop_heartbeat()

    for frame in fake_reliable.sent:
        assert frame["msg_type"] == MessageType.HEARTBEAT
        assert frame["session_id"] == 77
        assert frame["stream_id"] == 0
        assert frame["payload"] == b""


def test_heartbeat_sender_disabled_when_interval_is_zero() -> None:
    client = Client(_client_config(heartbeat_interval_ms=0))
    fake_reliable = FakeReliable()
    client.reliable = fake_reliable  # type: ignore[assignment]
    client.session_id = 77

    client._start_heartbeat()
    time.sleep(0.08)
    client._stop_heartbeat()

    assert client._heartbeat_thread is None
    assert fake_reliable.sent == []


def test_heartbeat_sender_stops_cleanly() -> None:
    client = Client(_client_config(heartbeat_interval_ms=20))
    fake_reliable = FakeReliable()
    client.reliable = fake_reliable  # type: ignore[assignment]
    client.session_id = 77
    client._start_heartbeat()
    assert _wait_until(lambda: len(fake_reliable.sent) >= 1)

    client._stop_heartbeat()
    sent_after_stop = len(fake_reliable.sent)
    time.sleep(0.08)

    assert client._heartbeat_thread is None
    assert len(fake_reliable.sent) == sent_after_stop
