from pathlib import Path

from icmp_proxy.auth import now_ms, sign_client_hello
from icmp_proxy.config import CommonConfig, ServerConfig, SessionConfig
from icmp_proxy.protocol import Frame, Hello, MessageType
from icmp_proxy.server import Server


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
    ) -> None:
        self.sent.append(
            {
                "msg_type": msg_type,
                "session_id": session_id,
                "stream_id": stream_id,
                "payload": payload,
                "ack_num": ack_num,
                "flags": flags,
            }
        )

    def clear_stream_state(self, stream_id: int) -> None:  # pragma: no cover - no-op in this test
        _ = stream_id


def _server_config(psk_file: Path) -> ServerConfig:
    return ServerConfig(
        bind_host="0.0.0.0",
        client_host="127.0.0.1",
        max_streams=32,
        target_connect_timeout_ms=1000,
        stream_idle_timeout_ms=30_000,
        common=CommonConfig(
            log_level="WARNING",
            psk_file=str(psk_file),
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


def test_process_hello_duplicate_nonce_resends_same_session(tmp_path) -> None:
    psk_file = tmp_path / "psk.txt"
    psk_file.write_text("test-secret\n", encoding="utf-8")
    server = Server(_server_config(psk_file))
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

    server.process_hello(frame1)
    server.process_hello(frame2)

    assert len(server.reliable.sent) == 2  # type: ignore[attr-defined]
    first = server.reliable.sent[0]  # type: ignore[attr-defined]
    second = server.reliable.sent[1]  # type: ignore[attr-defined]
    assert first["msg_type"] == MessageType.HELLO_ACK
    assert second["msg_type"] == MessageType.HELLO_ACK
    assert first["session_id"] == second["session_id"]
