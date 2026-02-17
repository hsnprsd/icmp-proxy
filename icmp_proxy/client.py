from __future__ import annotations

import logging
import socket
import time

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


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


class Client:
    def __init__(self, config: ClientConfig) -> None:
        self.config = config
        self.psk = load_psk(config.common.psk_file)
        self.session_id = 0
        self.client_nonce = b""

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
            frame = self.reliable.wait_for_frame(
                lambda f: f.stream_id == stream_id
                and f.msg_type in (MessageType.DATA, MessageType.CLOSE, MessageType.CLOSE_ACK),
                timeout_s=timeout_s,
            )
            if frame is None:
                break
            if frame.msg_type in (MessageType.CLOSE, MessageType.CLOSE_ACK):
                break
            parts.append(Data.decode(frame.payload).payload)
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


def main() -> None:
    config = load_client_config()
    configure_logging(config.common.log_level)
    with Client(config) as client:
        client.authenticate()
        stream_id = client.open_stream("google.com", 80)
        request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: google.com\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        started_at = time.monotonic()
        client.send_stream_data(stream_id, request)
        response = client.recv_stream_data(stream_id, timeout_s=8.0)
        LOGGER.info(
            "received response bytes=%d duration_ms=%.1f",
            len(response),
            (time.monotonic() - started_at) * 1000.0,
        )
        client.close_stream(stream_id)


if __name__ == "__main__":
    main()
