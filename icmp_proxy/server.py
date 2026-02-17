from __future__ import annotations

import logging
import os
import socket
from threading import Lock, Thread

from .auth import (
    ReplayCache,
    generate_nonce,
    load_psk,
    now_ms,
    sign_client_hello,
    sign_server_hello_ack,
    timestamp_within_window,
    verify_signature,
)
from .config import DEFAULT_PSK, ServerConfig, load_server_config
from .icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REQUEST, ICMP_ECHO_REQUEST_CODE
from .protocol import (
    Close,
    CloseAck,
    Data,
    Frame,
    Hello,
    HelloAck,
    MessageType,
    OpenErr,
    OpenOk,
    OpenStream,
)
from .transport import ReliableICMPSession

LOGGER = logging.getLogger("icmp_proxy.server")


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


class Server:
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.outbound_connections: dict[int, socket.socket] = {}
        self.connection_lock = Lock()
        self.psk = load_psk(config.common.psk)
        if config.common.psk.strip() == DEFAULT_PSK:
            LOGGER.warning(
                "using default PSK; set [common].psk in config.ini or ICMP_PROXY_PSK in the environment"
            )
        self.replay_cache = ReplayCache(
            ttl_ms=config.common.auth_replay_ttl_ms,
            max_entries=config.common.auth_replay_max_entries,
        )
        self.hello_cache: dict[bytes, tuple[int, HelloAck, int]] = {}
        self.active_session_id: int | None = None
        self.client_nonce: bytes | None = None

    def __enter__(self) -> "Server":
        LOGGER.info("starting server")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.socket.bind((self.config.bind_host, 0))
        session = self.config.session
        self.reliable = ReliableICMPSession(
            connection=self.socket,
            remote_host=self.config.client_host,
            outbound_icmp_type=ICMP_ECHO_REPLY,
            outbound_icmp_code=ICMP_ECHO_REPLY_CODE,
            inbound_icmp_type=ICMP_ECHO_REQUEST,
            inbound_icmp_code=ICMP_ECHO_REQUEST_CODE,
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
            on_frame=self.process_frame,
            on_retry_exhausted=self.on_retry_exhausted,
        )
        self.reliable.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        LOGGER.info("stopping server")
        self.reliable.stop()
        with self.connection_lock:
            connections = list(self.outbound_connections.values())
            self.outbound_connections.clear()
        for connection in connections:
            connection.close()
        self.socket.close()
        LOGGER.info("server stopped")

    def __call__(self) -> None:
        self.reliable.wait()

    def _allocate_stream_id(self) -> int:
        while True:
            stream_id = int.from_bytes(os.urandom(4), byteorder="big")
            if stream_id == 0:
                continue
            with self.connection_lock:
                if stream_id not in self.outbound_connections:
                    return stream_id

    def _stream_exists(self, stream_id: int) -> bool:
        with self.connection_lock:
            return stream_id in self.outbound_connections

    def _close_stream(self, stream_id: int) -> None:
        with self.connection_lock:
            outbound_connection = self.outbound_connections.pop(stream_id, None)
        if outbound_connection is not None:
            outbound_connection.close()

    def _send_open_err(self, *, session_id: int, error_code: int, reason: str) -> None:
        self.reliable.send_untracked(
            msg_type=MessageType.OPEN_ERR,
            session_id=session_id,
            stream_id=0,
            payload=OpenErr(error_code=error_code, reason=reason).encode(),
        )

    def relay(self, session_id: int, stream_id: int) -> None:
        with self.connection_lock:
            outbound_connection = self.outbound_connections.get(stream_id)
        if outbound_connection is None:
            return
        try:
            while True:
                data = outbound_connection.recv(4096)
                if not data:
                    break
                mtu_payload = max(1, self.config.session.mtu_payload)
                for offset in range(0, len(data), mtu_payload):
                    chunk = data[offset : offset + mtu_payload]
                    self.reliable.send_reliable(
                        msg_type=MessageType.DATA,
                        session_id=session_id,
                        stream_id=stream_id,
                        payload=Data(payload=chunk).encode(),
                    )
        except OSError:
            pass
        finally:
            if self._stream_exists(stream_id):
                self.reliable.send_untracked(
                    msg_type=MessageType.CLOSE,
                    session_id=session_id,
                    stream_id=stream_id,
                    payload=Close().encode(),
                )
            self._close_stream(stream_id)
            self.reliable.clear_stream_state(stream_id)

    def process_hello(self, frame: Frame) -> None:
        try:
            hello = Hello.decode(frame.payload)
        except ValueError:
            return

        cache_entry = self.hello_cache.get(hello.nonce)
        now_timestamp_ms = now_ms()
        if cache_entry is not None:
            cached_session_id, cached_ack, issued_at_ms = cache_entry
            if now_timestamp_ms - issued_at_ms <= self.config.common.auth_replay_ttl_ms:
                self.reliable.send_untracked(
                    msg_type=MessageType.HELLO_ACK,
                    session_id=cached_session_id,
                    stream_id=0,
                    payload=cached_ack.encode(),
                    ack_num=frame.seq_num,
                )
                return
            self.hello_cache.pop(hello.nonce, None)

        if hello.client_id != self.config.common.client_id:
            LOGGER.warning("rejecting unknown client id=%s", hello.client_id)
            return

        if not timestamp_within_window(
            timestamp_ms=hello.timestamp_ms,
            now_timestamp_ms=now_timestamp_ms,
            allowed_skew_ms=self.config.common.auth_skew_ms,
        ):
            LOGGER.warning("rejecting stale hello timestamp")
            return

        if not self.replay_cache.add_if_new(hello.nonce, now_timestamp_ms):
            LOGGER.warning("rejecting replayed hello nonce")
            return

        expected_sig = sign_client_hello(
            psk=self.psk,
            client_id=hello.client_id,
            nonce=hello.nonce,
            timestamp_ms=hello.timestamp_ms,
        )
        if not verify_signature(expected_sig, hello.hmac_sha256):
            LOGGER.warning("rejecting hello with invalid signature")
            return

        session_id = int.from_bytes(os.urandom(4), "big") or 1
        server_nonce = generate_nonce()
        ack_timestamp_ms = now_ms()
        ack_hmac = sign_server_hello_ack(
            psk=self.psk,
            session_id=session_id,
            client_nonce=hello.nonce,
            server_nonce=server_nonce,
            timestamp_ms=ack_timestamp_ms,
        )
        if self.active_session_id is not None and self.active_session_id != session_id:
            with self.connection_lock:
                old_stream_ids = list(self.outbound_connections.keys())
                old_connections = list(self.outbound_connections.values())
                self.outbound_connections.clear()
            for conn in old_connections:
                conn.close()
            for old_stream_id in old_stream_ids:
                self.reliable.clear_stream_state(old_stream_id)
        hello_ack = HelloAck(
            server_nonce=server_nonce,
            timestamp_ms=ack_timestamp_ms,
            hmac_sha256=ack_hmac,
        )
        self.hello_cache[hello.nonce] = (session_id, hello_ack, now_timestamp_ms)
        if len(self.hello_cache) > self.config.common.auth_replay_max_entries:
            oldest_nonce = next(iter(self.hello_cache))
            self.hello_cache.pop(oldest_nonce, None)
        self.active_session_id = session_id
        self.client_nonce = hello.nonce
        self.reliable.send_untracked(
            msg_type=MessageType.HELLO_ACK,
            session_id=session_id,
            stream_id=0,
            payload=hello_ack.encode(),
            ack_num=frame.seq_num,
        )

    def process_open_stream(self, frame: Frame) -> None:
        try:
            open_stream = OpenStream.decode(frame.payload)
        except ValueError:
            self._send_open_err(
                session_id=frame.session_id,
                error_code=400,
                reason="invalid open payload",
            )
            return

        with self.connection_lock:
            if len(self.outbound_connections) >= self.config.max_streams:
                self._send_open_err(
                    session_id=frame.session_id,
                    error_code=429,
                    reason="too many streams",
                )
                return

        outbound_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outbound_connection.settimeout(self.config.target_connect_timeout_ms / 1000.0)
        try:
            outbound_connection.connect((open_stream.remote_host, open_stream.remote_port))
        except OSError:
            outbound_connection.close()
            self._send_open_err(
                session_id=frame.session_id,
                error_code=503,
                reason="upstream connect failed",
            )
            return
        finally:
            outbound_connection.settimeout(None)

        stream_id = self._allocate_stream_id()
        with self.connection_lock:
            self.outbound_connections[stream_id] = outbound_connection

        relay_thread = Thread(
            target=self.relay,
            args=(frame.session_id, stream_id),
            daemon=True,
        )
        relay_thread.start()

        self.reliable.send_reliable(
            msg_type=MessageType.OPEN_OK,
            session_id=frame.session_id,
            stream_id=stream_id,
            payload=OpenOk(assigned_stream_id=stream_id).encode(),
        )

    def process_data(self, frame: Frame) -> None:
        payload = Data.decode(frame.payload).payload
        with self.connection_lock:
            connection = self.outbound_connections.get(frame.stream_id)
        if connection is None:
            return
        try:
            connection.sendall(payload)
        except OSError:
            self._close_stream(frame.stream_id)
            self.reliable.clear_stream_state(frame.stream_id)

    def process_close(self, frame: Frame) -> None:
        try:
            Close.decode(frame.payload)
        except ValueError:
            return
        self._close_stream(frame.stream_id)
        self.reliable.clear_stream_state(frame.stream_id)
        self.reliable.send_untracked(
            msg_type=MessageType.CLOSE_ACK,
            session_id=frame.session_id,
            stream_id=frame.stream_id,
            payload=CloseAck().encode(),
            ack_num=frame.seq_num,
        )

    def on_retry_exhausted(self, stream_id: int, msg_type: MessageType) -> None:
        if stream_id == 0:
            return
        LOGGER.warning("retry exhausted stream_id=%d msg_type=%s", stream_id, msg_type.name)
        self._close_stream(stream_id)
        self.reliable.clear_stream_state(stream_id)

    def process_frame(self, frame: Frame) -> None:
        if frame.msg_type == MessageType.HELLO:
            self.process_hello(frame)
            return

        if self.active_session_id is None:
            return
        if frame.session_id != self.active_session_id:
            return

        if frame.msg_type == MessageType.OPEN_STREAM:
            self.process_open_stream(frame)
        elif frame.msg_type == MessageType.DATA:
            self.process_data(frame)
        elif frame.msg_type == MessageType.CLOSE:
            self.process_close(frame)


def main() -> None:
    config = load_server_config()
    configure_logging(config.common.log_level)
    with Server(config) as server:
        server()


if __name__ == "__main__":
    main()
