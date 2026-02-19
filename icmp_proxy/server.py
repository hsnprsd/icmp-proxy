from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import logging
import os
import select
import socket
import time
from threading import Event, Lock, Thread

from ._version import __version__
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
from .metrics import MetricsHTTPServer, ServerPrometheusMetrics, start_prometheus_http_server
from .protocol import (
    Close,
    CloseAck,
    Data,
    DatagramPacket,
    Frame,
    Heartbeat,
    Hello,
    HelloAck,
    MessageType,
    OpenDatagram,
    OpenErr,
    OpenOk,
    OpenStream,
)
from .transport import ReliableICMPSession

LOGGER = logging.getLogger("icmp_proxy.server")


@dataclass
class TCPStreamState:
    socket: socket.socket


@dataclass
class DatagramStreamState:
    sockets: dict[int, socket.socket] = field(default_factory=dict)
    sockets_lock: Lock = field(default_factory=Lock)


@dataclass
class SessionState:
    remote_host: str
    client_nonce: bytes
    last_activity_ms: int
    stream_ids: set[int] = field(default_factory=set)


def configure_logging(level_name: str) -> None:
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


class Server:
    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.outbound_streams: dict[tuple[int, int], TCPStreamState | DatagramStreamState] = {}
        self.sessions: dict[int, SessionState] = {}
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
        self.hello_cache: dict[bytes, tuple[int, HelloAck, int, str]] = {}
        self._reaper_stop_event = Event()
        self._reaper_thread: Thread | None = None
        self._metrics_http_server: MetricsHTTPServer | None = None
        self._metrics = ServerPrometheusMetrics()
        self._sync_metrics_gauges()

    def _sync_metrics_gauges(self) -> None:
        with self.connection_lock:
            self._metrics.set_gauge("icmp_proxy_server_sessions_active", len(self.sessions))
            self._metrics.set_gauge("icmp_proxy_server_streams_active", len(self.outbound_streams))

    def __enter__(self) -> "Server":
        LOGGER.info("starting server")
        if self.config.prometheus_enable:
            self._metrics_http_server = start_prometheus_http_server(
                host=self.config.prometheus_bind_host,
                port=self.config.prometheus_port,
                metrics=self._metrics,
            )
            LOGGER.info(
                "prometheus metrics endpoint listening on %s:%d/metrics",
                self.config.prometheus_bind_host,
                self.config.prometheus_port,
            )
        else:
            LOGGER.info("prometheus metrics endpoint disabled")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            LOGGER.error("raw ICMP socket requires elevated privileges (root/sudo on macOS)")
            raise
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
        self._reaper_stop_event.clear()
        self._reaper_thread = Thread(target=self._session_reaper_loop, daemon=True, name="session-reaper")
        self._reaper_thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        LOGGER.info("stopping server")
        self._reaper_stop_event.set()
        if self._reaper_thread is not None:
            self._reaper_thread.join(timeout=1.0)
        self.reliable.stop()
        with self.connection_lock:
            stream_items = list(self.outbound_streams.items())
            self.outbound_streams.clear()
            self.sessions.clear()
        for stream_key, stream in stream_items:
            self._close_stream_state(stream)
            self.reliable.clear_stream_state(stream_key[0], stream_key[1])
        self.socket.close()
        if self._metrics_http_server is not None:
            self._metrics_http_server.stop()
            self._metrics_http_server = None
        self._sync_metrics_gauges()
        LOGGER.info("server stopped")

    def __call__(self) -> None:
        self.reliable.wait()

    def _allocate_session_id(self) -> int:
        while True:
            session_id = int.from_bytes(os.urandom(4), byteorder="big")
            if session_id == 0:
                continue
            with self.connection_lock:
                if session_id not in self.sessions:
                    return session_id

    def _allocate_stream_id(self, session_id: int) -> int:
        while True:
            stream_id = int.from_bytes(os.urandom(4), byteorder="big")
            if stream_id == 0:
                continue
            with self.connection_lock:
                if (session_id, stream_id) not in self.outbound_streams:
                    return stream_id

    def _stream_exists(self, session_id: int, stream_id: int) -> bool:
        with self.connection_lock:
            return (session_id, stream_id) in self.outbound_streams

    def _close_stream_state(self, stream: TCPStreamState | DatagramStreamState) -> None:
        if isinstance(stream, TCPStreamState):
            stream.socket.close()
            return
        with stream.sockets_lock:
            sockets = list(stream.sockets.values())
            stream.sockets.clear()
        for udp_socket in sockets:
            udp_socket.close()

    def _session_remote_host(self, session_id: int) -> str | None:
        with self.connection_lock:
            session = self.sessions.get(session_id)
            if session is None:
                return None
            return session.remote_host

    def _touch_session(self, session_id: int) -> None:
        with self.connection_lock:
            session = self.sessions.get(session_id)
            if session is not None:
                session.last_activity_ms = now_ms()

    def _close_stream(self, session_id: int, stream_id: int, *, clear_transport: bool = True) -> None:
        with self.connection_lock:
            stream = self.outbound_streams.pop((session_id, stream_id), None)
            session = self.sessions.get(session_id)
            if session is not None:
                session.stream_ids.discard(stream_id)
        if stream is not None:
            self._close_stream_state(stream)
        if clear_transport:
            self.reliable.clear_stream_state(session_id, stream_id)
        self._sync_metrics_gauges()

    def _close_session(self, session_id: int) -> None:
        with self.connection_lock:
            session = self.sessions.pop(session_id, None)
            if session is None:
                return
            stream_ids = list(session.stream_ids)
            streams: list[tuple[int, TCPStreamState | DatagramStreamState]] = []
            for stream_id in stream_ids:
                stream = self.outbound_streams.pop((session_id, stream_id), None)
                if stream is not None:
                    streams.append((stream_id, stream))
        for stream_id, stream in streams:
            self._close_stream_state(stream)
            self.reliable.clear_stream_state(session_id, stream_id)
        self._sync_metrics_gauges()

    def _session_reaper_loop(self) -> None:
        poll_interval_s = min(1.0, max(0.1, self.config.session_idle_timeout_ms / 2000.0))
        while not self._reaper_stop_event.wait(poll_interval_s):
            now_timestamp_ms = now_ms()
            expired_session_ids: list[int] = []
            with self.connection_lock:
                for session_id, session in self.sessions.items():
                    if now_timestamp_ms - session.last_activity_ms > self.config.session_idle_timeout_ms:
                        expired_session_ids.append(session_id)
            for session_id in expired_session_ids:
                LOGGER.info("evicting idle session session_id=%d", session_id)
                self._metrics.inc("icmp_proxy_server_sessions_evicted_idle_total")
                self._close_session(session_id)

    def _send_open_err(self, *, session_id: int, error_code: int, reason: str) -> None:
        remote_host = self._session_remote_host(session_id)
        if remote_host is None:
            return
        self.reliable.send_untracked(
            msg_type=MessageType.OPEN_ERR,
            session_id=session_id,
            stream_id=0,
            payload=OpenErr(error_code=error_code, reason=reason).encode(),
            remote_host=remote_host,
        )

    def relay_tcp(self, session_id: int, stream_id: int) -> None:
        with self.connection_lock:
            stream = self.outbound_streams.get((session_id, stream_id))
        if not isinstance(stream, TCPStreamState):
            return
        outbound_connection = stream.socket
        try:
            while True:
                data = outbound_connection.recv(4096)
                if not data:
                    break
                remote_host = self._session_remote_host(session_id)
                if remote_host is None:
                    break
                mtu_payload = max(1, self.config.session.mtu_payload)
                for offset in range(0, len(data), mtu_payload):
                    chunk = data[offset : offset + mtu_payload]
                    self.reliable.send_reliable(
                        msg_type=MessageType.DATA,
                        session_id=session_id,
                        stream_id=stream_id,
                        payload=Data(payload=chunk).encode(),
                        remote_host=remote_host,
                    )
        except OSError:
            pass
        finally:
            remote_host = self._session_remote_host(session_id)
            if remote_host is not None and self._stream_exists(session_id, stream_id):
                self.reliable.send_untracked(
                    msg_type=MessageType.CLOSE,
                    session_id=session_id,
                    stream_id=stream_id,
                    payload=Close().encode(),
                    remote_host=remote_host,
                )
            self._close_stream(session_id, stream_id)

    def _send_udp_datagram(self, stream: DatagramStreamState, packet: DatagramPacket) -> None:
        if packet.remote_port == 0:
            return
        try:
            addr_info = socket.getaddrinfo(
                packet.remote_host,
                packet.remote_port,
                type=socket.SOCK_DGRAM,
            )
        except OSError:
            return
        family, _socktype, proto, _canonname, sockaddr = addr_info[0]
        with stream.sockets_lock:
            udp_socket = stream.sockets.get(family)
            if udp_socket is None:
                try:
                    udp_socket = socket.socket(family, socket.SOCK_DGRAM, proto)
                    if family == socket.AF_INET6:
                        try:
                            udp_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                        except OSError:
                            pass
                        udp_socket.bind(("::", 0))
                    else:
                        udp_socket.bind(("0.0.0.0", 0))
                    udp_socket.setblocking(False)
                except OSError:
                    return
                stream.sockets[family] = udp_socket
        try:
            udp_socket.sendto(packet.payload, sockaddr)
        except OSError:
            return

    def relay_datagram(self, session_id: int, stream_id: int) -> None:
        with self.connection_lock:
            stream = self.outbound_streams.get((session_id, stream_id))
        if not isinstance(stream, DatagramStreamState):
            return
        try:
            while self._stream_exists(session_id, stream_id):
                with stream.sockets_lock:
                    sockets = list(stream.sockets.values())
                if not sockets:
                    time.sleep(0.05)
                    continue
                try:
                    readable, _, _ = select.select(sockets, [], [], 0.5)
                except OSError:
                    break
                remote_host = self._session_remote_host(session_id)
                if remote_host is None:
                    break
                mtu_payload = max(1, self.config.session.mtu_payload)
                for udp_socket in readable:
                    try:
                        payload, sender = udp_socket.recvfrom(65535)
                    except OSError:
                        continue
                    encoded = DatagramPacket(
                        remote_host=sender[0],
                        remote_port=sender[1],
                        payload=payload,
                    ).encode()
                    if len(encoded) > mtu_payload:
                        continue
                    self.reliable.send_reliable(
                        msg_type=MessageType.DATA,
                        session_id=session_id,
                        stream_id=stream_id,
                        payload=Data(payload=encoded).encode(),
                        remote_host=remote_host,
                    )
        finally:
            remote_host = self._session_remote_host(session_id)
            if remote_host is not None and self._stream_exists(session_id, stream_id):
                self.reliable.send_untracked(
                    msg_type=MessageType.CLOSE,
                    session_id=session_id,
                    stream_id=stream_id,
                    payload=Close().encode(),
                    remote_host=remote_host,
                )
            self._close_stream(session_id, stream_id)

    def process_hello(self, frame: Frame, source_host: str) -> None:
        self._metrics.inc("icmp_proxy_server_hello_total")
        try:
            hello = Hello.decode(frame.payload)
        except ValueError:
            self._metrics.inc_labeled("icmp_proxy_server_hello_rejected_total", "reason", "decode")
            return

        cache_entry = self.hello_cache.get(hello.nonce)
        now_timestamp_ms = now_ms()
        if cache_entry is not None:
            cached_session_id, cached_ack, issued_at_ms, cached_remote_host = cache_entry
            if now_timestamp_ms - issued_at_ms <= self.config.common.auth_replay_ttl_ms:
                self.reliable.send_untracked(
                    msg_type=MessageType.HELLO_ACK,
                    session_id=cached_session_id,
                    stream_id=0,
                    payload=cached_ack.encode(),
                    ack_num=frame.seq_num,
                    remote_host=cached_remote_host,
                )
                return
            self.hello_cache.pop(hello.nonce, None)

        if hello.client_id != self.config.common.client_id:
            LOGGER.warning("rejecting unknown client id=%s", hello.client_id)
            self._metrics.inc_labeled("icmp_proxy_server_hello_rejected_total", "reason", "client_id")
            return

        if not timestamp_within_window(
            timestamp_ms=hello.timestamp_ms,
            now_timestamp_ms=now_timestamp_ms,
            allowed_skew_ms=self.config.common.auth_skew_ms,
        ):
            LOGGER.warning("rejecting stale hello timestamp")
            self._metrics.inc_labeled("icmp_proxy_server_hello_rejected_total", "reason", "timestamp")
            return

        if not self.replay_cache.add_if_new(hello.nonce, now_timestamp_ms):
            LOGGER.warning("rejecting replayed hello nonce")
            self._metrics.inc_labeled("icmp_proxy_server_hello_rejected_total", "reason", "replay")
            return

        expected_sig = sign_client_hello(
            psk=self.psk,
            client_id=hello.client_id,
            nonce=hello.nonce,
            timestamp_ms=hello.timestamp_ms,
        )
        if not verify_signature(expected_sig, hello.hmac_sha256):
            LOGGER.warning("rejecting hello with invalid signature")
            self._metrics.inc_labeled("icmp_proxy_server_hello_rejected_total", "reason", "signature")
            return

        session_id = self._allocate_session_id()
        server_nonce = generate_nonce()
        ack_timestamp_ms = now_ms()
        ack_hmac = sign_server_hello_ack(
            psk=self.psk,
            session_id=session_id,
            client_nonce=hello.nonce,
            server_nonce=server_nonce,
            timestamp_ms=ack_timestamp_ms,
        )
        hello_ack = HelloAck(
            server_nonce=server_nonce,
            timestamp_ms=ack_timestamp_ms,
            hmac_sha256=ack_hmac,
        )

        with self.connection_lock:
            self.sessions[session_id] = SessionState(
                remote_host=source_host,
                client_nonce=hello.nonce,
                last_activity_ms=now_timestamp_ms,
            )
        self._metrics.inc("icmp_proxy_server_sessions_created_total")
        self._sync_metrics_gauges()

        self.hello_cache[hello.nonce] = (session_id, hello_ack, now_timestamp_ms, source_host)
        if len(self.hello_cache) > self.config.common.auth_replay_max_entries:
            oldest_nonce = next(iter(self.hello_cache))
            self.hello_cache.pop(oldest_nonce, None)

        self.reliable.send_untracked(
            msg_type=MessageType.HELLO_ACK,
            session_id=session_id,
            stream_id=0,
            payload=hello_ack.encode(),
            ack_num=frame.seq_num,
            remote_host=source_host,
        )

    def process_open_stream(self, frame: Frame) -> None:
        self._metrics.inc("icmp_proxy_server_open_stream_total")
        try:
            open_stream = OpenStream.decode(frame.payload)
        except ValueError:
            self._metrics.inc_labeled("icmp_proxy_server_open_stream_error_total", "reason", "decode")
            self._send_open_err(
                session_id=frame.session_id,
                error_code=400,
                reason="invalid open payload",
            )
            return

        try:
            outbound_connection = socket.create_connection(
                (open_stream.remote_host, open_stream.remote_port),
                timeout=self.config.target_connect_timeout_ms / 1000.0,
            )
        except OSError:
            self._metrics.inc_labeled("icmp_proxy_server_open_stream_error_total", "reason", "connect_failed")
            self._send_open_err(
                session_id=frame.session_id,
                error_code=503,
                reason="upstream connect failed",
            )
            return
        outbound_connection.settimeout(None)

        stream_id = self._allocate_stream_id(frame.session_id)
        with self.connection_lock:
            session = self.sessions.get(frame.session_id)
            if session is None:
                outbound_connection.close()
                self._metrics.inc_labeled("icmp_proxy_server_open_stream_error_total", "reason", "session_missing")
                return
            session.stream_ids.add(stream_id)
            self.outbound_streams[(frame.session_id, stream_id)] = TCPStreamState(socket=outbound_connection)
            remote_host = session.remote_host
        self._sync_metrics_gauges()

        relay_thread = Thread(
            target=self.relay_tcp,
            args=(frame.session_id, stream_id),
            daemon=True,
        )
        relay_thread.start()

        self.reliable.send_reliable(
            msg_type=MessageType.OPEN_OK,
            session_id=frame.session_id,
            stream_id=stream_id,
            payload=OpenOk(assigned_stream_id=stream_id).encode(),
            remote_host=remote_host,
        )

    def process_open_datagram(self, frame: Frame) -> None:
        try:
            OpenDatagram.decode(frame.payload)
        except ValueError:
            self._send_open_err(
                session_id=frame.session_id,
                error_code=400,
                reason="invalid open datagram payload",
            )
            return

        self._metrics.inc("icmp_proxy_server_open_datagram_total")
        stream_id = self._allocate_stream_id(frame.session_id)
        datagram_stream = DatagramStreamState()
        with self.connection_lock:
            session = self.sessions.get(frame.session_id)
            if session is None:
                return
            session.stream_ids.add(stream_id)
            self.outbound_streams[(frame.session_id, stream_id)] = datagram_stream
            remote_host = session.remote_host
        self._sync_metrics_gauges()

        relay_thread = Thread(
            target=self.relay_datagram,
            args=(frame.session_id, stream_id),
            daemon=True,
        )
        relay_thread.start()

        self.reliable.send_reliable(
            msg_type=MessageType.OPEN_OK,
            session_id=frame.session_id,
            stream_id=stream_id,
            payload=OpenOk(assigned_stream_id=stream_id).encode(),
            remote_host=remote_host,
        )

    def process_data(self, frame: Frame) -> None:
        self._metrics.inc("icmp_proxy_server_data_frames_total")
        payload = Data.decode(frame.payload).payload
        with self.connection_lock:
            stream = self.outbound_streams.get((frame.session_id, frame.stream_id))
        if stream is None:
            return
        if isinstance(stream, TCPStreamState):
            try:
                stream.socket.sendall(payload)
            except OSError:
                self._close_stream(frame.session_id, frame.stream_id)
            return
        try:
            packet = DatagramPacket.decode(payload)
        except ValueError:
            return
        self._send_udp_datagram(stream, packet)

    def process_close(self, frame: Frame) -> None:
        self._metrics.inc("icmp_proxy_server_close_frames_total")
        try:
            Close.decode(frame.payload)
        except ValueError:
            return

        remote_host = self._session_remote_host(frame.session_id)
        self._close_stream(frame.session_id, frame.stream_id)
        if remote_host is None:
            return
        self.reliable.send_untracked(
            msg_type=MessageType.CLOSE_ACK,
            session_id=frame.session_id,
            stream_id=frame.stream_id,
            payload=CloseAck().encode(),
            ack_num=frame.seq_num,
            remote_host=remote_host,
        )

    def process_heartbeat(self, frame: Frame) -> None:
        try:
            Heartbeat.decode(frame.payload)
        except ValueError:
            return

    def on_retry_exhausted(self, session_id: int, stream_id: int, msg_type: MessageType) -> None:
        if stream_id == 0:
            return
        LOGGER.warning(
            "retry exhausted session_id=%d stream_id=%d msg_type=%s",
            session_id,
            stream_id,
            msg_type.name,
        )
        self._close_stream(session_id, stream_id)

    def process_frame(self, frame: Frame, source_host: str) -> None:
        if frame.msg_type == MessageType.HELLO:
            self.process_hello(frame, source_host)
            return

        with self.connection_lock:
            session = self.sessions.get(frame.session_id)
            if session is None:
                return
            if session.remote_host != source_host:
                LOGGER.warning(
                    "rejecting frame with mismatched source session_id=%d expected=%s got=%s",
                    frame.session_id,
                    session.remote_host,
                    source_host,
                )
                return
            session.last_activity_ms = now_ms()

        if frame.msg_type == MessageType.OPEN_STREAM:
            self.process_open_stream(frame)
        elif frame.msg_type == MessageType.OPEN_DATAGRAM:
            self.process_open_datagram(frame)
        elif frame.msg_type == MessageType.DATA:
            self.process_data(frame)
        elif frame.msg_type == MessageType.CLOSE:
            self.process_close(frame)
        elif frame.msg_type == MessageType.HEARTBEAT:
            self.process_heartbeat(frame)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the ICMP Proxy server.")
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    _build_arg_parser().parse_args(argv)
    config = load_server_config()
    configure_logging(config.common.log_level)
    with Server(config) as server:
        server()


if __name__ == "__main__":
    main()
