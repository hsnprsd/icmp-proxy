import os
import logging
import socket
from threading import Lock, Thread

from icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REPLY_CODE
from proxy import (
    Frame,
    FrameType,
    ProxyClose,
    ProxyData,
    ProxyStart,
    ProxyStartResponse,
)
from reliable import ReliableICMPSession

CLIENT_HOST = "127.0.0.1"
RETX_TIMEOUT_MS = 100
RETX_MAX_RETRIES = 5
RETX_SCAN_INTERVAL_MS = 20

LOGGER = logging.getLogger("icmp_proxy.server")


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


class Server:
    def __init__(self) -> None:
        self.host_id = 0
        self.outbound_connections: dict[int, socket.socket] = {}
        self.connection_lock = Lock()

    def __enter__(self):
        LOGGER.info("Starting server")
        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        )
        self.socket.bind(("0.0.0.0", 0))
        self.reliable = ReliableICMPSession(
            connection=self.socket,
            local_host_id=self.host_id,
            remote_host=CLIENT_HOST,
            outbound_icmp_type=ICMP_ECHO_REPLY,
            outbound_icmp_code=ICMP_ECHO_REPLY_CODE,
            retx_timeout_ms=RETX_TIMEOUT_MS,
            retx_max_retries=RETX_MAX_RETRIES,
            retx_scan_interval_ms=RETX_SCAN_INTERVAL_MS,
            on_frame=self.process_frame,
            on_retry_exhausted=self.on_retry_exhausted,
        )
        self.reliable.start()
        LOGGER.info("Server ready; listening for ICMP proxy frames")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        LOGGER.info("Stopping server")
        self.reliable.stop()
        with self.connection_lock:
            connections = list(self.outbound_connections.values())
            self.outbound_connections.clear()
        for connection in connections:
            connection.close()
        self.socket.close()
        LOGGER.info("Server stopped")

    def __call__(self) -> None:
        LOGGER.info("Waiting for receive loop to exit")
        self.reliable.wait()

    def relay(
        self, stream_id: int
    ) -> None:
        LOGGER.debug("Relay loop started for stream_id=%d", stream_id)
        with self.connection_lock:
            outbound_connection = self.outbound_connections.get(stream_id)
        if outbound_connection is None:
            LOGGER.warning(
                "Relay could not start because stream_id=%d was not found", stream_id
            )
            return

        try:
            while True:
                data = outbound_connection.recv(4096)
                if not data:
                    LOGGER.info(
                        "Remote target closed connection for stream_id=%d", stream_id
                    )
                    break
                LOGGER.debug(
                    "Relaying %d bytes from target to client for stream_id=%d",
                    len(data),
                    stream_id,
                )
                self.reliable.send_reliable(
                    frame_type=FrameType.PROXY_DATA,
                    stream_id=stream_id,
                    payload=ProxyData(
                        size=len(data),
                        payload=data,
                    ).encode(),
                )
        except OSError as exc:
            LOGGER.warning(
                "Relay socket error for stream_id=%d: %s", stream_id, exc
            )
        finally:
            if self.stream_exists(stream_id):
                LOGGER.info("Sending PROXY_CLOSE for stream_id=%d", stream_id)
                self.reliable.send_reliable(
                    frame_type=FrameType.PROXY_CLOSE,
                    stream_id=stream_id,
                    payload=ProxyClose().encode(),
                )
            self.close_stream(stream_id)
            LOGGER.debug("Relay loop ended for stream_id=%d", stream_id)

    def process_proxy_start(self, proxy_start: ProxyStart) -> None:
        LOGGER.info(
            "Received PROXY_START target=%s:%d",
            proxy_start.remote_host,
            proxy_start.remote_port,
        )
        outbound_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            outbound_connection.connect(
                (proxy_start.remote_host, proxy_start.remote_port)
            )
        except OSError as exc:
            LOGGER.warning(
                "Failed to connect to target %s:%d: %s",
                proxy_start.remote_host,
                proxy_start.remote_port,
                exc,
            )
            outbound_connection.close()
            return

        stream_id = self.allocate_stream_id()
        with self.connection_lock:
            self.outbound_connections[stream_id] = outbound_connection

        relay_thread = Thread(target=self.relay, args=(stream_id,), daemon=True)
        relay_thread.start()
        LOGGER.info("Opened stream_id=%d and started relay thread", stream_id)

        self.reliable.send_reliable(
            frame_type=FrameType.PROXY_START_RESPONSE,
            stream_id=stream_id,
            payload=ProxyStartResponse(stream_id=stream_id).encode(),
        )
        LOGGER.debug("Sent PROXY_START_RESPONSE stream_id=%d", stream_id)

    def allocate_stream_id(self) -> int:
        while True:
            stream_id = int.from_bytes(os.urandom(4), byteorder="big")
            with self.connection_lock:
                if stream_id not in self.outbound_connections:
                    LOGGER.debug("Allocated stream_id=%d", stream_id)
                    return stream_id

    def process_proxy_data(self, stream_id: int, proxy_data: ProxyData) -> None:
        LOGGER.debug(
            "Received PROXY_DATA stream_id=%d size=%d",
            stream_id,
            proxy_data.size,
        )
        with self.connection_lock:
            connection = self.outbound_connections.get(stream_id)
        if connection is None:
            LOGGER.warning(
                "Dropping PROXY_DATA for unknown stream_id=%d", stream_id
            )
            return
        try:
            connection.sendall(proxy_data.payload)
        except OSError as exc:
            LOGGER.warning(
                "Failed to write to outbound stream_id=%d: %s", stream_id, exc
            )
            self.close_stream(stream_id)
            self.reliable.clear_stream_state(stream_id)

    def process_proxy_close(self, stream_id: int) -> None:
        LOGGER.info("Received PROXY_CLOSE stream_id=%d", stream_id)
        self.close_stream(stream_id)
        self.reliable.clear_stream_state(stream_id)

    def on_retry_exhausted(self, stream_id: int, frame_type: FrameType) -> None:
        LOGGER.warning(
            "Retry exhausted for stream_id=%d frame_type=%s",
            stream_id,
            frame_type.name,
        )
        if stream_id == 0:
            return
        self.close_stream(stream_id)
        self.reliable.clear_stream_state(stream_id)
        if frame_type != FrameType.PROXY_CLOSE:
            self.reliable.send_untracked(
                frame_type=FrameType.PROXY_CLOSE,
                stream_id=stream_id,
                payload=ProxyClose().encode(),
            )

    def close_stream(self, stream_id: int) -> None:
        with self.connection_lock:
            outbound_connection = self.outbound_connections.pop(stream_id, None)
        if outbound_connection is not None:
            outbound_connection.close()
            LOGGER.info("Closed outbound connection for stream_id=%d", stream_id)
        else:
            LOGGER.debug("Stream_id=%d already closed", stream_id)

    def stream_exists(self, stream_id: int) -> bool:
        with self.connection_lock:
            return stream_id in self.outbound_connections

    def process_frame(self, frame: Frame) -> None:
        LOGGER.debug(
            "Received frame type=%s stream_id=%d seq_num=%d payload=%d bytes",
            frame.frame_type.name,
            frame.stream_id,
            frame.seq_num,
            len(frame.payload),
        )
        if frame.frame_type == FrameType.PROXY_START:
            self.process_proxy_start(proxy_start=ProxyStart.decode(frame.payload))
        elif frame.frame_type == FrameType.PROXY_DATA:
            self.process_proxy_data(
                stream_id=frame.stream_id,
                proxy_data=ProxyData.decode(frame.payload),
            )
        elif frame.frame_type == FrameType.PROXY_CLOSE:
            self.process_proxy_close(stream_id=frame.stream_id)
        elif frame.frame_type == FrameType.PROXY_ACK:
            LOGGER.debug("Received PROXY_ACK stream_id=%d", frame.stream_id)
            return
        else:
            LOGGER.error("Invalid frame type %s", frame.frame_type)
            raise Exception("invalid frame type %s" % frame.frame_type)


if __name__ == "__main__":
    configure_logging()
    with Server() as srv:
        srv()
