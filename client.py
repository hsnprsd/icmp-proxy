import logging
import os
import socket

from icmp import (
    ICMP_ECHO_REQUEST,
    ICMP_ECHO_REQUEST_CODE,
)
from proxy import (
    FrameType,
    ProxyClose,
    ProxyData,
    ProxyStart,
    ProxyStartResponse,
)
from reliable import ReliableICMPSession

SERVER_HOST = "127.0.0.1"
RETX_TIMEOUT_MS = 100
RETX_MAX_RETRIES = 5
RETX_SCAN_INTERVAL_MS = 20

LOGGER = logging.getLogger("icmp_proxy.client")


def configure_logging() -> None:
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


def main():
    configure_logging()
    LOGGER.info("Starting client")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))
        LOGGER.info("Bound raw ICMP socket")

        reliable: ReliableICMPSession

        def on_retry_exhausted(stream_id: int, frame_type: FrameType) -> None:
            LOGGER.warning(
                "Retry exhausted for stream_id=%d frame_type=%s",
                stream_id,
                frame_type.name,
            )
            if stream_id == 0:
                return
            if frame_type != FrameType.PROXY_CLOSE:
                LOGGER.info(
                    "Sending untracked PROXY_CLOSE after retry exhaustion for stream_id=%d",
                    stream_id,
                )
                reliable.send_untracked(
                    frame_type=FrameType.PROXY_CLOSE,
                    stream_id=stream_id,
                    payload=ProxyClose().encode(),
                )

        reliable = ReliableICMPSession(
            connection=sock,
            local_host_id=1,
            remote_host=SERVER_HOST,
            outbound_icmp_type=ICMP_ECHO_REQUEST,
            outbound_icmp_code=ICMP_ECHO_REQUEST_CODE,
            retx_timeout_ms=RETX_TIMEOUT_MS,
            retx_max_retries=RETX_MAX_RETRIES,
            retx_scan_interval_ms=RETX_SCAN_INTERVAL_MS,
            on_retry_exhausted=on_retry_exhausted,
        )
        reliable.start()
        LOGGER.info("Reliable ICMP session started")
        stream_id = 0
        try:
            # send proxy request
            LOGGER.info("Sending PROXY_START target=google.com:80")
            reliable.send_reliable(
                frame_type=FrameType.PROXY_START,
                stream_id=0,
                payload=ProxyStart(
                    remote_host="google.com",
                    remote_port=80,
                ).encode(),
            )

            # receive proxy response
            frame = reliable.wait_for_frame(
                lambda f: f.frame_type == FrameType.PROXY_START_RESPONSE,
                timeout_s=5.0,
            )
            if frame is None:
                LOGGER.error("Timed out waiting for PROXY_START_RESPONSE")
                raise TimeoutError("timed out waiting for PROXY_START_RESPONSE")

            proxy_start_response = ProxyStartResponse.decode(frame.payload)
            stream_id = proxy_start_response.stream_id
            LOGGER.info("Received PROXY_START_RESPONSE stream_id=%d", stream_id)

            request = (
                "GET / HTTP/1.1\r\n"
                "Host: google.com\r\n"
                "Connection: close\r\n"
                "\r\n"
            ).encode()

            LOGGER.info("Sending PROXY_DATA stream_id=%d size=%d", stream_id, len(request))
            reliable.send_reliable(
                frame_type=FrameType.PROXY_DATA,
                stream_id=stream_id,
                payload=ProxyData(
                    size=len(request),
                    payload=request,
                ).encode(),
            )

            response_parts: list[bytes] = []
            while True:
                response_frame = reliable.wait_for_frame(
                    lambda f: f.stream_id == stream_id
                    and f.frame_type in (FrameType.PROXY_DATA, FrameType.PROXY_CLOSE),
                    timeout_s=2.0,
                )
                if response_frame is None:
                    LOGGER.info(
                        "No more response frames for stream_id=%d (timeout)",
                        stream_id,
                    )
                    break
                if response_frame.frame_type == FrameType.PROXY_CLOSE:
                    LOGGER.info("Received PROXY_CLOSE stream_id=%d", stream_id)
                    break
                proxy_data = ProxyData.decode(response_frame.payload)
                LOGGER.debug(
                    "Received PROXY_DATA stream_id=%d size=%d",
                    stream_id,
                    proxy_data.size,
                )
                response_parts.append(proxy_data.payload)

            if response_parts:
                payload = b"".join(response_parts)
                LOGGER.info(
                    "Received response payload stream_id=%d total_size=%d",
                    stream_id,
                    len(payload),
                )
                LOGGER.debug("Response payload stream_id=%d payload=%r", stream_id, payload)

            LOGGER.info("Sending PROXY_CLOSE stream_id=%d", stream_id)
            close_seq = reliable.send_reliable(
                frame_type=FrameType.PROXY_CLOSE,
                stream_id=stream_id,
                payload=ProxyClose().encode(),
            )
            close_acked = reliable.wait_for_ack(
                stream_id=stream_id,
                seq_num=close_seq,
                timeout_s=1.0,
            )
            LOGGER.info(
                "PROXY_CLOSE ack status stream_id=%d acked=%s",
                stream_id,
                close_acked,
            )
            reliable.clear_stream_state(stream_id)
            LOGGER.debug("Cleared stream state for stream_id=%d", stream_id)
        finally:
            LOGGER.info("Stopping client reliable session")
            reliable.stop()
            LOGGER.info("Client stopped")


if __name__ == "__main__":
    main()
