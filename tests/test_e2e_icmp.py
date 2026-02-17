import socket
from contextlib import contextmanager

import pytest

from icmp import ICMP_ECHO_REQUEST, ICMP_ECHO_REQUEST_CODE
from proxy import FrameType, ProxyClose, ProxyData, ProxyStart, ProxyStartResponse
from reliable import ReliableICMPSession


@contextmanager
def _client_session():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))
        session = ReliableICMPSession(
            connection=sock,
            local_host_id=1,
            remote_host="127.0.0.1",
            outbound_icmp_type=ICMP_ECHO_REQUEST,
            outbound_icmp_code=ICMP_ECHO_REQUEST_CODE,
            retx_timeout_ms=100,
            retx_max_retries=5,
            retx_scan_interval_ms=20,
        )
        session.start()
        try:
            yield session
        finally:
            session.stop()


def _open_stream(session: ReliableICMPSession, remote_host: str, remote_port: int) -> int:
    session.send_reliable(
        frame_type=FrameType.PROXY_START,
        stream_id=0,
        payload=ProxyStart(remote_host=remote_host, remote_port=remote_port).encode(),
    )
    frame = session.wait_for_frame(
        lambda f: f.frame_type == FrameType.PROXY_START_RESPONSE,
        timeout_s=5.0,
    )
    assert frame is not None, "timed out waiting for PROXY_START_RESPONSE"
    return ProxyStartResponse.decode(frame.payload).stream_id


def _collect_stream_payload(session: ReliableICMPSession, stream_id: int, timeout_s: float) -> bytes:
    chunks: list[bytes] = []
    while True:
        frame = session.wait_for_frame(
            lambda f: f.stream_id == stream_id
            and f.frame_type in (FrameType.PROXY_DATA, FrameType.PROXY_CLOSE),
            timeout_s=timeout_s,
        )
        assert frame is not None, f"timed out waiting for stream frame stream_id={stream_id}"
        if frame.frame_type == FrameType.PROXY_CLOSE:
            break
        payload = ProxyData.decode(frame.payload)
        chunks.append(payload.payload)
    return b"".join(chunks)


@pytest.mark.requires_root
@pytest.mark.e2e_local
def test_e2e_local_proxy_round_trip(icmp_server_process, local_http_backend) -> None:
    with _client_session() as session:
        stream_id = _open_stream(
            session,
            remote_host=local_http_backend["host"],
            remote_port=local_http_backend["port"],
        )

        request = (
            b"GET /health HTTP/1.1\r\n"
            b"Host: local.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        session.send_reliable(
            frame_type=FrameType.PROXY_DATA,
            stream_id=stream_id,
            payload=ProxyData(size=len(request), payload=request).encode(),
        )

        response = _collect_stream_payload(session, stream_id=stream_id, timeout_s=3.0)
        assert response == local_http_backend["response"]
        assert local_http_backend["requests"], "backend did not receive a request"
        assert b"GET /health HTTP/1.1" in local_http_backend["requests"][0]

        close_seq = session.send_reliable(
            frame_type=FrameType.PROXY_CLOSE,
            stream_id=stream_id,
            payload=ProxyClose().encode(),
        )
        assert session.wait_for_ack(stream_id=stream_id, seq_num=close_seq, timeout_s=2.0)
        session.clear_stream_state(stream_id)


@pytest.mark.requires_root
@pytest.mark.e2e_external
def test_e2e_external_proxy_round_trip(icmp_server_process) -> None:
    with _client_session() as session:
        stream_id = _open_stream(session, remote_host="google.com", remote_port=80)

        request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: google.com\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        session.send_reliable(
            frame_type=FrameType.PROXY_DATA,
            stream_id=stream_id,
            payload=ProxyData(size=len(request), payload=request).encode(),
        )

        response = _collect_stream_payload(session, stream_id=stream_id, timeout_s=8.0)
        assert response, "no response payload received from external target"
        assert b"HTTP/" in response[:32], "response does not look like HTTP"

        close_seq = session.send_reliable(
            frame_type=FrameType.PROXY_CLOSE,
            stream_id=stream_id,
            payload=ProxyClose().encode(),
        )
        assert session.wait_for_ack(stream_id=stream_id, seq_num=close_seq, timeout_s=2.0)
        session.clear_stream_state(stream_id)
