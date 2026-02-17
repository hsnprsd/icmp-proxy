import pytest

from icmp_proxy.client import Client
from icmp_proxy.config import ClientConfig, CommonConfig, SessionConfig


def _test_client_config() -> ClientConfig:
    common = CommonConfig(
        log_level="WARNING",
        psk="test-secret",
        client_id="test-client",
        auth_skew_ms=30_000,
        auth_replay_ttl_ms=30_000,
        auth_replay_max_entries=8192,
    )
    session = SessionConfig(
        retx_timeout_ms=100,
        retx_max_retries=5,
        retx_scan_interval_ms=20,
        seen_limit_per_stream=1024,
        max_inflight_per_stream=32,
        mtu_payload=1200,
    )
    return ClientConfig(
        server_host="127.0.0.1",
        http_proxy_bind_host="127.0.0.1",
        http_proxy_bind_port=8080,
        common=common,
        session=session,
    )


@pytest.mark.requires_root
@pytest.mark.e2e_local
def test_e2e_local_proxy_round_trip(icmp_server_process, local_http_backend) -> None:
    with Client(_test_client_config()) as client:
        client.authenticate()
        stream_id = client.open_stream(
            remote_host=local_http_backend["host"],
            remote_port=local_http_backend["port"],
        )

        request = (
            b"GET /health HTTP/1.1\r\n"
            b"Host: local.test\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        client.send_stream_data(stream_id, request)
        response = client.recv_stream_data(stream_id, timeout_s=3.0)
        assert response == local_http_backend["response"]
        assert local_http_backend["requests"], "backend did not receive a request"
        assert b"GET /health HTTP/1.1" in local_http_backend["requests"][0]
        client.close_stream(stream_id)


@pytest.mark.requires_root
@pytest.mark.e2e_external
def test_e2e_external_proxy_round_trip(icmp_server_process) -> None:
    with Client(_test_client_config()) as client:
        client.authenticate()
        stream_id = client.open_stream(remote_host="google.com", remote_port=80)

        request = (
            b"GET / HTTP/1.1\r\n"
            b"Host: google.com\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        client.send_stream_data(stream_id, request)
        response = client.recv_stream_data(stream_id, timeout_s=8.0)
        assert response, "no response payload received from external target"
        assert b"HTTP/" in response[:32], "response does not look like HTTP"
        client.close_stream(stream_id)
