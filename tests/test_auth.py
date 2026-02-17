from icmp_proxy.auth import (
    ReplayCache,
    sign_client_hello,
    sign_server_hello_ack,
    timestamp_within_window,
    verify_signature,
)


def test_client_hello_signature_verify() -> None:
    psk = b"secret"
    sig = sign_client_hello(
        psk=psk,
        client_id="client-a",
        nonce=b"a" * 16,
        timestamp_ms=1234,
    )
    assert verify_signature(
        sig,
        sign_client_hello(
            psk=psk,
            client_id="client-a",
            nonce=b"a" * 16,
            timestamp_ms=1234,
        ),
    )


def test_server_hello_ack_signature_changes_when_session_changes() -> None:
    psk = b"secret"
    sig1 = sign_server_hello_ack(
        psk=psk,
        session_id=1,
        client_nonce=b"a" * 16,
        server_nonce=b"b" * 16,
        timestamp_ms=10,
    )
    sig2 = sign_server_hello_ack(
        psk=psk,
        session_id=2,
        client_nonce=b"a" * 16,
        server_nonce=b"b" * 16,
        timestamp_ms=10,
    )
    assert sig1 != sig2


def test_replay_cache_rejects_duplicate_nonce() -> None:
    cache = ReplayCache(ttl_ms=1000, max_entries=32)
    assert cache.add_if_new(b"x" * 16, now_timestamp_ms=1000)
    assert not cache.add_if_new(b"x" * 16, now_timestamp_ms=1001)


def test_timestamp_window() -> None:
    assert timestamp_within_window(
        timestamp_ms=1000,
        now_timestamp_ms=1500,
        allowed_skew_ms=500,
    )
    assert not timestamp_within_window(
        timestamp_ms=1000,
        now_timestamp_ms=1601,
        allowed_skew_ms=500,
    )
