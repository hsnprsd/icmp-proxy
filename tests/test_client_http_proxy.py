from icmp_proxy.client import parse_proxy_request_head, read_http_request_head


class FakeConnection:
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = list(chunks)

    def recv(self, _size: int) -> bytes:
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


def test_parse_absolute_form_request_rewrites_for_upstream() -> None:
    head = (
        b"GET http://example.com:8080/health?ok=1 HTTP/1.1\r\n"
        b"Host: example.com:8080\r\n"
        b"Proxy-Connection: keep-alive\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
    )
    parsed = parse_proxy_request_head(head)

    assert parsed.method == "GET"
    assert parsed.remote_host == "example.com"
    assert parsed.remote_port == 8080
    assert parsed.rewritten_head is not None
    assert parsed.rewritten_head.startswith(b"GET /health?ok=1 HTTP/1.1\r\n")
    assert b"Proxy-Connection:" not in parsed.rewritten_head
    assert b"Connection: close\r\n" in parsed.rewritten_head


def test_parse_origin_form_request_uses_host_header() -> None:
    head = (
        b"GET /hello HTTP/1.1\r\n"
        b"Host: local.test\r\n"
        b"\r\n"
    )
    parsed = parse_proxy_request_head(head)

    assert parsed.remote_host == "local.test"
    assert parsed.remote_port == 80
    assert parsed.rewritten_head is not None
    assert parsed.rewritten_head.startswith(b"GET /hello HTTP/1.1\r\n")


def test_parse_connect_request_extracts_host_and_port() -> None:
    head = (
        b"CONNECT api.example.com:443 HTTP/1.1\r\n"
        b"Host: api.example.com:443\r\n"
        b"\r\n"
    )
    parsed = parse_proxy_request_head(head)

    assert parsed.method == "CONNECT"
    assert parsed.remote_host == "api.example.com"
    assert parsed.remote_port == 443
    assert parsed.rewritten_head is None


def test_parse_rejects_https_absolute_form() -> None:
    head = (
        b"GET https://example.com/ HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"\r\n"
    )
    try:
        parse_proxy_request_head(head)
    except ValueError as exc:
        assert "only http://" in str(exc)
    else:
        raise AssertionError("expected ValueError for https absolute-form")


def test_read_http_request_head_returns_head_and_remainder() -> None:
    connection = FakeConnection([b"GET / HTTP/1.1\r\nHost: a\r\n\r\nnext-bytes"])

    head, remainder = read_http_request_head(connection)  # type: ignore[arg-type]
    assert head == b"GET / HTTP/1.1\r\nHost: a\r\n\r\n"
    assert remainder == b"next-bytes"
