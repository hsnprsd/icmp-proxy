import pytest

from proxy import (
    Frame,
    FrameType,
    ProxyAck,
    ProxyClose,
    ProxyData,
    ProxyStart,
    ProxyStartResponse,
)


def test_frame_round_trip_for_all_frame_types() -> None:
    for frame_type in FrameType:
        frame = Frame(
            from_host=1,
            frame_type=frame_type,
            stream_id=12345,
            seq_num=99,
            payload=b"payload",
        )
        decoded = Frame.decode(frame.encode())
        assert decoded == frame


def test_frame_decode_rejects_short_payload() -> None:
    with pytest.raises(ValueError, match="frame too short"):
        Frame.decode(b"\x00" * 9)


def test_proxy_start_round_trip() -> None:
    start = ProxyStart(remote_host="example.com", remote_port=443)
    decoded = ProxyStart.decode(start.encode())
    assert decoded == start


def test_proxy_start_response_round_trip() -> None:
    response = ProxyStartResponse(stream_id=0xABCDEF01)
    decoded = ProxyStartResponse.decode(response.encode())
    assert decoded == response


def test_proxy_data_round_trip_with_empty_payload() -> None:
    data = ProxyData(size=0, payload=b"")
    decoded = ProxyData.decode(data.encode())
    assert decoded == data


def test_proxy_data_round_trip_with_payload() -> None:
    payload = b"hello"
    data = ProxyData(size=len(payload), payload=payload)
    decoded = ProxyData.decode(data.encode())
    assert decoded == data


def test_proxy_close_round_trip() -> None:
    close = ProxyClose()
    decoded = ProxyClose.decode(close.encode())
    assert isinstance(decoded, ProxyClose)


def test_proxy_ack_round_trip() -> None:
    ack = ProxyAck(stream_id=123, ack_seq_num=456)
    decoded = ProxyAck.decode(ack.encode())
    assert decoded == ack


def test_proxy_ack_decode_rejects_short_payload() -> None:
    with pytest.raises(ValueError, match="ack frame too short"):
        ProxyAck.decode(b"\x00" * 7)
