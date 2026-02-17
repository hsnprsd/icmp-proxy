import pytest

from icmp_proxy.protocol import (
    Close,
    CloseAck,
    Data,
    DatagramPacket,
    Frame,
    Hello,
    HelloAck,
    MessageType,
    OpenDatagram,
    OpenErr,
    OpenOk,
    OpenStream,
    UnsupportedProtocolVersion,
)


def test_frame_round_trip() -> None:
    frame = Frame.make(
        msg_type=MessageType.DATA,
        payload=b"hello",
        session_id=7,
        stream_id=8,
        seq_num=11,
        ack_num=10,
        flags=0x01,
    )
    decoded = Frame.decode(frame.encode())
    assert decoded == frame


def test_frame_decode_rejects_unknown_version() -> None:
    frame = Frame.make(msg_type=MessageType.KEEPALIVE, payload=b"", session_id=1)
    raw = bytearray(frame.encode())
    raw[0] = 2
    with pytest.raises(UnsupportedProtocolVersion):
        Frame.decode(bytes(raw))


def test_frame_decode_rejects_payload_length_mismatch() -> None:
    frame = Frame.make(msg_type=MessageType.DATA, payload=b"abc", session_id=1)
    raw = frame.encode() + b"\x00"
    with pytest.raises(ValueError, match="payload length mismatch"):
        Frame.decode(raw)


def test_hello_round_trip() -> None:
    hello = Hello(
        client_id="client-a",
        nonce=b"a" * 16,
        timestamp_ms=123456789,
        hmac_sha256=b"h" * 32,
    )
    assert Hello.decode(hello.encode()) == hello


def test_hello_ack_round_trip() -> None:
    hello_ack = HelloAck(server_nonce=b"b" * 16, timestamp_ms=123, hmac_sha256=b"c" * 32)
    assert HelloAck.decode(hello_ack.encode()) == hello_ack


def test_open_stream_round_trip() -> None:
    open_stream = OpenStream(remote_host="example.com", remote_port=443)
    assert OpenStream.decode(open_stream.encode()) == open_stream


def test_open_datagram_round_trip() -> None:
    open_datagram = OpenDatagram()
    assert OpenDatagram.decode(open_datagram.encode()) == open_datagram


def test_open_ok_round_trip() -> None:
    open_ok = OpenOk(assigned_stream_id=12345)
    assert OpenOk.decode(open_ok.encode()) == open_ok


def test_open_err_round_trip() -> None:
    open_err = OpenErr(error_code=503, reason="upstream connect failed")
    assert OpenErr.decode(open_err.encode()) == open_err


def test_data_round_trip() -> None:
    payload = Data(payload=b"chunk")
    assert Data.decode(payload.encode()) == payload


def test_datagram_packet_round_trip_domain() -> None:
    payload = DatagramPacket(remote_host="example.com", remote_port=53, payload=b"ping")
    assert DatagramPacket.decode(payload.encode()) == payload


def test_datagram_packet_round_trip_ipv6() -> None:
    payload = DatagramPacket(remote_host="2001:db8::1", remote_port=5353, payload=b"pong")
    assert DatagramPacket.decode(payload.encode()) == payload


def test_datagram_packet_rejects_invalid_atyp() -> None:
    try:
        DatagramPacket.decode(b"\x09")
    except ValueError as exc:
        assert "address type" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_close_decode_rejects_payload() -> None:
    with pytest.raises(ValueError, match="must be empty"):
        Close.decode(b"x")


def test_close_ack_decode_rejects_payload() -> None:
    with pytest.raises(ValueError, match="must be empty"):
        CloseAck.decode(b"x")
