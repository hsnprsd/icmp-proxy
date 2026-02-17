import pytest

from icmp_proxy.icmp import (
    ICMP_ECHO_REQUEST,
    ICMP_ECHO_REQUEST_CODE,
    ICMPPacket,
    internet_checksum,
)


IPV4_HEADER_LEN = 20


def _ipv4_wrap(icmp_payload: bytes) -> bytes:
    return (b"\x00" * IPV4_HEADER_LEN) + icmp_payload


def test_internet_checksum_known_value() -> None:
    data = bytes.fromhex("0001f203f4f5f6f7")
    assert internet_checksum(data) == 0x220D


def test_internet_checksum_odd_length_data() -> None:
    assert internet_checksum(b"abc") == 0x3B9D


def test_icmp_packet_round_trip_from_bytes() -> None:
    packet = ICMPPacket(icmp_type=8, icmp_code=0, payload=b"hello")
    wire = _ipv4_wrap(packet.to_bytes())

    parsed = ICMPPacket.from_bytes(wire)

    assert parsed.icmp_type == 8
    assert parsed.icmp_code == 0
    assert parsed.payload == b"hello"
    assert parsed.validate_checksum()


def test_icmp_packet_from_bytes_rejects_invalid_checksum() -> None:
    packet = ICMPPacket(icmp_type=8, icmp_code=0, payload=b"hello")
    tampered = bytearray(packet.to_bytes())
    tampered[2] ^= 0xFF

    with pytest.raises(ValueError, match="invalid checksum"):
        ICMPPacket.from_bytes(_ipv4_wrap(bytes(tampered)))


def test_icmp_constants() -> None:
    assert ICMP_ECHO_REQUEST == 8
    assert ICMP_ECHO_REQUEST_CODE == 0
