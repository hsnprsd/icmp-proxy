from __future__ import annotations

import struct
from dataclasses import dataclass

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REQUEST_CODE = 0
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REPLY_CODE = 0
IPV4_HEADER_LEN = 20
ICMP_HEADER_LEN = 8


def _extract_icmp_payload(buf: bytes) -> bytes:
    if len(buf) < ICMP_HEADER_LEN:
        raise ValueError("packet too short")

    first_byte = buf[0]
    version = first_byte >> 4
    ihl = first_byte & 0x0F
    ipv4_header_len = ihl * 4
    if version == 4 and ihl >= 5:
        if len(buf) < ipv4_header_len + ICMP_HEADER_LEN:
            raise ValueError("packet too short")
        return buf[ipv4_header_len:]

    return buf


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


@dataclass(frozen=True)
class ICMPPacket:
    icmp_type: int
    icmp_code: int
    payload: bytes
    icmp_checksum: int | None = None

    @staticmethod
    def from_bytes(buf: bytes) -> "ICMPPacket":
        icmp_packet = _extract_icmp_payload(buf)
        icmp_type, icmp_code, icmp_checksum, _id, _seq = struct.unpack(
            "!BBHHH", icmp_packet[:ICMP_HEADER_LEN]
        )
        payload = icmp_packet[ICMP_HEADER_LEN:]
        packet = ICMPPacket(
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            icmp_checksum=icmp_checksum,
            payload=payload,
        )
        if not packet.validate_checksum():
            raise ValueError("invalid checksum")
        return packet

    def calculate_checksum(self) -> int:
        return internet_checksum(self.to_bytes_no_checksum())

    def validate_checksum(self) -> bool:
        if self.icmp_checksum is None:
            return False
        return self.icmp_checksum == self.calculate_checksum()

    def to_bytes(self) -> bytes:
        header = struct.pack(
            "!BBHHH", self.icmp_type, self.icmp_code, self.calculate_checksum(), 0, 0
        )
        return header + self.payload

    def to_bytes_no_checksum(self) -> bytes:
        header = struct.pack("!BBHHH", self.icmp_type, self.icmp_code, 0, 0, 0)
        return header + self.payload
