import struct
from dataclasses import dataclass

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REQUEST_CODE = 0
ICMP_ECHO_REPLY = 0
ICMP_ECHO_REPLY_CODE = 0


def inernet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


@dataclass
class ICMPPacket:
    icmp_type: int
    icmp_code: int
    payload: bytes
    icmp_checksum: int | None = None

    @staticmethod
    def from_bytes(buf: bytes):
        icmp_packet = buf[20:]
        icmp_type, icmp_code, icmp_checksum = struct.unpack("!BBH", icmp_packet[:4])
        payload = icmp_packet[8:]
        packet = ICMPPacket(
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            icmp_checksum=icmp_checksum,
            payload=payload,
        )
        if not packet.validate_checksum():
            raise Exception("invalid checksum")
        return packet

    def calculate_checksum(self) -> int:
        return inernet_checksum(self.to_bytes_no_checksum())

    def validate_checksum(self):
        return self.icmp_checksum == self.calculate_checksum()

    def to_bytes(self) -> bytes:
        buf = struct.pack(
            "!BBHHH", self.icmp_type, self.icmp_code, self.calculate_checksum(), 0, 0
        )
        return buf + self.payload

    def to_bytes_no_checksum(self) -> bytes:
        buf = struct.pack("!BBHHH", self.icmp_type, self.icmp_code, 0, 0, 0)
        return buf + self.payload


def icmp_echo_request(payload: bytes) -> ICMPPacket:
    return ICMPPacket(
        icmp_type=ICMP_ECHO_REQUEST,
        icmp_code=ICMP_ECHO_REQUEST_CODE,
        payload=payload,
    )
