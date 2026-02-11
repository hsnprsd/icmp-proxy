import struct
from dataclasses import dataclass


ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REQUEST_CODE = 0


@dataclass
class ICMPPacket:
    icmp_type: int
    icmp_code: int
    icmp_checksum: int
    payload: bytes

    @staticmethod
    def from_bytes(buf: bytes):
        icmp_packet = buf[20:]
        icmp_type, icmp_code, icmp_checksum = struct.unpack("!BBH", icmp_packet[:4])
        payload = icmp_packet[8:]
        return ICMPPacket(icmp_type, icmp_code, icmp_checksum, payload)

    def to_bytes(self) -> bytes:
        buf = struct.pack("!BBHHH", self.icmp_type, self.icmp_code, self.icmp_checksum, 0, 0)
        return buf + self.payload
