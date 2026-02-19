from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from enum import IntEnum

NONCE_LEN = 16
HMAC_LEN = 32
MAX_PAYLOAD_LEN = (1 << 16) - 1


class MessageType(IntEnum):
    HELLO = 1
    HELLO_ACK = 2
    OPEN_STREAM = 3
    OPEN_OK = 4
    OPEN_ERR = 5
    DATA = 6
    CLOSE = 7
    CLOSE_ACK = 8
    KEEPALIVE = 9
    OPEN_DATAGRAM = 10
    HEARTBEAT = 11


FLAG_RELIABLE = 0x01
FLAG_FRAGMENTED = 0x02

FRAME_HEADER_STRUCT = struct.Struct("!BBBIIIIH")
FRAME_HEADER_LEN = FRAME_HEADER_STRUCT.size


def _pack_u8_len_bytes(value: bytes, *, label: str) -> bytes:
    if len(value) > 255:
        raise ValueError(f"{label} too long")
    return len(value).to_bytes(1, "big") + value


def _unpack_u8_len_bytes(buf: bytes, *, label: str) -> tuple[bytes, bytes]:
    if len(buf) < 1:
        raise ValueError(f"{label} missing length")
    size = buf[0]
    buf = buf[1:]
    if len(buf) < size:
        raise ValueError(f"{label} truncated")
    return buf[:size], buf[size:]


@dataclass(frozen=True)
class Frame:
    flags: int
    msg_type: MessageType
    reserved: int
    session_id: int
    stream_id: int
    seq_num: int
    ack_num: int
    payload: bytes

    def encode(self) -> bytes:
        payload_len = len(self.payload)
        if payload_len > MAX_PAYLOAD_LEN:
            raise ValueError("payload too large")
        return FRAME_HEADER_STRUCT.pack(
            self.flags,
            int(self.msg_type),
            self.reserved,
            self.session_id,
            self.stream_id,
            self.seq_num,
            self.ack_num,
            payload_len,
        ) + self.payload

    @staticmethod
    def decode(data: bytes) -> "Frame":
        if len(data) < FRAME_HEADER_LEN:
            raise ValueError("frame too short")
        (
            flags,
            msg_type_raw,
            reserved,
            session_id,
            stream_id,
            seq_num,
            ack_num,
            payload_len,
        ) = FRAME_HEADER_STRUCT.unpack(data[:FRAME_HEADER_LEN])
        try:
            msg_type = MessageType(msg_type_raw)
        except ValueError as exc:
            raise ValueError(f"invalid message type: {msg_type_raw}") from exc
        expected_size = FRAME_HEADER_LEN + payload_len
        if len(data) != expected_size:
            raise ValueError("frame payload length mismatch")
        payload = data[FRAME_HEADER_LEN:]
        return Frame(
            flags=flags,
            msg_type=msg_type,
            reserved=reserved,
            session_id=session_id,
            stream_id=stream_id,
            seq_num=seq_num,
            ack_num=ack_num,
            payload=payload,
        )

    @staticmethod
    def make(
        msg_type: MessageType,
        payload: bytes,
        *,
        session_id: int,
        stream_id: int = 0,
        seq_num: int = 0,
        ack_num: int = 0,
        flags: int = 0,
        reserved: int = 0,
    ) -> "Frame":
        return Frame(
            flags=flags,
            msg_type=msg_type,
            reserved=reserved,
            session_id=session_id,
            stream_id=stream_id,
            seq_num=seq_num,
            ack_num=ack_num,
            payload=payload,
        )


@dataclass(frozen=True)
class Hello:
    client_id: str
    nonce: bytes
    timestamp_ms: int
    hmac_sha256: bytes

    def encode(self) -> bytes:
        client_id = self.client_id.encode("utf-8")
        if len(self.nonce) != NONCE_LEN:
            raise ValueError("invalid client nonce size")
        if len(self.hmac_sha256) != HMAC_LEN:
            raise ValueError("invalid hello hmac size")
        return (
            _pack_u8_len_bytes(client_id, label="client_id")
            + self.nonce
            + self.timestamp_ms.to_bytes(8, "big")
            + self.hmac_sha256
        )

    @staticmethod
    def decode(data: bytes) -> "Hello":
        client_id_raw, remainder = _unpack_u8_len_bytes(data, label="client_id")
        if len(remainder) != NONCE_LEN + 8 + HMAC_LEN:
            raise ValueError("hello payload length mismatch")
        nonce = remainder[:NONCE_LEN]
        timestamp_ms = int.from_bytes(remainder[NONCE_LEN : NONCE_LEN + 8], "big")
        hmac_sha256 = remainder[NONCE_LEN + 8 :]
        return Hello(
            client_id=client_id_raw.decode("utf-8"),
            nonce=nonce,
            timestamp_ms=timestamp_ms,
            hmac_sha256=hmac_sha256,
        )


@dataclass(frozen=True)
class HelloAck:
    server_nonce: bytes
    timestamp_ms: int
    hmac_sha256: bytes

    def encode(self) -> bytes:
        if len(self.server_nonce) != NONCE_LEN:
            raise ValueError("invalid server nonce size")
        if len(self.hmac_sha256) != HMAC_LEN:
            raise ValueError("invalid hello ack hmac size")
        return self.server_nonce + self.timestamp_ms.to_bytes(8, "big") + self.hmac_sha256

    @staticmethod
    def decode(data: bytes) -> "HelloAck":
        if len(data) != NONCE_LEN + 8 + HMAC_LEN:
            raise ValueError("hello ack payload length mismatch")
        server_nonce = data[:NONCE_LEN]
        timestamp_ms = int.from_bytes(data[NONCE_LEN : NONCE_LEN + 8], "big")
        hmac_sha256 = data[NONCE_LEN + 8 :]
        return HelloAck(
            server_nonce=server_nonce,
            timestamp_ms=timestamp_ms,
            hmac_sha256=hmac_sha256,
        )


@dataclass(frozen=True)
class OpenStream:
    remote_host: str
    remote_port: int

    def encode(self) -> bytes:
        host = self.remote_host.encode("utf-8")
        if not (0 <= self.remote_port <= 65535):
            raise ValueError("remote_port out of range")
        return _pack_u8_len_bytes(host, label="remote_host") + self.remote_port.to_bytes(
            2, "big"
        )

    @staticmethod
    def decode(data: bytes) -> "OpenStream":
        host_raw, remainder = _unpack_u8_len_bytes(data, label="remote_host")
        if len(remainder) != 2:
            raise ValueError("open stream payload length mismatch")
        remote_port = int.from_bytes(remainder, "big")
        return OpenStream(remote_host=host_raw.decode("utf-8"), remote_port=remote_port)


@dataclass(frozen=True)
class OpenDatagram:
    def encode(self) -> bytes:
        return b""

    @staticmethod
    def decode(data: bytes) -> "OpenDatagram":
        if data:
            raise ValueError("open datagram payload must be empty")
        return OpenDatagram()


@dataclass(frozen=True)
class OpenOk:
    assigned_stream_id: int

    def encode(self) -> bytes:
        return self.assigned_stream_id.to_bytes(4, "big")

    @staticmethod
    def decode(data: bytes) -> "OpenOk":
        if len(data) != 4:
            raise ValueError("open ok payload length mismatch")
        return OpenOk(assigned_stream_id=int.from_bytes(data, "big"))


@dataclass(frozen=True)
class OpenErr:
    error_code: int
    reason: str

    def encode(self) -> bytes:
        reason = self.reason.encode("utf-8")
        if not (0 <= self.error_code <= 65535):
            raise ValueError("error_code out of range")
        return self.error_code.to_bytes(2, "big") + _pack_u8_len_bytes(
            reason, label="reason"
        )

    @staticmethod
    def decode(data: bytes) -> "OpenErr":
        if len(data) < 3:
            raise ValueError("open error payload too short")
        error_code = int.from_bytes(data[:2], "big")
        reason_raw, remainder = _unpack_u8_len_bytes(data[2:], label="reason")
        if remainder:
            raise ValueError("open error payload has trailing bytes")
        return OpenErr(error_code=error_code, reason=reason_raw.decode("utf-8"))


@dataclass(frozen=True)
class Data:
    payload: bytes

    def encode(self) -> bytes:
        if len(self.payload) > MAX_PAYLOAD_LEN:
            raise ValueError("data payload too large")
        return self.payload

    @staticmethod
    def decode(data: bytes) -> "Data":
        return Data(payload=data)


@dataclass(frozen=True)
class DatagramPacket:
    remote_host: str
    remote_port: int
    payload: bytes

    def encode(self) -> bytes:
        if not (0 <= self.remote_port <= 65535):
            raise ValueError("remote_port out of range")
        try:
            addr = ipaddress.ip_address(self.remote_host)
        except ValueError:
            host_bytes = self.remote_host.encode("idna")
            if not host_bytes:
                raise ValueError("remote_host is empty")
            if len(host_bytes) > 255:
                raise ValueError("remote_host too long")
            return (
                b"\x03"
                + len(host_bytes).to_bytes(1, "big")
                + host_bytes
                + self.remote_port.to_bytes(2, "big")
                + self.payload
            )
        if isinstance(addr, ipaddress.IPv4Address):
            return b"\x01" + addr.packed + self.remote_port.to_bytes(2, "big") + self.payload
        return b"\x04" + addr.packed + self.remote_port.to_bytes(2, "big") + self.payload

    @staticmethod
    def decode(data: bytes) -> "DatagramPacket":
        if len(data) < 1:
            raise ValueError("datagram payload too short")
        address_type = data[0]
        cursor = 1
        if address_type == 0x01:
            if len(data) < cursor + 4 + 2:
                raise ValueError("truncated datagram ipv4 payload")
            remote_host = str(ipaddress.IPv4Address(data[cursor : cursor + 4]))
            cursor += 4
        elif address_type == 0x03:
            if len(data) < cursor + 1:
                raise ValueError("truncated datagram domain payload")
            size = data[cursor]
            cursor += 1
            if size == 0:
                raise ValueError("empty datagram domain")
            if len(data) < cursor + size + 2:
                raise ValueError("truncated datagram domain payload")
            remote_host = data[cursor : cursor + size].decode("idna")
            cursor += size
        elif address_type == 0x04:
            if len(data) < cursor + 16 + 2:
                raise ValueError("truncated datagram ipv6 payload")
            remote_host = str(ipaddress.IPv6Address(data[cursor : cursor + 16]))
            cursor += 16
        else:
            raise ValueError("unsupported datagram address type")
        remote_port = int.from_bytes(data[cursor : cursor + 2], "big")
        cursor += 2
        return DatagramPacket(
            remote_host=remote_host,
            remote_port=remote_port,
            payload=data[cursor:],
        )


@dataclass(frozen=True)
class Close:
    def encode(self) -> bytes:
        return b""

    @staticmethod
    def decode(data: bytes) -> "Close":
        if data:
            raise ValueError("close payload must be empty")
        return Close()


@dataclass(frozen=True)
class CloseAck:
    def encode(self) -> bytes:
        return b""

    @staticmethod
    def decode(data: bytes) -> "CloseAck":
        if data:
            raise ValueError("close ack payload must be empty")
        return CloseAck()


@dataclass(frozen=True)
class Keepalive:
    def encode(self) -> bytes:
        return b""

    @staticmethod
    def decode(data: bytes) -> "Keepalive":
        if data:
            raise ValueError("keepalive payload must be empty")
        return Keepalive()


@dataclass(frozen=True)
class Heartbeat:
    def encode(self) -> bytes:
        return b""

    @staticmethod
    def decode(data: bytes) -> "Heartbeat":
        if data:
            raise ValueError("heartbeat payload must be empty")
        return Heartbeat()
