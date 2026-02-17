from dataclasses import dataclass
from enum import Enum


class FrameType(Enum):
    PROXY_START = 0
    PROXY_START_RESPONSE = 1
    PROXY_DATA = 2
    PROXY_CLOSE = 3
    PROXY_ACK = 4


@dataclass
class Frame:
    from_host: int  # 0 = Server, 1 = Client
    frame_type: FrameType
    stream_id: int
    seq_num: int
    payload: bytes

    def encode(self) -> bytes:
        return (
            self.from_host.to_bytes(1)
            + self.frame_type.value.to_bytes(1)
            + self.stream_id.to_bytes(4)
            + self.seq_num.to_bytes(4)
            + self.payload
        )

    @staticmethod
    def decode(data: bytes) -> "Frame":
        if len(data) < 10:
            raise ValueError("frame too short")
        from_host = int.from_bytes(data[:1], byteorder="big")
        data = data[1:]
        frame_type = FrameType(int.from_bytes(data[:1], byteorder="big"))
        data = data[1:]
        stream_id = int.from_bytes(data[:4], byteorder="big")
        data = data[4:]
        seq_num = int.from_bytes(data[:4], byteorder="big")
        data = data[4:]
        payload = data
        return Frame(
            from_host=from_host,
            frame_type=frame_type,
            stream_id=stream_id,
            seq_num=seq_num,
            payload=payload,
        )


@dataclass
class ProxyStart:
    remote_host: str
    remote_port: int

    def encode(self) -> bytes:
        return (
            len(self.remote_host.encode()).to_bytes(1)
            + self.remote_host.encode()
            + self.remote_port.to_bytes(2)
        )

    @staticmethod
    def decode(data: bytes) -> "ProxyStart":
        remote_host_length = int.from_bytes(data[:1], byteorder="big")
        data = data[1:]
        remote_host = data[:remote_host_length].decode()
        data = data[remote_host_length:]
        remote_port = int.from_bytes(data[:2], byteorder="big")
        return ProxyStart(
            remote_host=remote_host,
            remote_port=remote_port,
        )


@dataclass
class ProxyStartResponse:
    stream_id: int

    def encode(self) -> bytes:
        return self.stream_id.to_bytes(4)

    @staticmethod
    def decode(data: bytes) -> "ProxyStartResponse":
        return ProxyStartResponse(stream_id=int.from_bytes(data[:4], byteorder="big"))


@dataclass
class ProxyData:
    size: int
    payload: bytes

    def encode(self) -> bytes:
        return self.size.to_bytes(2) + self.payload

    @staticmethod
    def decode(data: bytes) -> "ProxyData":
        size = int.from_bytes(data[:2], byteorder="big")
        data = data[2:]
        payload = data[:size]
        return ProxyData(
            size=size,
            payload=payload,
        )


@dataclass
class ProxyClose:
    def encode(self) -> bytes:
        return b""

    @staticmethod
    def decode(data: bytes) -> "ProxyClose":
        return ProxyClose()


@dataclass
class ProxyAck:
    stream_id: int
    ack_seq_num: int

    def encode(self) -> bytes:
        return self.stream_id.to_bytes(4) + self.ack_seq_num.to_bytes(4)

    @staticmethod
    def decode(data: bytes) -> "ProxyAck":
        if len(data) < 8:
            raise ValueError("ack frame too short")
        stream_id = int.from_bytes(data[:4], byteorder="big")
        ack_seq_num = int.from_bytes(data[4:8], byteorder="big")
        return ProxyAck(stream_id=stream_id, ack_seq_num=ack_seq_num)
