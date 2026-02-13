from dataclasses import dataclass
from enum import Enum


class FrameType(Enum):
    PROXY_START = 0
    PROXY_START_RESPONSE = 1
    PROXY_DATA = 2
    PROXY_CLOSE = 3


@dataclass
class Frame:
    from_host: int  # 0 = Server, 1 = Client
    frame_type: FrameType
    payload: bytes

    def encode(self) -> bytes:
        return (
            self.from_host.to_bytes(1)
            + self.frame_type.value.to_bytes(1)
            + self.payload
        )

    @staticmethod
    def decode(data: bytes):
        from_host = int.from_bytes(data[:1])
        data = data[1:]
        frame_type = FrameType(int.from_bytes(data[:1]))
        data = data[1:]
        payload = data
        return Frame(
            from_host=from_host,
            frame_type=frame_type,
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
    def decode(data: bytes):
        remote_host_length = int.from_bytes(data[:1])
        data = data[1:]
        remote_host = data[:remote_host_length].decode()
        data = data[remote_host_length:]
        remote_port = int.from_bytes(data[:2])
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
    def decode(data: bytes):
        return ProxyStartResponse(stream_id=int.from_bytes(data[:4]))


@dataclass
class ProxyData:
    stream_id: int
    size: int
    payload: bytes

    def encode(self) -> bytes:
        return self.stream_id.to_bytes(4) + self.size.to_bytes(2) + self.payload

    @staticmethod
    def decode(data: bytes):
        stream_id = int.from_bytes(data[:4])
        data = data[4:]
        size = int.from_bytes(data[:2])
        data = data[2:]
        payload = data[:size]
        return ProxyData(
            stream_id=stream_id,
            size=size,
            payload=payload,
        )


@dataclass
class ProxyClose:
    stream_id: int

    def encode(self) -> bytes:
        return self.stream_id.to_bytes(4)

    @staticmethod
    def decode(data: bytes):
        stream_id = int.from_bytes(data[:4])
        return ProxyClose(stream_id=stream_id)
