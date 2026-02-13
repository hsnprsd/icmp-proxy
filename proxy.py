from dataclasses import dataclass

FRAME_TYPE_PROXY_REQUEST = 0
FRAME_TYPE_PROXY_RESPONSE = 1
FRAME_TYPE_DATA = 2


@dataclass
class Frame:
    frame_type: int
    payload: bytes

    def encode(self) -> bytes:
        return self.frame_type.to_bytes(1) + self.payload

    @staticmethod
    def decode(data: bytes):
        frame_type = int.from_bytes(data[:1])
        data = data[1:]
        payload = data
        return Frame(
            frame_type=frame_type,
            payload=payload,
        )


@dataclass
class ProxyRequest:
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
        return ProxyRequest(
            remote_host=remote_host,
            remote_port=remote_port,
        )


@dataclass
class ProxyResponse:
    stream_id: int

    def encode(self) -> bytes:
        return self.stream_id.to_bytes(4)

    @staticmethod
    def decode(data: bytes):
        return ProxyResponse(stream_id=int.from_bytes(data[:4]))


@dataclass
class Data:
    from_host: int  # 0 = Server, 1 = Client
    stream_id: int
    size: int
    payload: bytes

    def encode(self) -> bytes:
        return self.from_host.to_bytes(1) + self.stream_id.to_bytes(4) + self.size.to_bytes(2) + self.payload

    @staticmethod
    def decode(data: bytes):
        from_host = int.from_bytes(data[:1])
        data = data[1:]
        stream_id = int.from_bytes(data[:4])
        data = data[4:]
        size = int.from_bytes(data[:2])
        data = data[2:]
        payload = data[:size]
        return Data(
            from_host=from_host,
            stream_id=stream_id,
            size=size,
            payload=payload,
        )
