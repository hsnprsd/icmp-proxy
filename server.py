import os
import socket
from threading import Thread

from icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REQUEST, ICMPPacket
from proxy import (
    Frame,
    FrameType,
    ProxyClose,
    ProxyData,
    ProxyStart,
    ProxyStartResponse,
)

CLIENT_HOST = "127.0.0.1"


class Server:
    def __init__(self) -> None:
        self.host_id = 0
        self.outbound_connections: dict[int, socket.socket] = {}

    def __enter__(self):
        self.socket = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        )
        self.socket.bind(("0.0.0.0", 0))
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.socket.close()

    def __call__(self) -> None:
        while True:
            packet = self.socket.recv(4096)
            print(packet)
            packet = ICMPPacket.from_bytes(packet)
            frame = Frame.decode(packet.payload)
            if frame.from_host == self.host_id:
                continue

            self.process_frame(
                connection=self.socket,
                client_host=CLIENT_HOST,
                frame=frame,
            )

    def relay(
        self,
        client_host: str,
        stream_id: int,
    ):
        outboud_connection = self.outbound_connections[stream_id]
        while True:
            data = outboud_connection.recv(4096)
            if not data:
                break

            packet = ICMPPacket(
                icmp_type=ICMP_ECHO_REPLY,
                icmp_code=ICMP_ECHO_REPLY_CODE,
                payload=Frame(
                    from_host=self.host_id,
                    frame_type=FrameType.PROXY_DATA,
                    payload=ProxyData(
                        stream_id=stream_id,
                        size=len(data),
                        payload=data,
                    ).encode(),
                ).encode(),
            )
            self.socket.sendto(packet.to_bytes(), (client_host, 0))

        packet = ICMPPacket(
            icmp_type=ICMP_ECHO_REPLY,
            icmp_code=ICMP_ECHO_REPLY_CODE,
            payload=Frame(
                from_host=self.host_id,
                frame_type=FrameType.PROXY_CLOSE,
                payload=ProxyClose(stream_id=stream_id).encode(),
            ).encode(),
        )
        self.socket.sendto(packet.to_bytes(), (client_host, 0))

    def process_proxy_start(
        self,
        client_host: str,
        proxy_start: ProxyStart,
    ) -> None:
        while True:
            stream_id = int.from_bytes(os.urandom(4))
            if stream_id in self.outbound_connections:
                continue
            break
        outbound_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outbound_connection.connect((proxy_start.remote_host, proxy_start.remote_port))

        self.outbound_connections[stream_id] = outbound_connection

        relay_thread = Thread(
            target=self.relay, args=(client_host, stream_id)
        )
        relay_thread.start()

        packet = ICMPPacket(
            icmp_type=ICMP_ECHO_REPLY,
            icmp_code=ICMP_ECHO_REPLY_CODE,
            payload=Frame(
                from_host=self.host_id,
                frame_type=FrameType.PROXY_START_RESPONSE,
                payload=ProxyStartResponse(stream_id=stream_id).encode(),
            ).encode(),
        )

        self.socket.sendto(packet.to_bytes(), (client_host, 0))

    def process_proxy_data(self, proxy_data: ProxyData) -> None:
        connection = self.outbound_connections[proxy_data.stream_id]
        connection.sendall(proxy_data.payload)

    def process_proxy_close(self, proxy_close: ProxyClose) -> None:
        if proxy_close.stream_id in self.outbound_connections:
            outbound_connection = self.outbound_connections[proxy_close.stream_id]
            del self.outbound_connections[proxy_close.stream_id]
            outbound_connection.close()

    def process_frame(self, connection: socket.socket, client_host: str, frame: Frame):
        if frame.frame_type == FrameType.PROXY_START:
            self.process_proxy_start(
                client_host=client_host,
                proxy_start=ProxyStart.decode(frame.payload),
            )
        elif frame.frame_type == FrameType.PROXY_DATA:
            self.process_proxy_data(proxy_data=ProxyData.decode(frame.payload))
        elif frame.frame_type == FrameType.PROXY_CLOSE:
            self.process_proxy_close(proxy_close=ProxyClose.decode(frame.payload))
        else:
            raise Exception("invalid frame type %s" % frame.frame_type)


if __name__ == "__main__":
    with Server() as srv:
        srv()
