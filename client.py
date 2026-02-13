import socket

from icmp import (
    ICMP_ECHO_REQUEST,
    ICMP_ECHO_REQUEST_CODE,
    ICMPPacket,
    icmp_echo_request,
)
from proxy import (
    Frame,
    FrameType,
    ProxyClose,
    ProxyData,
    ProxyStart,
    ProxyStartResponse,
)

SERVER_HOST = "127.0.0.1"


def send_frame(connection: socket.socket, frame: Frame) -> None:
    connection.sendto(
        icmp_echo_request(payload=frame.encode()).to_bytes(),
        (SERVER_HOST, 0),
    )


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))

        # send proxy request
        send_frame(
            connection=sock,
            frame=Frame(
                from_host=1,
                frame_type=FrameType.PROXY_START,
                payload=ProxyStart(
                    remote_host="google.com",
                    remote_port=80,
                ).encode(),
            ),
        )

        # receive proxy response
        while True:
            packet = sock.recv(4096)
            packet = ICMPPacket.from_bytes(packet)
            frame = Frame.decode(packet.payload)
            if frame.from_host != 0:
                continue

            if frame.frame_type != FrameType.PROXY_START_RESPONSE:
                raise Exception("Expected a proxy response frame")
            break

        proxy_start_response = ProxyStartResponse.decode(frame.payload)
        stream_id = proxy_start_response.stream_id

        request = "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n".encode()

        send_frame(
            connection=sock,
            frame=Frame(
                from_host=1,
                frame_type=FrameType.PROXY_DATA,
                payload=ProxyData(
                    stream_id=stream_id,
                    size=len(request),
                    payload=request,
                ).encode(),
            ),
        )

        while True:
            packet = sock.recv(4096)
            packet = ICMPPacket.from_bytes(packet)
            frame = Frame.decode(packet.payload)
            if frame.from_host != 0:
                continue

            if frame.frame_type != FrameType.PROXY_DATA:
                raise Exception("Expected a data frame")
            break

        proxy_data = ProxyData.decode(frame.payload)
        print(proxy_data.stream_id)
        print(proxy_data.size)
        print(proxy_data.payload)

        packet = ICMPPacket(
            icmp_type=ICMP_ECHO_REQUEST,
            icmp_code=ICMP_ECHO_REQUEST_CODE,
            payload=Frame(
                from_host=1,
                frame_type=FrameType.PROXY_CLOSE,
                payload=ProxyClose(stream_id=stream_id).encode(),
            ).encode(),
        )


if __name__ == "__main__":
    main()
