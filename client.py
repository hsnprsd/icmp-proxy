import socket

from icmp import ICMPPacket, icmp_echo_request
from proxy import Data, Frame, FrameType, ProxyRequest, ProxyResponse

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
                frame_type=FrameType.PROXY_REQUEST,
                payload=ProxyRequest(
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

            if frame.frame_type != FrameType.PROXY_RESPONSE:
                raise Exception("Expected a proxy response frame")
            break

        proxy_response = ProxyResponse.decode(frame.payload)
        stream_id = proxy_response.stream_id

        request = "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n".encode()

        send_frame(
            connection=sock,
            frame=Frame(
                from_host=1,
                frame_type=FrameType.DATA,
                payload=Data(
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

            if frame.frame_type != FrameType.DATA:
                raise Exception("Expected a data frame")
            break

        data = Data.decode(frame.payload)
        print(data.stream_id)
        print(data.size)
        print(data.payload)


if __name__ == "__main__":
    main()
