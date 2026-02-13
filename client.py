import socket

from icmp import ICMPPacket, icmp_echo_request
from proxy import (
    FRAME_TYPE_DATA,
    FRAME_TYPE_PROXY_REQUEST,
    FRAME_TYPE_PROXY_RESPONSE,
    Data,
    Frame,
    ProxyRequest,
    ProxyResponse,
)

SERVER_HOST = "127.0.0.1"


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))

        # send proxy request
        packet = icmp_echo_request(
            payload=Frame(
                from_host=1,
                frame_type=FRAME_TYPE_PROXY_REQUEST,
                payload=ProxyRequest(
                    remote_host="google.com",
                    remote_port=80,
                ).encode(),
            ).encode()
        )
        sock.sendto(packet.to_bytes(), (SERVER_HOST, 1))

        # receive proxy response
        while True:
            packet = sock.recv(4096)
            packet = ICMPPacket.from_bytes(packet)
            frame = Frame.decode(packet.payload)
            if frame.from_host != 0:
                continue

            if frame.frame_type != FRAME_TYPE_PROXY_RESPONSE:
                raise Exception("Expected a proxy response frame")
            break

        proxy_response = ProxyResponse.decode(frame.payload)
        stream_id = proxy_response.stream_id

        request = "GET / HTTP/1.1\r\nHost: google.com\r\n\r\n".encode()

        packet = icmp_echo_request(
            payload=Frame(
                from_host=1,
                frame_type=FRAME_TYPE_DATA,
                payload=Data(
                    stream_id=stream_id,
                    size=len(request),
                    payload=request,
                ).encode(),
            ).encode()
        )
        sock.sendto(packet.to_bytes(), (SERVER_HOST, 1))

        while True:
            packet = sock.recv(4096)
            packet = ICMPPacket.from_bytes(packet)
            frame = Frame.decode(packet.payload)
            if frame.from_host != 0:
                continue

            if frame.frame_type != FRAME_TYPE_DATA:
                raise Exception("Expected a data frame")
            break

        data = Data.decode(frame.payload)
        print(data.stream_id)
        print(data.size)
        print(data.payload)

        parts = data.payload.split(b"\r\n")
        print(parts)


if __name__ == "__main__":
    main()
