import socket

from icmp import ICMPPacket
from proxy import (
    FRAME_TYPE_DATA,
    FRAME_TYPE_PROXY_REQUEST,
    FRAME_TYPE_PROXY_RESPONSE,
    Data,
    Frame,
    ProxyRequest,
    ProxyResponse,
)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))

        # receive proxy request
        while True:
            packet = sock.recv(4096)
            packet = ICMPPacket.from_bytes(packet)
            frame = Frame.decode(packet.payload)
            if frame.frame_type != FRAME_TYPE_PROXY_REQUEST:
                pass
            else:
                break

        proxy_request = ProxyRequest.decode(frame.payload)
        print(proxy_request.remote_host, proxy_request.remote_port)

        remote_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_conn.connect((proxy_request.remote_host, proxy_request.remote_port))

        stream_id = 0
        proxy_response = ProxyResponse(stream_id=stream_id)
        frame = Frame(
            frame_type=FRAME_TYPE_PROXY_RESPONSE,
            payload=proxy_response.encode(),
        )
        packet = ICMPPacket(icmp_type=0, icmp_code=0, payload=frame.encode())
        sock.sendto(packet.to_bytes(), ("127.0.0.1", 0))

        while True:
            packet = sock.recv(4096)
            packet = ICMPPacket.from_bytes(packet)
            frame = Frame.decode(packet.payload)
            if frame.frame_type != FRAME_TYPE_DATA:
                continue

            data = Data.decode(frame.payload)
            if data.from_host == 1:
                break

        data = Data.decode(frame.payload)
        print(data.stream_id)
        print(data.size)
        print(data.payload)

        if data.stream_id != stream_id:
            raise Exception("invalid stream_id")

        remote_conn.sendall(data.payload)

        packet = remote_conn.recv(4096)
        data = Data(from_host=0, stream_id=stream_id, size=len(packet), payload=packet)
        frame = Frame(frame_type=FRAME_TYPE_DATA, payload=data.encode())
        packet = ICMPPacket(icmp_type=0, icmp_code=0, payload=frame.encode())
        sock.sendto(packet.to_bytes(), ("127.0.0.1", 0))

        sock.close()


if __name__ == "__main__":
    main()
