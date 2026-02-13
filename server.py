import os
import socket
from threading import Thread

from icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REQUEST, ICMPPacket
from proxy import Data, Frame, FrameType, ProxyRequest, ProxyResponse

CLIENT_HOST = "127.0.0.1"

host_id = 0
outbound_connections: dict[int, socket.socket] = {}


def relay(
    connection: socket.socket,
    client_address: str,
    stream_id: int,
):
    outboud_connection = outbound_connections[stream_id]
    data = outboud_connection.recv(4096)

    packet = ICMPPacket(
        icmp_type=ICMP_ECHO_REPLY,
        icmp_code=ICMP_ECHO_REPLY_CODE,
        payload=Frame(
            from_host=host_id,
            frame_type=FrameType.DATA,
            payload=Data(
                stream_id=stream_id,
                size=len(data),
                payload=data,
            ).encode(),
        ).encode(),
    )
    connection.sendto(packet.to_bytes(), (client_address, 0))


def process_proxy_request(
    connection: socket.socket,
    client_address: str,
    proxy_request: ProxyRequest,
) -> None:
    while True:
        stream_id = int.from_bytes(os.urandom(4))
        if stream_id in outbound_connections:
            continue
        break
    outbound_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    outbound_connection.connect((proxy_request.remote_host, proxy_request.remote_port))

    outbound_connections[stream_id] = outbound_connection

    relay_thread = Thread(
        target=relay, args=(connection, client_address, stream_id)
    )
    relay_thread.start()

    packet = ICMPPacket(
        icmp_type=ICMP_ECHO_REPLY,
        icmp_code=ICMP_ECHO_REPLY_CODE,
        payload=Frame(
            from_host=host_id,
            frame_type=FrameType.PROXY_RESPONSE,
            payload=ProxyResponse(stream_id=stream_id).encode(),
        ).encode(),
    )

    connection.sendto(packet.to_bytes(), (client_address, 0))


def process_data(data: Data) -> None:
    connection = outbound_connections[data.stream_id]
    connection.sendall(data.payload)


def process_frame(connection: socket.socket, client_address: str, frame: Frame):
    if frame.frame_type == FrameType.PROXY_REQUEST:
        process_proxy_request(
            connection=connection,
            client_address=client_address,
            proxy_request=ProxyRequest.decode(frame.payload),
        )
    elif frame.frame_type == FrameType.DATA:
        process_data(data=Data.decode(frame.payload))
    else:
        raise Exception("invalid frame type %s" % frame.frame_type)


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))

        # receive proxy request
        while True:
            packet = sock.recv(4096)
            print(packet)
            packet = ICMPPacket.from_bytes(packet)
            frame = Frame.decode(packet.payload)
            if frame.from_host == host_id:
                continue

            process_frame(
                connection=sock,
                client_address=CLIENT_HOST,
                frame=frame,
            )


if __name__ == "__main__":
    main()
