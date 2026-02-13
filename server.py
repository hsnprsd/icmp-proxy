import os
import socket
from threading import Thread

from icmp import ICMP_ECHO_REPLY, ICMP_ECHO_REPLY_CODE, ICMP_ECHO_REQUEST, ICMPPacket
from proxy import Frame, FrameType, ProxyData, ProxyStart, ProxyStartResponse

CLIENT_HOST = "127.0.0.1"

host_id = 0
outbound_connections: dict[int, socket.socket] = {}


def relay(
    connection: socket.socket,
    client_address: str,
    stream_id: int,
):
    outboud_connection = outbound_connections[stream_id]
    while True:
        data = outboud_connection.recv(4096)
        if not data:
            break

        packet = ICMPPacket(
            icmp_type=ICMP_ECHO_REPLY,
            icmp_code=ICMP_ECHO_REPLY_CODE,
            payload=Frame(
                from_host=host_id,
                frame_type=FrameType.PROXY_DATA,
                payload=ProxyData(
                    stream_id=stream_id,
                    size=len(data),
                    payload=data,
                ).encode(),
            ).encode(),
        )
        connection.sendto(packet.to_bytes(), (client_address, 0))


def process_proxy_start(
    connection: socket.socket,
    client_address: str,
    proxy_start: ProxyStart,
) -> None:
    while True:
        stream_id = int.from_bytes(os.urandom(4))
        if stream_id in outbound_connections:
            continue
        break
    outbound_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    outbound_connection.connect((proxy_start.remote_host, proxy_start.remote_port))

    outbound_connections[stream_id] = outbound_connection

    relay_thread = Thread(target=relay, args=(connection, client_address, stream_id))
    relay_thread.start()

    packet = ICMPPacket(
        icmp_type=ICMP_ECHO_REPLY,
        icmp_code=ICMP_ECHO_REPLY_CODE,
        payload=Frame(
            from_host=host_id,
            frame_type=FrameType.PROXY_START_RESPONSE,
            payload=ProxyStartResponse(stream_id=stream_id).encode(),
        ).encode(),
    )

    connection.sendto(packet.to_bytes(), (client_address, 0))


def process_data(data: ProxyData) -> None:
    connection = outbound_connections[data.stream_id]
    connection.sendall(data.payload)


def process_frame(connection: socket.socket, client_address: str, frame: Frame):
    if frame.frame_type == FrameType.PROXY_START:
        process_proxy_start(
            connection=connection,
            client_address=client_address,
            proxy_start=ProxyStart.decode(frame.payload),
        )
    elif frame.frame_type == FrameType.PROXY_DATA:
        process_data(data=ProxyData.decode(frame.payload))
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
