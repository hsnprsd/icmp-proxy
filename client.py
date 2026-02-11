import socket

from icmp import ICMP_ECHO_REQUEST, ICMPPacket


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))
        packet = ICMPPacket(
            icmp_type=ICMP_ECHO_REQUEST,
            icmp_code=0,
            payload=b"hello world",
        )
        sock.sendto(packet.to_bytes(), ("127.0.0.1", 1))


if __name__ == "__main__":
    main()
