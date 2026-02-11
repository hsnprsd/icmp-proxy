import socket

from icmp import ICMPPacket


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))
        while True:
            buf, _ = sock.recvfrom(65535)
            icmp_packet = ICMPPacket.from_bytes(buf)
            print(icmp_packet)


if __name__ == "__main__":
    main()
