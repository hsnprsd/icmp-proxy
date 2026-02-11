import socket

from icmp import icmp_echo_request


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as sock:
        sock.bind(("0.0.0.0", 0))
        packet = icmp_echo_request(payload=b"hello world")
        sock.sendto(packet.to_bytes(), ("127.0.0.1", 1))


if __name__ == "__main__":
    main()
