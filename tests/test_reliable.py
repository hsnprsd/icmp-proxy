import queue
import socket
import threading
import time

from icmp_proxy.icmp import ICMPPacket
from icmp_proxy.protocol import FLAG_RELIABLE, Frame, MessageType
from icmp_proxy.transport import ReliableICMPSession


class FakeRawSocket:
    def __init__(self) -> None:
        self.timeout = 0.1
        self._inbound: queue.Queue[bytes | None] = queue.Queue()
        self._send_lock = threading.Lock()
        self.sent_packets: list[bytes] = []
        self.sent_addrs: list[tuple[str, int]] = []
        self.closed = False

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        with self._send_lock:
            self.sent_packets.append(data)
            self.sent_addrs.append(addr)

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        if self.closed:
            raise OSError("socket closed")
        try:
            packet = self._inbound.get(timeout=self.timeout)
        except queue.Empty as exc:
            raise socket.timeout() from exc
        if packet is None:
            raise OSError("socket closed")
        return packet, ("127.0.0.1", 0)

    def inject_packet(self, packet: bytes) -> None:
        self._inbound.put(packet)

    def close(self) -> None:
        self.closed = True
        self._inbound.put(None)


def _wrap_frame_for_recv(frame: Frame) -> bytes:
    icmp_packet = ICMPPacket(icmp_type=0, icmp_code=0, payload=frame.encode())
    return (b"\x00" * 20) + icmp_packet.to_bytes()


def _decode_sent_frames(fake_socket: FakeRawSocket) -> list[Frame]:
    frames: list[Frame] = []
    for packet in fake_socket.sent_packets:
        frames.append(Frame.decode(packet[8:]))
    return frames


def _wait_until(predicate, timeout_s: float = 1.0, interval_s: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval_s)
    return False


def _new_session(fake: FakeRawSocket, **kwargs) -> ReliableICMPSession:
    return ReliableICMPSession(
        connection=fake,
        remote_host="127.0.0.1",
        outbound_icmp_type=8,
        outbound_icmp_code=0,
        inbound_icmp_type=0,
        inbound_icmp_code=0,
        **kwargs,
    )


def test_send_reliable_ack_clears_pending() -> None:
    fake = FakeRawSocket()
    session = _new_session(fake)
    session.start()
    try:
        seq_num = session.send_reliable(
            msg_type=MessageType.DATA,
            session_id=1,
            stream_id=7,
            payload=b"abc",
        )
        assert _wait_until(lambda: len(fake.sent_packets) >= 1)

        ack_frame = Frame.make(
            msg_type=MessageType.KEEPALIVE,
            payload=b"",
            session_id=1,
            stream_id=7,
            ack_num=seq_num,
        )
        fake.inject_packet(_wrap_frame_for_recv(ack_frame))
        assert session.wait_for_ack(session_id=1, stream_id=7, seq_num=seq_num, timeout_s=1.0)
    finally:
        session.stop()
        fake.close()


def test_retransmit_and_retry_exhaustion_callback() -> None:
    fake = FakeRawSocket()
    exhausted: list[tuple[int, int, MessageType]] = []

    def on_retry_exhausted(session_id: int, stream_id: int, msg_type: MessageType) -> None:
        exhausted.append((session_id, stream_id, msg_type))

    session = _new_session(
        fake,
        retx_timeout_ms=30,
        retx_max_retries=1,
        retx_scan_interval_ms=10,
        on_retry_exhausted=on_retry_exhausted,
    )
    session.start()
    try:
        seq_num = session.send_reliable(
            msg_type=MessageType.DATA,
            session_id=2,
            stream_id=42,
            payload=b"x",
        )
        assert _wait_until(lambda: len(fake.sent_packets) >= 2, timeout_s=1.0)
        assert _wait_until(lambda: exhausted, timeout_s=1.0)
        assert exhausted == [(2, 42, MessageType.DATA)]
        assert (2, 42, seq_num) not in session._pending
    finally:
        session.stop()
        fake.close()


def test_duplicate_inbound_reliable_is_acked_twice_delivered_once() -> None:
    fake = FakeRawSocket()
    session = _new_session(fake, retx_timeout_ms=500)
    session.start()
    try:
        inbound = Frame.make(
            msg_type=MessageType.DATA,
            payload=b"ping",
            session_id=3,
            stream_id=9,
            seq_num=100,
            flags=FLAG_RELIABLE,
        )
        wrapped = _wrap_frame_for_recv(inbound)
        fake.inject_packet(wrapped)
        fake.inject_packet(wrapped)

        received = session.wait_for_frame(
            lambda frame: frame.stream_id == 9 and frame.msg_type == MessageType.DATA,
            timeout_s=1.0,
        )
        assert received is not None
        assert received.stream_id == 9
        assert received.seq_num == 100

        duplicate = session.wait_for_frame(
            lambda frame: frame.stream_id == 9 and frame.msg_type == MessageType.DATA,
            timeout_s=0.1,
        )
        assert duplicate is None

        sent_frames = _decode_sent_frames(fake)
        ack_frames = [frame for frame in sent_frames if frame.msg_type == MessageType.KEEPALIVE]
        assert len(ack_frames) == 2
        assert ack_frames[0].ack_num == 100
        assert ack_frames[1].ack_num == 100
    finally:
        session.stop()
        fake.close()


def test_inbound_type_mismatch_is_ignored() -> None:
    fake = FakeRawSocket()
    session = _new_session(fake)
    session.start()
    try:
        wrong_type_packet = ICMPPacket(icmp_type=8, icmp_code=0, payload=Frame.make(
            msg_type=MessageType.DATA,
            payload=b"self",
            session_id=1,
            stream_id=5,
            seq_num=1,
            flags=FLAG_RELIABLE,
        ).encode())
        fake.inject_packet((b"\x00" * 20) + wrong_type_packet.to_bytes())

        assert session.wait_for_frame(lambda _frame: True, timeout_s=0.2) is None
        assert fake.sent_packets == []
    finally:
        session.stop()
        fake.close()


def test_flowcontrol_increases_window_when_stream_is_saturated() -> None:
    fake = FakeRawSocket()
    session = _new_session(
        fake,
        retx_timeout_ms=1000,
        retx_scan_interval_ms=10,
        min_inflight_per_stream=1,
        max_inflight_per_stream=5,
        max_global_inflight=16,
        flowcontrol_enable=True,
        flowcontrol_increase_step=2,
        stats_interval_ms=50,
    )
    session.start()
    try:
        session.send_reliable(
            msg_type=MessageType.DATA,
            session_id=7,
            stream_id=17,
            payload=b"a",
        )
        assert _wait_until(
            lambda: session._stream_windows.get((7, 17), 0) >= 3,  # pylint: disable=protected-access
            timeout_s=0.8,
        )
    finally:
        session.stop()
        fake.close()


def test_flowcontrol_decreases_window_when_retries_spike() -> None:
    fake = FakeRawSocket()
    session = _new_session(
        fake,
        retx_timeout_ms=20,
        retx_max_retries=10,
        retx_scan_interval_ms=10,
        min_inflight_per_stream=1,
        max_inflight_per_stream=16,
        max_global_inflight=16,
        flowcontrol_enable=True,
        flowcontrol_decrease_factor=0.5,
        flowcontrol_loss_threshold=0.01,
        stats_interval_ms=50,
    )
    session.start()
    try:
        with session._state_lock:  # pylint: disable=protected-access
            session._stream_windows[(9, 23)] = 12  # pylint: disable=protected-access
        session.send_reliable(
            msg_type=MessageType.DATA,
            session_id=9,
            stream_id=23,
            payload=b"b",
        )
        assert _wait_until(
            lambda: session._stream_windows.get((9, 23), 12) <= 6,  # pylint: disable=protected-access
            timeout_s=1.0,
        )
    finally:
        session.stop()
        fake.close()


def test_global_inflight_cap_blocks_until_ack() -> None:
    fake = FakeRawSocket()
    session = _new_session(
        fake,
        retx_timeout_ms=500,
        min_inflight_per_stream=2,
        max_inflight_per_stream=2,
        max_global_inflight=2,
        flowcontrol_enable=False,
    )
    session.start()
    try:
        seq1 = session.send_reliable(
            msg_type=MessageType.DATA,
            session_id=11,
            stream_id=1,
            payload=b"x",
        )
        session.send_reliable(
            msg_type=MessageType.DATA,
            session_id=11,
            stream_id=2,
            payload=b"y",
        )

        done = threading.Event()
        failure: list[Exception] = []

        def _sender() -> None:
            try:
                session.send_reliable(
                    msg_type=MessageType.DATA,
                    session_id=11,
                    stream_id=3,
                    payload=b"z",
                )
            except Exception as exc:  # pragma: no cover - assertion below validates this path is unused
                failure.append(exc)
            finally:
                done.set()

        sender_thread = threading.Thread(target=_sender, daemon=True)
        sender_thread.start()

        assert not done.wait(timeout=0.2)

        ack_frame = Frame.make(
            msg_type=MessageType.KEEPALIVE,
            payload=b"",
            session_id=11,
            stream_id=1,
            ack_num=seq1,
        )
        fake.inject_packet(_wrap_frame_for_recv(ack_frame))
        assert done.wait(timeout=1.0)
        assert not failure
    finally:
        session.stop()
        fake.close()


def test_ack_isolated_by_session_id() -> None:
    fake = FakeRawSocket()
    session = _new_session(fake)
    session.start()
    try:
        seq_num = session.send_reliable(
            msg_type=MessageType.DATA,
            session_id=101,
            stream_id=7,
            payload=b"abc",
        )
        wrong_ack = Frame.make(
            msg_type=MessageType.KEEPALIVE,
            payload=b"",
            session_id=102,
            stream_id=7,
            ack_num=seq_num,
        )
        fake.inject_packet(_wrap_frame_for_recv(wrong_ack))
        time.sleep(0.05)
        assert (101, 7, seq_num) in session._pending  # pylint: disable=protected-access

        correct_ack = Frame.make(
            msg_type=MessageType.KEEPALIVE,
            payload=b"",
            session_id=101,
            stream_id=7,
            ack_num=seq_num,
        )
        fake.inject_packet(_wrap_frame_for_recv(correct_ack))
        assert session.wait_for_ack(session_id=101, stream_id=7, seq_num=seq_num, timeout_s=1.0)
    finally:
        session.stop()
        fake.close()


def test_send_untracked_remote_host_override() -> None:
    fake = FakeRawSocket()
    session = _new_session(fake)
    session.start()
    try:
        session.send_untracked(
            msg_type=MessageType.KEEPALIVE,
            session_id=1,
            stream_id=0,
            payload=b"",
            remote_host="10.10.10.10",
        )
        assert _wait_until(lambda: len(fake.sent_packets) == 1)
        assert fake.sent_addrs[0][0] == "10.10.10.10"
    finally:
        session.stop()
        fake.close()
