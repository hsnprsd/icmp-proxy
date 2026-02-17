from __future__ import annotations

import os
import socket
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable

from .icmp import ICMPPacket
from .protocol import FLAG_RELIABLE, Frame, MessageType

MAX_SEQUENCE_NUMBER = (1 << 32) - 1


@dataclass
class PendingFrame:
    frame: Frame
    sent_at: float
    retries: int


class ReliableICMPSession:
    def __init__(
        self,
        connection: socket.socket,
        remote_host: str,
        outbound_icmp_type: int,
        outbound_icmp_code: int,
        inbound_icmp_type: int,
        inbound_icmp_code: int,
        *,
        retx_timeout_ms: int = 100,
        retx_max_retries: int = 5,
        retx_scan_interval_ms: int = 20,
        seen_limit_per_stream: int = 1024,
        max_inflight_per_stream: int = 32,
        on_frame: Callable[[Frame], None] | None = None,
        on_retry_exhausted: Callable[[int, MessageType], None] | None = None,
    ) -> None:
        self.connection = connection
        self.remote_host = remote_host
        self.outbound_icmp_type = outbound_icmp_type
        self.outbound_icmp_code = outbound_icmp_code
        self.inbound_icmp_type = inbound_icmp_type
        self.inbound_icmp_code = inbound_icmp_code
        self.retx_timeout_s = retx_timeout_ms / 1000.0
        self.retx_max_retries = retx_max_retries
        self.retx_scan_interval_s = retx_scan_interval_ms / 1000.0
        self.seen_limit_per_stream = seen_limit_per_stream
        self.max_inflight_per_stream = max_inflight_per_stream
        self.on_frame = on_frame
        self.on_retry_exhausted = on_retry_exhausted

        self._state_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._received_cv = threading.Condition()
        self._inflight_cv = threading.Condition(self._state_lock)
        self._stop_event = threading.Event()

        self._next_seq_num = int.from_bytes(os.urandom(4), byteorder="big")
        if self._next_seq_num == 0:
            self._next_seq_num = 1
        self._pending: dict[tuple[int, int], PendingFrame] = {}
        self._seen: dict[int, OrderedDict[int, None]] = {}
        self._received: deque[Frame] = deque()
        self._recv_thread: threading.Thread | None = None
        self._retx_thread: threading.Thread | None = None

    def start(self) -> None:
        self.connection.settimeout(0.2)
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._retx_thread = threading.Thread(target=self._retx_loop, daemon=True)
        self._recv_thread.start()
        self._retx_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        with self._state_lock:
            self._inflight_cv.notify_all()
        with self._received_cv:
            self._received_cv.notify_all()
        if self._recv_thread is not None:
            self._recv_thread.join(timeout=1.0)
        if self._retx_thread is not None:
            self._retx_thread.join(timeout=1.0)

    def wait(self) -> None:
        if self._recv_thread is not None:
            self._recv_thread.join()

    def _wait_for_inflight_slot(self, stream_id: int, timeout_s: float = 2.0) -> None:
        deadline = time.monotonic() + timeout_s
        with self._state_lock:
            while True:
                inflight = 0
                for pending_key in self._pending:
                    if pending_key[0] == stream_id:
                        inflight += 1
                if inflight < self.max_inflight_per_stream:
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"stream {stream_id} inflight queue is full"
                    )
                self._inflight_cv.wait(timeout=remaining)

    def send_reliable(
        self,
        *,
        msg_type: MessageType,
        session_id: int,
        stream_id: int,
        payload: bytes,
        flags: int = 0,
    ) -> int:
        self._wait_for_inflight_slot(stream_id)
        seq_num = self._next_sequence_number()
        frame = Frame.make(
            msg_type=msg_type,
            payload=payload,
            session_id=session_id,
            stream_id=stream_id,
            seq_num=seq_num,
            flags=flags | FLAG_RELIABLE,
        )
        with self._state_lock:
            self._pending[(stream_id, seq_num)] = PendingFrame(
                frame=frame,
                sent_at=time.monotonic(),
                retries=0,
            )
        self._send_frame(frame)
        return seq_num

    def send_untracked(
        self,
        *,
        msg_type: MessageType,
        session_id: int,
        stream_id: int,
        payload: bytes,
        ack_num: int = 0,
        flags: int = 0,
    ) -> None:
        frame = Frame.make(
            msg_type=msg_type,
            payload=payload,
            session_id=session_id,
            stream_id=stream_id,
            ack_num=ack_num,
            flags=flags,
        )
        self._send_frame(frame)

    def wait_for_ack(self, stream_id: int, seq_num: int, timeout_s: float) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            with self._state_lock:
                if (stream_id, seq_num) not in self._pending:
                    return True
            time.sleep(0.01)
        return False

    def wait_for_frame(
        self,
        predicate: Callable[[Frame], bool],
        timeout_s: float | None = None,
    ) -> Frame | None:
        deadline = None if timeout_s is None else (time.monotonic() + timeout_s)
        with self._received_cv:
            while True:
                matched_index = None
                for index, frame in enumerate(self._received):
                    if predicate(frame):
                        matched_index = index
                        break
                if matched_index is not None:
                    self._received.rotate(-matched_index)
                    frame = self._received.popleft()
                    self._received.rotate(matched_index)
                    return frame
                if self._stop_event.is_set():
                    return None
                if deadline is None:
                    self._received_cv.wait()
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._received_cv.wait(timeout=remaining)

    def clear_stream_state(self, stream_id: int) -> None:
        with self._state_lock:
            keys = [key for key in self._pending if key[0] == stream_id]
            for key in keys:
                self._pending.pop(key, None)
            self._seen.pop(stream_id, None)
            self._inflight_cv.notify_all()

    def _next_sequence_number(self) -> int:
        with self._state_lock:
            seq_num = self._next_seq_num
            self._next_seq_num += 1
            if self._next_seq_num > MAX_SEQUENCE_NUMBER:
                self._next_seq_num = 1
            return seq_num

    def _send_frame(self, frame: Frame) -> None:
        packet = ICMPPacket(
            icmp_type=self.outbound_icmp_type,
            icmp_code=self.outbound_icmp_code,
            payload=frame.encode(),
        )
        with self._send_lock:
            try:
                self.connection.sendto(packet.to_bytes(), (self.remote_host, 0))
            except OSError:
                return

    def _handle_ack_num(self, frame: Frame) -> None:
        if frame.ack_num == 0:
            return
        with self._state_lock:
            self._pending.pop((frame.stream_id, frame.ack_num), None)
            self._inflight_cv.notify_all()

    def _send_ack(self, frame: Frame) -> None:
        self.send_untracked(
            msg_type=MessageType.KEEPALIVE,
            session_id=frame.session_id,
            stream_id=frame.stream_id,
            payload=b"",
            ack_num=frame.seq_num,
        )

    def _is_duplicate(self, stream_id: int, seq_num: int) -> bool:
        if seq_num == 0:
            return False
        with self._state_lock:
            if stream_id not in self._seen:
                self._seen[stream_id] = OrderedDict()
            seen_stream = self._seen[stream_id]
            if seq_num in seen_stream:
                return True
            seen_stream[seq_num] = None
            if len(seen_stream) > self.seen_limit_per_stream:
                seen_stream.popitem(last=False)
            return False

    def _handle_inbound_frame(self, frame: Frame) -> None:
        self._handle_ack_num(frame)
        if frame.flags & FLAG_RELIABLE:
            self._send_ack(frame)
            if self._is_duplicate(frame.stream_id, frame.seq_num):
                return
        if frame.msg_type == MessageType.KEEPALIVE and not frame.payload:
            return

        if self.on_frame is not None:
            try:
                self.on_frame(frame)
            except Exception:
                return
            return

        with self._received_cv:
            self._received.append(frame)
            self._received_cv.notify_all()

    def _recv_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                packet = self.connection.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                icmp_packet = ICMPPacket.from_bytes(packet)
                if icmp_packet.icmp_type != self.inbound_icmp_type:
                    continue
                if icmp_packet.icmp_code != self.inbound_icmp_code:
                    continue
                frame = Frame.decode(icmp_packet.payload)
            except Exception:
                continue
            self._handle_inbound_frame(frame)

    def _retx_loop(self) -> None:
        while not self._stop_event.is_set():
            now = time.monotonic()
            resend: list[Frame] = []
            exhausted: dict[int, MessageType] = {}
            with self._state_lock:
                for key, pending in list(self._pending.items()):
                    if now - pending.sent_at < self.retx_timeout_s:
                        continue
                    if pending.retries >= self.retx_max_retries:
                        exhausted.setdefault(key[0], pending.frame.msg_type)
                        del self._pending[key]
                        self._inflight_cv.notify_all()
                        continue
                    pending.retries += 1
                    pending.sent_at = now
                    resend.append(pending.frame)

            for frame in resend:
                self._send_frame(frame)

            if self.on_retry_exhausted is not None:
                for stream_id, msg_type in exhausted.items():
                    try:
                        self.on_retry_exhausted(stream_id, msg_type)
                    except Exception:
                        continue

            time.sleep(self.retx_scan_interval_s)
