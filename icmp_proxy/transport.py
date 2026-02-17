from __future__ import annotations

import logging
import os
import socket
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Callable

from .icmp import ICMPPacket
from .protocol import FLAG_RELIABLE, Frame, MessageType

LOGGER = logging.getLogger("icmp_proxy.transport")

MAX_SEQUENCE_NUMBER = (1 << 32) - 1


@dataclass
class PendingFrame:
    frame: Frame
    sent_at: float
    retries: int


@dataclass(frozen=True)
class StatsSnapshot:
    duration_s: float
    sent_frames: int
    acked_bytes: int
    retry_frames: int
    dropped_frames: int
    global_inflight: int
    active_streams: int
    avg_window: float
    max_window: int
    retry_ratio: float
    rtt_ms: float | None


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
        max_inflight_per_stream: int = 1024,
        max_global_inflight: int = 2048,
        min_inflight_per_stream: int = 32,
        flowcontrol_enable: bool = True,
        flowcontrol_alpha: float = 0.125,
        flowcontrol_beta: float = 0.25,
        flowcontrol_increase_step: int = 8,
        flowcontrol_decrease_factor: float = 0.7,
        flowcontrol_loss_threshold: float = 0.02,
        stats_interval_ms: int = 1000,
        performance_metrics_enable: bool = False,
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
        self.max_inflight_per_stream = max(1, max_inflight_per_stream)
        self.min_inflight_per_stream = max(
            1, min(min_inflight_per_stream, self.max_inflight_per_stream)
        )
        self.max_global_inflight = max(1, max_global_inflight)
        self.flowcontrol_enable = flowcontrol_enable
        self.flowcontrol_alpha = max(0.01, min(1.0, flowcontrol_alpha))
        self.flowcontrol_beta = max(0.01, min(1.0, flowcontrol_beta))
        self.flowcontrol_increase_step = max(1, flowcontrol_increase_step)
        self.flowcontrol_decrease_factor = max(0.1, min(0.99, flowcontrol_decrease_factor))
        self.flowcontrol_loss_threshold = max(0.0, flowcontrol_loss_threshold)
        self.stats_interval_s = max(0.1, stats_interval_ms / 1000.0)
        self.performance_metrics_enable = performance_metrics_enable
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
        self._inflight_by_stream: dict[int, int] = {}
        self._global_inflight = 0
        self._stream_windows: dict[int, int] = {}
        self._seen: dict[int, OrderedDict[int, None]] = {}
        self._received: deque[Frame] = deque()
        self._recv_thread: threading.Thread | None = None
        self._retx_thread: threading.Thread | None = None
        self._rtt_ewma_s: float | None = None
        self._rtt_var_s: float | None = None
        now = time.monotonic()
        self._stats_window_started = now
        self._last_flowcontrol_at = now
        self._stats_sent_frames = 0
        self._stats_acked_bytes = 0
        self._stats_retry_frames = 0
        self._stats_dropped_frames = 0

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

    def send_reliable(
        self,
        *,
        msg_type: MessageType,
        session_id: int,
        stream_id: int,
        payload: bytes,
        flags: int = 0,
    ) -> int:
        deadline = time.monotonic() + 2.0
        with self._state_lock:
            while True:
                stream_window = self._stream_windows.get(
                    stream_id, self.min_inflight_per_stream
                )
                stream_inflight = self._inflight_by_stream.get(stream_id, 0)
                if (
                    stream_inflight < stream_window
                    and self._global_inflight < self.max_global_inflight
                ):
                    self._stream_windows.setdefault(stream_id, stream_window)
                    seq_num = self._next_sequence_number_locked()
                    frame = Frame.make(
                        msg_type=msg_type,
                        payload=payload,
                        session_id=session_id,
                        stream_id=stream_id,
                        seq_num=seq_num,
                        flags=flags | FLAG_RELIABLE,
                    )
                    self._pending[(stream_id, seq_num)] = PendingFrame(
                        frame=frame,
                        sent_at=time.monotonic(),
                        retries=0,
                    )
                    self._inflight_by_stream[stream_id] = stream_inflight + 1
                    self._global_inflight += 1
                    self._stats_sent_frames += 1
                    break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"stream {stream_id} inflight queue is full "
                        f"(stream={stream_inflight}/{stream_window}, "
                        f"global={self._global_inflight}/{self.max_global_inflight})"
                    )
                self._inflight_cv.wait(timeout=remaining)
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
            if keys:
                self._global_inflight = max(0, self._global_inflight - len(keys))
            self._inflight_by_stream.pop(stream_id, None)
            self._stream_windows.pop(stream_id, None)
            self._seen.pop(stream_id, None)
            self._inflight_cv.notify_all()

    def _next_sequence_number_locked(self) -> int:
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
            pending = self._pending.pop((frame.stream_id, frame.ack_num), None)
            if pending is None:
                return
            self._decrement_inflight_locked(frame.stream_id)
            self._stats_acked_bytes += len(pending.frame.payload)
            self._update_rtt_locked(time.monotonic() - pending.sent_at)
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

    def _decrement_inflight_locked(self, stream_id: int) -> None:
        stream_inflight = self._inflight_by_stream.get(stream_id, 0)
        if stream_inflight <= 1:
            self._inflight_by_stream.pop(stream_id, None)
        else:
            self._inflight_by_stream[stream_id] = stream_inflight - 1
        if self._global_inflight > 0:
            self._global_inflight -= 1

    def _update_rtt_locked(self, sample_rtt_s: float) -> None:
        if sample_rtt_s <= 0:
            return
        if self._rtt_ewma_s is None:
            self._rtt_ewma_s = sample_rtt_s
            self._rtt_var_s = sample_rtt_s / 2.0
            return
        error = sample_rtt_s - self._rtt_ewma_s
        self._rtt_ewma_s += self.flowcontrol_alpha * error
        rtt_var = self._rtt_var_s if self._rtt_var_s is not None else abs(error)
        self._rtt_var_s = rtt_var + self.flowcontrol_beta * (abs(error) - rtt_var)

    def _flowcontrol_interval_locked(self) -> float:
        if self._rtt_ewma_s is None:
            return self.stats_interval_s
        return max(0.05, min(self.stats_interval_s, self._rtt_ewma_s))

    def _run_flowcontrol_locked(self, now: float) -> bool:
        self._last_flowcontrol_at = now
        if not self.flowcontrol_enable:
            return False

        retry_denominator = self._stats_sent_frames + self._stats_retry_frames
        retry_ratio = self._stats_retry_frames / max(1, retry_denominator)
        loss_detected = (
            self._stats_retry_frames > 0
            and retry_ratio >= self.flowcontrol_loss_threshold
        )

        changed = False
        stream_ids = set(self._stream_windows)
        stream_ids.update(self._inflight_by_stream)
        for stream_id in stream_ids:
            current_window = self._stream_windows.get(
                stream_id, self.min_inflight_per_stream
            )
            inflight = self._inflight_by_stream.get(stream_id, 0)
            new_window = current_window

            if loss_detected and inflight > 0:
                new_window = max(
                    self.min_inflight_per_stream,
                    int(current_window * self.flowcontrol_decrease_factor),
                )
            elif (
                inflight >= current_window
                and self._global_inflight < self.max_global_inflight
            ):
                new_window = min(
                    self.max_inflight_per_stream,
                    current_window + self.flowcontrol_increase_step,
                )

            if new_window != current_window:
                self._stream_windows[stream_id] = new_window
                changed = True
        return changed

    def _take_stats_snapshot_locked(self, now: float) -> StatsSnapshot:
        duration_s = max(now - self._stats_window_started, 1e-6)
        retry_denominator = self._stats_sent_frames + self._stats_retry_frames
        windows = list(self._stream_windows.values())
        snapshot = StatsSnapshot(
            duration_s=duration_s,
            sent_frames=self._stats_sent_frames,
            acked_bytes=self._stats_acked_bytes,
            retry_frames=self._stats_retry_frames,
            dropped_frames=self._stats_dropped_frames,
            global_inflight=self._global_inflight,
            active_streams=sum(
                1 for value in self._inflight_by_stream.values() if value > 0
            ),
            avg_window=(
                (sum(windows) / len(windows))
                if windows
                else float(self.min_inflight_per_stream)
            ),
            max_window=max(windows) if windows else self.min_inflight_per_stream,
            retry_ratio=(self._stats_retry_frames / max(1, retry_denominator)),
            rtt_ms=(None if self._rtt_ewma_s is None else self._rtt_ewma_s * 1000.0),
        )
        self._stats_window_started = now
        self._stats_sent_frames = 0
        self._stats_acked_bytes = 0
        self._stats_retry_frames = 0
        self._stats_dropped_frames = 0
        return snapshot

    def _log_stats(self, snapshot: StatsSnapshot) -> None:
        if (
            snapshot.sent_frames == 0
            and snapshot.retry_frames == 0
            and snapshot.dropped_frames == 0
            and snapshot.global_inflight == 0
        ):
            return
        goodput_mb_s = snapshot.acked_bytes / snapshot.duration_s / (1024 * 1024)
        rtt_value = "n/a" if snapshot.rtt_ms is None else f"{snapshot.rtt_ms:.1f}ms"
        LOGGER.info(
            "flow stats goodput=%.2f MB/s inflight=%d/%d streams=%d avg_window=%.1f "
            "max_window=%d retry_ratio=%.3f dropped=%d rtt=%s",
            goodput_mb_s,
            snapshot.global_inflight,
            self.max_global_inflight,
            snapshot.active_streams,
            snapshot.avg_window,
            snapshot.max_window,
            snapshot.retry_ratio,
            snapshot.dropped_frames,
            rtt_value,
        )

    def _retx_loop(self) -> None:
        while not self._stop_event.is_set():
            now = time.monotonic()
            resend: list[Frame] = []
            exhausted: dict[int, MessageType] = {}
            stats_snapshot: StatsSnapshot | None = None
            with self._state_lock:
                for key, pending in list(self._pending.items()):
                    if now - pending.sent_at < self.retx_timeout_s:
                        continue
                    if pending.retries >= self.retx_max_retries:
                        exhausted.setdefault(key[0], pending.frame.msg_type)
                        del self._pending[key]
                        self._decrement_inflight_locked(key[0])
                        self._stats_dropped_frames += 1
                        self._inflight_cv.notify_all()
                        continue
                    pending.retries += 1
                    pending.sent_at = now
                    resend.append(pending.frame)
                    self._stats_retry_frames += 1

                if now - self._last_flowcontrol_at >= self._flowcontrol_interval_locked():
                    if self._run_flowcontrol_locked(now):
                        self._inflight_cv.notify_all()

                if now - self._stats_window_started >= self.stats_interval_s:
                    stats_snapshot = self._take_stats_snapshot_locked(now)

            for frame in resend:
                self._send_frame(frame)

            if stats_snapshot is not None and self.performance_metrics_enable:
                self._log_stats(stats_snapshot)

            if self.on_retry_exhausted is not None:
                for stream_id, msg_type in exhausted.items():
                    try:
                        self.on_retry_exhausted(stream_id, msg_type)
                    except Exception:
                        continue

            time.sleep(self.retx_scan_interval_s)
