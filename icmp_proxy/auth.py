from __future__ import annotations

import hmac
import os
import time
from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256


def load_psk(psk_file: str) -> bytes:
    with open(psk_file, "rb") as f:
        psk = f.read().strip()
    if not psk:
        raise ValueError("PSK file is empty")
    return psk


def now_ms() -> int:
    return int(time.time() * 1000)


def generate_nonce(size: int = 16) -> bytes:
    return os.urandom(size)


def sign_client_hello(
    *,
    psk: bytes,
    client_id: str,
    nonce: bytes,
    timestamp_ms: int,
) -> bytes:
    msg = (
        client_id.encode("utf-8")
        + b"\x00"
        + nonce
        + timestamp_ms.to_bytes(8, "big")
    )
    return hmac.new(psk, msg, sha256).digest()


def sign_server_hello_ack(
    *,
    psk: bytes,
    session_id: int,
    client_nonce: bytes,
    server_nonce: bytes,
    timestamp_ms: int,
) -> bytes:
    msg = (
        session_id.to_bytes(4, "big")
        + client_nonce
        + server_nonce
        + timestamp_ms.to_bytes(8, "big")
    )
    return hmac.new(psk, msg, sha256).digest()


def verify_signature(expected: bytes, received: bytes) -> bool:
    return hmac.compare_digest(expected, received)


@dataclass
class ReplayCache:
    ttl_ms: int
    max_entries: int

    def __post_init__(self) -> None:
        self._entries: OrderedDict[bytes, int] = OrderedDict()

    def _prune(self, now_timestamp_ms: int) -> None:
        while self._entries:
            key, seen_at = next(iter(self._entries.items()))
            if now_timestamp_ms - seen_at <= self.ttl_ms:
                break
            self._entries.pop(key, None)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)

    def add_if_new(self, nonce: bytes, now_timestamp_ms: int) -> bool:
        self._prune(now_timestamp_ms)
        if nonce in self._entries:
            return False
        self._entries[nonce] = now_timestamp_ms
        return True


def timestamp_within_window(
    *,
    timestamp_ms: int,
    now_timestamp_ms: int,
    allowed_skew_ms: int,
) -> bool:
    delta = abs(now_timestamp_ms - timestamp_ms)
    return delta <= allowed_skew_ms
