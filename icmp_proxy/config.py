from __future__ import annotations

import os
from dataclasses import dataclass


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    return int(value)


def _env_str(name: str, default: str) -> str:
    return os.getenv(name, default)


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    return float(value)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    return normalized not in {"0", "false", "no", "off"}


def _clamp(value: float, *, low: float, high: float) -> float:
    if value < low:
        return low
    if value > high:
        return high
    return value


@dataclass(frozen=True)
class SessionConfig:
    retx_timeout_ms: int
    retx_max_retries: int
    retx_scan_interval_ms: int
    seen_limit_per_stream: int
    max_inflight_per_stream: int
    mtu_payload: int
    max_global_inflight: int = 2048
    min_inflight_per_stream: int = 32
    flowcontrol_enable: bool = True
    flowcontrol_alpha: float = 0.125
    flowcontrol_beta: float = 0.25
    flowcontrol_increase_step: int = 8
    flowcontrol_decrease_factor: float = 0.7
    flowcontrol_loss_threshold: float = 0.02
    stats_interval_ms: int = 1000
    performance_metrics_enable: bool = False


@dataclass(frozen=True)
class CommonConfig:
    log_level: str
    psk_file: str
    client_id: str
    auth_skew_ms: int
    auth_replay_ttl_ms: int
    auth_replay_max_entries: int


@dataclass(frozen=True)
class ServerConfig:
    bind_host: str
    client_host: str
    max_streams: int
    target_connect_timeout_ms: int
    stream_idle_timeout_ms: int
    common: CommonConfig
    session: SessionConfig


@dataclass(frozen=True)
class ClientConfig:
    server_host: str
    http_proxy_bind_host: str
    http_proxy_bind_port: int
    common: CommonConfig
    session: SessionConfig
    socks_proxy_enable: bool = True
    socks_proxy_bind_host: str = "127.0.0.1"
    socks_proxy_bind_port: int = 1080


def load_common_config() -> CommonConfig:
    return CommonConfig(
        log_level=_env_str("ICMP_PROXY_LOG_LEVEL", "INFO").upper(),
        psk_file=_env_str("ICMP_PROXY_PSK_FILE", "./psk.txt"),
        client_id=_env_str("ICMP_PROXY_CLIENT_ID", "default-client"),
        auth_skew_ms=_env_int("ICMP_PROXY_AUTH_SKEW_MS", 30_000),
        auth_replay_ttl_ms=_env_int("ICMP_PROXY_AUTH_REPLAY_TTL_MS", 30_000),
        auth_replay_max_entries=_env_int("ICMP_PROXY_AUTH_REPLAY_MAX_ENTRIES", 8192),
    )


def load_session_config() -> SessionConfig:
    max_inflight_per_stream = max(1, _env_int("ICMP_PROXY_MAX_INFLIGHT_PER_STREAM", 1024))
    min_inflight_per_stream = max(1, _env_int("ICMP_PROXY_MIN_INFLIGHT_PER_STREAM", 32))
    if min_inflight_per_stream > max_inflight_per_stream:
        min_inflight_per_stream = max_inflight_per_stream

    flowcontrol_alpha = _clamp(
        _env_float("ICMP_PROXY_FLOWCONTROL_ALPHA", 0.125),
        low=0.01,
        high=1.0,
    )
    flowcontrol_beta = _clamp(
        _env_float("ICMP_PROXY_FLOWCONTROL_BETA", 0.25),
        low=0.01,
        high=1.0,
    )
    flowcontrol_decrease_factor = _clamp(
        _env_float("ICMP_PROXY_FLOWCONTROL_DECREASE_FACTOR", 0.7),
        low=0.1,
        high=0.99,
    )
    return SessionConfig(
        retx_timeout_ms=_env_int("ICMP_PROXY_RETX_TIMEOUT_MS", 100),
        retx_max_retries=_env_int("ICMP_PROXY_RETX_MAX_RETRIES", 5),
        retx_scan_interval_ms=_env_int("ICMP_PROXY_RETX_SCAN_INTERVAL_MS", 20),
        seen_limit_per_stream=_env_int("ICMP_PROXY_SEEN_LIMIT_PER_STREAM", 1024),
        max_inflight_per_stream=max_inflight_per_stream,
        mtu_payload=_env_int("ICMP_PROXY_MTU_PAYLOAD", 1200),
        max_global_inflight=max(1, _env_int("ICMP_PROXY_MAX_GLOBAL_INFLIGHT", 2048)),
        min_inflight_per_stream=min_inflight_per_stream,
        flowcontrol_enable=_env_bool("ICMP_PROXY_FLOWCONTROL_ENABLE", True),
        flowcontrol_alpha=flowcontrol_alpha,
        flowcontrol_beta=flowcontrol_beta,
        flowcontrol_increase_step=max(1, _env_int("ICMP_PROXY_FLOWCONTROL_INCREASE_STEP", 8)),
        flowcontrol_decrease_factor=flowcontrol_decrease_factor,
        flowcontrol_loss_threshold=max(0.0, _env_float("ICMP_PROXY_FLOWCONTROL_LOSS_THRESHOLD", 0.02)),
        stats_interval_ms=max(100, _env_int("ICMP_PROXY_STATS_INTERVAL_MS", 1000)),
        performance_metrics_enable=_env_bool("ICMP_PROXY_PERFORMANCE_METRICS_ENABLE", False),
    )


def load_server_config() -> ServerConfig:
    return ServerConfig(
        bind_host=_env_str("ICMP_PROXY_BIND_HOST", "0.0.0.0"),
        client_host=_env_str("ICMP_PROXY_CLIENT_HOST", "127.0.0.1"),
        max_streams=_env_int("ICMP_PROXY_MAX_STREAMS", 512),
        target_connect_timeout_ms=_env_int("ICMP_PROXY_TARGET_CONNECT_TIMEOUT_MS", 3000),
        stream_idle_timeout_ms=_env_int("ICMP_PROXY_STREAM_IDLE_TIMEOUT_MS", 60_000),
        common=load_common_config(),
        session=load_session_config(),
    )


def load_client_config() -> ClientConfig:
    return ClientConfig(
        server_host=_env_str("ICMP_PROXY_REMOTE_HOST", "127.0.0.1"),
        http_proxy_bind_host=_env_str("ICMP_PROXY_HTTP_PROXY_BIND_HOST", "127.0.0.1"),
        http_proxy_bind_port=_env_int("ICMP_PROXY_HTTP_PROXY_BIND_PORT", 8080),
        common=load_common_config(),
        session=load_session_config(),
        socks_proxy_enable=_env_bool("ICMP_PROXY_SOCKS_PROXY_ENABLE", True),
        socks_proxy_bind_host=_env_str("ICMP_PROXY_SOCKS_PROXY_BIND_HOST", "127.0.0.1"),
        socks_proxy_bind_port=_env_int("ICMP_PROXY_SOCKS_PROXY_BIND_PORT", 1080),
    )
