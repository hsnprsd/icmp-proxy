from __future__ import annotations

import configparser
import os
from dataclasses import dataclass
from pathlib import Path


CONFIG_FILE_ENV = "ICMP_PROXY_CONFIG_FILE"
DEFAULT_CONFIG_FILE = "config.ini"
DEFAULT_PSK = "change-me"

_ENV_TO_INI_KEY: dict[str, tuple[str, str]] = {
    "ICMP_PROXY_LOG_LEVEL": ("common", "log_level"),
    "ICMP_PROXY_PSK": ("common", "psk"),
    "ICMP_PROXY_CLIENT_ID": ("common", "client_id"),
    "ICMP_PROXY_AUTH_SKEW_MS": ("common", "auth_skew_ms"),
    "ICMP_PROXY_AUTH_REPLAY_TTL_MS": ("common", "auth_replay_ttl_ms"),
    "ICMP_PROXY_AUTH_REPLAY_MAX_ENTRIES": ("common", "auth_replay_max_entries"),
    "ICMP_PROXY_RETX_TIMEOUT_MS": ("session", "retx_timeout_ms"),
    "ICMP_PROXY_RETX_MAX_RETRIES": ("session", "retx_max_retries"),
    "ICMP_PROXY_RETX_SCAN_INTERVAL_MS": ("session", "retx_scan_interval_ms"),
    "ICMP_PROXY_SEEN_LIMIT_PER_STREAM": ("session", "seen_limit_per_stream"),
    "ICMP_PROXY_MAX_INFLIGHT_PER_STREAM": ("session", "max_inflight_per_stream"),
    "ICMP_PROXY_MIN_INFLIGHT_PER_STREAM": ("session", "min_inflight_per_stream"),
    "ICMP_PROXY_MAX_GLOBAL_INFLIGHT": ("session", "max_global_inflight"),
    "ICMP_PROXY_MTU_PAYLOAD": ("session", "mtu_payload"),
    "ICMP_PROXY_FLOWCONTROL_ENABLE": ("session", "flowcontrol_enable"),
    "ICMP_PROXY_FLOWCONTROL_ALPHA": ("session", "flowcontrol_alpha"),
    "ICMP_PROXY_FLOWCONTROL_BETA": ("session", "flowcontrol_beta"),
    "ICMP_PROXY_FLOWCONTROL_INCREASE_STEP": ("session", "flowcontrol_increase_step"),
    "ICMP_PROXY_FLOWCONTROL_DECREASE_FACTOR": ("session", "flowcontrol_decrease_factor"),
    "ICMP_PROXY_FLOWCONTROL_LOSS_THRESHOLD": ("session", "flowcontrol_loss_threshold"),
    "ICMP_PROXY_STATS_INTERVAL_MS": ("session", "stats_interval_ms"),
    "ICMP_PROXY_PERFORMANCE_METRICS_ENABLE": ("session", "performance_metrics_enable"),
    "ICMP_PROXY_BIND_HOST": ("server", "bind_host"),
    "ICMP_PROXY_CLIENT_HOST": ("server", "client_host"),
    "ICMP_PROXY_TARGET_CONNECT_TIMEOUT_MS": ("server", "target_connect_timeout_ms"),
    "ICMP_PROXY_SESSION_IDLE_TIMEOUT_MS": ("server", "session_idle_timeout_ms"),
    # Client uses ICMP_PROXY_REMOTE_HOST in env but server_host in INI.
    "ICMP_PROXY_REMOTE_HOST": ("client", "server_host"),
    "ICMP_PROXY_HTTP_PROXY_BIND_HOST": ("client", "http_proxy_bind_host"),
    "ICMP_PROXY_HTTP_PROXY_BIND_PORT": ("client", "http_proxy_bind_port"),
    "ICMP_PROXY_SOCKS_PROXY_ENABLE": ("client", "socks_proxy_enable"),
    "ICMP_PROXY_SOCKS_PROXY_BIND_HOST": ("client", "socks_proxy_bind_host"),
    "ICMP_PROXY_SOCKS_PROXY_BIND_PORT": ("client", "socks_proxy_bind_port"),
}

_VALID_INI_KEYS: dict[str, set[str]] = {}
for section_name, key_name in _ENV_TO_INI_KEY.values():
    _VALID_INI_KEYS.setdefault(section_name, set()).add(key_name)


@dataclass(frozen=True)
class _ConfigResolver:
    ini_values: dict[tuple[str, str], str]

    @classmethod
    def from_environment(cls) -> "_ConfigResolver":
        return cls(ini_values=_load_ini_values())

    def raw(self, env_name: str) -> str | None:
        env_value = os.getenv(env_name)
        if env_value is not None:
            return env_value
        ini_key = _ENV_TO_INI_KEY.get(env_name)
        if ini_key is None:
            return None
        return self.ini_values.get(ini_key)

    def env_int(self, name: str, default: int) -> int:
        value = self.raw(name)
        if value is None:
            return default
        return int(value)

    def env_str(self, name: str, default: str) -> str:
        value = self.raw(name)
        if value is None:
            return default
        return value

    def env_float(self, name: str, default: float) -> float:
        value = self.raw(name)
        if value is None:
            return default
        return float(value)

    def env_bool(self, name: str, default: bool) -> bool:
        value = self.raw(name)
        if value is None:
            return default
        normalized = value.strip().lower()
        return normalized not in {"0", "false", "no", "off"}


def _resolve_config_file_path() -> tuple[Path, bool]:
    configured_path = os.getenv(CONFIG_FILE_ENV)
    if configured_path is not None:
        normalized = configured_path.strip()
        if not normalized:
            raise ValueError(f"{CONFIG_FILE_ENV} is set but empty")
        return Path(normalized), True
    return Path(DEFAULT_CONFIG_FILE), False


def _load_ini_values() -> dict[tuple[str, str], str]:
    config_path, explicit = _resolve_config_file_path()
    if not config_path.exists():
        if explicit:
            raise ValueError(f"config file not found: {config_path}")
        return {}

    parser = configparser.ConfigParser(
        interpolation=None,
        default_section="__unused_defaults__",
    )
    try:
        with config_path.open("r", encoding="utf-8") as config_file:
            parser.read_file(config_file)
    except (OSError, configparser.Error) as exc:
        raise ValueError(f"failed to load config file {config_path}: {exc}") from exc

    ini_values: dict[tuple[str, str], str] = {}
    for section_name in parser.sections():
        section = section_name.strip().lower()
        valid_keys = _VALID_INI_KEYS.get(section)
        if valid_keys is None:
            raise ValueError(f"unknown config section [{section_name}] in {config_path}")

        for key_name, value in parser.items(section_name, raw=True):
            key = key_name.strip().lower()
            if key not in valid_keys:
                raise ValueError(f"unknown config key '{key_name}' in section [{section_name}] in {config_path}")
            ini_values[(section, key)] = value

    return ini_values


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
    psk: str
    client_id: str
    auth_skew_ms: int
    auth_replay_ttl_ms: int
    auth_replay_max_entries: int


@dataclass(frozen=True)
class ServerConfig:
    bind_host: str
    client_host: str
    target_connect_timeout_ms: int
    session_idle_timeout_ms: int
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


def _load_common_config(resolver: _ConfigResolver) -> CommonConfig:
    return CommonConfig(
        log_level=resolver.env_str("ICMP_PROXY_LOG_LEVEL", "INFO").upper(),
        psk=resolver.env_str("ICMP_PROXY_PSK", DEFAULT_PSK),
        client_id=resolver.env_str("ICMP_PROXY_CLIENT_ID", "default-client"),
        auth_skew_ms=resolver.env_int("ICMP_PROXY_AUTH_SKEW_MS", 30_000),
        auth_replay_ttl_ms=resolver.env_int("ICMP_PROXY_AUTH_REPLAY_TTL_MS", 30_000),
        auth_replay_max_entries=resolver.env_int("ICMP_PROXY_AUTH_REPLAY_MAX_ENTRIES", 8192),
    )


def load_common_config() -> CommonConfig:
    resolver = _ConfigResolver.from_environment()
    return _load_common_config(resolver)


def _load_session_config(resolver: _ConfigResolver) -> SessionConfig:
    max_inflight_per_stream = max(1, resolver.env_int("ICMP_PROXY_MAX_INFLIGHT_PER_STREAM", 1024))
    min_inflight_per_stream = max(1, resolver.env_int("ICMP_PROXY_MIN_INFLIGHT_PER_STREAM", 32))
    if min_inflight_per_stream > max_inflight_per_stream:
        min_inflight_per_stream = max_inflight_per_stream

    flowcontrol_alpha = _clamp(
        resolver.env_float("ICMP_PROXY_FLOWCONTROL_ALPHA", 0.125),
        low=0.01,
        high=1.0,
    )
    flowcontrol_beta = _clamp(
        resolver.env_float("ICMP_PROXY_FLOWCONTROL_BETA", 0.25),
        low=0.01,
        high=1.0,
    )
    flowcontrol_decrease_factor = _clamp(
        resolver.env_float("ICMP_PROXY_FLOWCONTROL_DECREASE_FACTOR", 0.7),
        low=0.1,
        high=0.99,
    )
    return SessionConfig(
        retx_timeout_ms=resolver.env_int("ICMP_PROXY_RETX_TIMEOUT_MS", 100),
        retx_max_retries=resolver.env_int("ICMP_PROXY_RETX_MAX_RETRIES", 5),
        retx_scan_interval_ms=resolver.env_int("ICMP_PROXY_RETX_SCAN_INTERVAL_MS", 20),
        seen_limit_per_stream=resolver.env_int("ICMP_PROXY_SEEN_LIMIT_PER_STREAM", 1024),
        max_inflight_per_stream=max_inflight_per_stream,
        mtu_payload=resolver.env_int("ICMP_PROXY_MTU_PAYLOAD", 1200),
        max_global_inflight=max(1, resolver.env_int("ICMP_PROXY_MAX_GLOBAL_INFLIGHT", 2048)),
        min_inflight_per_stream=min_inflight_per_stream,
        flowcontrol_enable=resolver.env_bool("ICMP_PROXY_FLOWCONTROL_ENABLE", True),
        flowcontrol_alpha=flowcontrol_alpha,
        flowcontrol_beta=flowcontrol_beta,
        flowcontrol_increase_step=max(1, resolver.env_int("ICMP_PROXY_FLOWCONTROL_INCREASE_STEP", 8)),
        flowcontrol_decrease_factor=flowcontrol_decrease_factor,
        flowcontrol_loss_threshold=max(0.0, resolver.env_float("ICMP_PROXY_FLOWCONTROL_LOSS_THRESHOLD", 0.02)),
        stats_interval_ms=max(100, resolver.env_int("ICMP_PROXY_STATS_INTERVAL_MS", 1000)),
        performance_metrics_enable=resolver.env_bool("ICMP_PROXY_PERFORMANCE_METRICS_ENABLE", False),
    )


def load_session_config() -> SessionConfig:
    resolver = _ConfigResolver.from_environment()
    return _load_session_config(resolver)


def load_server_config() -> ServerConfig:
    resolver = _ConfigResolver.from_environment()
    return ServerConfig(
        bind_host=resolver.env_str("ICMP_PROXY_BIND_HOST", "0.0.0.0"),
        client_host=resolver.env_str("ICMP_PROXY_CLIENT_HOST", "127.0.0.1"),
        target_connect_timeout_ms=resolver.env_int("ICMP_PROXY_TARGET_CONNECT_TIMEOUT_MS", 3000),
        session_idle_timeout_ms=resolver.env_int("ICMP_PROXY_SESSION_IDLE_TIMEOUT_MS", 60_000),
        common=_load_common_config(resolver),
        session=_load_session_config(resolver),
    )


def load_client_config() -> ClientConfig:
    resolver = _ConfigResolver.from_environment()
    return ClientConfig(
        server_host=resolver.env_str("ICMP_PROXY_REMOTE_HOST", "127.0.0.1"),
        http_proxy_bind_host=resolver.env_str("ICMP_PROXY_HTTP_PROXY_BIND_HOST", "127.0.0.1"),
        http_proxy_bind_port=resolver.env_int("ICMP_PROXY_HTTP_PROXY_BIND_PORT", 8080),
        common=_load_common_config(resolver),
        session=_load_session_config(resolver),
        socks_proxy_enable=resolver.env_bool("ICMP_PROXY_SOCKS_PROXY_ENABLE", True),
        socks_proxy_bind_host=resolver.env_str("ICMP_PROXY_SOCKS_PROXY_BIND_HOST", "127.0.0.1"),
        socks_proxy_bind_port=resolver.env_int("ICMP_PROXY_SOCKS_PROXY_BIND_PORT", 1080),
    )
