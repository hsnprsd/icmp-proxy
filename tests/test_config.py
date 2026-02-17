import pytest

from icmp_proxy.config import load_client_config, load_server_config, load_session_config


_BASE_ENV_VARS = [
    "ICMP_PROXY_CONFIG_FILE",
]

_COMMON_ENV_VARS = [
    "ICMP_PROXY_LOG_LEVEL",
    "ICMP_PROXY_PSK_FILE",
    "ICMP_PROXY_CLIENT_ID",
    "ICMP_PROXY_AUTH_SKEW_MS",
    "ICMP_PROXY_AUTH_REPLAY_TTL_MS",
    "ICMP_PROXY_AUTH_REPLAY_MAX_ENTRIES",
]

_SESSION_ENV_VARS = [
    "ICMP_PROXY_RETX_TIMEOUT_MS",
    "ICMP_PROXY_RETX_MAX_RETRIES",
    "ICMP_PROXY_RETX_SCAN_INTERVAL_MS",
    "ICMP_PROXY_SEEN_LIMIT_PER_STREAM",
    "ICMP_PROXY_MAX_INFLIGHT_PER_STREAM",
    "ICMP_PROXY_MIN_INFLIGHT_PER_STREAM",
    "ICMP_PROXY_MAX_GLOBAL_INFLIGHT",
    "ICMP_PROXY_MTU_PAYLOAD",
    "ICMP_PROXY_FLOWCONTROL_ENABLE",
    "ICMP_PROXY_FLOWCONTROL_ALPHA",
    "ICMP_PROXY_FLOWCONTROL_BETA",
    "ICMP_PROXY_FLOWCONTROL_INCREASE_STEP",
    "ICMP_PROXY_FLOWCONTROL_DECREASE_FACTOR",
    "ICMP_PROXY_FLOWCONTROL_LOSS_THRESHOLD",
    "ICMP_PROXY_STATS_INTERVAL_MS",
    "ICMP_PROXY_PERFORMANCE_METRICS_ENABLE",
]

_CLIENT_ONLY_ENV_VARS = [
    "ICMP_PROXY_REMOTE_HOST",
    "ICMP_PROXY_HTTP_PROXY_BIND_HOST",
    "ICMP_PROXY_HTTP_PROXY_BIND_PORT",
    "ICMP_PROXY_SOCKS_PROXY_ENABLE",
    "ICMP_PROXY_SOCKS_PROXY_BIND_HOST",
    "ICMP_PROXY_SOCKS_PROXY_BIND_PORT",
]

_SERVER_ENV_VARS = [
    "ICMP_PROXY_BIND_HOST",
    "ICMP_PROXY_CLIENT_HOST",
    "ICMP_PROXY_MAX_STREAMS",
    "ICMP_PROXY_TARGET_CONNECT_TIMEOUT_MS",
    "ICMP_PROXY_STREAM_IDLE_TIMEOUT_MS",
]


def _clear_session_env(monkeypatch) -> None:
    for name in _BASE_ENV_VARS + _COMMON_ENV_VARS + _SESSION_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _clear_client_env(monkeypatch) -> None:
    _clear_session_env(monkeypatch)
    for name in _CLIENT_ONLY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _clear_server_env(monkeypatch) -> None:
    _clear_session_env(monkeypatch)
    for name in _SERVER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _isolated_cwd(monkeypatch, tmp_path) -> None:
    monkeypatch.chdir(tmp_path)


def _write_ini(tmp_path, content: str, *, name: str = "config.ini") -> None:
    (tmp_path / name).write_text(content, encoding="utf-8")


def test_load_session_config_defaults(monkeypatch) -> None:
    _clear_session_env(monkeypatch)

    config = load_session_config()

    assert config.max_inflight_per_stream == 1024
    assert config.min_inflight_per_stream == 32
    assert config.max_global_inflight == 2048
    assert config.flowcontrol_enable is True
    assert config.flowcontrol_alpha == 0.125
    assert config.flowcontrol_beta == 0.25
    assert config.flowcontrol_increase_step == 8
    assert config.flowcontrol_decrease_factor == 0.7
    assert config.flowcontrol_loss_threshold == 0.02
    assert config.stats_interval_ms == 1000
    assert config.performance_metrics_enable is False


def test_load_session_config_clamps_min_inflight_to_max(monkeypatch) -> None:
    _clear_session_env(monkeypatch)
    monkeypatch.setenv("ICMP_PROXY_MAX_INFLIGHT_PER_STREAM", "64")
    monkeypatch.setenv("ICMP_PROXY_MIN_INFLIGHT_PER_STREAM", "128")

    config = load_session_config()

    assert config.max_inflight_per_stream == 64
    assert config.min_inflight_per_stream == 64


def test_load_session_config_clamps_flowcontrol_values(monkeypatch) -> None:
    _clear_session_env(monkeypatch)
    monkeypatch.setenv("ICMP_PROXY_FLOWCONTROL_ALPHA", "5")
    monkeypatch.setenv("ICMP_PROXY_FLOWCONTROL_BETA", "0")
    monkeypatch.setenv("ICMP_PROXY_FLOWCONTROL_DECREASE_FACTOR", "2")
    monkeypatch.setenv("ICMP_PROXY_FLOWCONTROL_LOSS_THRESHOLD", "-1")
    monkeypatch.setenv("ICMP_PROXY_STATS_INTERVAL_MS", "10")

    config = load_session_config()

    assert config.flowcontrol_alpha == 1.0
    assert config.flowcontrol_beta == 0.01
    assert config.flowcontrol_decrease_factor == 0.99
    assert config.flowcontrol_loss_threshold == 0.0
    assert config.stats_interval_ms == 100


def test_load_session_config_enables_performance_metrics(monkeypatch) -> None:
    _clear_session_env(monkeypatch)
    monkeypatch.setenv("ICMP_PROXY_PERFORMANCE_METRICS_ENABLE", "1")

    config = load_session_config()

    assert config.performance_metrics_enable is True


def test_load_client_config_socks_defaults(monkeypatch) -> None:
    _clear_client_env(monkeypatch)

    config = load_client_config()

    assert config.socks_proxy_enable is True
    assert config.socks_proxy_bind_host == "127.0.0.1"
    assert config.socks_proxy_bind_port == 1080


def test_load_client_config_socks_overrides(monkeypatch) -> None:
    _clear_client_env(monkeypatch)
    monkeypatch.setenv("ICMP_PROXY_SOCKS_PROXY_ENABLE", "0")
    monkeypatch.setenv("ICMP_PROXY_SOCKS_PROXY_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("ICMP_PROXY_SOCKS_PROXY_BIND_PORT", "11080")

    config = load_client_config()

    assert config.socks_proxy_enable is False
    assert config.socks_proxy_bind_host == "0.0.0.0"
    assert config.socks_proxy_bind_port == 11080


def test_load_client_config_from_ini(monkeypatch, tmp_path) -> None:
    _clear_client_env(monkeypatch)
    _write_ini(
        tmp_path,
        """
[common]
log_level = debug
psk_file = /tmp/from-ini.psk
client_id = ini-client

[session]
max_inflight_per_stream = 64
min_inflight_per_stream = 16
flowcontrol_enable = 0
performance_metrics_enable = 1

[client]
server_host = 10.1.2.3
http_proxy_bind_host = 0.0.0.0
http_proxy_bind_port = 18080
socks_proxy_enable = off
socks_proxy_bind_host = 0.0.0.0
socks_proxy_bind_port = 11080
""",
    )

    config = load_client_config()

    assert config.common.log_level == "DEBUG"
    assert config.common.psk_file == "/tmp/from-ini.psk"
    assert config.common.client_id == "ini-client"
    assert config.session.max_inflight_per_stream == 64
    assert config.session.min_inflight_per_stream == 16
    assert config.session.flowcontrol_enable is False
    assert config.session.performance_metrics_enable is True
    assert config.server_host == "10.1.2.3"
    assert config.http_proxy_bind_host == "0.0.0.0"
    assert config.http_proxy_bind_port == 18080
    assert config.socks_proxy_enable is False
    assert config.socks_proxy_bind_host == "0.0.0.0"
    assert config.socks_proxy_bind_port == 11080


def test_env_overrides_ini(monkeypatch, tmp_path) -> None:
    _clear_client_env(monkeypatch)
    _write_ini(
        tmp_path,
        """
[client]
server_host = 10.1.2.3
socks_proxy_enable = 0
""",
    )
    monkeypatch.setenv("ICMP_PROXY_REMOTE_HOST", "127.0.0.55")
    monkeypatch.setenv("ICMP_PROXY_SOCKS_PROXY_ENABLE", "1")

    config = load_client_config()

    assert config.server_host == "127.0.0.55"
    assert config.socks_proxy_enable is True


def test_config_file_env_path_override(monkeypatch, tmp_path) -> None:
    _clear_server_env(monkeypatch)
    _write_ini(
        tmp_path,
        """
[server]
bind_host = 127.0.0.1
max_streams = 900
""",
        name="custom.ini",
    )
    monkeypatch.setenv("ICMP_PROXY_CONFIG_FILE", str(tmp_path / "custom.ini"))

    config = load_server_config()

    assert config.bind_host == "127.0.0.1"
    assert config.max_streams == 900


def test_missing_explicit_config_file_raises(monkeypatch, tmp_path) -> None:
    _clear_client_env(monkeypatch)
    monkeypatch.setenv("ICMP_PROXY_CONFIG_FILE", str(tmp_path / "missing.ini"))

    with pytest.raises(ValueError, match="config file not found"):
        load_client_config()


def test_unknown_ini_section_raises(monkeypatch, tmp_path) -> None:
    _clear_session_env(monkeypatch)
    _write_ini(
        tmp_path,
        """
[mystery]
enabled = 1
""",
    )

    with pytest.raises(ValueError, match="unknown config section"):
        load_session_config()


def test_unknown_ini_key_raises(monkeypatch, tmp_path) -> None:
    _clear_session_env(monkeypatch)
    _write_ini(
        tmp_path,
        """
[session]
unknown_knob = 1
""",
    )

    with pytest.raises(ValueError, match="unknown config key"):
        load_session_config()


def test_invalid_ini_type_raises(monkeypatch, tmp_path) -> None:
    _clear_client_env(monkeypatch)
    _write_ini(
        tmp_path,
        """
[client]
http_proxy_bind_port = not-an-int
""",
    )

    with pytest.raises(ValueError):
        load_client_config()


def test_load_session_config_clamps_values_from_ini(monkeypatch, tmp_path) -> None:
    _clear_session_env(monkeypatch)
    _write_ini(
        tmp_path,
        """
[session]
flowcontrol_alpha = 5
flowcontrol_beta = 0
flowcontrol_decrease_factor = 2
flowcontrol_loss_threshold = -1
stats_interval_ms = 10
""",
    )

    config = load_session_config()

    assert config.flowcontrol_alpha == 1.0
    assert config.flowcontrol_beta == 0.01
    assert config.flowcontrol_decrease_factor == 0.99
    assert config.flowcontrol_loss_threshold == 0.0
    assert config.stats_interval_ms == 100
