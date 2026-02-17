from icmp_proxy.config import load_session_config


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


def _clear_session_env(monkeypatch) -> None:
    for name in _SESSION_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


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
