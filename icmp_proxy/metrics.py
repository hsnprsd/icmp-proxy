from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock, Thread
from typing import Callable


@dataclass
class Metrics:
    counters: Counter[str] = field(default_factory=Counter)
    gauges: dict[str, int] = field(default_factory=dict)

    def inc(self, name: str, value: int = 1) -> None:
        self.counters[name] += value

    def set_gauge(self, name: str, value: int) -> None:
        self.gauges[name] = value


class ServerPrometheusMetrics:
    def __init__(self) -> None:
        self._counters = Metrics()
        self._lock = Lock()

    def inc(self, name: str, value: int = 1) -> None:
        with self._lock:
            self._counters.inc(name, value)

    def inc_labeled(self, name: str, label_name: str, label_value: str, value: int = 1) -> None:
        metric_name = f'{name}{{{label_name}="{label_value}"}}'
        with self._lock:
            self._counters.inc(metric_name, value)

    def set_gauge(self, name: str, value: int) -> None:
        with self._lock:
            self._counters.set_gauge(name, value)

    def render_text(self) -> str:
        lines: list[str] = []
        with self._lock:
            for name, value in sorted(self._counters.counters.items()):
                lines.append(f"{name} {float(value):.1f}")
            for name, value in sorted(self._counters.gauges.items()):
                lines.append(f"{name} {float(value):.1f}")
        return "\n".join(lines) + "\n"


class _MetricsHandler(BaseHTTPRequestHandler):
    metrics_getter: Callable[[], str]

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/metrics":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"not found\n")
            return
        payload = self.metrics_getter().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


@dataclass
class MetricsHTTPServer:
    _http_server: ThreadingHTTPServer
    _thread: Thread

    def stop(self) -> None:
        self._http_server.shutdown()
        self._thread.join(timeout=1.0)
        self._http_server.server_close()


def start_prometheus_http_server(host: str, port: int, metrics: ServerPrometheusMetrics) -> MetricsHTTPServer:
    class Handler(_MetricsHandler):
        metrics_getter = metrics.render_text

    http_server = ThreadingHTTPServer((host, port), Handler)
    http_thread = Thread(target=http_server.serve_forever, daemon=True, name="prometheus-metrics-http")
    http_thread.start()
    return MetricsHTTPServer(_http_server=http_server, _thread=http_thread)
