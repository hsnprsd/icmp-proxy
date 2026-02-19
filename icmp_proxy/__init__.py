"""ICMP proxy package."""

from ._version import __version__

__all__ = ["Client", "Server", "__version__"]


def __getattr__(name: str):
    if name == "Client":
        from .client import Client

        return Client
    if name == "Server":
        from .server import Server

        return Server
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
