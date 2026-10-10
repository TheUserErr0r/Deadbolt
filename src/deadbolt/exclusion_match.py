"""Reference exact-host matcher for the external proxy integration contract.

The proxy must call equivalent logic before writing request/response body evidence.
Deadbolt itself does not inspect or route proxy traffic.
"""

from __future__ import annotations

from collections.abc import Collection

from deadbolt.config import ConfigurationError, normalize_hosts


def _hostname(value: str, *, http_host: bool) -> str | None:
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    name = value
    if http_host and ":" in value:
        if value.count(":") != 1:
            return None
        name, port = value.rsplit(":", 1)
        if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
            return None
    name = name.removesuffix(".").lower()
    try:
        normalize_hosts([name])
    except ConfigurationError:
        return None
    return name


def body_excluded(sni: str | None, http_host: str | None,
                  exact_hosts: Collection[str]) -> bool:
    """Use SNI authoritatively when supplied; use Host only if SNI is absent."""
    selected = _hostname(sni, http_host=False) if sni is not None else _hostname(http_host, http_host=True)
    return selected is not None and selected in exact_hosts
