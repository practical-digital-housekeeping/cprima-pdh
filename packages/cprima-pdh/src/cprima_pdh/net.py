"""The only place pdh talks to the network: one small HTTPS GET with the standard library.

Everything else calls `net.fetch` / `net.pause` through this module, so tests replace them and never touch the internet.
Nothing is sent unless a command was given `--online`.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.request

USER_AGENT = "cprima-pdh (https://pdh.cprima.net)"


class NetworkError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def fetch(url: str, headers: dict[str, str] | None = None, timeout: float = 15) -> bytes:
    """GET an https URL and return the body. HTTP errors and connection problems raise `NetworkError`."""
    if not url.startswith("https://"):
        raise NetworkError(f"refusing a non-https URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - https only, checked above
            return response.read()
    except urllib.error.HTTPError as exc:
        raise NetworkError(f"{url}: HTTP {exc.code}", status=exc.code) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise NetworkError(f"could not connect to {url.split('/')[2]}: {getattr(exc, 'reason', exc)}") from None


def pause(seconds: float) -> None:
    """Wait between requests that a service rate-limits."""
    time.sleep(seconds)
