"""Practical Digital Housekeeping (PDH): the companion tool of the methodology."""
from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("cprima-pdh")
except PackageNotFoundError:  # running from a source tree without installation
    __version__ = "0.0.0"

from . import policy  # noqa: E402,F401  (pdh's choices for the backends: made once, before anything opens a vault)
