"""secured-claude — Claude Code wrapper, secured by design."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("secured-claude")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

__all__ = ["__version__"]
