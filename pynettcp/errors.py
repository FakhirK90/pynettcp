"""The one exception every pynettcp failure inherits from.

Callers should be able to write ``except PyNetTcpError`` and catch anything the
library raises on its own behalf, rather than having to know that the encoding
layer raises a ``ValueError`` subclass and the framing layer does not.

Transport errors from the standard library (``OSError``, ``TimeoutError``) are
deliberately *not* rewritten -- they mean what they always mean.
"""

from __future__ import annotations

__all__ = ["PyNetTcpError"]


class PyNetTcpError(Exception):
    """Base class for every error pynettcp raises."""
