""".NET NegotiateStream Protocol -- [MS-NNS].

Once a ``net.tcp`` client asks to upgrade with ``application/negotiate``, the
socket stops being a plain byte stream.  Two phases follow, and they use
*different* framing -- which is the detail that catches people out.

**Handshake.** Five-byte header, then an SPNEGO token::

    [type:1][major:1][minor:1][length:2 BIG-endian][token]

    0x16 HandshakeInProgress   0x14 HandshakeDone   0x15 HandshakeError

**Data.** After HandshakeDone the header changes shape entirely::

    [length:4 LITTLE-endian][wrapped bytes]

Captured from a stock WCF client against the local demo service::

    client -> 09 15 "application/negotiate"      UpgradeRequest (framing layer)
              16 01 00 00 7b <NegTokenInit>      first token, sent immediately
    server -> 0a                                 UpgradeResponse
              16 01 00 01 1b <NegTokenResp>
    client -> 16 01 00 00 79 <token>
    server -> 14 01 00 00 1d <token>             HandshakeDone, and it has a payload
    client -> 11 00 00 00 <17 bytes>             = 16-byte signature + 0x0c PreambleEnd

That last line is worth reading twice: the framing records resume *inside*
encrypted frames.  PreambleEnd, SizedEnvelope and End all travel this way, so
:class:`NegotiateStream` is a transparent stream and ``framing.py`` needs no
knowledge of it.

Two traps this module avoids
----------------------------
*Never hardcode the wrap overhead.*  It was exactly 16 bytes in the capture
above because localhost negotiated NTLM; Kerberos AES-256 has different, and
variable, overhead.  Every frame is sized from ``len(wrapped)``.

*Do not drop the HandshakeDone payload.*  It carries a mechListMIC that the
context must verify.  Ignoring it appears to work under NTLM and fails under
Kerberos.
"""

from __future__ import annotations

import struct
from typing import BinaryIO, Protocol

from .errors import PyNetTcpError

__all__ = [
    "MessageType",
    "NnsError",
    "HandshakeFailed",
    "NegotiateStream",
    "SecurityContext",
    "MAX_PLAINTEXT_CHUNK",
]


class MessageType:
    HANDSHAKE_ERROR = 0x15
    HANDSHAKE_IN_PROGRESS = 0x16
    HANDSHAKE_DONE = 0x14


MAJOR_VERSION = 1
MINOR_VERSION = 0

#: Plaintext bytes per data frame.  .NET's NegotiateStream works in units a
#: little under 64 KB; staying below that keeps every frame inside the peer's
#: read buffer while still amortising the per-frame overhead on large messages.
MAX_PLAINTEXT_CHUNK = 60 * 1024

_HANDSHAKE_HEADER = struct.Struct(">BBBH")
_DATA_LENGTH = struct.Struct("<I")


class NnsError(PyNetTcpError):
    """The NegotiateStream layer failed."""


class HandshakeFailed(NnsError):
    """The peer rejected authentication, or the exchange went wrong."""


class SecurityContext(Protocol):
    """The slice of a GSSAPI/SSPI context this module needs.

    Deliberately narrow so the transport can be tested with a fake, and so a
    non-Windows backend can be dropped in without touching this file.
    """

    @property
    def complete(self) -> bool: ...

    def step(self, in_token: bytes | None = None) -> bytes | None: ...

    def wrap(self, data: bytes) -> bytes: ...

    def unwrap(self, data: bytes) -> bytes: ...


class NegotiateStream:
    """A stream that authenticates, then encrypts every frame.

    Presents the same surface ``framing.FramingConnection`` expects of a
    buffered binary stream -- ``read`` returns exactly the requested number of
    bytes unless the connection ends.
    """

    def __init__(self, stream: BinaryIO, context: SecurityContext) -> None:
        self._stream = stream
        self._context = context
        self._plaintext = bytearray()
        self._eof = False
        self.handshake_complete = False

    # -- raw helpers ------------------------------------------------------
    def _read_exact(self, count: int) -> bytes:
        data = self._stream.read(count)
        if data is None or len(data) < count:
            got = 0 if data is None else len(data)
            raise NnsError(f"connection closed after {got} of {count} bytes")
        return data

    def _send_raw(self, data: bytes) -> None:
        self._stream.write(data)
        self._stream.flush()

    # -- handshake --------------------------------------------------------
    def send_token(self, token: bytes, message_type: int = MessageType.HANDSHAKE_IN_PROGRESS) -> None:
        if len(token) > 0xFFFF:
            raise NnsError(f"handshake token too large for a 16-bit length: {len(token)}")
        self._send_raw(
            _HANDSHAKE_HEADER.pack(message_type, MAJOR_VERSION, MINOR_VERSION, len(token)) + token
        )

    def read_token(self) -> tuple[int, bytes]:
        """Read one handshake frame as ``(message_type, token)``."""
        header = self._read_exact(_HANDSHAKE_HEADER.size)
        message_type, major, minor, length = _HANDSHAKE_HEADER.unpack(header)

        if message_type not in (
            MessageType.HANDSHAKE_IN_PROGRESS,
            MessageType.HANDSHAKE_DONE,
            MessageType.HANDSHAKE_ERROR,
        ):
            raise NnsError(
                f"expected a handshake frame, got type 0x{message_type:02X} "
                f"(v{major}.{minor}, length {length})"
            )

        token = self._read_exact(length) if length else b""

        if message_type == MessageType.HANDSHAKE_ERROR:
            raise HandshakeFailed(
                "peer reported a handshake error; the usual causes are an SPN "
                "the KDC does not know, a service running as a different "
                f"account, or clock skew. ({len(token)}-byte error token "
                "withheld: it is authentication material and would end up in "
                "logs)"
            )

        return message_type, token

    def handshake(self, first_token: bytes | None = None) -> None:
        """Drive the token exchange to completion.

        ``first_token`` is the token already sent -- WCF pipelines it behind
        the UpgradeRequest rather than waiting for the UpgradeResponse, and we
        do the same, so by the time this is called the first leg may be gone.
        """
        if first_token is None:
            token = self._context.step(None)
            if token:
                self.send_token(token)

        while True:
            message_type, token = self.read_token()

            # HandshakeDone still carries a token (a mechListMIC); feeding it
            # to the context is what verifies it.
            response = self._context.step(token) if token else None

            if message_type == MessageType.HANDSHAKE_DONE:
                if not self._context.complete:
                    raise HandshakeFailed(
                        "peer signalled HandshakeDone but the security context "
                        "is not complete"
                    )
                self.handshake_complete = True
                return

            if response:
                self.send_token(response)
            elif self._context.complete:
                # Nothing left to send, but the peer has not said Done yet --
                # keep reading rather than deadlocking on a write.
                continue

    # -- data phase -------------------------------------------------------
    def _require_handshake(self) -> None:
        if not self.handshake_complete:
            raise NnsError("cannot transfer data before the handshake completes")

    def write(self, data: bytes) -> int:
        self._require_handshake()
        total = len(data)
        for start in range(0, total, MAX_PLAINTEXT_CHUNK):
            chunk = data[start:start + MAX_PLAINTEXT_CHUNK]
            wrapped = self._context.wrap(bytes(chunk))
            # Size from the wrapped length -- the overhead is not a constant.
            self._stream.write(_DATA_LENGTH.pack(len(wrapped)) + wrapped)
        return total

    def flush(self) -> None:
        self._stream.flush()

    def _fill(self) -> bool:
        """Pull and decrypt one frame. False once the peer stops sending."""
        header = self._stream.read(_DATA_LENGTH.size)
        if not header or len(header) < _DATA_LENGTH.size:
            self._eof = True
            return False

        (length,) = _DATA_LENGTH.unpack(header)
        if length == 0:
            return True

        self._plaintext += self._context.unwrap(self._read_exact(length))
        return True

    def read(self, size: int = -1) -> bytes:
        """Return exactly ``size`` bytes, or everything until EOF if negative."""
        self._require_handshake()

        if size < 0:
            while self._fill():
                pass
            data, self._plaintext = bytes(self._plaintext), bytearray()
            return data

        while len(self._plaintext) < size:
            if self._eof or not self._fill():
                break

        data = bytes(self._plaintext[:size])
        del self._plaintext[:size]
        return data

    def close(self) -> None:
        try:
            self._stream.close()
        except OSError:
            pass

    # Enough of the io surface for callers that probe it.
    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False
