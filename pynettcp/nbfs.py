""".NET Binary Format: SOAP Data Structure -- [MC-NBFS], session mode.

``NetTcpBinding`` negotiates KnownEncoding ``0x08``
(``application/soap+msbinsession1``), and the payload of a SizedEnvelope record
is **not** a bare NBFX document.  It is prefixed by the strings this message
adds to the dictionary that both peers build up over the life of the
connection::

    <MultiByteInt31 : byte length of the block>
    <MultiByteInt31 len><UTF-8 bytes>   ... repeated, the strings added now
    <NBFX document>

Missing that prefix is the classic way to get an immediate connection reset,
because the server reads the first string length as a record type.

Verified against WCF's own session encoder.  A first message carrying a
DataContract body opens with a 103-byte block::

    67  0c "LeaveRequest"  0f "urn:DemoService"
        29 "http://www.w3.org/2001/XMLSchema-instance"
        0a "EmployeeId"  0a "ReasonText"  09 "TotalDays"

and the second and third messages of the same session open with ``00`` and
refer to those six strings by id.  That compression is the entire point of
session mode: the example drops from 216 bytes to 114.

Two independent dictionaries per connection
-------------------------------------------
The strings *we* intern and the strings the *server* interns are separate
tables with separate numbering.  Sharing one table between reading and writing
desynchronises the ids and corrupts every later message -- and it corrupts
them silently, since the first message still decodes.  :class:`SessionCodec`
therefore holds one :class:`SessionDictionary` for each direction.
"""

from __future__ import annotations

from .nbfx import BinaryXmlReader, BinaryXmlWriter, NbfxError
from .varint import decode_multibyte_int31, encode_multibyte_int31

__all__ = [
    "SessionDictionary",
    "SessionCodec",
    "SessionSizeExceeded",
    "DEFAULT_MAX_SESSION_SIZE",
]

#: WCF's ``BinaryMessageEncodingBindingElement.MaxSessionSize`` default, in bytes.
DEFAULT_MAX_SESSION_SIZE = 2048


class SessionSizeExceeded(NbfxError):
    """The session dictionary outgrew the peer's advertised budget.

    WCF resets the session dictionary when it exceeds ``MaxSessionSize``.  We
    do not implement that reset yet, so we refuse to intern rather than let
    our table silently diverge from the server's.
    """


class SessionDictionary:
    """One direction's string table: the static table plus interned strings.

    Wire ids are pre-shifted so the low bit selects the table --
    ``index << 1`` static, ``index << 1 | 1`` session ([MC-NBFS] 2.2).
    """

    def __init__(self, max_size: int = DEFAULT_MAX_SESSION_SIZE) -> None:
        self.max_size = max_size
        self._strings: list[str] = []
        self._ids: dict[str, int] = {}
        #: Strings interned since the last :meth:`take_new_strings` -- i.e. the
        #: ones that still have to be announced to the peer.
        self._pending: list[str] = []
        self._size = 0

    # -- reading ----------------------------------------------------------
    def __len__(self) -> int:
        return len(self._strings)

    @property
    def strings(self) -> tuple[str, ...]:
        return tuple(self._strings)

    def static_id(self, value: str) -> int | None:
        from .dictionary import static_id

        return static_id(value)

    def session_id(self, value: str) -> int:
        """Wire id for ``value``, interning it if this is the first use."""
        existing = self._ids.get(value)
        if existing is not None:
            return existing
        return self._intern(value, announce=True)

    def add_known(self, value: str) -> int:
        """Record a string the *peer* announced. Never queued for sending."""
        existing = self._ids.get(value)
        if existing is not None:
            return existing
        return self._intern(value, announce=False)

    def _intern(self, value: str, *, announce: bool) -> int:
        cost = len(value.encode("utf-8"))
        if self._size + cost > self.max_size:
            raise SessionSizeExceeded(
                f"interning {value!r} would take the session dictionary to "
                f"{self._size + cost} bytes, past MaxSessionSize={self.max_size}"
            )

        index = len(self._strings)
        self._strings.append(value)
        wire_id = index << 1 | 1
        self._ids[value] = wire_id
        self._size += cost
        if announce:
            self._pending.append(value)
        return wire_id

    def lookup(self, wire_id: int) -> str:
        if not wire_id & 1:
            from .dictionary import lookup_static

            return lookup_static(wire_id >> 1)

        index = wire_id >> 1
        try:
            return self._strings[index]
        except IndexError:
            raise NbfxError(
                f"session dictionary id {wire_id} (index {index}) is unknown; "
                f"this session has only {len(self._strings)} string(s). "
                "The new-strings block was probably skipped or mis-parsed."
            ) from None

    # -- the announcement block -------------------------------------------
    def take_new_strings(self) -> list[str]:
        """Drain the strings interned since the last call."""
        pending, self._pending = self._pending, []
        return pending

    def encode_new_strings_block(self) -> bytes:
        """Serialise and drain the pending strings as a message prefix."""
        body = bytearray()
        for value in self.take_new_strings():
            encoded = value.encode("utf-8")
            body += encode_multibyte_int31(len(encoded))
            body += encoded
        return encode_multibyte_int31(len(body)) + bytes(body)

    def absorb_new_strings_block(self, data: bytes, offset: int = 0) -> int:
        """Read a peer's block at ``offset``; return where the document starts."""
        size, pos = decode_multibyte_int31(data, offset)
        end = pos + size
        if end > len(data):
            raise NbfxError(
                f"new-strings block claims {size} bytes but only "
                f"{len(data) - pos} remain"
            )

        while pos < end:
            length, pos = decode_multibyte_int31(data, pos)
            if pos + length > end:
                raise NbfxError("string in new-strings block overruns the block")
            self.add_known(data[pos:pos + length].decode("utf-8"))
            pos += length

        return end


class SessionCodec:
    """Encodes and decodes SizedEnvelope payloads for one connection.

    Holds the two direction-specific dictionaries, so callers cannot
    accidentally share one::

        codec = SessionCodec()
        payload = codec.encode(lambda w: build_envelope(w, ...))
        events = codec.decode(reply_payload)
    """

    def __init__(self, max_session_size: int = DEFAULT_MAX_SESSION_SIZE) -> None:
        self.outgoing = SessionDictionary(max_session_size)
        self.incoming = SessionDictionary(max_session_size)

    def encode(self, build) -> bytes:
        """Build a document with ``build(writer)`` and frame it for the session.

        The block has to precede the document but is only known once the
        document has been written -- interning happens as a side effect of
        writing -- so the document is buffered first, exactly as WCF does.
        """
        writer = BinaryXmlWriter(self.outgoing)
        build(writer)
        document = writer.getvalue()
        return self.outgoing.encode_new_strings_block() + document

    def decode(self, payload: bytes) -> list[tuple]:
        """Absorb the peer's new strings, then decode the document."""
        start = self.incoming.absorb_new_strings_block(payload)
        return BinaryXmlReader(payload[start:], self.incoming).read()

    def split(self, payload: bytes) -> tuple[list[str], bytes]:
        """Diagnostic helper: the announced strings and the raw document."""
        before = len(self.incoming)
        start = self.incoming.absorb_new_strings_block(payload)
        return list(self.incoming.strings[before:]), payload[start:]
