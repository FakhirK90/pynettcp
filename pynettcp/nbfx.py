""".NET Binary Format: XML Data Structure -- [MC-NBFX].

WCF never puts angle brackets on a ``net.tcp`` wire.  It sends a record-oriented
binary encoding of the XML infoset in which every element, attribute and
namespace is either a length-prefixed UTF-8 string or -- far more often -- a
small integer index into a shared string dictionary.

Layout of a document is simply a flat sequence of records::

    <element record>  <attribute records...>  <content>  [EndElement]

The one rule that trips everyone up: **every text record type is even, and
setting the low bit means "and also close the current element"**.  So a leaf
element ``<a>hi</a>`` ends with ``99 02 'h' 'i'`` (Chars8TextWithEndElement)
and emits no explicit EndElement byte at all.
"""

from __future__ import annotations

import datetime as _dt
import math as _math
import struct
import uuid as _uuid
from typing import Protocol

from .errors import PyNetTcpError
from .varint import decode_multibyte_int31, encode_multibyte_int31

__all__ = [
    "Dictionary",
    "DictStr",
    "SessionStr",
    "StaticDictionary",
    "BinaryXmlWriter",
    "BinaryXmlReader",
    "NbfxError",
    "records",
]


class DictStr(str):
    """A string carried by reference to the **static** dictionary.

    Dictionary compression in NBFX is opt-in per string, not automatic.  .NET
    expresses this through overloads -- ``WriteStartElement(string, ...)``
    writes a literal record while ``WriteStartElement(XmlDictionaryString, ...)``
    writes a dictionary record -- and a plain string whose text happens to
    appear in the table is *not* compressed.

    Use this for the SOAP/WS-Addressing infrastructure names that WCF takes
    from ``ServiceModelDictionary``::

        writer.start_element("s", DictStr("Envelope"), DictStr(SOAP12_NS))

    The string must exist in the static table; if it does not, that is a bug
    in the caller rather than something to paper over, so it raises.
    """

    __slots__ = ()


class SessionStr(str):
    """A string interned in the **per-session** dictionary.

    The choice between static and session is *not* made by looking the text up
    in the static table -- it is decided by which dictionary the string came
    from.  WCF proves this: ``http://www.w3.org/2001/XMLSchema-instance`` sits
    at static index 441, yet a DataContract body still interns it into the
    session, because the serializer's strings belong to its own dictionary
    rather than to ``ServiceModelDictionary``.

    So use ``SessionStr`` for anything originating in the data contract --
    element names, the contract namespace, ``xsi`` -- and ``DictStr`` only for
    envelope infrastructure.
    """

    __slots__ = ()

_A = ord("a")
_Z = ord("z")
_XML_NS = "http://www.w3.org/XML/1998/namespace"


class NbfxError(PyNetTcpError, ValueError):
    """Malformed or unsupported binary XML."""


# --------------------------------------------------------------------------
# Record types ([MC-NBFX] 2.1.2)
# --------------------------------------------------------------------------
class records:  # noqa: N801 - namespace, deliberately lowercase like a module
    """Record type bytes. Names follow the specification exactly."""

    END_ELEMENT = 0x01
    COMMENT = 0x02
    ARRAY = 0x03

    SHORT_ATTRIBUTE = 0x04
    ATTRIBUTE = 0x05
    SHORT_DICTIONARY_ATTRIBUTE = 0x06
    DICTIONARY_ATTRIBUTE = 0x07

    SHORT_XMLNS_ATTRIBUTE = 0x08
    XMLNS_ATTRIBUTE = 0x09
    SHORT_DICTIONARY_XMLNS_ATTRIBUTE = 0x0A
    DICTIONARY_XMLNS_ATTRIBUTE = 0x0B

    #: 0x0C..0x25 -- PrefixDictionaryAttribute[A-Z], i.e. prefixes 'a'..'z'
    PREFIX_DICTIONARY_ATTRIBUTE_A = 0x0C
    #: 0x26..0x3F -- PrefixAttribute[A-Z]
    PREFIX_ATTRIBUTE_A = 0x26

    SHORT_ELEMENT = 0x40
    ELEMENT = 0x41
    SHORT_DICTIONARY_ELEMENT = 0x42
    DICTIONARY_ELEMENT = 0x43

    #: 0x44..0x5D -- PrefixDictionaryElement[A-Z]
    PREFIX_DICTIONARY_ELEMENT_A = 0x44
    #: 0x5E..0x77 -- PrefixElement[A-Z]
    PREFIX_ELEMENT_A = 0x5E

    # Text records. Even = value only; odd (value | 1) = value + EndElement.
    ZERO_TEXT = 0x80
    ONE_TEXT = 0x82
    FALSE_TEXT = 0x84
    TRUE_TEXT = 0x86
    INT8_TEXT = 0x88
    INT16_TEXT = 0x8A
    INT32_TEXT = 0x8C
    INT64_TEXT = 0x8E
    FLOAT_TEXT = 0x90
    DOUBLE_TEXT = 0x92
    DECIMAL_TEXT = 0x94
    DATETIME_TEXT = 0x96
    CHARS8_TEXT = 0x98
    CHARS16_TEXT = 0x9A
    CHARS32_TEXT = 0x9C
    BYTES8_TEXT = 0x9E
    BYTES16_TEXT = 0xA0
    BYTES32_TEXT = 0xA2
    START_LIST_TEXT = 0xA4
    END_LIST_TEXT = 0xA6
    EMPTY_TEXT = 0xA8
    DICTIONARY_TEXT = 0xAA
    UNIQUE_ID_TEXT = 0xAC
    TIMESPAN_TEXT = 0xAE
    UUID_TEXT = 0xB0
    UINT64_TEXT = 0xB2
    BOOL_TEXT = 0xB4
    UNICODE_CHARS8_TEXT = 0xB6
    UNICODE_CHARS16_TEXT = 0xB8
    UNICODE_CHARS32_TEXT = 0xBA
    QNAME_DICTIONARY_TEXT = 0xBC

    WITH_END_ELEMENT = 0x01  # OR into any text record


# --------------------------------------------------------------------------
# Dictionary plumbing
# --------------------------------------------------------------------------
class Dictionary(Protocol):
    """String table seen by the codec.

    Wire ids are pre-shifted: ``index << 1`` for the static table, and
    ``index << 1 | 1`` for a per-session table ([MC-NBFS] 2.2).
    """

    def static_id(self, value: str) -> int | None:
        """Wire id for ``value`` in the static table, or None if absent."""

    def session_id(self, value: str) -> int:
        """Wire id for ``value`` in the session table, interning it if new."""

    def lookup(self, wire_id: int) -> str:
        """Resolve a wire id back to its string."""


class StaticDictionary:
    """Static table only -- no session state.

    Correct for plain ``application/soap+msbin1`` (KnownEncoding 0x07).
    Session mode (0x08) uses :class:`pynettcp.nbfs.SessionDictionary`.
    """

    __slots__ = ()

    def static_id(self, value: str) -> int | None:
        from .dictionary import static_id

        return static_id(value)

    def session_id(self, value: str) -> int:
        raise NbfxError(
            f"cannot intern {value!r}: this encoding has no session dictionary"
        )

    def lookup(self, wire_id: int) -> str:
        from .dictionary import lookup_static

        if wire_id & 1:
            raise NbfxError(
                f"dictionary id {wire_id} references a session string, "
                "but this encoding has no session dictionary"
            )
        return lookup_static(wire_id >> 1)


def _prefix_index(prefix: str) -> int | None:
    """Return 0..25 if ``prefix`` is a single lowercase letter, else None."""
    if len(prefix) == 1 and _A <= ord(prefix) <= _Z:
        return ord(prefix) - _A
    return None


# --------------------------------------------------------------------------
# Writer
# --------------------------------------------------------------------------
class BinaryXmlWriter:
    """Streaming encoder.

    Calls must follow document order, exactly as they appear on the wire::

        w.start_element("s", "Envelope")
        w.xmlns("s", SOAP12_NS)
        w.start_element("s", "Body")
        w.end_element()
        w.end_element()

    ``end_element`` is a no-op when the preceding text record already carried
    the WithEndElement bit, so callers can always pair start/end symmetrically.
    """

    def __init__(self, dictionary: Dictionary | None = None) -> None:
        self._out = bytearray()
        self._dict: Dictionary = dictionary if dictionary is not None else StaticDictionary()
        self._depth = 0
        # The most recent content text record, held back so that a following
        # end_element() can be folded into it as the WithEndElement variant.
        # WCF always emits the merged form, so deferring is what makes our
        # output byte-identical without callers having to think about it.
        self._pending: tuple[int, bytes] | None = None
        self._in_attribute = False
        # Namespace declarations wait until the element's ordinary attributes
        # have been written: WCF emits <element> <attrs> <xmlns decls> <content>,
        # even though the declaration is discovered before the attribute.
        self._pending_xmlns: list[tuple[str, str]] = []
        # Namespace scopes, innermost last. Each maps prefix -> namespace so we
        # emit an xmlns record only when a prefix is not already bound to that
        # namespace -- matching what .NET's XmlDictionaryWriter puts on the wire.
        self._scopes: list[dict[str, str]] = [{"xml": _XML_NS, "": ""}]

    def _in_scope(self, prefix: str) -> str | None:
        for scope in reversed(self._scopes):
            if prefix in scope:
                return scope[prefix]
        return None

    def _bind(self, prefix: str, namespace: str) -> None:
        self._scopes[-1][prefix] = namespace

    # -- output -----------------------------------------------------------
    def getvalue(self) -> bytes:
        self._flush_text()
        if self._depth:
            raise NbfxError(f"{self._depth} element(s) left unclosed")
        return bytes(self._out)

    def _flush_xmlns(self) -> None:
        """Emit queued namespace declarations, in the order they were declared."""
        if not self._pending_xmlns:
            return
        queued, self._pending_xmlns = self._pending_xmlns, []
        for prefix, namespace in queued:
            self._emit_xmlns(prefix, namespace)

    def _flush_text(self, *, merge_end: bool = False) -> bool:
        """Emit the deferred text record, optionally folding EndElement in.

        Returns True if a record was emitted with the end folded in, so
        :meth:`end_element` knows not to write a separate EndElement byte.
        """
        if self._pending is None:
            return False
        record, payload = self._pending
        self._pending = None
        self._byte(record | records.WITH_END_ELEMENT if merge_end else record)
        self._raw(payload)
        return merge_end

    def _raw(self, data: bytes) -> None:
        self._out += data

    def _byte(self, value: int) -> None:
        self._out.append(value)

    def _string(self, value: str) -> None:
        """Length-prefixed UTF-8, as used for inline names and prefixes."""
        encoded = value.encode("utf-8")
        self._out += encode_multibyte_int31(len(encoded))
        self._out += encoded

    def _wire_id(self, value: str) -> int | None:
        """Wire id for a marked string, or None if it must be written literally.

        The single place that decides literal vs static vs session -- see
        :class:`DictStr` and :class:`SessionStr` for why the choice cannot be
        made by looking the text up.
        """
        if isinstance(value, SessionStr):
            return self._dict.session_id(value)
        if isinstance(value, DictStr):
            wire_id = self._dict.static_id(value)
            if wire_id is None:
                raise NbfxError(
                    f"DictStr({value!r}) is not in the static dictionary; "
                    "use SessionStr to intern it in the session instead"
                )
            return wire_id
        return None

    # -- elements ---------------------------------------------------------
    def start_element(self, prefix: str, name: str, namespace: str | None = None) -> None:
        """Open an element.

        If ``namespace`` is given and ``prefix`` is not already bound to it in
        an enclosing scope, an xmlns record is emitted straight after the
        element record -- which is exactly where it sits on the wire.  Pass
        ``namespace=None`` to manage declarations yourself with :meth:`xmlns`.
        """
        self._flush_xmlns()
        self._flush_text()
        wire_id = self._wire_id(name)
        pidx = _prefix_index(prefix)

        if wire_id is not None:
            if not prefix:
                self._byte(records.SHORT_DICTIONARY_ELEMENT)
            elif pidx is not None:
                self._byte(records.PREFIX_DICTIONARY_ELEMENT_A + pidx)
            else:
                self._byte(records.DICTIONARY_ELEMENT)
                self._string(prefix)
            self._raw(encode_multibyte_int31(wire_id))
        else:
            if not prefix:
                self._byte(records.SHORT_ELEMENT)
            elif pidx is not None:
                self._byte(records.PREFIX_ELEMENT_A + pidx)
            else:
                self._byte(records.ELEMENT)
                self._string(prefix)
            self._string(name)

        self._depth += 1
        self._scopes.append({})

        if namespace is not None and self._in_scope(prefix) != namespace:
            self.xmlns(prefix, namespace)

    def end_element(self) -> None:
        if self._depth == 0:
            raise NbfxError("end_element with no open element")
        self._flush_xmlns()
        if not self._flush_text(merge_end=True):
            self._byte(records.END_ELEMENT)
        self._depth -= 1
        self._scopes.pop()

    # -- namespaces and attributes ----------------------------------------
    def xmlns(self, prefix: str, namespace: str) -> None:
        """Declare ``xmlns:prefix="namespace"`` (or the default ns if no prefix).

        Queued rather than written immediately -- see ``_pending_xmlns``.
        """
        self._bind(prefix, str(namespace))
        self._pending_xmlns.append((prefix, namespace))

    def _emit_xmlns(self, prefix: str, namespace: str) -> None:
        wire_id = self._wire_id(namespace)

        if wire_id is not None:
            if prefix:
                self._byte(records.DICTIONARY_XMLNS_ATTRIBUTE)
                self._string(prefix)
            else:
                self._byte(records.SHORT_DICTIONARY_XMLNS_ATTRIBUTE)
            self._raw(encode_multibyte_int31(wire_id))
        else:
            if prefix:
                self._byte(records.XMLNS_ATTRIBUTE)
                self._string(prefix)
            else:
                self._byte(records.SHORT_XMLNS_ATTRIBUTE)
            self._string(namespace)

    def attribute(
        self, prefix: str, name: str, value: object = None, namespace: str | None = None
    ) -> None:
        """Emit an attribute record.

        The value is written as a normal text record immediately after, so
        ``value`` accepts the same types as :meth:`value`.  Pass ``value=None``
        to write the attribute header only and supply the text yourself.
        """
        self._flush_text()
        if namespace is not None and prefix and self._in_scope(prefix) != namespace:
            self.xmlns(prefix, namespace)

        wire_id = self._wire_id(name)
        pidx = _prefix_index(prefix)

        if wire_id is not None:
            if not prefix:
                self._byte(records.SHORT_DICTIONARY_ATTRIBUTE)
            elif pidx is not None:
                self._byte(records.PREFIX_DICTIONARY_ATTRIBUTE_A + pidx)
            else:
                self._byte(records.DICTIONARY_ATTRIBUTE)
                self._string(prefix)
            self._raw(encode_multibyte_int31(wire_id))
        else:
            if not prefix:
                self._byte(records.SHORT_ATTRIBUTE)
            elif pidx is not None:
                self._byte(records.PREFIX_ATTRIBUTE_A + pidx)
            else:
                self._byte(records.ATTRIBUTE)
                self._string(prefix)
            self._string(name)

        if value is not None:
            self._in_attribute = True
            try:
                self.value(value)
            finally:
                self._in_attribute = False

    # -- text records -----------------------------------------------------
    def _text(self, record: int, payload: bytes = b"") -> None:
        """Emit or queue a text record.

        Content text is held back until the next structural record so it can be
        merged into the WithEndElement form.  An *attribute* value is written
        straight out -- merging there would close the element early.
        """
        if not self._in_attribute:
            self._flush_xmlns()
        self._flush_text()
        if self._in_attribute:
            self._byte(record)
            self._raw(payload)
        else:
            self._pending = (record, payload)

    def value(self, value: object) -> None:
        """Write ``value`` using the most compact record its type allows.

        Type dispatch is deliberate rather than clever: generated code should
        prefer the explicit ``write_*`` methods, because the XSD type -- not the
        Python type -- decides the record WCF expects.
        """
        if value is None:
            self._text(records.EMPTY_TEXT)
        elif isinstance(value, bool):
            self.write_bool(value)
        elif isinstance(value, int):
            self.write_int(value)
        elif isinstance(value, float):
            self.write_double(value)
        elif isinstance(value, str):
            self.write_string(value)
        elif isinstance(value, (bytes, bytearray)):
            self.write_bytes(bytes(value))
        elif isinstance(value, _dt.datetime):
            self.write_datetime(value)
        elif isinstance(value, _dt.date):
            self.write_datetime(
                _dt.datetime(value.year, value.month, value.day),
            )
        elif isinstance(value, _uuid.UUID):
            self.write_uuid(value)
        else:
            raise NbfxError(f"no text record for {type(value).__name__}")

    def write_string(self, value: str) -> None:
        if isinstance(value, (DictStr, SessionStr)):
            self.write_dictionary_string(value)
            return
        if value == "":
            self._text(records.EMPTY_TEXT)
            return

        encoded = value.encode("utf-8")
        size = len(encoded)
        if size <= 0xFF:
            head = struct.pack("<B", size)
            record = records.CHARS8_TEXT
        elif size <= 0xFFFF:
            head = struct.pack("<H", size)
            record = records.CHARS16_TEXT
        else:
            head = struct.pack("<I", size)
            record = records.CHARS32_TEXT
        self._text(record, head + encoded)

    def write_dictionary_string(self, value: str) -> None:
        """Write ``value`` as a DictionaryText record."""
        wire_id = self._wire_id(value)
        if wire_id is None:
            raise NbfxError(
                f"{value!r} is a plain str; wrap it in DictStr or SessionStr "
                "to write it as a dictionary reference"
            )
        self._text(records.DICTIONARY_TEXT, encode_multibyte_int31(wire_id))

    def write_bool(self, value: bool) -> None:
        self._text(records.TRUE_TEXT if value else records.FALSE_TEXT)

    def write_int(self, value: int) -> None:
        """Smallest signed integer record that fits, matching WCF's choice."""
        if value == 0:
            self._text(records.ZERO_TEXT)
        elif value == 1:
            self._text(records.ONE_TEXT)
        elif -0x80 <= value <= 0x7F:
            self._text(records.INT8_TEXT, struct.pack("<b", value))
        elif -0x8000 <= value <= 0x7FFF:
            self._text(records.INT16_TEXT, struct.pack("<h", value))
        elif -0x8000_0000 <= value <= 0x7FFF_FFFF:
            self._text(records.INT32_TEXT, struct.pack("<i", value))
        elif -(1 << 63) <= value < (1 << 63):
            self._text(records.INT64_TEXT, struct.pack("<q", value))
        elif 0 <= value < (1 << 64):
            self._text(records.UINT64_TEXT, struct.pack("<Q", value))
        else:
            raise NbfxError(f"integer out of range for any text record: {value}")

    def write_float(self, value: float) -> None:
        self._text(records.FLOAT_TEXT, struct.pack("<f", value))

    def write_double(self, value: float) -> None:
        """Write a double the way WCF does -- narrowing wherever it is lossless.

        .NET does not blindly emit eight bytes: an integral value goes out
        through the integer ladder (``2.0`` becomes Int8Text), and a value that
        survives a round trip through float32 becomes FloatText.  Only when
        neither holds does it fall back to DoubleText.
        """
        if _math.isfinite(value):
            if value.is_integer() and -(1 << 63) <= value < (1 << 63):
                self.write_int(int(value))
                return
            try:
                narrowed = struct.pack("<f", value)
            except OverflowError:
                narrowed = None  # magnitude exceeds float32 entirely
            if narrowed is not None and struct.unpack("<f", narrowed)[0] == value:
                self._text(records.FLOAT_TEXT, narrowed)
                return
        self._text(records.DOUBLE_TEXT, struct.pack("<d", value))

    def write_bytes(self, value: bytes) -> None:
        size = len(value)
        if size <= 0xFF:
            head, record = struct.pack("<B", size), records.BYTES8_TEXT
        elif size <= 0xFFFF:
            head, record = struct.pack("<H", size), records.BYTES16_TEXT
        else:
            head, record = struct.pack("<I", size), records.BYTES32_TEXT
        self._text(record, head + value)

    def write_uuid(self, value: _uuid.UUID) -> None:
        self._text(records.UUID_TEXT, value.bytes_le)

    def write_unique_id(self, value: _uuid.UUID) -> None:
        """A ``urn:uuid:`` UniqueId -- how WS-Addressing MessageIDs are sent."""
        self._text(records.UNIQUE_ID_TEXT, value.bytes_le)

    def write_timespan(self, value: _dt.timedelta) -> None:
        ticks = _to_ticks(value)
        self._text(records.TIMESPAN_TEXT, struct.pack("<q", ticks))

    def write_datetime(
        self, value: _dt.datetime, *, kind: int | None = None
    ) -> None:
        """Write a .NET ``DateTime``: 8 bytes little-endian, ``ticks | kind << 62``.

        ``kind`` is 0 Unspecified, 1 UTC, 2 Local.  It defaults to UTC for
        aware datetimes and Unspecified for naive ones -- which is what you
        want for X++ date fields, since emitting Local makes the server shift
        the value by the timezone offset and silently store the wrong day.
        """
        if kind is None:
            kind = 1 if value.tzinfo is not None else 0
        if kind == 1 and value.tzinfo is not None:
            value = value.astimezone(_dt.timezone.utc)
        naive = value.replace(tzinfo=None)

        ticks = _to_ticks(naive - _NET_EPOCH)
        if not 0 <= ticks < (1 << 62):
            raise NbfxError(f"datetime out of .NET DateTime range: {value!r}")

        self._text(
            records.DATETIME_TEXT,
            struct.pack("<Q", ticks | (kind << 62)),
        )


_NET_EPOCH = _dt.datetime(1, 1, 1)


def _to_ticks(delta: _dt.timedelta) -> int:
    """timedelta -> .NET ticks (100 ns units), in exact integer arithmetic.

    Done by hand rather than via ``delta / timedelta(...)`` because a tick is
    finer than timedelta's microsecond resolution, so the obvious division
    silently truncates to zero.
    """
    return (delta.days * 86_400 + delta.seconds) * 10_000_000 + delta.microseconds * 10


def _from_ticks(ticks: int) -> _dt.datetime:
    """.NET ticks -> datetime. Sub-microsecond precision is not representable."""
    return _NET_EPOCH + _dt.timedelta(microseconds=ticks // 10)


# --------------------------------------------------------------------------
# Reader
# --------------------------------------------------------------------------
class BinaryXmlReader:
    """Decoder producing a flat event stream.

    Events are tuples, chosen to be directly comparable in tests::

        ("start", prefix, name)
        ("xmlns", prefix, namespace)
        ("attr",  prefix, name)
        ("text",  value)
        ("end",)
    """

    def __init__(self, data: bytes, dictionary: Dictionary | None = None) -> None:
        self._data = data
        self._pos = 0
        self._dict: Dictionary = dictionary if dictionary is not None else StaticDictionary()

    # -- primitives -------------------------------------------------------
    def _take(self, count: int) -> bytes:
        end = self._pos + count
        if end > len(self._data):
            raise NbfxError(f"truncated record: wanted {count} bytes at {self._pos}")
        chunk = self._data[self._pos:end]
        self._pos = end
        return chunk

    def _u8(self) -> int:
        return self._take(1)[0]

    def _varint(self) -> int:
        value, self._pos = decode_multibyte_int31(self._data, self._pos)
        return value

    def _string(self) -> str:
        return self._take(self._varint()).decode("utf-8")

    def _dict_string(self) -> str:
        return self._dict.lookup(self._varint())

    # -- driver -----------------------------------------------------------
    def read(self) -> list[tuple]:
        events: list[tuple] = []
        while self._pos < len(self._data):
            events.extend(self._record())
        return events

    def _record(self) -> list[tuple]:
        record = self._u8()

        if record == records.END_ELEMENT:
            return [("end",)]
        if record == records.COMMENT:
            return [("comment", self._string())]
        if record == records.ARRAY:
            return self._array()

        # Elements -------------------------------------------------------
        if record == records.SHORT_ELEMENT:
            return [("start", "", self._string())]
        if record == records.ELEMENT:
            prefix = self._string()
            return [("start", prefix, self._string())]
        if record == records.SHORT_DICTIONARY_ELEMENT:
            return [("start", "", self._dict_string())]
        if record == records.DICTIONARY_ELEMENT:
            prefix = self._string()
            return [("start", prefix, self._dict_string())]
        if records.PREFIX_DICTIONARY_ELEMENT_A <= record <= records.PREFIX_DICTIONARY_ELEMENT_A + 25:
            prefix = chr(_A + record - records.PREFIX_DICTIONARY_ELEMENT_A)
            return [("start", prefix, self._dict_string())]
        if records.PREFIX_ELEMENT_A <= record <= records.PREFIX_ELEMENT_A + 25:
            prefix = chr(_A + record - records.PREFIX_ELEMENT_A)
            return [("start", prefix, self._string())]

        # Namespace declarations ------------------------------------------
        if record == records.SHORT_XMLNS_ATTRIBUTE:
            return [("xmlns", "", self._string())]
        if record == records.XMLNS_ATTRIBUTE:
            prefix = self._string()
            return [("xmlns", prefix, self._string())]
        if record == records.SHORT_DICTIONARY_XMLNS_ATTRIBUTE:
            return [("xmlns", "", self._dict_string())]
        if record == records.DICTIONARY_XMLNS_ATTRIBUTE:
            prefix = self._string()
            return [("xmlns", prefix, self._dict_string())]

        # Attributes ------------------------------------------------------
        if record == records.SHORT_ATTRIBUTE:
            return [("attr", "", self._string())]
        if record == records.ATTRIBUTE:
            prefix = self._string()
            return [("attr", prefix, self._string())]
        if record == records.SHORT_DICTIONARY_ATTRIBUTE:
            return [("attr", "", self._dict_string())]
        if record == records.DICTIONARY_ATTRIBUTE:
            prefix = self._string()
            return [("attr", prefix, self._dict_string())]
        if records.PREFIX_DICTIONARY_ATTRIBUTE_A <= record <= records.PREFIX_DICTIONARY_ATTRIBUTE_A + 25:
            prefix = chr(_A + record - records.PREFIX_DICTIONARY_ATTRIBUTE_A)
            return [("attr", prefix, self._dict_string())]
        if records.PREFIX_ATTRIBUTE_A <= record <= records.PREFIX_ATTRIBUTE_A + 25:
            prefix = chr(_A + record - records.PREFIX_ATTRIBUTE_A)
            return [("attr", prefix, self._string())]

        # Text -------------------------------------------------------------
        if record >= records.ZERO_TEXT:
            base = record & ~records.WITH_END_ELEMENT
            events = [("text", self._text_value(base))]
            if record & records.WITH_END_ELEMENT:
                events.append(("end",))
            return events

        raise NbfxError(f"unknown record type 0x{record:02X} at offset {self._pos - 1}")

    def _text_value(self, base: int) -> object:
        if base == records.ZERO_TEXT:
            return 0
        if base == records.ONE_TEXT:
            return 1
        if base == records.FALSE_TEXT:
            return False
        if base == records.TRUE_TEXT:
            return True
        if base == records.EMPTY_TEXT:
            return ""
        if base == records.INT8_TEXT:
            return struct.unpack("<b", self._take(1))[0]
        if base == records.INT16_TEXT:
            return struct.unpack("<h", self._take(2))[0]
        if base == records.INT32_TEXT:
            return struct.unpack("<i", self._take(4))[0]
        if base == records.INT64_TEXT:
            return struct.unpack("<q", self._take(8))[0]
        if base == records.UINT64_TEXT:
            return struct.unpack("<Q", self._take(8))[0]
        if base == records.FLOAT_TEXT:
            return struct.unpack("<f", self._take(4))[0]
        if base == records.DOUBLE_TEXT:
            return struct.unpack("<d", self._take(8))[0]
        if base == records.BOOL_TEXT:
            return bool(self._take(1)[0])
        if base == records.CHARS8_TEXT:
            return self._take(self._take(1)[0]).decode("utf-8")
        if base == records.CHARS16_TEXT:
            return self._take(struct.unpack("<H", self._take(2))[0]).decode("utf-8")
        if base == records.CHARS32_TEXT:
            return self._take(struct.unpack("<I", self._take(4))[0]).decode("utf-8")
        if base == records.UNICODE_CHARS8_TEXT:
            return self._take(self._take(1)[0]).decode("utf-16-le")
        if base == records.UNICODE_CHARS16_TEXT:
            return self._take(struct.unpack("<H", self._take(2))[0]).decode("utf-16-le")
        if base == records.UNICODE_CHARS32_TEXT:
            return self._take(struct.unpack("<I", self._take(4))[0]).decode("utf-16-le")
        if base == records.BYTES8_TEXT:
            return self._take(self._take(1)[0])
        if base == records.BYTES16_TEXT:
            return self._take(struct.unpack("<H", self._take(2))[0])
        if base == records.BYTES32_TEXT:
            return self._take(struct.unpack("<I", self._take(4))[0])
        if base == records.DICTIONARY_TEXT:
            return self._dict_string()
        if base in (records.UUID_TEXT, records.UNIQUE_ID_TEXT):
            return _uuid.UUID(bytes_le=self._take(16))
        if base == records.TIMESPAN_TEXT:
            return _dt.timedelta(microseconds=struct.unpack("<q", self._take(8))[0] // 10)
        if base == records.DATETIME_TEXT:
            raw = struct.unpack("<Q", self._take(8))[0]
            return _from_ticks(raw & ((1 << 62) - 1))
        if base == records.DECIMAL_TEXT:
            return _decode_decimal(self._take(16))
        if base == records.START_LIST_TEXT:
            return _LIST_START
        if base == records.END_LIST_TEXT:
            return _LIST_END
        if base == records.QNAME_DICTIONARY_TEXT:
            prefix = chr(_A + self._u8())
            return f"{prefix}:{self._dict_string()}"

        raise NbfxError(f"unhandled text record 0x{base:02X}")

    def _array(self) -> list[tuple]:
        """Array record: element template, EndElement, value record, count, values."""
        events = self._record()  # the element record being repeated
        terminator = self._u8()
        if terminator != records.END_ELEMENT:
            raise NbfxError("array template must be followed by EndElement")
        value_record = self._u8() & ~records.WITH_END_ELEMENT
        count = self._varint()

        template = events[0]
        out: list[tuple] = []
        for _ in range(count):
            out.append(template)
            out.append(("text", self._text_value(value_record)))
            out.append(("end",))
        return out


_LIST_START = object()
_LIST_END = object()


def _decode_decimal(raw: bytes) -> str:
    """.NET ``decimal``: flags, hi, lo, mid (each little-endian uint32).

    Returned as a string so no precision is lost through float.
    """
    flags, hi, lo, mid = struct.unpack("<IIII", raw)
    scale = (flags >> 16) & 0xFF
    negative = bool(flags & 0x8000_0000)
    magnitude = (hi << 64) | (mid << 32) | lo

    digits = str(magnitude).rjust(scale + 1, "0")
    text = f"{digits[:len(digits) - scale]}.{digits[len(digits) - scale:]}" if scale else digits
    return f"-{text}" if negative else text
