"""SOAP 1.2 + WS-Addressing 1.0 envelopes, shaped the way WCF writes them.

``NetTcpBinding`` defaults to SOAP 1.2 with WS-Addressing 10, so a request is::

    <s:Envelope xmlns:s="...soap-envelope" xmlns:a="...ws/2005/08/addressing">
      <s:Header>
        <a:Action s:mustUnderstand="1">urn:Service/Operation</a:Action>
        <a:To     s:mustUnderstand="1">net.tcp://host:port/Path</a:To>
      </s:Header>
      <s:Body> ... </s:Body>
    </s:Envelope>

Every name here comes from ``ServiceModelDictionary``, so all of it is written
with :class:`~pynettcp.nbfx.DictStr` and costs one or two bytes on the wire.
Body content comes from the data contract instead, so it uses
:class:`~pynettcp.nbfx.SessionStr` -- see that class for why the distinction
cannot be inferred.

Header order matters for byte-comparison against WCF: Action then To.
"""

from __future__ import annotations

import uuid as _uuid
from typing import Callable, Iterable

from .nbfx import BinaryXmlWriter, DictStr

__all__ = [
    "SOAP12_NS",
    "WSA10_NS",
    "SOAP_PREFIX",
    "WSA_PREFIX",
    "write_envelope",
    "parse_envelope",
    "Envelope",
]

SOAP12_NS = DictStr("http://www.w3.org/2003/05/soap-envelope")
WSA10_NS = DictStr("http://www.w3.org/2005/08/addressing")
WSA10_ANONYMOUS = DictStr("http://www.w3.org/2005/08/addressing/anonymous")

SOAP_PREFIX = "s"
WSA_PREFIX = "a"

_ENVELOPE = DictStr("Envelope")
_HEADER = DictStr("Header")
_BODY = DictStr("Body")
_ACTION = DictStr("Action")
_TO = DictStr("To")
_MESSAGE_ID = DictStr("MessageID")
_REPLY_TO = DictStr("ReplyTo")
_ADDRESS = DictStr("Address")
_MUST_UNDERSTAND = DictStr("mustUnderstand")

#: A body writer receives the live writer and emits the payload elements.
BodyWriter = Callable[[BinaryXmlWriter], None]


def _addressing_header(writer: BinaryXmlWriter, name: DictStr, value: str) -> None:
    """One ``<a:Name s:mustUnderstand="1">value</a:Name>`` header."""
    writer.start_element(WSA_PREFIX, name, WSA10_NS)
    writer.attribute(SOAP_PREFIX, _MUST_UNDERSTAND, 1, namespace=SOAP12_NS)
    writer.value(value)
    writer.end_element()


def write_envelope(
    writer: BinaryXmlWriter,
    *,
    action: str,
    to: str,
    body: BodyWriter | None = None,
    message_id: _uuid.UUID | None = None,
    reply_to_anonymous: bool = False,
    headers: Iterable[BodyWriter] = (),
) -> None:
    """Write a complete request envelope.

    ``headers`` are extra header writers -- this is where service-specific
    headers go, such as a Dynamics ``CallContext``, which is a SOAP header
    rather than a body parameter.

    ``message_id`` and ``reply_to_anonymous`` are off by default because WCF
    omits them for a plain request/reply operation over a session; turn them
    on only when the contract needs them.
    """
    writer.start_element(SOAP_PREFIX, _ENVELOPE, SOAP12_NS)
    # Declared up front on the envelope, as WCF does, so every later header
    # and the Body reuse the same two prefixes.
    writer.xmlns(WSA_PREFIX, WSA10_NS)

    writer.start_element(SOAP_PREFIX, _HEADER, SOAP12_NS)
    _addressing_header(writer, _ACTION, action)

    if message_id is not None:
        writer.start_element(WSA_PREFIX, _MESSAGE_ID, WSA10_NS)
        writer.write_unique_id(message_id)
        writer.end_element()

    if reply_to_anonymous:
        writer.start_element(WSA_PREFIX, _REPLY_TO, WSA10_NS)
        writer.start_element(WSA_PREFIX, _ADDRESS, WSA10_NS)
        writer.value(WSA10_ANONYMOUS)
        writer.end_element()
        writer.end_element()

    _addressing_header(writer, _TO, to)

    for write_header in headers:
        write_header(writer)

    writer.end_element()  # Header

    writer.start_element(SOAP_PREFIX, _BODY, SOAP12_NS)
    if body is not None:
        body(writer)
    writer.end_element()  # Body

    writer.end_element()  # Envelope


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
class Envelope:
    """A decoded envelope: addressing headers plus the Body event slice.

    Kept as raw events rather than a tree because deserialisation is driven by
    the contract, which only the generated client knows.
    """

    __slots__ = ("action", "to", "relates_to", "header_events", "body_events")

    def __init__(
        self,
        action: str | None,
        to: str | None,
        relates_to: object,
        header_events: list[tuple],
        body_events: list[tuple],
    ) -> None:
        self.action = action
        self.to = to
        self.relates_to = relates_to
        self.header_events = header_events
        self.body_events = body_events

    @property
    def is_fault(self) -> bool:
        return any(
            event[0] == "start" and event[2] == "Fault" for event in self.body_events
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"Envelope(action={self.action!r}, is_fault={self.is_fault}, "
            f"body_events={len(self.body_events)})"
        )


def parse_envelope(events: list[tuple]) -> Envelope:
    """Split a decoded event stream into headers and body.

    Works on depth rather than on names, so unexpected headers pass through
    untouched instead of throwing the split off.
    """
    depth = 0
    header_events: list[tuple] = []
    body_events: list[tuple] = []
    section: str | None = None
    section_depth = 0

    action = to = None
    relates_to = None
    current_header: str | None = None

    for event in events:
        kind = event[0]

        if kind == "start":
            name = event[2]
            depth += 1
            if section is None and depth == 2 and name in ("Header", "Body"):
                section = name
                section_depth = depth
                continue
            if section == "Header" and depth == section_depth + 1:
                current_header = name
        elif kind == "end":
            if section is not None and depth == section_depth:
                section = None
                depth -= 1
                continue
            if section == "Header" and depth == section_depth + 1:
                current_header = None
            depth -= 1
        elif kind == "text" and section == "Header":
            if current_header == "Action":
                action = event[1]
            elif current_header == "To":
                to = event[1]
            elif current_header == "RelatesTo":
                relates_to = event[1]

        if section == "Header":
            header_events.append(event)
        elif section == "Body":
            body_events.append(event)

    return Envelope(action, to, relates_to, header_events, body_events)
