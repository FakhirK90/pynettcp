"""SOAP 1.2 fault parsing.

A fault is not an error string -- it is a structured document, and the useful
part is usually the ``Detail`` element rather than the human-readable reason::

    <s:Fault>
      <s:Code><s:Value>s:Sender</s:Value></s:Code>
      <s:Reason><s:Text xml:lang="en-US">order failed validation</s:Text></s:Reason>
      <s:Detail>
        <ValidationFault>
          <Code>INVALID</Code>
          <Problems><string>order has no lines</string></Problems>
        </ValidationFault>
      </s:Detail>
    </s:Fault>

Scraping every text out of that gives a caller a pile of fragments; keeping the
structure lets a generated client hand back the fault's own contract type, so
``except ServiceFault as e: e.detail.Problems`` works.

One wrinkle worth knowing: a QName like ``s:Sender`` arrives as *three* text
events -- ``'s'``, ``':'``, ``'Sender'`` -- because the encoder writes the
prefix, the colon and the local name as separate records. Adjacent text is
therefore joined rather than taken one event at a time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["SoapFault", "parse_fault", "FAULT_ELEMENT"]

FAULT_ELEMENT = "Fault"


@dataclass
class SoapFault:
    """A decoded SOAP 1.2 fault."""

    code: str | None = None
    subcode: str | None = None
    reason: str | None = None
    #: Name of the element inside ``Detail``, e.g. ``ValidationFault``.
    detail_name: str | None = None
    #: The detail element's own events, ready for ``contract.read_element``.
    detail_events: list[tuple] = field(default_factory=list)

    @property
    def is_sender_fault(self) -> bool:
        """True when the service blamed the request rather than itself."""
        return bool(self.code) and self.code.rsplit(":", 1)[-1] == "Sender"

    def __str__(self) -> str:  # pragma: no cover - presentation only
        parts = [self.reason or "SOAP fault"]
        if self.code:
            parts.append(f"[{self.code}]")
        if self.detail_name:
            parts.append(f"detail={self.detail_name}")
        return " ".join(parts)


def _section(events: list[tuple], start: int) -> tuple[list[tuple], int]:
    """Return the events of the element opening at ``start``, and the index after it."""
    depth = 0
    for index in range(start, len(events)):
        kind = events[index][0]
        if kind == "start":
            depth += 1
        elif kind == "end":
            depth -= 1
            if depth == 0:
                return events[start:index + 1], index + 1
    return events[start:], len(events)


def _joined_text(events: list[tuple]) -> str | None:
    """Element text in a subtree, concatenated -- QNames arrive in pieces.

    A text event directly after an ``attr`` event is that attribute's value,
    not content. Skipping it matters here: ``Reason/Text`` carries
    ``xml:lang="en-US"``, which would otherwise be glued onto the front of
    every fault message.
    """
    parts = []
    previous_was_attribute = False
    for event in events:
        if event[0] == "attr":
            previous_was_attribute = True
            continue
        if event[0] == "text":
            if not previous_was_attribute and isinstance(event[1], str):
                parts.append(event[1])
        previous_was_attribute = False
    return "".join(parts) if parts else None


def _find_child(events: list[tuple], name: str) -> list[tuple] | None:
    """Events of the first direct child element called ``name``.

    ``events`` must be a whole element, i.e. start ... end.
    """
    index, depth = 1, 0
    while index < len(events) - 1:
        kind = events[index][0]
        if kind == "start":
            if depth == 0 and events[index][2] == name:
                section, _ = _section(events, index)
                return section
            section, index = _section(events, index)
            continue
        index += 1
    return None


def parse_fault(body_events: list[tuple]) -> SoapFault | None:
    """Parse the ``Fault`` in a decoded SOAP body, or None if there is none."""
    start = next(
        (
            index
            for index, event in enumerate(body_events)
            if event[0] == "start" and event[2] == FAULT_ELEMENT
        ),
        None,
    )
    if start is None:
        return None

    fault_events, _ = _section(body_events, start)
    fault = SoapFault()

    code = _find_child(fault_events, "Code")
    if code is not None:
        value = _find_child(code, "Value")
        fault.code = _joined_text(value) if value else None

        subcode = _find_child(code, "Subcode")
        if subcode is not None:
            subvalue = _find_child(subcode, "Value")
            fault.subcode = _joined_text(subvalue) if subvalue else None

    reason = _find_child(fault_events, "Reason")
    if reason is not None:
        text = _find_child(reason, "Text")
        fault.reason = _joined_text(text) if text else None

    detail = _find_child(fault_events, "Detail")
    if detail is not None:
        # The detail carries a single application-defined element.
        for index in range(1, len(detail) - 1):
            if detail[index][0] == "start":
                section, _ = _section(detail, index)
                fault.detail_name = detail[index][2]
                fault.detail_events = section
                break

    return fault
