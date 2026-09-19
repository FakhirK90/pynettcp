"""Turn a decoded NBFX event stream into a standard ElementTree.

The codec deliberately produces a flat event stream rather than a tree, because
deserialising a message body is driven by its contract.  Metadata is the
exception: a WSDL really is a document, and every XML tool expects a tree.

Uses ``xml.etree`` from the standard library, so reading metadata pulls in no
third-party dependency.

Namespaces need a second pass.  NBFX writes an element record *before* the
xmlns records that bind its prefix::

    ("start", "s", "Envelope")        <- prefix not yet bound
    ("xmlns", "s", "http://...")      <- binding arrives here

so the tree is built as prefixed nodes first and qualified afterwards, once
every declaration in scope is known.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

__all__ = ["events_to_element", "events_to_string"]

_XML_NS = "http://www.w3.org/XML/1998/namespace"


class _Node:
    __slots__ = ("prefix", "name", "namespaces", "attributes", "children", "text")

    def __init__(self, prefix: str, name: str) -> None:
        self.prefix = prefix
        self.name = name
        self.namespaces: list[tuple[str, str]] = []
        self.attributes: list[tuple[str, str, object]] = []
        self.children: list["_Node"] = []
        self.text: list[str] = []


def _build(events: list[tuple]) -> list[_Node]:
    """First pass: a prefixed tree, no namespace resolution yet."""
    roots: list[_Node] = []
    stack: list[_Node] = []
    pending_attribute: tuple[str, str] | None = None

    for event in events:
        kind = event[0]
        current = stack[-1] if stack else None

        if kind == "start":
            node = _Node(event[1], event[2])
            if current is None:
                roots.append(node)
            else:
                current.children.append(node)
            stack.append(node)
            pending_attribute = None

        elif kind == "end":
            if stack:
                stack.pop()
            pending_attribute = None

        elif kind == "xmlns":
            if current is not None:
                current.namespaces.append((event[1], event[2]))

        elif kind == "attr":
            pending_attribute = (event[1], event[2])

        elif kind == "text":
            if current is None:
                continue
            if pending_attribute is not None:
                prefix, name = pending_attribute
                current.attributes.append((prefix, name, event[1]))
                pending_attribute = None
            elif event[1] is not None:
                current.text.append(_as_text(event[1]))

    return roots


def _as_text(value: object) -> str:
    """Render a typed text record the way its XML equivalent would read."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (bytes, bytearray)):
        import base64

        return base64.b64encode(bytes(value)).decode("ascii")
    return str(value)


def _qualify(name: str, prefix: str, scopes: list[dict[str, str]], *, is_attribute: bool) -> str:
    """Resolve a prefixed name to ``{namespace}local``.

    An unprefixed *attribute* has no namespace -- that is an XML rule, not an
    oversight; only elements pick up the default declaration.
    """
    if not prefix and is_attribute:
        return name

    for scope in reversed(scopes):
        if prefix in scope:
            namespace = scope[prefix]
            return f"{{{namespace}}}{name}" if namespace else name

    if prefix == "xml":
        return f"{{{_XML_NS}}}{name}"
    return name if not prefix else f"{prefix}:{name}"


def _convert(node: _Node, scopes: list[dict[str, str]]) -> ET.Element:
    scopes.append(dict(node.namespaces))
    try:
        element = ET.Element(_qualify(node.name, node.prefix, scopes, is_attribute=False))

        for prefix, name, value in node.attributes:
            element.set(_qualify(name, prefix, scopes, is_attribute=True), _as_text(value))

        if node.text:
            element.text = "".join(node.text)

        for child in node.children:
            element.append(_convert(child, scopes))

        return element
    finally:
        scopes.pop()


def events_to_element(events: list[tuple]) -> ET.Element | None:
    """Convert an event stream to a single root element.

    Returns None when the stream has no elements -- an empty SOAP body, say.
    If several roots are present (a Body holding more than one child) they are
    wrapped so nothing is silently dropped.
    """
    roots = _build(events)
    if not roots:
        return None

    base: list[dict[str, str]] = [{"xml": _XML_NS}]
    if len(roots) == 1:
        return _convert(roots[0], base)

    wrapper = ET.Element("fragments")
    for root in roots:
        wrapper.append(_convert(root, base))
    return wrapper


def events_to_string(events: list[tuple]) -> str:
    """Serialise an event stream back to XML text -- mainly a debugging aid."""
    element = events_to_element(events)
    return "" if element is None else ET.tostring(element, encoding="unicode")
