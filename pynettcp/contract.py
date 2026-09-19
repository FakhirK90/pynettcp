"""Declarative message contracts -- the runtime the generated clients drive.

Code generation emits *data*, not imperative serialisation code: a table of
:class:`ElementSpec` and :class:`Field` objects that this module walks.  When a
byte comes out wrong, the fix is here and applies to every generated client,
rather than in the generator where it would have to be regenerated to take
effect.

Two details of how WCF's ``DataContractSerializer`` puts a body on the wire:

* Contract-derived names are session-dictionary strings, never static ones.
  Everything written here is wrapped in :class:`~pynettcp.nbfx.SessionStr` --
  see that class for why the distinction cannot be inferred from the text.
* An absent value is not an empty element.  A nillable field is sent as
  ``xsi:nil="true"``; a non-nillable optional field is omitted entirely.
"""

from __future__ import annotations

import datetime as _dt
import decimal as _decimal
import keyword as _keyword
import re as _re
from dataclasses import dataclass, field as _dataclass_field
from typing import Any, Callable

from .nbfx import BinaryXmlWriter, DictStr, SessionStr

__all__ = [
    "Field",
    "ElementSpec",
    "HeaderSpec",
    "ComplexType",
    "TypeRegistry",
    "XSI_NS",
    "write_element",
    "write_header",
    "header_writers",
    "read_element",
    "python_type_name",
    "python_identifier",
]

XSI_NS = SessionStr("http://www.w3.org/2001/XMLSchema-instance")
XSI_PREFIX = "i"

_NON_IDENTIFIER = _re.compile(r"\W|^(?=\d)")


def python_identifier(name: str) -> str:
    """A safe Python identifier for an XML name, preserving it where possible.

    Lives here rather than in the generator because *both* sides need the same
    answer: the generator names the dataclass attribute, and this module has to
    find that attribute again from the wire name.  When they disagreed, a field
    called ``Order-Id`` or ``class`` was silently dropped on the way out and
    raised ``TypeError`` on the way back in.
    """
    identifier = _NON_IDENTIFIER.sub("_", name)
    return f"{identifier}_" if _keyword.iskeyword(identifier) else identifier

UNBOUNDED = -1


@dataclass(frozen=True)
class Field:
    """One child element of a complex type or message wrapper."""

    name: str
    type: str                  # an ``xs:*`` builtin or a complex type name
    min_occurs: int = 0
    max_occurs: int = 1        # UNBOUNDED for maxOccurs="unbounded"
    nillable: bool = False

    @property
    def repeats(self) -> bool:
        return self.max_occurs == UNBOUNDED or self.max_occurs > 1

    @property
    def required(self) -> bool:
        return self.min_occurs > 0


@dataclass(frozen=True)
class ComplexType:
    """A named complex type, i.e. a DataContract."""

    name: str
    namespace: str
    fields: tuple[Field, ...] = ()


@dataclass(frozen=True)
class ElementSpec:
    """A top-level element -- the wrapper around an operation's parameters."""

    name: str
    namespace: str
    fields: tuple[Field, ...] = ()


@dataclass(frozen=True)
class HeaderSpec:
    """A SOAP header attached to an operation.

    A header is declared in ``wsdl:binding`` rather than in the portType, so it
    never appears among the body parameters -- Dynamics ``CallContext`` is the
    obvious example, and a call omitting it is rejected.  Unlike a body field, a
    header is a whole element of a given type rather than a member of a wrapper.
    """

    name: str
    namespace: str
    type: str
    nillable: bool = False
    must_understand: bool = False


@dataclass
class TypeRegistry:
    """Complex types by name, plus how to build a Python object from a dict."""

    types: dict[str, ComplexType] = _dataclass_field(default_factory=dict)
    factories: dict[str, Callable[..., Any]] = _dataclass_field(default_factory=dict)

    def is_complex(self, type_name: str) -> bool:
        return type_name in self.types

    def build(self, type_name: str, values: dict) -> Any:
        """Build the contract object, keying by the factory's attribute names.

        ``values`` is keyed by wire name; a generated dataclass is keyed by the
        identifier form of it.  Translating here keeps every caller free of the
        distinction.
        """
        factory = self.factories.get(type_name)
        if factory is None:
            return values
        return factory(**{python_identifier(k): v for k, v in values.items()})


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------
_SCALAR_WRITERS: dict[str, str] = {
    "xs:string": "write_string",
    "xs:boolean": "write_bool",
    "xs:int": "write_int",
    "xs:integer": "write_int",
    "xs:long": "write_int",
    "xs:short": "write_int",
    "xs:byte": "write_int",
    "xs:unsignedInt": "write_int",
    "xs:unsignedLong": "write_int",
    "xs:unsignedShort": "write_int",
    "xs:unsignedByte": "write_int",
    "xs:double": "write_double",
    "xs:float": "write_double",
    "xs:dateTime": "write_datetime",
    "xs:date": "write_datetime",
    "xs:base64Binary": "write_bytes",
}


def _write_scalar(writer: BinaryXmlWriter, xsd_type: str, value: Any) -> None:
    """Write a value using the record its *schema* type implies.

    Driven by the XSD type rather than the Python type, because the two
    disagree in ways that matter: ``2`` for an ``xs:double`` must still go out
    as a number the server will read as a double, and a ``date`` has to become
    a .NET ``DateTime``.
    """
    method = _SCALAR_WRITERS.get(xsd_type)
    if method is None:
        # decimal, duration/TimeSpan, Guid and enum restrictions all travel as
        # their XSD lexical form.  Passing a Decimal or a timedelta straight to
        # ``value()`` used to raise NbfxError; convert instead.
        converted = _lexical(value)
        if isinstance(converted, str) and not isinstance(value, str):
            writer.write_string(converted)
        else:
            writer.value(converted)
        return

    if method == "write_datetime" and isinstance(value, _dt.date) and not isinstance(value, _dt.datetime):
        value = _dt.datetime(value.year, value.month, value.day)
    if method == "write_int" and isinstance(value, bool):
        value = int(value)
    if method == "write_string" and not isinstance(value, str):
        value = str(value)

    getattr(writer, method)(value)


def _write_lexical(writer: BinaryXmlWriter, value: Any) -> None:
    """Write a schema-text type, converting the natural Python object first."""
    writer.write_string(_lexical(value) if not isinstance(value, str) else value)


def _lexical(value: Any) -> Any:
    """Render the types WCF carries as schema text rather than typed records.

    ``decimal``, ``duration``/TimeSpan and ``Guid`` all reach the wire as their
    XSD lexical form, which DataContractSerializer parses.  Accepting the
    natural Python object and converting here means callers are not forced to
    pre-format them into strings.
    """
    if isinstance(value, _decimal.Decimal):
        return format(value, "f")
    if isinstance(value, _dt.timedelta):
        total = value.total_seconds()
        sign = "-" if total < 0 else ""
        return f"{sign}PT{abs(total):.7f}".rstrip("0").rstrip(".") + "S"
    return value


_MISSING = object()


def _field_value(source: Any, name: str) -> Any:
    """Read ``name`` off a dict or an object, by wire name or by attribute name.

    A generated dataclass stores ``Order-Id`` as ``Order_Id`` and ``class`` as
    ``class_``, so the wire name alone does not find it.
    """
    attribute = python_identifier(name)
    if isinstance(source, dict):
        value = source.get(name, _MISSING)
        if value is _MISSING and attribute != name:
            value = source.get(attribute, _MISSING)
        return None if value is _MISSING else value

    value = getattr(source, name, _MISSING)
    if value is _MISSING and attribute != name:
        value = getattr(source, attribute, _MISSING)
    return None if value is _MISSING else value


def _write_field(
    writer: BinaryXmlWriter,
    field: Field,
    value: Any,
    registry: TypeRegistry,
    namespace: str,
) -> None:
    """Write one field.

    ``namespace`` is the namespace of the type *declaring* this field.  Under
    ``elementFormDefault="qualified"`` a local element belongs to the schema it
    was declared in, which is not always the namespace of its own type -- WCF's
    dictionary contracts are exactly this case, with ``PropertyBag`` declared
    alongside ``CallContext`` but typed from the Arrays namespace.
    """
    element_name = SessionStr(field.name)

    if value is None:
        if field.nillable:
            writer.start_element("", element_name, SessionStr(namespace))
            writer.attribute(XSI_PREFIX, SessionStr("nil"), True, namespace=XSI_NS)
            writer.end_element()
        # A non-nillable optional field is simply left out.
        elif field.required:
            raise ValueError(f"field {field.name!r} is required but was None")
        return

    values = value if field.repeats and isinstance(value, (list, tuple)) else [value]
    for item in values:
        writer.start_element("", element_name, SessionStr(namespace))
        if registry.is_complex(field.type):
            complex_type = registry.types[field.type]
            # Children belong to the namespace of the type that declares them.
            _write_fields(
                writer, complex_type.fields, item, registry, complex_type.namespace or namespace
            )
        else:
            _write_scalar(writer, field.type, item)
        writer.end_element()


def _write_fields(
    writer: BinaryXmlWriter,
    fields: tuple[Field, ...],
    source: Any,
    registry: TypeRegistry,
    namespace: str,
) -> None:
    # Order follows xs:sequence: DataContractSerializer is order-sensitive.
    for field in fields:
        _write_field(writer, field, _field_value(source, field.name), registry, namespace)


def write_element(
    writer: BinaryXmlWriter, spec: ElementSpec, values: Any, registry: TypeRegistry
) -> None:
    """Write the message wrapper and its contents."""
    writer.start_element("", SessionStr(spec.name), SessionStr(spec.namespace))
    _write_fields(writer, spec.fields, values, registry, spec.namespace)
    writer.end_element()


def write_header(
    writer: BinaryXmlWriter, spec: HeaderSpec, value: Any, registry: TypeRegistry
) -> None:
    """Write one SOAP header element into the envelope's Header section."""
    writer.start_element("", SessionStr(spec.name), SessionStr(spec.namespace))

    if spec.must_understand:
        from .soap import SOAP12_NS, SOAP_PREFIX

        writer.attribute(SOAP_PREFIX, DictStr("mustUnderstand"), 1, namespace=SOAP12_NS)

    if value is None:
        writer.attribute(XSI_PREFIX, SessionStr("nil"), True, namespace=XSI_NS)
    elif registry.is_complex(spec.type):
        complex_type = registry.types[spec.type]
        _write_fields(
            writer, complex_type.fields, value, registry,
            complex_type.namespace or spec.namespace,
        )
    else:
        _write_scalar(writer, spec.type, value)

    writer.end_element()


def header_writers(
    specs: tuple[HeaderSpec, ...], values: dict[str, Any], registry: TypeRegistry
) -> list:
    """Build the header callables that :func:`pynettcp.soap.write_envelope` takes.

    Headers whose value is None are skipped entirely rather than sent as nil --
    an absent optional header and an explicitly null one are different things,
    and services that do not expect the header at all reject the nil form.
    """
    writers = []
    for spec in specs:
        value = values.get(spec.name)
        if value is None:
            continue
        writers.append(
            lambda writer, spec=spec, value=value: write_header(writer, spec, value, registry)
        )
    return writers


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def _tree(events: list[tuple]) -> list[dict]:
    """Group a flat event stream into nested nodes."""
    roots: list[dict] = []
    stack: list[dict] = []
    pending_attribute: str | None = None

    for event in events:
        kind = event[0]
        current = stack[-1] if stack else None

        if kind == "start":
            node = {"name": event[2], "children": [], "attrs": {}, "text": None}
            (current["children"] if current else roots).append(node)
            stack.append(node)
            pending_attribute = None
        elif kind == "end":
            if stack:
                stack.pop()
            pending_attribute = None
        elif kind == "attr":
            pending_attribute = event[2]
        elif kind == "text":
            if current is None:
                continue
            if pending_attribute is not None:
                current["attrs"][pending_attribute] = event[1]
                pending_attribute = None
            else:
                current["text"] = event[1]

    return roots


def _is_nil(node: dict) -> bool:
    value = node["attrs"].get("nil")
    return value is True or value == "true"


def _coerce(xsd_type: str, value: Any) -> Any:
    """Bring a decoded text record into line with its schema type.

    The binary encoding already carries types, so this mostly passes values
    through; it matters when the peer chose a narrower record than the schema
    (an ``xs:double`` sent as Int8Text, say).
    """
    if value is None:
        return None
    if xsd_type in ("xs:double", "xs:float") and isinstance(value, int) and not isinstance(value, bool):
        return float(value)
    if xsd_type == "xs:string" and not isinstance(value, str):
        return "" if value is None else str(value)
    if xsd_type == "xs:boolean" and isinstance(value, str):
        return value == "true"
    return value


def _read_node(node: dict, type_name: str, registry: TypeRegistry) -> Any:
    if _is_nil(node):
        return None

    if not registry.is_complex(type_name):
        return _coerce(type_name, node["text"])

    complex_type = registry.types[type_name]
    values: dict[str, Any] = {}
    by_name = {field.name: field for field in complex_type.fields}

    for child in node["children"]:
        field = by_name.get(child["name"])
        if field is None:
            continue
        value = _read_node(child, field.type, registry)
        if field.repeats:
            values.setdefault(field.name, []).append(value)
        else:
            values[field.name] = value

    for field in complex_type.fields:
        values.setdefault(field.name, [] if field.repeats else None)

    return registry.build(type_name, values)


def read_element(
    events: list[tuple], spec: ElementSpec, registry: TypeRegistry
) -> dict[str, Any]:
    """Read a response wrapper into ``{field name: value}``.

    Returns every declared field, defaulted to None (or an empty list), so
    callers never have to distinguish "absent" from "not in the reply".
    """
    roots = _tree(events)
    wrapper = next((node for node in roots if node["name"] == spec.name), None)

    values: dict[str, Any] = {
        field.name: [] if field.repeats else None for field in spec.fields
    }
    if wrapper is None:
        return values

    by_name = {field.name: field for field in spec.fields}
    for child in wrapper["children"]:
        field = by_name.get(child["name"])
        if field is None:
            continue
        value = _read_node(child, field.type, registry)
        if field.repeats:
            values[field.name].append(value)
        else:
            values[field.name] = value

    return values


# ---------------------------------------------------------------------------
# Type names for generated annotations
# ---------------------------------------------------------------------------
_PYTHON_TYPES = {
    "xs:string": "str",
    "xs:boolean": "bool",
    "xs:int": "int",
    "xs:integer": "int",
    "xs:long": "int",
    "xs:short": "int",
    "xs:byte": "int",
    "xs:unsignedInt": "int",
    "xs:unsignedLong": "int",
    "xs:unsignedShort": "int",
    "xs:unsignedByte": "int",
    "xs:double": "float",
    "xs:float": "float",
    "xs:decimal": "str",       # kept as text so precision survives
    "xs:dateTime": "datetime",
    "xs:date": "datetime",
    "xs:base64Binary": "bytes",
    "xs:anyType": "Any",
    "xs:QName": "str",
}


def python_type_name(xsd_type: str, registry: TypeRegistry | None = None) -> str:
    """The annotation to emit for an XSD type."""
    if registry is not None and registry.is_complex(xsd_type):
        return xsd_type
    return _PYTHON_TYPES.get(xsd_type, "Any")
