"""Parse WSDL 1.1 and the XSD subset WCF's DataContractSerializer emits.

Scope is deliberately narrow -- the shapes a ``NetTcpBinding`` service actually
publishes: document/literal operations whose messages are a single wrapper
element, ``xs:sequence`` complex types, and the built-in simple types.

Anything outside that raises :class:`UnsupportedSchema` rather than being
quietly skipped.  A generator that silently drops a construct produces a client
that fails at runtime with a mysterious server fault; failing here names the
construct and the element it appeared in.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field as _dataclass_field

from ..contract import UNBOUNDED, ComplexType, ElementSpec, Field, HeaderSpec

__all__ = [
    "ServiceDescription",
    "Operation",
    "UnsupportedSchema",
    "parse_metadata",
]

WSDL_NS = "http://schemas.xmlsoap.org/wsdl/"
SOAP12_NS = "http://schemas.xmlsoap.org/wsdl/soap12/"
XSD_NS = "http://www.w3.org/2001/XMLSchema"
WSAW_NS = "http://www.w3.org/2006/05/addressing/wsdl"
WSAM_NS = "http://www.w3.org/2007/05/addressing/metadata"

W = f"{{{WSDL_NS}}}"
X = f"{{{XSD_NS}}}"


class UnsupportedSchema(NotImplementedError):
    """A WSDL or XSD construct outside the supported subset."""


@dataclass
class Operation:
    name: str
    action: str
    reply_action: str | None
    input_element: ElementSpec
    output_element: ElementSpec | None
    headers: tuple[HeaderSpec, ...] = ()


@dataclass
class ServiceDescription:
    service_name: str
    port_name: str | None = None
    address: str | None = None
    target_namespace: str | None = None
    operations: list[Operation] = _dataclass_field(default_factory=list)
    types: dict[str, ComplexType] = _dataclass_field(default_factory=dict)


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------
def _local(qname: str | None) -> str | None:
    """Strip a QName prefix. Namespaces are tracked separately per document."""
    if qname is None:
        return None
    return qname.split(":", 1)[1] if ":" in qname else qname


#: The built-in simple types a DataContract can use. Membership of this set --
#: not the prefix -- decides whether a type is a builtin, because ElementTree
#: discards xmlns declarations and the prefix bound to the XML Schema namespace
#: varies between documents (xs, xsd, s, or the default).
XSD_BUILTINS = frozenset(
    """anyType anyURI base64Binary boolean byte date dateTime decimal double duration
    float gDay gMonth gMonthDay gYear gYearMonth hexBinary ID IDREF int integer language
    long Name NCName negativeInteger NMTOKEN nonNegativeInteger nonPositiveInteger
    normalizedString positiveInteger QName short string time token unsignedByte
    unsignedInt unsignedLong unsignedShort""".split()
)


def _xsd_type_name(qname: str | None) -> str:
    """Normalise a type QName to ``xs:local`` for builtins, or a bare name."""
    if qname is None:
        return "xs:anyType"
    local = _local(qname)
    return f"xs:{local}" if local in XSD_BUILTINS else local


# ---------------------------------------------------------------------------
# XSD
# ---------------------------------------------------------------------------
def _parse_fields(
    container: ET.Element,
    where: str,
    namespace: str = "",
    types: dict[str, ComplexType] | None = None,
) -> tuple[Field, ...]:
    """Parse an ``xs:sequence`` into fields.

    ``types`` receives any anonymous inline complexType found along the way,
    promoted to a named type.  WCF emits these for dictionaries -- a
    ``Dictionary<string,string>`` becomes ``ArrayOfKeyValueOfstringstring``
    holding a repeated ``KeyValueOfstringstring`` whose type is declared
    inline -- so refusing them would rule out a very common contract.
    """
    sequence = container.find(f"{X}sequence")
    if sequence is None:
        for unsupported in ("choice", "all", "complexContent", "simpleContent"):
            if container.find(f"{X}{unsupported}") is not None:
                raise UnsupportedSchema(
                    f"xs:{unsupported} in {where} is not supported; only xs:sequence is"
                )
        return ()

    fields: list[Field] = []
    for element in sequence:
        if element.tag == f"{X}any":
            raise UnsupportedSchema(f"xs:any in {where} is not supported")
        if element.tag != f"{X}element":
            continue

        name = element.get("name")
        if name is None:
            reference = element.get("ref")
            if reference is None:
                continue
            name = _local(reference)

        max_occurs_text = element.get("maxOccurs", "1")
        max_occurs = UNBOUNDED if max_occurs_text == "unbounded" else int(max_occurs_text)

        type_name = element.get("type")
        inline = element.find(f"{X}complexType")

        if type_name is None and inline is not None:
            # Promote the anonymous type, naming it after the element that
            # carries it. Collisions get qualified by their container.
            synthetic = name if types is not None and name not in types else f"{where}_{name}"
            if types is not None:
                types[synthetic] = ComplexType(
                    name=synthetic,
                    namespace=namespace,
                    fields=_parse_fields(inline, synthetic, namespace, types),
                )
            resolved_type = synthetic
        else:
            resolved_type = _xsd_type_name(type_name)

        fields.append(
            Field(
                name=name,
                type=resolved_type,
                min_occurs=int(element.get("minOccurs", "1")),
                max_occurs=max_occurs,
                nillable=element.get("nillable") == "true",
            )
        )
    return tuple(fields)


def _parse_schema(
    schema: ET.Element,
) -> tuple[dict[str, ElementSpec], dict[str, ComplexType], dict[str, tuple[str, str, bool]], dict[str, str]]:
    namespace = schema.get("targetNamespace", "")

    elements: dict[str, ElementSpec] = {}
    types: dict[str, ComplexType] = {}
    declarations: dict[str, tuple[str, str, bool]] = {}
    simple_types: dict[str, str] = {}

    # A named simpleType is an alias for a built-in, and on the wire it *is*
    # that built-in. WCF leans on this: Guid and enums are both restrictions of
    # xs:string, so without resolving them a field's type looks unknown and its
    # value would be written by guessing from the Python type instead.
    for simple_type in schema.findall(f"{X}simpleType"):
        name = simple_type.get("name")
        if not name:
            continue
        restriction = simple_type.find(f"{X}restriction")
        if restriction is not None:
            simple_types[name] = _xsd_type_name(restriction.get("base"))
        elif simple_type.find(f"{X}list") is not None:
            # A list of enum values serialises as space-separated text.
            simple_types[name] = "xs:string"

    for complex_type in schema.findall(f"{X}complexType"):
        name = complex_type.get("name")
        if name:
            types[name] = ComplexType(
                name=name,
                namespace=namespace,
                fields=_parse_fields(complex_type, name, namespace, types),
            )

    for element in schema.findall(f"{X}element"):
        name = element.get("name")
        if not name:
            continue
        inline = element.find(f"{X}complexType")
        if inline is not None:
            elements[name] = ElementSpec(
                name=name,
                namespace=namespace,
                fields=_parse_fields(inline, name, namespace, types),
            )
        else:
            # A top-level element aliasing a named type. Message wrappers always
            # declare their content inline, but SOAP *headers* are declared this
            # way -- CallContext is `<xs:element name="CallContext"
            # type="tns:CallContext"/>` -- so the alias has to be recorded.
            declarations[name] = (
                namespace,
                _xsd_type_name(element.get("type")),
                element.get("nillable") == "true",
            )

    return elements, types, declarations, simple_types


# ---------------------------------------------------------------------------
# WSDL
# ---------------------------------------------------------------------------
def _action_of(node: ET.Element | None) -> str | None:
    if node is None:
        return None
    return node.get(f"{{{WSAW_NS}}}Action") or node.get(f"{{{WSAM_NS}}}Action")


def parse_metadata(roots: list[ET.Element]) -> ServiceDescription:
    """Turn fetched metadata into a :class:`ServiceDescription`."""
    definitions = [r for r in roots if r.tag == f"{W}definitions"]
    schemas = [r for r in roots if r.tag == f"{X}schema"]

    # Schemas may also be inlined under wsdl:types.
    for document in definitions:
        for types_node in document.findall(f"{W}types"):
            schemas.extend(types_node.findall(f"{X}schema"))

    if not definitions:
        raise UnsupportedSchema("no wsdl:definitions found in the metadata")

    elements: dict[str, ElementSpec] = {}
    types: dict[str, ComplexType] = {}
    declarations: dict[str, tuple[str, str, bool]] = {}
    simple_types: dict[str, str] = {}
    for schema in schemas:
        schema_elements, schema_types, schema_declarations, schema_simple = _parse_schema(schema)
        elements.update(schema_elements)
        types.update(schema_types)
        declarations.update(schema_declarations)
        simple_types.update(schema_simple)

    # Collapse simpleType aliases now that every schema has been seen.
    def resolve(type_name: str) -> str:
        seen = set()
        while type_name in simple_types and type_name not in seen:
            seen.add(type_name)
            type_name = simple_types[type_name]
        return type_name

    def resolve_fields(fields):
        return tuple(
            f if resolve(f.type) == f.type else Field(
                name=f.name, type=resolve(f.type), min_occurs=f.min_occurs,
                max_occurs=f.max_occurs, nillable=f.nillable,
            )
            for f in fields
        )

    types = {
        name: ComplexType(name=t.name, namespace=t.namespace, fields=resolve_fields(t.fields))
        for name, t in types.items()
    }
    elements = {
        name: ElementSpec(name=e.name, namespace=e.namespace, fields=resolve_fields(e.fields))
        for name, e in elements.items()
    }
    declarations = {
        name: (ns, resolve(type_name), nillable)
        for name, (ns, type_name, nillable) in declarations.items()
    }

    messages: dict[str, str] = {}                    # message -> wrapper element
    message_parts: dict[tuple[str, str], str] = {}   # (message, part) -> element
    for document in definitions:
        for message in document.findall(f"{W}message"):
            message_name = message.get("name")
            for part in message.findall(f"{W}part"):
                element_name = _local(part.get("element"))
                if element_name is None:
                    raise UnsupportedSchema(
                        f"message {message_name} uses a type-based part; "
                        "only document/literal element parts are supported"
                    )
                message_parts[(message_name, part.get("name"))] = element_name

            first = message.find(f"{W}part")
            if first is not None:
                messages[message_name] = _local(first.get("element"))

    # SOAP headers live in wsdl:binding, not in the portType, so they have to be
    # collected separately and matched back to their operation by name.
    headers_by_operation: dict[str, list[HeaderSpec]] = {}
    for document in definitions:
        for binding in document.findall(f"{W}binding"):
            for operation in binding.findall(f"{W}operation"):
                input_node = operation.find(f"{W}input")
                if input_node is None:
                    continue

                specs: list[HeaderSpec] = []
                for header in input_node.findall(f"{{{SOAP12_NS}}}header"):
                    message_name = _local(header.get("message"))
                    part_name = header.get("part")
                    element_name = message_parts.get((message_name, part_name))
                    if element_name is None:
                        raise UnsupportedSchema(
                            f"header {part_name!r} of operation "
                            f"{operation.get('name')} refers to message "
                            f"{message_name!r}, which was not found"
                        )

                    declaration = declarations.get(element_name)
                    if declaration is None:
                        raise UnsupportedSchema(
                            f"no schema declaration found for header element "
                            f"{element_name!r} of operation {operation.get('name')}"
                        )

                    header_namespace, header_type, nillable = declaration
                    specs.append(
                        HeaderSpec(
                            name=element_name,
                            namespace=header_namespace,
                            type=header_type,
                            nillable=nillable,
                            must_understand=header.get("mustUnderstand") == "1",
                        )
                    )

                if specs:
                    headers_by_operation[operation.get("name")] = specs

    description = ServiceDescription(service_name="Service", types=types)

    for document in definitions:
        for service in document.findall(f"{W}service"):
            description.service_name = service.get("name") or description.service_name
            port = service.find(f"{W}port")
            if port is not None:
                description.port_name = port.get("name")
                address = port.find(f"{{{SOAP12_NS}}}address")
                if address is not None:
                    description.address = address.get("location")

    for document in definitions:
        for port_type in document.findall(f"{W}portType"):
            description.target_namespace = document.get("targetNamespace")
            for operation in port_type.findall(f"{W}operation"):
                name = operation.get("name")
                input_node = operation.find(f"{W}input")
                output_node = operation.find(f"{W}output")
                if input_node is None:
                    continue

                action = _action_of(input_node)
                if action is None:
                    raise UnsupportedSchema(
                        f"operation {name} has no wsaw:Action; the SOAP action "
                        "cannot be inferred"
                    )

                input_element = elements.get(_local(messages.get(_local(input_node.get("message")))))
                if input_element is None:
                    raise UnsupportedSchema(
                        f"no schema element found for the input of operation {name}"
                    )

                output_element = None
                if output_node is not None:
                    output_element = elements.get(
                        _local(messages.get(_local(output_node.get("message"))))
                    )

                description.operations.append(
                    Operation(
                        name=name,
                        action=action,
                        reply_action=_action_of(output_node),
                        input_element=input_element,
                        output_element=output_element,
                        headers=tuple(headers_by_operation.get(name, ())),
                    )
                )

    if not description.operations:
        raise UnsupportedSchema("no operations found in the metadata")

    return description
