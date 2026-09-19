"""Emit a typed Python client module from a parsed service description.

The output is deliberately *declarative*: dataclasses plus ``ElementSpec``
tables that :mod:`pynettcp.contract` walks at runtime.  Generating imperative
serialisation code would move every encoding bug into the generator, where
fixing it means regenerating every client; keeping the logic in the runtime
means a fix ships once.
"""

from __future__ import annotations


import re

from ..contract import (
    UNBOUNDED, ComplexType, ElementSpec, Field, HeaderSpec, python_identifier,
)
from .wsdl import ServiceDescription

__all__ = ["emit_module", "python_identifier", "snake_case"]

#: Names the generated client class already uses.  An operation called ``Close``
#: would otherwise emit ``def close(self, ...)`` straight over the client's own
#: ``close()`` -- which ``__exit__`` calls, so leaving the context manager would
#: invoke the service instead of shutting the channel down and leak the socket.
RESERVED_METHODS = frozenset({
    "close", "channel", "open", "send", "receive",
    "_invoke", "_channel", "__enter__", "__exit__", "__init__",
})


def snake_case(name: str) -> str:
    """``CreateLeave`` -> ``create_leave``, ``EchoLarge`` -> ``echo_large``."""
    without_leading = name.lstrip("_")
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", without_leading)
    return python_identifier(spaced.lower())


def method_name(name: str) -> str:
    """The method to emit for an operation, kept clear of the client's own API."""
    method = snake_case(name)
    return f"{method}_" if method in RESERVED_METHODS else method


def operation_constant(name: str) -> str:
    """The ``_OP_*`` constant name, unique and always a valid identifier.

    ``name.upper()`` alone collides for case-variant operations and produces
    invalid syntax for names carrying a dot or a hyphen.
    """
    return "_OP_" + python_identifier(name).upper()


_SCALAR_ANNOTATIONS = {
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
    "xs:decimal": "str",
    "xs:dateTime": "datetime",
    "xs:date": "datetime",
    "xs:base64Binary": "bytes",
}


def _annotation(field: Field, types: dict[str, ComplexType]) -> str:
    base = _SCALAR_ANNOTATIONS.get(field.type)
    if base is None:
        base = python_identifier(field.type) if field.type in types else "Any"
    if field.repeats:
        return f"list[{base}]"
    return f"{base} | None"


def _field_repr(field: Field) -> str:
    parts = [f"name={field.name!r}", f"type={field.type!r}"]
    if field.min_occurs != 0:
        parts.append(f"min_occurs={field.min_occurs}")
    if field.max_occurs != 1:
        parts.append(
            "max_occurs=UNBOUNDED" if field.max_occurs == UNBOUNDED
            else f"max_occurs={field.max_occurs}"
        )
    if field.nillable:
        parts.append("nillable=True")
    return f"Field({', '.join(parts)})"


def _fields_repr(fields: tuple[Field, ...], indent: str) -> str:
    if not fields:
        return "()"
    body = "".join(f"{indent}    {_field_repr(f)},\n" for f in fields)
    return f"(\n{body}{indent})"


def _docstring_safe(text: str) -> str:
    """Make a path or URI safe to embed in a docstring.

    A Windows path such as ``C:\\Users\\...`` would otherwise be read as escape
    sequences -- ``\\U`` starts a unicode escape and fails to compile. Forward
    slashes are accepted by Windows, so normalising sidesteps the whole class.
    """
    return text.replace("\\", "/").replace('"""', "'''")


def _element_repr(spec: ElementSpec, indent: str) -> str:
    return (
        f"ElementSpec(\n"
        f"{indent}    name={spec.name!r},\n"
        f"{indent}    namespace={spec.namespace!r},\n"
        f"{indent}    fields={_fields_repr(spec.fields, indent + '    ')},\n"
        f"{indent})"
    )


def _header_repr(spec: HeaderSpec, indent: str) -> str:
    parts = [f"name={spec.name!r}", f"namespace={spec.namespace!r}", f"type={spec.type!r}"]
    if spec.nillable:
        parts.append("nillable=True")
    if spec.must_understand:
        parts.append("must_understand=True")
    return f"HeaderSpec({', '.join(parts)})"


def _headers_repr(specs, indent: str) -> str:
    if not specs:
        return "()"
    body = "".join(f"{indent}    {_header_repr(s, indent)},\n" for s in specs)
    return f"(\n{body}{indent})"


def _type_annotation(type_name: str, types: dict[str, ComplexType]) -> str:
    base = _SCALAR_ANNOTATIONS.get(type_name)
    if base is None:
        base = python_identifier(type_name) if type_name in types else "Any"
    return f"{base} | None"


def _emit_dataclass(complex_type: ComplexType, types: dict[str, ComplexType]) -> str:
    class_name = python_identifier(complex_type.name)
    lines = ["@dataclass", f"class {class_name}:", f'    """{complex_type.name} ({complex_type.namespace})."""', ""]

    if not complex_type.fields:
        lines.append("    pass")
    for field in complex_type.fields:
        annotation = _annotation(field, types)
        default = "field(default_factory=list)" if field.repeats else "None"
        lines.append(f"    {python_identifier(field.name)}: {annotation} = {default}")

    return "\n".join(lines)


def _emit_operation(operation, types: dict[str, ComplexType]) -> str:
    method = method_name(operation.name)
    parameters = []
    for field in operation.input_element.fields:
        annotation = _annotation(field, types)
        default = "" if field.required else " = None"
        parameters.append(f"{python_identifier(field.name)}: {annotation}{default}")

    signature = ", ".join(["self", *parameters])

    output = operation.output_element
    result_fields = output.fields if output else ()
    single_result = result_fields[0] if len(result_fields) == 1 else None

    if single_result is not None:
        returns = _annotation(single_result, types)
    elif result_fields:
        returns = "dict[str, Any]"
    else:
        returns = "None"

    # SOAP headers are keyword-only: they are metadata about the call rather
    # than parameters of it, and putting them after * keeps the positional
    # signature identical to the service contract.
    header_names = {}
    header_parameters = []
    for header in operation.headers:
        parameter = snake_case(header.name)
        header_names[header.name] = parameter
        header_parameters.append(
            f"{parameter}: {_type_annotation(header.type, types)} = None"
        )
    if header_parameters:
        signature = ", ".join(["self", *parameters, "*", *header_parameters])

    argument_dict = ", ".join(
        f"{field.name!r}: {python_identifier(field.name)}"
        for field in operation.input_element.fields
    )
    header_dict = ", ".join(f"{name!r}: {parameter}" for name, parameter in header_names.items())

    lines = [
        f"    def {method}({signature}) -> {returns}:",
        f'        """{operation.name} -- {operation.action}"""',
        f"        values = {{{argument_dict}}}",
        (f"        reply = self._invoke({operation_constant(operation.name)}, values, {{{header_dict}}})"
         if header_dict else
         f"        reply = self._invoke({operation_constant(operation.name)}, values)"),
    ]
    if single_result is not None:
        lines.append(f"        return reply[{single_result.name!r}]")
    elif result_fields:
        lines.append("        return reply")
    else:
        lines.append("        return None")

    return "\n".join(lines)


HEADER = '''"""Generated by pynettcp -- do not edit.

Client for {service} ({address}).

Regenerate with:
    python -m pynettcp.codegen {source} -o {output}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from pynettcp.channel import Channel
from pynettcp.contract import UNBOUNDED, ComplexType, ElementSpec, Field, HeaderSpec
from pynettcp.contract import TypeRegistry, header_writers, read_element, write_element
from pynettcp.faults import parse_fault

DEFAULT_ADDRESS = {address!r}
'''

CLIENT_TEMPLATE = '''
class {class_name}:
    """Typed client for {service}.

    Wraps a :class:`pynettcp.channel.Channel`, so it is a session: open it
    once and make many calls.

        with {class_name}() as client:
            client.{example}
    """

    def __init__(self, address: str | None = None, **channel_options) -> None:
        self._channel = Channel(address or DEFAULT_ADDRESS, **channel_options)

    def __enter__(self) -> "{class_name}":
        self._channel.open()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def close(self) -> None:
        self._channel.close()

    @property
    def channel(self) -> Channel:
        return self._channel

    def _invoke(self, operation, values, headers=None):
        request, response, action, header_specs = operation
        reply = self._channel.call(
            action=action,
            body=lambda writer: write_element(writer, request, values, REGISTRY),
            headers=header_writers(header_specs, headers or {{}}, REGISTRY),
        )
        if reply.is_fault:
            raise ServiceFault.from_envelope(reply)
        if response is None:
            return {{}}
        return read_element(reply.body_events, response, REGISTRY)

'''

FAULT_TEMPLATE = '''
class ServiceFault(Exception):
    """A SOAP fault returned by the service.

    ``detail`` is the fault's own contract type when the service declared one,
    so the structured information is reachable::

        except ServiceFault as e:
            e.reason          # 'order failed validation'
            e.code            # 's:Sender'
            e.detail.Problems # ['order has no lines', ...]
    """

    def __init__(self, reason, code=None, detail=None, detail_name=None) -> None:
        super().__init__(reason or "service returned a SOAP fault")
        self.reason = reason
        self.code = code
        self.detail = detail
        self.detail_name = detail_name

    @classmethod
    def from_envelope(cls, envelope) -> "ServiceFault":
        fault = parse_fault(envelope.body_events)
        if fault is None:
            return cls("service returned a SOAP fault")

        detail = None
        if fault.detail_name and fault.detail_name in REGISTRY.types:
            # The detail element is an instance of a known contract type, so it
            # can be deserialised into the same dataclass a normal reply would.
            contract = REGISTRY.types[fault.detail_name]
            spec = ElementSpec(
                name=fault.detail_name,
                namespace=contract.namespace,
                fields=contract.fields,
            )
            detail = REGISTRY.build(
                fault.detail_name, read_element(fault.detail_events, spec, REGISTRY)
            )

        return cls(
            fault.reason,
            code=fault.code,
            detail=detail,
            detail_name=fault.detail_name,
        )
'''


def emit_module(
    description: ServiceDescription,
    *,
    source: str = "<metadata>",
    output: str = "client.py",
    class_name: str | None = None,
) -> str:
    """Render the generated client module as source text."""
    types = description.types
    class_name = class_name or f"{python_identifier(description.service_name)}Client"

    example = (
        f"{method_name(description.operations[0].name)}(...)"
        if description.operations
        else "..."
    )

    parts = [
        HEADER.format(
            service=description.service_name,
            address=description.address,
            source=_docstring_safe(source),
            output=_docstring_safe(output),
        )
    ]

    if types:
        parts.append("\n# --- data contracts ---\n")
        for complex_type in types.values():
            parts.append(_emit_dataclass(complex_type, types) + "\n")

    parts.append("\n# --- type registry ---\n")
    registry_types = "".join(
        f"        {name!r}: ComplexType(\n"
        f"            name={t.name!r},\n"
        f"            namespace={t.namespace!r},\n"
        f"            fields={_fields_repr(t.fields, '            ')},\n"
        f"        ),\n"
        for name, t in types.items()
    )
    factories = "".join(
        f"        {name!r}: {python_identifier(name)},\n" for name in types
    )
    parts.append(
        "REGISTRY = TypeRegistry(\n"
        f"    types={{\n{registry_types}    }},\n"
        f"    factories={{\n{factories}    }},\n"
        ")\n"
    )

    parts.append("\n# --- operations ---\n")
    for operation in description.operations:
        request = _element_repr(operation.input_element, "    ")
        response = (
            _element_repr(operation.output_element, "    ")
            if operation.output_element
            else "None"
        )
        parts.append(
            f"{operation_constant(operation.name)} = (\n"
            f"    {request},\n"
            f"    {response},\n"
            f"    {operation.action!r},\n"
            f"    {_headers_repr(operation.headers, '    ')},\n"
            ")\n"
        )

    parts.append(FAULT_TEMPLATE)
    parts.append(
        CLIENT_TEMPLATE.format(
            class_name=class_name, service=description.service_name, example=example
        )
    )

    for operation in description.operations:
        parts.append(_emit_operation(operation, types) + "\n\n")

    return "".join(parts)
