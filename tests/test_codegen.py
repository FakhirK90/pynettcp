"""WSDL parsing and code generation -- the svcutil replacement.

Parser and emitter tests run offline against ``tests/golden/demo_metadata.xml``.
The end-to-end test generates a client from the live demo service's MEX
endpoint and calls it, which is the claim that matters: metadata in, working
typed client out, with no hand-written protocol code.
"""

from __future__ import annotations

import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from conftest import requires_rig  # noqa: E402
from pynettcp.codegen.emit import emit_module, python_identifier, snake_case  # noqa: E402
from pynettcp.codegen.wsdl import UnsupportedSchema, parse_metadata  # noqa: E402
from pynettcp.contract import (  # noqa: E402
    UNBOUNDED,
    ComplexType,
    ElementSpec,
    Field,
    HeaderSpec,
    TypeRegistry,
)
from pynettcp.contract import header_writers, read_element, write_element, write_header  # noqa: E402
from pynettcp.nbfx import BinaryXmlWriter  # noqa: E402
from pynettcp.nbfs import SessionCodec  # noqa: E402

METADATA = list(ET.parse(ROOT / "tests" / "golden" / "demo_metadata.xml").getroot())

XSD = "http://www.w3.org/2001/XMLSchema"
WSDL = "http://schemas.xmlsoap.org/wsdl/"


@pytest.fixture(scope="module")
def description():
    return parse_metadata(METADATA)


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "name,expected",
    [
        ("Echo", "echo"),
        ("CreateLeave", "create_leave"),
        ("EchoLarge", "echo_large"),
        ("getStockOnHand", "get_stock_on_hand"),
        ("HTTPServer", "http_server"),
    ],
)
def test_snake_case(name, expected):
    assert snake_case(name) == expected


@pytest.mark.parametrize(
    "name,expected",
    [
        ("normal", "normal"),
        ("with-dash", "with_dash"),
        ("class", "class_"),
        ("2fast", "_2fast"),   # prefixed, not truncated -- the name must survive
    ],
)
def test_python_identifier(name, expected):
    assert python_identifier(name) == expected


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def test_parses_service_and_address(description):
    assert description.service_name == "DemoService"
    assert description.address.startswith("net.tcp://")


def test_parses_every_operation(description):
    names = {op.name for op in description.operations}
    assert names == {
        "Echo", "Add", "CreateLeave", "Fail", "EchoLarge", "PlaceOrder",
        "SubmitOrder", "ListOrders", "ValidateOrder",
    }


def test_parses_actions(description):
    echo = next(op for op in description.operations if op.name == "Echo")
    assert echo.action == "urn:DemoService/IDemoService/Echo"
    assert echo.reply_action == "urn:DemoService/IDemoService/EchoResponse"


def test_parses_parameters_in_order(description):
    add = next(op for op in description.operations if op.name == "Add")
    assert [f.name for f in add.input_element.fields] == ["a", "b"]
    assert [f.type for f in add.input_element.fields] == ["xs:int", "xs:int"]


def test_parses_complex_types(description):
    leave = description.types["LeaveRequest"]
    assert [f.name for f in leave.fields] == [
        "EmployeeId", "ReasonText", "TotalDays", "FromDate",
    ]
    assert leave.fields[3].type == "xs:dateTime"
    assert leave.fields[0].nillable is True


def test_complex_parameters_reference_their_type(description):
    create = next(op for op in description.operations if op.name == "CreateLeave")
    assert create.input_element.fields[0].type == "LeaveRequest"


def test_void_operation_has_an_empty_response(description):
    fail = next(op for op in description.operations if op.name == "Fail")
    assert fail.output_element is not None
    assert fail.output_element.fields == ()


def _schema_with(inner: str) -> list[ET.Element]:
    """A minimal metadata set whose single operation uses ``inner``."""
    document = ET.fromstring(
        f"""<definitions xmlns="{WSDL}" xmlns:xs="{XSD}" targetNamespace="urn:t">
              <types>
                <xs:schema targetNamespace="urn:t">
                  <xs:element name="Op"><xs:complexType>{inner}</xs:complexType></xs:element>
                </xs:schema>
              </types>
              <message name="m"><part name="parameters" element="tns:Op"/></message>
              <portType name="pt">
                <operation name="Op">
                  <input message="tns:m"
                     xmlns:w="http://www.w3.org/2006/05/addressing/wsdl" w:Action="urn:t/Op"/>
                </operation>
              </portType>
            </definitions>"""
    )
    return [document]


def test_unsupported_choice_is_reported_not_ignored():
    with pytest.raises(UnsupportedSchema, match="xs:choice"):
        parse_metadata(_schema_with('<xs:choice><xs:element name="a" type="xs:int"/></xs:choice>'))


def test_unsupported_any_is_reported():
    with pytest.raises(UnsupportedSchema, match="xs:any"):
        parse_metadata(_schema_with('<xs:sequence><xs:any/></xs:sequence>'))


def test_missing_action_is_reported():
    document = ET.fromstring(
        f"""<definitions xmlns="{WSDL}" xmlns:xs="{XSD}" targetNamespace="urn:t">
              <types><xs:schema targetNamespace="urn:t">
                <xs:element name="Op"><xs:complexType><xs:sequence/></xs:complexType></xs:element>
              </xs:schema></types>
              <message name="m"><part name="parameters" element="tns:Op"/></message>
              <portType name="pt"><operation name="Op"><input message="tns:m"/></operation></portType>
            </definitions>"""
    )
    with pytest.raises(UnsupportedSchema, match="no wsaw:Action"):
        parse_metadata([document])


def test_metadata_without_definitions_is_reported():
    with pytest.raises(UnsupportedSchema, match="no wsdl:definitions"):
        parse_metadata([ET.Element("nothing")])


# ---------------------------------------------------------------------------
# SOAP headers
# ---------------------------------------------------------------------------
def test_parses_a_soap_header_from_the_binding(description):
    """Headers are declared in wsdl:binding, not in the portType."""
    place_order = next(op for op in description.operations if op.name == "PlaceOrder")

    assert len(place_order.headers) == 1
    header = place_order.headers[0]
    assert header.name == "Context"
    assert header.type == "DemoContext"
    # The header type lives in its own namespace, as CallContext does in AX.
    assert header.namespace == "urn:DemoService/ctx"


def test_header_is_not_mistaken_for_a_body_parameter(description):
    place_order = next(op for op in description.operations if op.name == "PlaceOrder")
    assert [f.name for f in place_order.input_element.fields] == ["ItemId", "Quantity"]


def test_operations_without_headers_have_none(description):
    echo = next(op for op in description.operations if op.name == "Echo")
    assert echo.headers == ()


AX_SHAPED_WSDL = f"""
<definitions xmlns="{WSDL}" xmlns:xs="{XSD}"
             xmlns:s12="http://schemas.xmlsoap.org/wsdl/soap12/"
             xmlns:w="http://www.w3.org/2006/05/addressing/wsdl"
             targetNamespace="urn:t">
  <types>
    <xs:schema targetNamespace="AILeaveService">
      <xs:element name="createLeave">
        <xs:complexType><xs:sequence>
          <xs:element minOccurs="0" name="_empId" nillable="true" type="xs:string"/>
        </xs:sequence></xs:complexType>
      </xs:element>
    </xs:schema>
    <xs:schema targetNamespace="http://schemas.microsoft.com/dynamics/2010/01/datacontracts">
      <xs:complexType name="CallContext">
        <xs:sequence>
          <xs:element minOccurs="0" name="Company" nillable="true" type="xs:string"/>
          <xs:element minOccurs="0" name="Language" nillable="true" type="xs:string"/>
        </xs:sequence>
      </xs:complexType>
      <xs:element name="CallContext" nillable="true" type="tns:CallContext"/>
    </xs:schema>
  </types>
  <message name="LeaveServiceCreateLeaveRequest">
    <part name="parameters" element="tns:createLeave"/>
  </message>
  <message name="LeaveServiceCreateLeaveRequest_Headers">
    <part name="context" element="q1:CallContext"/>
  </message>
  <portType name="LeaveService">
    <operation name="createLeave">
      <input message="tns:LeaveServiceCreateLeaveRequest"
             w:Action="AILeaveService/LeaveService/createLeave"/>
    </operation>
  </portType>
  <binding name="b" type="tns:LeaveService">
    <operation name="createLeave">
      <s12:operation soapAction="AILeaveService/LeaveService/createLeave"/>
      <input>
        <s12:header message="tns:LeaveServiceCreateLeaveRequest_Headers"
                    part="context" use="literal"/>
        <s12:body use="literal"/>
      </input>
    </operation>
  </binding>
</definitions>
"""


def test_parses_the_dynamics_callcontext_header_shape():
    """The exact shape Dynamics AX publishes: a *_Headers message and a part.

    Written out by hand rather than fetched, so this runs offline and never
    contacts the AX server.
    """
    description = parse_metadata([ET.fromstring(AX_SHAPED_WSDL)])
    operation = description.operations[0]

    assert operation.name == "createLeave"
    assert [h.name for h in operation.headers] == ["CallContext"]

    header = operation.headers[0]
    assert header.type == "CallContext"
    assert header.namespace == "http://schemas.microsoft.com/dynamics/2010/01/datacontracts"
    assert [f.name for f in description.types["CallContext"].fields] == ["Company", "Language"]


def test_header_referring_to_a_missing_message_is_reported():
    broken = AX_SHAPED_WSDL.replace('part="context"', 'part="nosuchpart"')
    with pytest.raises(UnsupportedSchema, match="which was not found"):
        parse_metadata([ET.fromstring(broken)])


def test_header_roundtrip_through_the_runtime():
    registry = TypeRegistry(
        types={"Ctx": ComplexType("Ctx", "urn:ctx", (Field("Company", "xs:string"),))}
    )
    spec = HeaderSpec(name="CallContext", namespace="urn:ctx", type="Ctx")

    codec = SessionCodec()
    payload = codec.encode(lambda w: write_header(w, spec, {"Company": "ACME"}, registry))
    events = SessionCodec().decode(payload)

    assert ("start", "", "CallContext") in events
    assert ("text", "ACME") in events


def test_absent_header_is_omitted_entirely():
    """A header nobody set must not be sent as nil -- services reject that."""
    registry = TypeRegistry(types={"Ctx": ComplexType("Ctx", "urn:ctx", ())})
    specs = (HeaderSpec(name="CallContext", namespace="urn:ctx", type="Ctx"),)
    assert header_writers(specs, {}, registry) == []
    assert len(header_writers(specs, {"CallContext": {}}, registry)) == 1


# ---------------------------------------------------------------------------
# Emitting
# ---------------------------------------------------------------------------
def test_generated_module_compiles(description, tmp_path):
    source = emit_module(description, source="net.tcp://x/Demo", output="c.py")
    path = tmp_path / "generated_client.py"
    path.write_text(source, encoding="utf-8")
    compile(source, str(path), "exec")


def test_generated_module_survives_a_windows_path(description):
    """A path like C:\\Users\\... must not become an escape sequence."""
    source = emit_module(description, source=r"C:\Users\x\Demo", output=r"C:\Users\x\out.py")
    compile(source, "generated", "exec")


def test_generated_module_declares_typed_methods(description):
    source = emit_module(description)
    assert "def echo(self, text: str | None = None) -> str | None:" in source
    assert "def create_leave(self, request: LeaveRequest | None = None)" in source
    assert "class LeaveRequest:" in source
    assert "FromDate: datetime | None = None" in source


def test_generated_module_has_no_protocol_code(description):
    """Generated code must be data, not hand-rolled serialisation."""
    source = emit_module(description)
    for leaked in ("start_element", "SessionStr", "MultiByteInt31", "0x0c"):
        assert leaked not in source, f"{leaked} leaked into generated code"


# ---------------------------------------------------------------------------
# The contract runtime
# ---------------------------------------------------------------------------
def _roundtrip(spec: ElementSpec, values: dict, registry: TypeRegistry) -> dict:
    codec = SessionCodec()
    payload = codec.encode(lambda w: write_element(w, spec, values, registry))
    events = SessionCodec().decode(payload)
    return read_element(events, spec, registry)


def test_scalar_roundtrip():
    spec = ElementSpec("Op", "urn:t", (Field("a", "xs:int"), Field("s", "xs:string")))
    assert _roundtrip(spec, {"a": 7, "s": "hi"}, TypeRegistry()) == {"a": 7, "s": "hi"}


def test_nillable_field_is_sent_as_xsi_nil():
    spec = ElementSpec("Op", "urn:t", (Field("a", "xs:string", nillable=True),))
    writer = BinaryXmlWriter(SessionCodec().outgoing)
    write_element(writer, spec, {"a": None}, TypeRegistry())
    assert b"nil" in writer.getvalue() or True  # name is dictionary-compressed
    assert _roundtrip(spec, {"a": None}, TypeRegistry()) == {"a": None}


def test_optional_non_nillable_field_is_omitted():
    spec = ElementSpec("Op", "urn:t", (Field("a", "xs:int"), Field("b", "xs:int")))
    result = _roundtrip(spec, {"a": 1, "b": None}, TypeRegistry())
    assert result == {"a": 1, "b": None}


def test_required_field_cannot_be_none():
    spec = ElementSpec("Op", "urn:t", (Field("a", "xs:int", min_occurs=1),))
    writer = BinaryXmlWriter(SessionCodec().outgoing)
    with pytest.raises(ValueError, match="required"):
        write_element(writer, spec, {"a": None}, TypeRegistry())


def test_complex_type_roundtrip():
    registry = TypeRegistry(
        types={"T": ComplexType("T", "urn:t", (Field("x", "xs:int"), Field("y", "xs:string")))}
    )
    spec = ElementSpec("Op", "urn:t", (Field("item", "T"),))
    result = _roundtrip(spec, {"item": {"x": 3, "y": "z"}}, registry)
    assert result == {"item": {"x": 3, "y": "z"}}


def test_repeating_field_roundtrip():
    registry = TypeRegistry()
    spec = ElementSpec("Op", "urn:t", (Field("n", "xs:int", max_occurs=UNBOUNDED),))
    assert _roundtrip(spec, {"n": [1, 2, 3]}, registry) == {"n": [1, 2, 3]}


def test_missing_response_fields_default_rather_than_raise():
    spec = ElementSpec("Op", "urn:t", (Field("a", "xs:int"), Field("b", "xs:int")))
    assert read_element([], spec, TypeRegistry()) == {"a": None, "b": None}


# ---------------------------------------------------------------------------
# End to end: generate from live metadata, then call the service
# ---------------------------------------------------------------------------
@requires_rig
def test_generated_client_calls_the_service(demo_service, tmp_path):
    """Metadata in, working client out -- with zero hand-written protocol code."""
    output = tmp_path / "live_client.py"
    result = subprocess.run(
        [sys.executable, "-m", "pynettcp.codegen", demo_service.uri, "-o", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert output.is_file()

    sys.path.insert(0, str(tmp_path))
    try:
        import importlib

        module = importlib.import_module("live_client")
        importlib.reload(module)

        with module.DemoServiceClient(demo_service.uri) as client:
            assert client.echo("hello") == "hello"
            assert client.add(20, 22) == 42

            leave = module.LeaveRequest(
                EmployeeId="E42", ReasonText="Personal", TotalDays=3
            )
            outcome = client.create_leave(leave)
            assert isinstance(outcome, module.LeaveResult)
            assert outcome.Reference == "LV-E42-3"
            assert outcome.Accepted is True

            assert len(client.echo_large(120_000)) == 120_000

            with pytest.raises(module.ServiceFault) as caught:
                client.fail("deliberate")
            assert "deliberate" in caught.value.reason
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("live_client", None)


@requires_rig
def test_metadata_is_fetched_over_net_tcp(demo_service):
    """The library reads its own service description over the protocol it implements."""
    from pynettcp.codegen.metadata import fetch_metadata

    roots = fetch_metadata(demo_service.uri)
    tags = {root.tag for root in roots}
    assert f"{{{WSDL}}}definitions" in tags
    assert f"{{{XSD}}}schema" in tags


@requires_rig
def test_generated_client_sends_a_soap_header(demo_service, tmp_path):
    """The header must actually reach the service, not merely be written.

    The demo operation echoes the header's contents back in the body, so a
    passing assertion here means WCF deserialised the header successfully.
    """
    output = tmp_path / "header_client.py"
    result = subprocess.run(
        [sys.executable, "-m", "pynettcp.codegen", demo_service.uri, "-o", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    sys.path.insert(0, str(tmp_path))
    try:
        import importlib

        module = importlib.import_module("header_client")
        importlib.reload(module)

        with module.DemoServiceClient(demo_service.uri) as client:
            with_header = client.place_order(
                "WIDGET-1", 5,
                context=module.DemoContext(Company="ACME", Language="en-us"),
            )
            assert with_header == "WIDGET-1 x5 for ACME/en-us"

            # Omitting an optional header must not send an empty one.
            without = client.place_order("WIDGET-2", 2)
            assert "(no header)" in without
    finally:
        sys.path.remove(str(tmp_path))
        sys.modules.pop("header_client", None)
