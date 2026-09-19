"""The awkward contract shapes: enums, arrays, nesting, decimal, faults.

The earlier suites prove the protocol; these prove the *type system* on top of
it. Every assertion here is a round trip through the local demo service, so a
value that survives has been serialised by us, deserialised by WCF, and sent
back -- which a self-contained encoder test cannot show.
"""

from __future__ import annotations

import datetime as dt
import importlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from conftest import requires_rig  # noqa: E402
from pynettcp.faults import parse_fault  # noqa: E402


@pytest.fixture(scope="module")
def client_module(demo_service, tmp_path_factory):
    """Generate a client from the live service once for this module."""
    directory = tmp_path_factory.mktemp("rich")
    output = directory / "rich_client.py"

    result = subprocess.run(
        [sys.executable, "-m", "pynettcp.codegen", demo_service.uri, "-o", str(output)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr

    sys.path.insert(0, str(directory))
    try:
        module = importlib.import_module("rich_client")
        yield importlib.reload(module)
    finally:
        sys.path.remove(str(directory))
        sys.modules.pop("rich_client", None)


@pytest.fixture
def client(client_module, demo_service):
    with client_module.DemoServiceClient(demo_service.uri) as opened:
        yield opened


def sample_order(module):
    return module.Order(
        Id="12345678-1234-5678-1234-567812345678",
        Status="Draft",
        ShipTo=module.Address(Street="1 Main St", City="Karachi"),
        Lines=module.ArrayOfOrderLine(
            OrderLine=[
                module.OrderLine(Sku="A-1", Quantity=2, UnitPrice="10.50"),
                module.OrderLine(Sku="B-2", Quantity=3, UnitPrice="4.25"),
            ]
        ),
        Tags=module.ArrayOfstring(string=["urgent", "export"]),
        Total="0",
        LeadTime="PT48H",
        Priority=7,
        CreatedUtc=dt.datetime(2026, 3, 1, 9, 30),
    )


# ---------------------------------------------------------------------------
# Round trips
# ---------------------------------------------------------------------------
@requires_rig
def test_enum_round_trip(client, client_module):
    """An enum is a string restriction on the wire; the server changes it."""
    result = client.submit_order(sample_order(client_module))
    assert result.Status == "Submitted"


@requires_rig
def test_decimal_arithmetic_survives(client, client_module):
    """The strongest check: the *server* computes from the decimals we sent.

    10.50 x 2 + 4.25 x 3 = 33.75. Getting that back means WCF parsed both
    values at full precision, which a string comparison would not prove.
    """
    result = client.submit_order(sample_order(client_module))
    assert str(result.Total) == "33.75"


@requires_rig
def test_nested_complex_type(client, client_module):
    result = client.submit_order(sample_order(client_module))
    assert result.ShipTo.Street == "1 Main St"
    assert result.ShipTo.City == "Karachi"


@requires_rig
def test_array_of_complex_type(client, client_module):
    result = client.submit_order(sample_order(client_module))
    lines = result.Lines.OrderLine
    assert [line.Sku for line in lines] == ["A-1", "B-2"]
    assert [line.Quantity for line in lines] == [2, 3]


@requires_rig
def test_array_of_scalars(client, client_module):
    result = client.submit_order(sample_order(client_module))
    assert result.Tags.string == ["urgent", "export"]


@requires_rig
def test_nullable_value_type(client, client_module):
    order = sample_order(client_module)
    assert client.submit_order(order).Priority == 7

    order.Priority = None
    assert client.submit_order(order).Priority is None


@requires_rig
def test_datetime_round_trip(client, client_module):
    result = client.submit_order(sample_order(client_module))
    assert result.CreatedUtc == dt.datetime(2026, 3, 1, 9, 30)


@requires_rig
def test_guid_round_trip(client, client_module):
    result = client.submit_order(sample_order(client_module))
    assert result.Id == "12345678-1234-5678-1234-567812345678"


@requires_rig
def test_duration_round_trip(client, client_module):
    """WCF normalises the lexical form, so compare meaning not spelling."""
    result = client.submit_order(sample_order(client_module))
    assert result.LeadTime in ("PT48H", "P2D")


# ---------------------------------------------------------------------------
# Arrays as return values
# ---------------------------------------------------------------------------
@requires_rig
@pytest.mark.parametrize("count", [0, 1, 3])
def test_array_return_including_empty(client, count):
    result = client.list_orders(count)
    orders = result.Order if result is not None else []
    assert len(orders) == count


@requires_rig
def test_array_return_contents(client):
    orders = client.list_orders(3).Order
    assert [o.Lines.OrderLine[0].Sku for o in orders] == ["SKU-0", "SKU-1", "SKU-2"]


# ---------------------------------------------------------------------------
# Typed faults
# ---------------------------------------------------------------------------
@requires_rig
def test_typed_fault_carries_its_contract_type(client, client_module):
    with pytest.raises(client_module.ServiceFault) as caught:
        client.validate_order(client_module.Order(Status="Draft"))

    fault = caught.value
    assert fault.reason == "order failed validation"
    assert fault.code == "s:Sender"
    assert isinstance(fault.detail, client_module.ValidationFault)
    assert fault.detail.Code == "INVALID"
    assert "order has no lines" in fault.detail.Problems.string


@requires_rig
def test_untyped_fault_still_reports_its_reason(client, client_module):
    with pytest.raises(client_module.ServiceFault) as caught:
        client.fail("plain fault")

    assert caught.value.reason == "plain fault"
    assert caught.value.detail is None


# ---------------------------------------------------------------------------
# Fault parsing, offline
# ---------------------------------------------------------------------------
def test_parse_fault_returns_none_without_a_fault():
    assert parse_fault([("start", "", "EchoResponse"), ("end",)]) is None


def test_parse_fault_joins_a_qname_split_across_records():
    """A QName arrives as prefix, colon and local name in separate records."""
    events = [
        ("start", "s", "Fault"),
        ("start", "s", "Code"),
        ("start", "s", "Value"),
        ("text", "s"), ("text", ":"), ("text", "Sender"),
        ("end",), ("end",), ("end",),
    ]
    assert parse_fault(events).code == "s:Sender"


def test_parse_fault_ignores_the_xml_lang_attribute():
    """xml:lang would otherwise be glued to the front of every message."""
    events = [
        ("start", "s", "Fault"),
        ("start", "s", "Reason"),
        ("start", "s", "Text"),
        ("attr", "xml", "lang"), ("text", "en-US"),
        ("text", "it broke"),
        ("end",), ("end",), ("end",),
    ]
    assert parse_fault(events).reason == "it broke"


def test_parse_fault_extracts_the_detail_element():
    events = [
        ("start", "s", "Fault"),
        ("start", "s", "Detail"),
        ("start", "", "ValidationFault"),
        ("start", "", "Code"), ("text", "INVALID"), ("end",),
        ("end",),
        ("end",), ("end",),
    ]
    fault = parse_fault(events)
    assert fault.detail_name == "ValidationFault"
    assert ("text", "INVALID") in fault.detail_events


def test_sender_fault_is_distinguished_from_a_server_fault():
    def fault_with(code):
        return parse_fault([
            ("start", "s", "Fault"), ("start", "s", "Code"), ("start", "s", "Value"),
            ("text", code), ("end",), ("end",), ("end",),
        ])

    assert fault_with("s:Sender").is_sender_fault
    assert not fault_with("s:Receiver").is_sender_fault
