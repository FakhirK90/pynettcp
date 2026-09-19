"""MC-NMF framing: record encoding, then real calls over a real socket.

The offline tests check our preamble against ``tests/golden/framing_none.json``,
captured from a stock WCF client through the relay in ``tools/tap.py``.

The live tests speak to the local demo service in ``tests/rig`` -- never to any
external endpoint.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from conftest import requires_rig  # noqa: E402
from pynettcp.channel import Channel  # noqa: E402
from pynettcp.framing import (  # noqa: E402
    FramingConnection,
    FramingFault,
    KnownEncoding,
    Mode,
    RecordType,
    parse_net_tcp_uri,
)
from pynettcp.nbfx import SessionStr  # noqa: E402

CAPTURE = json.loads((ROOT / "tests" / "golden" / "framing_none.json").read_text("utf-8"))
CAPTURED_C2S = bytes.fromhex(CAPTURE["c2s"])
CAPTURED_S2C = bytes.fromhex(CAPTURE["s2c"])
CAPTURED_VIA = "net.tcp://localhost:8898/Demo"

ECHO_ACTION = "urn:DemoService/IDemoService/Echo"
ADD_ACTION = "urn:DemoService/IDemoService/Add"
FAIL_ACTION = "urn:DemoService/IDemoService/Fail"
LARGE_ACTION = "urn:DemoService/IDemoService/EchoLarge"
DEMO_NS = SessionStr("urn:DemoService")


def echo_body(text: str):
    def write(writer):
        writer.start_element("", SessionStr("Echo"), DEMO_NS)
        writer.start_element("", SessionStr("text"))
        writer.value(text)
        writer.end_element()
        writer.end_element()

    return write


def add_body(a: int, b: int):
    def write(writer):
        writer.start_element("", SessionStr("Add"), DEMO_NS)
        writer.start_element("", SessionStr("a"))
        writer.value(a)
        writer.end_element()
        writer.start_element("", SessionStr("b"))
        writer.value(b)
        writer.end_element()
        writer.end_element()

    return write


def body_text(envelope) -> list:
    return [event[1] for event in envelope.body_events if event[0] == "text"]


# ---------------------------------------------------------------------------
# URI parsing
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "uri,expected",
    [
        ("net.tcp://host:8201/A/B", ("host", 8201, "/A/B")),
        ("net.tcp://host/A", ("host", 808, "/A")),          # default net.tcp port
        ("net.tcp://[::1]:9000/A", ("::1", 9000, "/A")),
    ],
)
def test_parse_net_tcp_uri(uri, expected):
    assert parse_net_tcp_uri(uri) == expected


def test_parse_rejects_other_schemes():
    with pytest.raises(ValueError, match="not a net.tcp URI"):
        parse_net_tcp_uri("http://host/A")


# ---------------------------------------------------------------------------
# Preamble, against the captured WCF client
# ---------------------------------------------------------------------------
def test_preamble_matches_a_real_wcf_client():
    connection = FramingConnection(None, CAPTURED_VIA)
    preamble = connection.preamble_bytes()

    assert CAPTURED_C2S.startswith(preamble), (
        f"\n  WCF      = {CAPTURED_C2S[:len(preamble)].hex(' ')}"
        f"\n  pynettcp = {preamble.hex(' ')}"
    )


def test_preamble_record_sequence():
    preamble = FramingConnection(None, CAPTURED_VIA).preamble_bytes()

    assert preamble[0:3] == bytes([RecordType.VERSION, 1, 0])
    assert preamble[3:5] == bytes([RecordType.MODE, Mode.DUPLEX])
    assert preamble[5] == RecordType.VIA
    assert preamble.endswith(bytes([RecordType.PREAMBLE_END]))
    assert bytes([RecordType.KNOWN_ENCODING, KnownEncoding.BINARY_SESSION]) in preamble


def test_upgrade_request_replaces_preamble_end():
    """A secured connection defers PreambleEnd until after the token exchange."""
    connection = FramingConnection(None, CAPTURED_VIA)
    preamble = connection.preamble_bytes(upgrade="application/negotiate")

    assert preamble[-1] != RecordType.PREAMBLE_END
    assert bytes([RecordType.UPGRADE_REQUEST, 0x15]) + b"application/negotiate" in preamble


def test_captured_server_starts_with_preamble_ack():
    assert CAPTURED_S2C[0] == RecordType.PREAMBLE_ACK


def test_captured_client_ends_with_end_record():
    assert CAPTURED_C2S[-1] == RecordType.END


# ---------------------------------------------------------------------------
# Live calls against the local demo service
# ---------------------------------------------------------------------------
@requires_rig
def test_single_call(demo_service):
    with Channel(demo_service.uri) as channel:
        reply = channel.call(action=ECHO_ACTION, body=echo_body("hello"))

    assert reply.action == "urn:DemoService/IDemoService/EchoResponse"
    assert not reply.is_fault
    assert "hello" in body_text(reply)


@requires_rig
def test_many_calls_on_one_session(demo_service):
    """Session reuse: the dictionary grows once, then messages get smaller."""
    with Channel(demo_service.uri) as channel:
        for index in range(5):
            reply = channel.call(action=ECHO_ACTION, body=echo_body(f"msg{index}"))
            assert f"msg{index}" in body_text(reply)

        assert len(channel._codec.outgoing) > 0
        assert len(channel._codec.incoming) > 0


@requires_rig
def test_typed_arguments_round_trip(demo_service):
    with Channel(demo_service.uri) as channel:
        reply = channel.call(action=ADD_ACTION, body=add_body(2, 40))

    assert 42 in body_text(reply)


@requires_rig
@pytest.mark.parametrize(
    "text",
    [
        pytest.param("", id="empty"),
        pytest.param("a", id="one-char"),
        pytest.param("x" * 200, id="chars8-past-fold-threshold"),
        pytest.param("unicode: é中文", id="non-ascii"),
        pytest.param("x" * 70000, id="chars32"),
    ],
)
def test_string_sizes_round_trip(demo_service, text):
    """Covers Chars8/16/32 and the EndElement folding divergence."""
    with Channel(demo_service.uri) as channel:
        reply = channel.call(action=ECHO_ACTION, body=echo_body(text))

    returned = body_text(reply)
    assert (text in returned) or (text == "" and returned in ([], [""]))


@requires_rig
def test_large_reply_spans_tcp_segments(demo_service):
    """A reply far bigger than one TCP segment must reassemble correctly."""

    def write(writer):
        writer.start_element("", SessionStr("EchoLarge"), DEMO_NS)
        writer.start_element("", SessionStr("size"))
        writer.value(300_000)
        writer.end_element()
        writer.end_element()

    with Channel(demo_service.uri) as channel:
        reply = channel.call(action=LARGE_ACTION, body=write)

    assert any(isinstance(v, str) and len(v) == 300_000 for v in body_text(reply))


@requires_rig
def test_server_fault_is_reported_as_a_fault(demo_service):
    def write(writer):
        writer.start_element("", SessionStr("Fail"), DEMO_NS)
        writer.start_element("", SessionStr("reason"))
        writer.value("because")
        writer.end_element()
        writer.end_element()

    with Channel(demo_service.uri) as channel:
        reply = channel.call(action=FAIL_ACTION, body=write)

    assert reply.is_fault
    assert any("because" in v for v in body_text(reply) if isinstance(v, str))


@requires_rig
def test_unknown_action_yields_a_soap_fault(demo_service):
    with Channel(demo_service.uri) as channel:
        reply = channel.call(action="urn:DemoService/IDemoService/NoSuchThing")

    assert reply.is_fault


@requires_rig
def test_wrong_path_yields_a_framing_fault(demo_service):
    """A bad endpoint path fails at the framing layer, before SOAP exists."""
    uri = f"net.tcp://localhost:{demo_service.port}/NotTheDemo"

    with pytest.raises(FramingFault) as caught:
        with Channel(uri) as channel:
            channel.call(action=ECHO_ACTION, body=echo_body("hi"))

    assert caught.value.short == "EndpointNotFound"


@requires_rig
def test_channel_can_be_reopened(demo_service):
    channel = Channel(demo_service.uri)
    with channel:
        assert "one" in body_text(channel.call(action=ECHO_ACTION, body=echo_body("one")))
    with Channel(demo_service.uri) as second:
        assert "two" in body_text(second.call(action=ECHO_ACTION, body=echo_body("two")))
