"""SOAP envelope tests, culminating in byte-exact reproduction of a real message.

``test_reproduces_wcf_message_byte_for_byte`` is the strongest evidence in the
project so far: given the same logical message, our framing of the session
block, our dictionary id allocation, our namespace placement and our text
record choices must all agree with WCF simultaneously.  A single wrong byte
anywhere fails it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pynettcp.nbfs import SessionCodec  # noqa: E402
from pynettcp.nbfx import SessionStr  # noqa: E402
from pynettcp.soap import SOAP12_NS, WSA10_NS, parse_envelope, write_envelope  # noqa: E402

FIXTURE = json.loads((ROOT / "tests" / "golden" / "session_messages.json").read_text("utf-8"))
MESSAGES = [bytes.fromhex(m["hex"]) for m in FIXTURE["messages"]]
ACTION = FIXTURE["action"]
TO = FIXTURE["to"]

# The DataContract used to generate the fixture: LeaveRequest{EmployeeId,
# ReasonText, TotalDays} in urn:DemoService, with the xsi namespace declared
# by the serializer. Written by hand here to prove our encoder can produce it.
DEMO_NS = SessionStr("urn:DemoService")
XSI_NS = SessionStr("http://www.w3.org/2001/XMLSchema-instance")


def demo_body(employee_id: str, total_days: int):
    """Reproduce what DataContractSerializer emits for a LeaveRequest."""

    def write(writer):
        writer.start_element("", SessionStr("LeaveRequest"), DEMO_NS)
        writer.xmlns("i", XSI_NS)
        writer.start_element("", SessionStr("EmployeeId"))
        writer.value(employee_id)
        writer.end_element()
        writer.start_element("", SessionStr("ReasonText"))
        writer.value("Personal")
        writer.end_element()
        writer.start_element("", SessionStr("TotalDays"))
        writer.value(total_days)
        writer.end_element()
        writer.end_element()

    return write


def encode_demo_message(codec: SessionCodec, employee_id: str, total_days: int) -> bytes:
    return codec.encode(
        lambda writer: write_envelope(
            writer, action=ACTION, to=TO, body=demo_body(employee_id, total_days)
        )
    )


# ---------------------------------------------------------------------------
# The headline test
# ---------------------------------------------------------------------------
def test_reproduces_wcf_message_byte_for_byte():
    codec = SessionCodec()
    ours = encode_demo_message(codec, "E1", 1)
    theirs = MESSAGES[0]

    assert ours == theirs, (
        f"\n  WCF      ({len(theirs)}) = {theirs.hex(' ')}"
        f"\n  pynettcp ({len(ours)}) = {ours.hex(' ')}"
    )


def test_reproduces_a_whole_session_byte_for_byte():
    """Message 2 and 3 must reuse the session ids and carry an empty block."""
    codec = SessionCodec()
    for message, expected in zip(FIXTURE["messages"], MESSAGES):
        ours = encode_demo_message(codec, message["employee_id"], message["total_days"])
        assert ours == expected, (
            f"\n  message {message['employee_id']}"
            f"\n  WCF      = {expected.hex(' ')}"
            f"\n  pynettcp = {ours.hex(' ')}"
        )


def test_session_strings_interned_in_wcf_order():
    codec = SessionCodec()
    encode_demo_message(codec, "E1", 1)
    assert list(codec.outgoing.strings) == FIXTURE["expected_session_strings"]


# ---------------------------------------------------------------------------
# Envelope shape
# ---------------------------------------------------------------------------
def test_envelope_declares_both_namespaces_up_front():
    codec = SessionCodec()
    events = SessionCodec().decode(encode_demo_message(codec, "E1", 1))

    assert events[0] == ("start", "s", "Envelope")
    assert events[1] == ("xmlns", "s", SOAP12_NS)
    assert events[2] == ("xmlns", "a", WSA10_NS)


def test_action_precedes_to():
    codec = SessionCodec()
    events = SessionCodec().decode(encode_demo_message(codec, "E1", 1))
    names = [event[2] for event in events if event[0] == "start"]
    assert names.index("Action") < names.index("To")


def test_optional_headers_are_omitted_by_default():
    codec = SessionCodec()
    events = SessionCodec().decode(encode_demo_message(codec, "E1", 1))
    names = {event[2] for event in events if event[0] == "start"}
    assert "MessageID" not in names
    assert "ReplyTo" not in names


def test_extra_headers_are_written_after_addressing():
    """Service-specific headers -- e.g. a Dynamics CallContext -- go last."""

    def call_context(writer):
        writer.start_element("", SessionStr("CallContext"), SessionStr("urn:ctx"))
        writer.start_element("", SessionStr("Company"))
        writer.value("oes")
        writer.end_element()
        writer.end_element()

    codec = SessionCodec()
    payload = codec.encode(
        lambda writer: write_envelope(
            writer, action=ACTION, to=TO, body=None, headers=[call_context]
        )
    )
    events = SessionCodec().decode(payload)
    names = [event[2] for event in events if event[0] == "start"]

    assert names.index("To") < names.index("CallContext")
    assert names.index("CallContext") < names.index("Body")


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def test_parse_envelope_extracts_addressing_and_body():
    envelope = parse_envelope(SessionCodec().decode(MESSAGES[0]))

    assert envelope.action == ACTION
    assert envelope.to == TO
    assert not envelope.is_fault

    body_starts = [event[2] for event in envelope.body_events if event[0] == "start"]
    assert body_starts[0] == "LeaveRequest"
    assert "EmployeeId" in body_starts
    assert ("text", "E1") in envelope.body_events


def test_parse_envelope_excludes_the_envelope_and_section_elements():
    envelope = parse_envelope(SessionCodec().decode(MESSAGES[0]))
    for events in (envelope.header_events, envelope.body_events):
        names = [event[2] for event in events if event[0] == "start"]
        assert "Envelope" not in names
        assert "Header" not in names
        assert "Body" not in names


def test_parse_envelope_detects_a_fault():
    def fault_body(writer):
        writer.start_element("s", SessionStr("Fault"), SOAP12_NS)
        writer.end_element()

    payload = SessionCodec().encode(
        lambda writer: write_envelope(writer, action=ACTION, to=TO, body=fault_body)
    )
    assert parse_envelope(SessionCodec().decode(payload)).is_fault
