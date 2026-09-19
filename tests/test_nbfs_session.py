"""Session-mode tests against real WCF messages.

Fixtures in ``tests/golden/session_messages.json`` are three consecutive
messages from WCF's own binary session encoder (see
``tools/gen_session_fixtures.py``).  They run without pythonnet.

A session dictionary bug does not show up on message 1 -- it shows up on
message 40, once the id numbering has drifted.  So these assert the state
*evolves* correctly, not merely that one message parses.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pynettcp.nbfs import (  # noqa: E402
    SessionCodec,
    SessionDictionary,
    SessionSizeExceeded,
)
from pynettcp.nbfx import BinaryXmlReader, DictStr, NbfxError, SessionStr  # noqa: E402
from pynettcp.varint import encode_multibyte_int31  # noqa: E402

FIXTURE = json.loads((ROOT / "tests" / "golden" / "session_messages.json").read_text("utf-8"))
MESSAGES = [bytes.fromhex(m["hex"]) for m in FIXTURE["messages"]]
EXPECTED_STRINGS = FIXTURE["expected_session_strings"]

SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
WSA10 = "http://www.w3.org/2005/08/addressing"


# ---------------------------------------------------------------------------
# The new-strings block
# ---------------------------------------------------------------------------
def test_first_message_announces_the_session_strings():
    codec = SessionCodec()
    announced, document = codec.split(MESSAGES[0])

    assert announced == EXPECTED_STRINGS
    assert document[0] != 0x67, "block must not be counted as part of the document"


def test_block_length_covers_the_length_prefixes():
    """The block size counts each string's own length prefix, not just text."""
    block_size = MESSAGES[0][0]
    assert block_size == 0x67 == 103
    assert block_size == sum(
        len(encode_multibyte_int31(len(s.encode()))) + len(s.encode())
        for s in EXPECTED_STRINGS
    )


def test_later_messages_announce_nothing():
    for index, message in enumerate(MESSAGES[1:], start=2):
        assert message[0] == 0x00, f"message {index} should have an empty block"


def test_session_compresses_later_messages():
    """The whole point of session mode: 216 bytes down to 114."""
    assert len(MESSAGES[0]) > len(MESSAGES[1])
    assert len(MESSAGES[1]) == len(MESSAGES[2])


# ---------------------------------------------------------------------------
# Decoding a whole session
# ---------------------------------------------------------------------------
def test_decodes_all_three_messages_with_one_codec():
    codec = SessionCodec()
    decoded = [codec.decode(message) for message in MESSAGES]

    for index, events in enumerate(decoded):
        starts = [event for event in events if event[0] == "start"]
        names = [name for _, _, name in starts]
        assert "Envelope" in names and "Body" in names
        assert "LeaveRequest" in names, f"message {index + 1} lost the body element"

    # Body values differ per message; the dictionary ids do not.
    texts = [[e[1] for e in events if e[0] == "text"] for events in decoded]
    assert "E1" in texts[0] and "E2" in texts[1] and "E3" in texts[2]


def test_ids_stay_stable_across_the_session():
    codec = SessionCodec()
    for message in MESSAGES:
        codec.decode(message)
    assert list(codec.incoming.strings) == EXPECTED_STRINGS


def test_second_message_alone_is_undecodable():
    """Without message 1's block, the ids are meaningless -- and must say so."""
    codec = SessionCodec()
    with pytest.raises(NbfxError, match="session dictionary id"):
        codec.decode(MESSAGES[1])


def test_reading_does_not_pollute_the_writing_dictionary():
    """The two directions are numbered independently; sharing one desyncs both."""
    codec = SessionCodec()
    codec.decode(MESSAGES[0])

    assert len(codec.incoming) == len(EXPECTED_STRINGS)
    assert len(codec.outgoing) == 0, "decoding must not touch the outgoing table"


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------
def test_encode_emits_block_then_document():
    codec = SessionCodec()

    def build(writer):
        writer.start_element("", SessionStr("Thing"), SessionStr("urn:demo"))
        writer.value("x")
        writer.end_element()

    payload = codec.encode(build)
    announced, _ = SessionCodec().split(payload)
    assert announced == ["Thing", "urn:demo"]


def test_encode_announces_each_string_once():
    codec = SessionCodec()

    def build(writer):
        writer.start_element("", SessionStr("Thing"), SessionStr("urn:demo"))
        writer.end_element()

    first = codec.encode(build)
    second = codec.encode(build)

    assert first[0] != 0x00, "first message must announce its strings"
    assert second[0] == 0x00, "second message must reuse them"
    assert len(second) < len(first)


def test_encode_decode_roundtrip_between_two_peers():
    """Our encoder's output must decode in a peer that saw only the wire."""
    writer_side, reader_side = SessionCodec(), SessionCodec()

    def build(writer):
        writer.start_element("s", DictStr("Envelope"), DictStr(SOAP12))
        writer.start_element("s", DictStr("Body"), DictStr(SOAP12))
        writer.start_element("", SessionStr("createLeave"), SessionStr("urn:demo"))
        writer.start_element("", SessionStr("empId"))
        writer.value("E7")
        writer.end_element()
        writer.end_element()
        writer.end_element()
        writer.end_element()

    for _ in range(3):
        events = reader_side.decode(writer_side.encode(build))
        assert ("start", "", "createLeave") in events
        assert ("text", "E7") in events

    assert list(reader_side.incoming.strings) == list(writer_side.outgoing.strings)


def test_static_strings_are_not_interned():
    """Envelope infrastructure uses static ids and never enters the session."""
    codec = SessionCodec()

    def build(writer):
        writer.start_element("s", DictStr("Envelope"), DictStr(SOAP12))
        writer.start_element("s", DictStr("Body"), DictStr(SOAP12))
        writer.end_element()
        writer.end_element()

    payload = codec.encode(build)
    assert payload[0] == 0x00, "no session strings expected"
    assert len(codec.outgoing) == 0


# ---------------------------------------------------------------------------
# Dictionary mechanics
# ---------------------------------------------------------------------------
def test_wire_ids_are_odd_and_sequential():
    dictionary = SessionDictionary()
    assert dictionary.session_id("a") == 1     # index 0 -> 0 << 1 | 1
    assert dictionary.session_id("b") == 3     # index 1 -> 1 << 1 | 1
    assert dictionary.session_id("a") == 1     # stable on re-use
    assert dictionary.lookup(3) == "b"


def test_static_ids_are_even():
    dictionary = SessionDictionary()
    assert dictionary.static_id("Envelope") == 2      # static index 1
    assert dictionary.lookup(2) == "Envelope"
    assert dictionary.static_id("not-a-static-string") is None


def test_session_size_budget_is_enforced():
    dictionary = SessionDictionary(max_size=16)
    dictionary.session_id("x" * 10)
    with pytest.raises(SessionSizeExceeded, match="MaxSessionSize"):
        dictionary.session_id("y" * 10)


def test_truncated_block_is_rejected():
    codec = SessionCodec()
    with pytest.raises(NbfxError, match="claims 99 bytes"):
        codec.decode(bytes([99]) + b"\x02ab")


def test_dictstr_must_exist_in_the_static_table():
    codec = SessionCodec()

    def build(writer):
        writer.start_element("", DictStr("definitely-not-static"))
        writer.end_element()

    with pytest.raises(NbfxError, match="use SessionStr"):
        codec.encode(build)


# ---------------------------------------------------------------------------
# The envelope WCF actually produced
# ---------------------------------------------------------------------------
def test_fixture_envelope_structure():
    """Sanity-check the decoded shape of a genuine WCF request."""
    codec = SessionCodec()
    events = codec.decode(MESSAGES[0])

    assert events[0] == ("start", "s", "Envelope")
    assert ("xmlns", "s", SOAP12) in events
    assert ("xmlns", "a", WSA10) in events
    assert ("start", "a", "Action") in events
    assert ("text", FIXTURE["action"]) in events
    assert ("start", "a", "To") in events
    assert ("text", FIXTURE["to"]) in events
    assert ("start", "s", "Body") in events


def test_reader_rejects_session_ids_without_a_session():
    """A bare NBFX reader must refuse session references rather than guess."""
    document = MESSAGES[0][1 + MESSAGES[0][0]:]
    with pytest.raises(NbfxError, match="no session dictionary"):
        BinaryXmlReader(document).read()
