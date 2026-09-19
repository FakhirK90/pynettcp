"""Differential tests: our NBFX encoder vs the real .NET binary XML writer.

These are the highest-leverage tests in the project.  They need no network and
no AX server -- correctness is decided by byte equality with WCF's own encoder,
running in-process through pythonnet.

Skipped automatically where pythonnet / .NET Framework is unavailable, so the
suite still runs on a machine that only has the shipped library.

Op-list shape (document order)::

    ("start", prefix, name, namespace | None)
    ("xmlns", prefix, namespace)
    ("attr",  prefix, name, namespace | None, value)
    ("text",  value)
    ("end",)
"""

from __future__ import annotations

import datetime as _dt
import sys
import uuid as _uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from pynettcp.nbfx import BinaryXmlReader, BinaryXmlWriter, DictStr  # noqa: E402
from pynettcp.varint import decode_multibyte_int31, encode_multibyte_int31  # noqa: E402

oracle = pytest.importorskip("oracle", reason="needs pythonnet + .NET Framework")

SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
WSA10 = "http://www.w3.org/2005/08/addressing"

D_SOAP12 = DictStr(SOAP12)
D_WSA10 = DictStr(WSA10)


def replay(ops) -> bytes:
    """Replay an op list through *our* writer."""
    writer = BinaryXmlWriter()
    for op in ops:
        kind = op[0]
        if kind == "start":
            writer.start_element(op[1], op[2], op[3])
        elif kind == "xmlns":
            writer.xmlns(op[1], op[2])
        elif kind == "attr":
            writer.attribute(op[1], op[2], op[4], namespace=op[3])
        elif kind == "text":
            writer.value(op[1])
        elif kind == "end":
            writer.end_element()
        else:
            raise AssertionError(f"unknown op {kind!r}")
    return writer.getvalue()


def assert_matches_dotnet(ops) -> bytes:
    expected = oracle.encode(ops)
    actual = replay(ops)
    assert actual == expected, (
        f"\n  ops      = {ops}"
        f"\n  .NET     = {expected.hex(' ')}"
        f"\n  pynettcp = {actual.hex(' ')}"
    )
    return actual


# ---------------------------------------------------------------------------
# varint
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [(0, "00"), (1, "01"), (123, "7b"), (127, "7f"), (128, "80 01"), (205, "cd 01"),
     (16383, "ff 7f"), (16384, "80 80 01"), (2**31 - 1, "ff ff ff ff 07")],
)
def test_multibyte_int31_known_values(value, expected):
    assert encode_multibyte_int31(value).hex(" ") == expected


@pytest.mark.parametrize("value", [0, 1, 127, 128, 300, 65535, 2**20, 2**31 - 1])
def test_multibyte_int31_roundtrip(value):
    encoded = encode_multibyte_int31(value)
    assert decode_multibyte_int31(encoded) == (value, len(encoded))


# ---------------------------------------------------------------------------
# Structure records
# ---------------------------------------------------------------------------
def test_short_element_with_text():
    data = assert_matches_dotnet([("start", "", "r", None), ("text", "hello"), ("end",)])
    assert data.hex(" ") == "40 01 72 99 05 68 65 6c 6c 6f"


def test_prefixed_element():
    assert_matches_dotnet([("start", "a", "Envelope", "urn:x"), ("end",)])


def test_dictionary_element_uses_static_table():
    assert_matches_dotnet(
        [("start", "s", "Envelope", SOAP12), ("start", "s", "Body", SOAP12), ("end",), ("end",)]
    )


def test_nested_elements():
    assert_matches_dotnet(
        [("start", "", "a", None), ("start", "", "b", None), ("start", "", "c", None),
         ("end",), ("end",), ("end",)]
    )


def test_xmlns_dictionary_and_literal():
    assert_matches_dotnet([("start", "s", "Envelope", SOAP12), ("end",)])
    assert_matches_dotnet([("start", "p", "x", "urn:not-in-dictionary"), ("end",)])


def test_default_xmlns():
    assert_matches_dotnet([("start", "", "r", "urn:default"), ("end",)])


def test_namespace_declared_once_across_nesting():
    """A prefix already bound in an enclosing scope must not be re-declared."""
    assert_matches_dotnet(
        [("start", "s", "Envelope", SOAP12),
         ("start", "s", "Header", SOAP12),
         ("end",),
         ("start", "s", "Body", SOAP12),
         ("end",),
         ("end",)]
    )


def test_attributes():
    assert_matches_dotnet([("start", "", "r", None), ("attr", "", "id", None, "7"), ("end",)])
    assert_matches_dotnet(
        [("start", "a", "Action", WSA10), ("attr", "s", "mustUnderstand", SOAP12, 1),
         ("text", "urn:doThing"), ("end",)]
    )


# ---------------------------------------------------------------------------
# Text records
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("value", [0, 1, 5, -1, 127, -128, 300, -300, 70000, -70000, 2**40, -(2**40)])
def test_integer_record_selection(value):
    assert_matches_dotnet([("start", "", "n", None), ("text", value), ("end",)])


@pytest.mark.parametrize("value", [True, False])
def test_bool(value):
    assert_matches_dotnet([("start", "", "b", None), ("text", value), ("end",)])


@pytest.mark.parametrize(
    "value",
    ["a", "hello", "unicode: é中文", "x" * 169,
     "AILeaveService/LeaveService/createLeave"],
)
def test_strings(value):
    assert_matches_dotnet([("start", "", "s", None), ("text", value), ("end",)])


@pytest.mark.parametrize("length", [170, 255, 256, 65535, 65536, 70000])
def test_long_strings_are_semantically_equal_to_dotnet(length):
    """Long text: same meaning, one byte of deliberate divergence.

    Past ~169 UTF-8 bytes .NET stops folding EndElement into the text record,
    because the string no longer fits in the 512-byte buffer it would have to
    rewrite.  That is an artefact of its internal buffering, not a protocol
    rule -- ``98 <len> <bytes> 01`` and ``99 <len> <bytes>`` are both valid
    NBFX and decode identically.  We always fold, so this asserts equal
    *events* rather than equal bytes, and checks the record type still agrees.
    """
    ops = [("start", "", "s", None), ("text", "x" * length), ("end",)]
    theirs, ours = oracle.encode(ops), replay(ops)

    assert BinaryXmlReader(ours).read() == BinaryXmlReader(theirs).read()
    assert ours[3] | 1 == theirs[3] | 1, "same Chars8/16/32 record expected"
    assert len(ours) == len(theirs) - 1, "expected exactly one folded EndElement byte"


def test_plain_string_matching_a_dictionary_entry_stays_literal():
    """Compression is opt-in: a plain str is never silently dictionary-compressed."""
    data = assert_matches_dotnet([("start", "", "s", None), ("text", "Envelope"), ("end",)])
    assert data.hex(" ").startswith("40 01 73 99 08"), "expected a literal Chars8Text"


# ---------------------------------------------------------------------------
# Dictionary compression (opt-in via DictStr)
# ---------------------------------------------------------------------------
def test_dictionary_element_name():
    data = assert_matches_dotnet([("start", "", DictStr("Envelope"), None), ("end",)])
    # ShortDictionaryElement, id = index 1 << 1 = 2
    assert data.hex(" ") == "42 02 01"


def test_dictionary_element_with_prefix():
    assert_matches_dotnet(
        [("start", "s", DictStr("Envelope"), D_SOAP12),
         ("start", "s", DictStr("Body"), D_SOAP12), ("end",), ("end",)]
    )


def test_dictionary_xmlns():
    data = assert_matches_dotnet([("start", "s", DictStr("Envelope"), D_SOAP12), ("end",)])
    # PrefixDictionaryElement 's' (0x44+18=0x56) id 2, then DictionaryXmlnsAttribute
    assert data.hex(" ").startswith("56 02 0b 01 73 04")


def test_dictionary_attribute():
    assert_matches_dotnet(
        [("start", "a", DictStr("Action"), D_WSA10),
         ("attr", "s", DictStr("mustUnderstand"), D_SOAP12, 1),
         ("text", "urn:doThing"), ("end",)]
    )


def test_dictionary_text_value():
    data = assert_matches_dotnet(
        [("start", "", "s", None), ("text", DictStr("Envelope")), ("end",)]
    )
    # DictionaryTextWithEndElement (0xAB) + id 2
    assert data.hex(" ") == "40 01 73 ab 02"


def test_soap_envelope_shape_matches_wcf():
    """The real header shape WCF puts on the wire for a net.tcp request."""
    assert_matches_dotnet(
        [("start", "s", DictStr("Envelope"), D_SOAP12),
         ("start", "s", DictStr("Header"), D_SOAP12),
         ("start", "a", DictStr("Action"), D_WSA10),
         ("attr", "s", DictStr("mustUnderstand"), D_SOAP12, 1),
         ("text", "AILeaveService/LeaveService/createLeave"),
         ("end",),
         ("start", "a", DictStr("To"), D_WSA10),
         ("attr", "s", DictStr("mustUnderstand"), D_SOAP12, 1),
         ("text", "net.tcp://appsrv:8201/Application/Services/OrderServiceGroup"),
         ("end",),
         ("end",),
         ("start", "s", DictStr("Body"), D_SOAP12),
         ("end",),
         ("end",)]
    )


@pytest.mark.parametrize("value", [0.0, 1.5, -2.25, 1e300])
def test_double(value):
    assert_matches_dotnet([("start", "", "d", None), ("text", value), ("end",)])


@pytest.mark.parametrize(
    "value",
    [_dt.datetime(2026, 7, 22), _dt.datetime(2026, 8, 12, 13, 45, 30), _dt.datetime(1, 1, 1)],
)
def test_datetime(value):
    assert_matches_dotnet([("start", "", "t", None), ("text", value), ("end",)])


def test_datetime_naive_is_unspecified_kind():
    """X++ date fields must go out as Kind=Unspecified or AX shifts the day."""
    writer = BinaryXmlWriter()
    writer.start_element("", "t")
    writer.write_datetime(_dt.datetime(2026, 7, 22))
    writer.end_element()
    data = writer.getvalue()
    # Top two bits of the 8-byte little-endian value carry DateTimeKind.
    assert data[-1] >> 6 == 0, f"expected Kind=Unspecified, got {data[-1] >> 6}"


def test_guid():
    value = _uuid.UUID("12345678-1234-5678-1234-567812345678")
    assert_matches_dotnet([("start", "", "g", None), ("text", value), ("end",)])


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------
def expected_events(ops):
    """Reduce an op list to the event stream the reader should produce."""
    out = []
    scopes: list[dict[str, str]] = [{"xml": "http://www.w3.org/XML/1998/namespace", "": ""}]

    def in_scope(prefix):
        for scope in reversed(scopes):
            if prefix in scope:
                return scope[prefix]
        return None

    for op in ops:
        kind = op[0]
        if kind == "start":
            _, prefix, name, namespace = op
            out.append(("start", prefix, name))
            scopes.append({})
            if namespace is not None and in_scope(prefix) != namespace:
                out.append(("xmlns", prefix, namespace))
                scopes[-1][prefix] = namespace
        elif kind == "xmlns":
            out.append(("xmlns", op[1], op[2]))
            scopes[-1][op[1]] = op[2]
        elif kind == "attr":
            _, prefix, name, namespace, value = op
            if namespace is not None and prefix and in_scope(prefix) != namespace:
                out.append(("xmlns", prefix, namespace))
                scopes[-1][prefix] = namespace
            out.append(("attr", prefix, name))
            out.append(("text", value))
        elif kind == "text":
            out.append(("text", op[1]))
        elif kind == "end":
            out.append(("end",))
            scopes.pop()
    return out


@pytest.mark.parametrize(
    "ops",
    [
        [("start", "", "r", None), ("text", "hello"), ("end",)],
        [("start", "s", "Envelope", SOAP12), ("start", "s", "Body", SOAP12), ("end",), ("end",)],
        [("start", "", "n", None), ("text", 300), ("end",)],
        [("start", "", "b", None), ("text", True), ("end",)],
        [("start", "p", "x", "urn:not-in-dictionary"), ("text", "v"), ("end",)],
    ],
)
def test_reader_decodes_dotnet_bytes(ops):
    """Decode bytes produced by .NET and recover the logical event stream."""
    assert BinaryXmlReader(oracle.encode(ops)).read() == expected_events(ops)


def test_reader_roundtrips_writer():
    ops = [
        ("start", "s", "Envelope", SOAP12),
        ("start", "s", "Header", SOAP12),
        ("start", "a", "Action", WSA10), ("text", "urn:doThing"), ("end",),
        ("end",),
        ("start", "s", "Body", SOAP12), ("end",),
        ("end",),
    ]
    assert BinaryXmlReader(replay(ops)).read() == expected_events(ops)
