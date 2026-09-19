"""Windows transport security -- [MS-NNS] framing and live authenticated calls.

The live tests run against the local demo service in ``tests/rig`` started with
``SecurityMode.Transport``, which is the ``NetTcpBinding`` default. As
everywhere else in this suite, no external service is involved.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from conftest import requires_rig, requires_security  # noqa: E402
from pynettcp.channel import Channel  # noqa: E402
from pynettcp.framing import RecordType  # noqa: E402
from pynettcp.nbfx import SessionStr  # noqa: E402
from pynettcp.nns import MessageType, NegotiateStream, NnsError  # noqa: E402
from pynettcp.security import default_spn, describe_spn_problem, split_spn  # noqa: E402

CAPTURE = json.loads((ROOT / "tests" / "golden" / "framing_transport.json").read_text("utf-8"))
C2S = bytes.fromhex(CAPTURE["c2s"])
S2C = bytes.fromhex(CAPTURE["s2c"])

ECHO_ACTION = "urn:DemoService/IDemoService/Echo"
ADD_ACTION = "urn:DemoService/IDemoService/Add"
DEMO_NS = SessionStr("urn:DemoService")


def echo_body(text: str):
    def write(writer):
        writer.start_element("", SessionStr("Echo"), DEMO_NS)
        writer.start_element("", SessionStr("text"))
        writer.value(text)
        writer.end_element()
        writer.end_element()

    return write


def body_text(envelope) -> list:
    return [event[1] for event in envelope.body_events if event[0] == "text"]


# ---------------------------------------------------------------------------
# SPN handling
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "spn,expected",
    [
        ("host/server.corp.com", ("host", "server.corp.com")),
        ("AIF/appsrv", ("AIF", "appsrv")),
        ("svc@corp.com", ("", "svc@corp.com")),   # a UPN has no service part
    ],
)
def test_split_spn(spn, expected):
    assert split_spn(spn) == expected


def test_default_spn_resolves_loopback():
    """host/localhost is never a real principal, so loopback maps to the machine."""
    assert default_spn("localhost") != "host/localhost"
    assert default_spn("appsrv") == "host/appsrv"


def test_spn_diagnostics_are_actionable():
    """A failed handshake should point at setspn, not at the library."""
    assert "setspn -Q AIF/appsrv" in describe_spn_problem("AIF/appsrv")
    assert "setspn -L svcaccount" in describe_spn_problem("svcaccount@example.com")


# ---------------------------------------------------------------------------
# NNS framing, against the captured WCF exchange
# ---------------------------------------------------------------------------
def test_captured_upgrade_request_then_token():
    """The preamble ends with UpgradeRequest, and the token follows it."""
    assert bytes([RecordType.UPGRADE_REQUEST, 0x15]) + b"application/negotiate" in C2S[:61]

    message_type, major, minor, length = struct.unpack(">BBBH", C2S[61:66])
    assert message_type == MessageType.HANDSHAKE_IN_PROGRESS
    assert (major, minor) == (1, 0)
    assert length == 123
    # SPNEGO NegTokenInit: GSS-API framing with the SPNEGO OID 1.3.6.1.5.5.2
    assert C2S[66:76].hex(" ") == "60 79 06 06 2b 06 01 05 05 02"


def test_captured_server_sends_upgrade_response_first():
    assert S2C[0] == RecordType.UPGRADE_RESPONSE


def test_captured_handshake_ends_with_handshake_done():
    """The server's second frame is HandshakeDone, and it carries a token."""
    message_type, _, _, length = struct.unpack(">BBBH", S2C[289:294])
    assert message_type == MessageType.HANDSHAKE_DONE
    assert length == 29, "HandshakeDone carries a mechListMIC that must be consumed"


def test_captured_data_frames_are_little_endian():
    """Framing flips from 5-byte big-endian headers to 4-byte little-endian."""
    (length,) = struct.unpack("<I", C2S[315:319])
    assert length == 17
    # 16 bytes of NTLM signature plus one byte of plaintext: PreambleEnd.
    assert C2S[319:323].hex(" ") == "01 00 00 00"


def test_write_before_handshake_is_refused():
    stream = NegotiateStream(None, None)
    with pytest.raises(NnsError, match="before the handshake"):
        stream.write(b"x")


def test_unknown_handshake_frame_is_rejected():
    class FakeStream:
        def read(self, count):
            return b"\x99\x01\x00\x00\x00"[:count]

    stream = NegotiateStream(FakeStream(), None)
    with pytest.raises(NnsError, match="expected a handshake frame"):
        stream.read_token()


# ---------------------------------------------------------------------------
# Live authenticated calls
# ---------------------------------------------------------------------------
@requires_rig
@requires_security
def test_authenticated_call(secure_demo_service, local_spn):
    with Channel(secure_demo_service.uri, security="transport", spn=local_spn) as channel:
        reply = channel.call(action=ECHO_ACTION, body=echo_body("hello"))

    assert not reply.is_fault
    assert "hello" in body_text(reply)


@requires_rig
@requires_security
def test_many_authenticated_calls_on_one_session(secure_demo_service, local_spn):
    """One handshake, many calls -- the expensive part is paid once."""
    with Channel(secure_demo_service.uri, security="transport", spn=local_spn) as channel:
        for index in range(5):
            reply = channel.call(action=ECHO_ACTION, body=echo_body(f"msg{index}"))
            assert f"msg{index}" in body_text(reply)


@requires_rig
@requires_security
def test_typed_arguments_over_a_secured_channel(secure_demo_service, local_spn):
    def write(writer):
        writer.start_element("", SessionStr("Add"), DEMO_NS)
        writer.start_element("", SessionStr("a"))
        writer.value(20)
        writer.end_element()
        writer.start_element("", SessionStr("b"))
        writer.value(22)
        writer.end_element()
        writer.end_element()

    with Channel(secure_demo_service.uri, security="transport", spn=local_spn) as channel:
        reply = channel.call(action=ADD_ACTION, body=write)

    assert 42 in body_text(reply)


@requires_rig
@requires_security
def test_large_message_is_chunked_across_frames(secure_demo_service, local_spn):
    """Payloads past MAX_PLAINTEXT_CHUNK must split and reassemble."""

    def write(writer):
        writer.start_element("", SessionStr("EchoLarge"), DEMO_NS)
        writer.start_element("", SessionStr("size"))
        writer.value(300_000)
        writer.end_element()
        writer.end_element()

    with Channel(secure_demo_service.uri, security="transport", spn=local_spn) as channel:
        reply = channel.call(
            action="urn:DemoService/IDemoService/EchoLarge", body=write
        )

    assert any(isinstance(v, str) and len(v) == 300_000 for v in body_text(reply))


@requires_rig
@requires_security
def test_unsecured_client_cannot_talk_to_a_secured_service(secure_demo_service):
    """Skipping the upgrade must fail, not silently downgrade."""
    with pytest.raises(Exception) as caught:
        with Channel(secure_demo_service.uri) as channel:
            channel.call(action=ECHO_ACTION, body=echo_body("hi"))

    assert not isinstance(caught.value, AssertionError)


@requires_rig
@requires_security
def test_secured_client_cannot_talk_to_an_unsecured_service(demo_service, local_spn):
    with pytest.raises(Exception) as caught:
        with Channel(demo_service.uri, security="transport", spn=local_spn) as channel:
            channel.call(action=ECHO_ACTION, body=echo_body("hi"))

    assert not isinstance(caught.value, AssertionError)


def test_channel_rejects_an_unknown_security_mode():
    with pytest.raises(ValueError, match="'none' or 'transport'"):
        Channel("net.tcp://localhost:1/X", security="ssl")
