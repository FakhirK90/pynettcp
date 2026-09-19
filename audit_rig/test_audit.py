"""Audit-only tests: pynettcp client vs an independent MC-NMF mock server."""
from __future__ import annotations

import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, __import__("os").path.dirname(__file__))
from mock_server import MockServer  # noqa: E402

from pynettcp import Channel                                   # noqa: E402
from pynettcp.framing import FramingFault, FramingError, connect  # noqa: E402
from pynettcp.nbfs import SessionCodec                          # noqa: E402
from pynettcp.nbfx import SessionStr                            # noqa: E402
from pynettcp.soap import write_envelope                        # noqa: E402


def make_reply(action="urn:Demo/EchoResponse", text="hello", size=None, fault=False):
    """Build a session-encoded reply the way a server would, per connection."""
    codec = SessionCodec()

    def body(w):
        if fault:
            w.start_element("s", SessionStr("Fault"), SessionStr(
                "http://www.w3.org/2003/05/soap-envelope"))
            w.start_element("s", SessionStr("Code"))
            w.start_element("s", SessionStr("Value"))
            w.value("s:Sender")
            w.end_element()
            w.end_element()
            w.start_element("s", SessionStr("Reason"))
            w.start_element("s", SessionStr("Text"))
            w.value("it broke")
            w.end_element()
            w.end_element()
            w.end_element()
        else:
            w.start_element("", SessionStr("EchoResponse"), SessionStr("urn:Demo"))
            w.start_element("", SessionStr("EchoResult"), SessionStr("urn:Demo"))
            w.value(text if size is None else "x" * size)
            w.end_element()
            w.end_element()

    return codec.encode(lambda w: write_envelope(
        w, action=action, to="net.tcp://127.0.0.1/Demo", body=body))


def echo_replier(size=None, fault=False):
    # One codec per connection would be correct; the mock makes a fresh reply
    # each time with a fresh codec, which is still valid session framing only
    # for the FIRST message. So keep one codec per server instance instead.
    state = {}

    def build(_payload):
        codec = state.setdefault("codec", SessionCodec())

        def body(w):
            if fault:
                w.start_element("s", SessionStr("Fault"), SessionStr(
                    "http://www.w3.org/2003/05/soap-envelope"))
                w.start_element("s", SessionStr("Code"))
                w.start_element("s", SessionStr("Value"))
                w.value("s:Sender")
                w.end_element()
                w.end_element()
                w.start_element("s", SessionStr("Reason"))
                w.start_element("s", SessionStr("Text"))
                w.value("it broke")
                w.end_element()
                w.end_element()
                w.end_element()
            else:
                w.start_element("", SessionStr("EchoResponse"), SessionStr("urn:Demo"))
                w.start_element("", SessionStr("EchoResult"), SessionStr("urn:Demo"))
                w.value("hello" if size is None else "x" * size)
                w.end_element()
                w.end_element()

        return codec.encode(lambda w: write_envelope(
            w, action="urn:Demo/EchoResponse", to="net.tcp://127.0.0.1/Demo", body=body))

    return build


# --- 1. basic round trip ---------------------------------------------------
def test_basic_call():
    srv = MockServer(builder_factory=lambda: echo_replier())
    try:
        with Channel(srv.uri) as ch:
            reply = ch.call(action="urn:Demo/Echo", body=lambda w: None)
        assert reply.action == "urn:Demo/EchoResponse"
        assert srv.preamble["mode"] == 0x02
        assert srv.preamble["encoding"] == 0x08
        assert srv.preamble["via"] == srv.uri
        assert srv.error is None
    finally:
        srv.close()


# --- 2. many calls on one session -----------------------------------------
def test_many_calls_same_session():
    srv = MockServer(builder_factory=lambda: echo_replier())
    try:
        with Channel(srv.uri) as ch:
            for _ in range(200):
                ch.call(action="urn:Demo/Echo", body=lambda w: None)
        assert len(srv.requests) == 200
        assert srv.error is None
    finally:
        srv.close()


# --- 3. session dictionary growth ------------------------------------------
def test_session_dictionary_growth_hits_limit():
    """Distinct element names per call grow the outgoing dictionary forever."""
    srv = MockServer(builder_factory=lambda: echo_replier())
    try:
        with Channel(srv.uri) as ch:
            n = 0
            with pytest.raises(Exception) as exc:
                for i in range(2000):
                    n = i

                    def body(w, i=i):
                        w.start_element("", SessionStr(f"Field{i:05d}"),
                                        SessionStr("urn:Demo"))
                        w.value("x")
                        w.end_element()

                    ch.call(action="urn:Demo/Echo", body=body)
            print(f"\n  session dictionary exhausted after {n} calls: "
                  f"{type(exc.value).__name__}: {exc.value}")
    finally:
        srv.close()


# --- 4. fragmented TCP (1 byte at a time) ----------------------------------
def test_fragmented_reply():
    srv = MockServer(behaviour="drip", builder_factory=lambda: echo_replier())
    try:
        with Channel(srv.uri) as ch:
            reply = ch.call(action="urn:Demo/Echo", body=lambda w: None)
        assert reply.action == "urn:Demo/EchoResponse"
    finally:
        srv.close()


# --- 5. large reply --------------------------------------------------------
def test_large_reply():
    srv = MockServer(builder_factory=lambda: echo_replier(size=400_000))
    try:
        with Channel(srv.uri) as ch:
            reply = ch.call(action="urn:Demo/Echo", body=lambda w: None)
        texts = [e[1] for e in reply.body_events if e[0] == "text"]
        assert any(isinstance(t, str) and len(t) == 400_000 for t in texts)
    finally:
        srv.close()


# --- 6. large request ------------------------------------------------------
def test_large_request():
    srv = MockServer(builder_factory=lambda: echo_replier())
    try:
        with Channel(srv.uri) as ch:
            ch.call(action="urn:Demo/Echo",
                    body=lambda w: (w.start_element("", SessionStr("Big"),
                                                    SessionStr("urn:Demo")),
                                    w.value("y" * 500_000), w.end_element()))
        assert len(srv.requests[0]) > 500_000
    finally:
        srv.close()


# --- 7. SOAP fault ---------------------------------------------------------
def test_soap_fault_is_flagged():
    srv = MockServer(builder_factory=lambda: echo_replier(fault=True))
    try:
        with Channel(srv.uri) as ch:
            reply = ch.call(action="urn:Demo/Echo", body=lambda w: None)
        assert reply.is_fault
        from pynettcp.faults import parse_fault
        fault = parse_fault(reply.body_events)
        assert fault.reason == "it broke"
        assert fault.code == "s:Sender"
    finally:
        srv.close()


# --- 8. framing fault ------------------------------------------------------
def test_framing_fault():
    srv = MockServer(behaviour="framing_fault")
    try:
        with pytest.raises(FramingFault) as exc:
            with Channel(srv.uri) as ch:
                ch.call(action="urn:Demo/Echo", body=lambda w: None)
        assert exc.value.short == "EndpointNotFound"
    finally:
        srv.close()


# --- 9. peer sends End -----------------------------------------------------
def test_peer_ends_session():
    srv = MockServer(behaviour="end")
    try:
        with Channel(srv.uri) as ch:
            with pytest.raises(Exception) as exc:
                ch.call(action="urn:Demo/Echo", body=lambda w: None)
        print(f"\n  end-of-session raised {type(exc.value).__name__}: {exc.value}")
    finally:
        srv.close()


# --- 10. connection reset --------------------------------------------------
def test_connection_reset():
    srv = MockServer(behaviour="reset")
    try:
        with pytest.raises(Exception) as exc:
            with Channel(srv.uri) as ch:
                ch.call(action="urn:Demo/Echo", body=lambda w: None)
        print(f"\n  reset raised {type(exc.value).__name__}: {exc.value}")
    finally:
        srv.close()


# --- 11. timeout -----------------------------------------------------------
def test_read_timeout():
    srv = MockServer(behaviour="silent")
    try:
        start = time.monotonic()
        with pytest.raises(Exception) as exc:
            with Channel(srv.uri, timeout=1.0) as ch:
                ch.call(action="urn:Demo/Echo", body=lambda w: None)
        elapsed = time.monotonic() - start
        print(f"\n  timeout raised {type(exc.value).__name__}: {exc.value!r} "
              f"after {elapsed:.2f}s")
        assert elapsed < 5
    finally:
        srv.close()


# --- 12. malformed payload -------------------------------------------------
def test_malformed_payload():
    srv = MockServer(behaviour="garbage")
    try:
        with pytest.raises(Exception) as exc:
            with Channel(srv.uri) as ch:
                ch.call(action="urn:Demo/Echo", body=lambda w: None)
        print(f"\n  garbage raised {type(exc.value).__name__}: {exc.value}")
    finally:
        srv.close()


# --- 13. connect to nothing ------------------------------------------------
def test_connection_refused():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(Exception) as exc:
        with Channel(f"net.tcp://127.0.0.1:{port}/Demo") as ch:
            ch.call(action="urn:Demo/Echo", body=lambda w: None)
    print(f"\n  refused raised {type(exc.value).__name__}: {exc.value}")


# --- 14. thread safety -----------------------------------------------------
def test_concurrent_calls_on_one_channel():
    srv = MockServer(builder_factory=lambda: echo_replier())
    errors = []
    try:
        with Channel(srv.uri) as ch:
            def worker():
                try:
                    for _ in range(20):
                        ch.call(action="urn:Demo/Echo", body=lambda w: None)
                except Exception as exc:                  # noqa: BLE001
                    errors.append(exc)

            threads = [threading.Thread(target=worker) for _ in range(4)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)
        print(f"\n  concurrent calls produced {len(errors)} error(s): "
              f"{[type(e).__name__ for e in errors][:3]}")
    finally:
        srv.close()


# --- 15. socket/fd leak ----------------------------------------------------
def test_no_fd_leak_over_many_connections():
    import os
    srv = MockServer(builder_factory=lambda: echo_replier())
    try:
        def fds():
            return len(os.listdir("/proc/self/fd"))
        for _ in range(5):
            with Channel(srv.uri) as ch:
                ch.call(action="urn:Demo/Echo", body=lambda w: None)
        before = fds()
        for _ in range(60):
            with Channel(srv.uri) as ch:
                ch.call(action="urn:Demo/Echo", body=lambda w: None)
        after = fds()
        print(f"\n  fds before={before} after={after}")
        assert after - before < 10, f"fd leak: {before} -> {after}"
    finally:
        srv.close()


# --- 16. leak when the caller forgets to close -----------------------------
def test_fd_leak_without_close():
    import os, gc
    srv = MockServer(builder_factory=lambda: echo_replier())
    try:
        def fds():
            return len(os.listdir("/proc/self/fd"))
        for _ in range(3):
            ch = Channel(srv.uri)
            ch.call(action="urn:Demo/Echo", body=lambda w: None)
            del ch
        gc.collect()
        before = fds()
        for _ in range(40):
            ch = Channel(srv.uri)
            ch.call(action="urn:Demo/Echo", body=lambda w: None)
            del ch
        gc.collect()
        after = fds()
        print(f"\n  no-close fds before={before} after={after}")
    finally:
        srv.close()


# --- 17. slow PreambleAck / pipelining ------------------------------------
def test_delayed_ack():
    srv = MockServer(builder_factory=lambda: echo_replier(), ack_delay=0.4)
    try:
        with Channel(srv.uri) as ch:
            reply = ch.call(action="urn:Demo/Echo", body=lambda w: None)
        assert reply.action == "urn:Demo/EchoResponse"
    finally:
        srv.close()
