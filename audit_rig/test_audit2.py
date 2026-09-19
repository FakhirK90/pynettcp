"""Second round: correlation, reuse-after-error, dictionary sizing."""
from __future__ import annotations
import sys, os, threading, time
sys.path.insert(0, os.path.dirname(__file__))
import pytest
from mock_server import MockServer
from pynettcp import Channel
from pynettcp.nbfs import SessionCodec, SessionDictionary
from pynettcp.nbfx import SessionStr
from pynettcp.soap import write_envelope
from pynettcp.contract import ElementSpec, Field, TypeRegistry, write_element


def correlating_builder():
    """Echo back the request's MessageID so cross-talk is detectable."""
    state = {}
    def build(payload):
        codec = state.setdefault("codec", SessionCodec())
        # decode request with a *separate* codec that mirrors the client's outgoing dict
        rd = state.setdefault("read", SessionCodec())
        events = rd.decode(payload)
        marker = None
        for i, e in enumerate(events):
            if e[0] == "start" and e[2] == "Marker":
                marker = events[i+1][1]
        def body(w):
            w.start_element("", SessionStr("EchoResponse"), SessionStr("urn:Demo"))
            w.start_element("", SessionStr("Marker"), SessionStr("urn:Demo"))
            w.value(str(marker))
            w.end_element()
            w.end_element()
        return codec.encode(lambda w: write_envelope(
            w, action="urn:Demo/EchoResponse", to="net.tcp://x/Demo", body=body))
    return build


def test_concurrent_calls_correlation():
    srv = MockServer(builder_factory=correlating_builder)
    bad, errs = [], []
    try:
        with Channel(srv.uri) as ch:
            def worker(tid):
                try:
                    for i in range(25):
                        tag = f"{tid}-{i}"
                        def body(w, tag=tag):
                            w.start_element("", SessionStr("Marker"), SessionStr("urn:Demo"))
                            w.value(tag)
                            w.end_element()
                        r = ch.call(action="urn:Demo/Echo", body=body)
                        got = [e[1] for e in r.body_events if e[0]=="text"]
                        if tag not in got:
                            bad.append((tag, got))
                except Exception as e:
                    errs.append(repr(e))
            ts=[threading.Thread(target=worker,args=(i,)) for i in range(4)]
            for t in ts: t.start()
            for t in ts: t.join(timeout=30)
        print(f"\n  MISMATCHED replies: {len(bad)}  errors: {len(errs)}")
        print(f"  sample errors: {errs[:3]}")
        print(f"  sample mismatches: {bad[:3]}")
    finally:
        srv.close()


def test_one_big_contract_exceeds_session_budget():
    """A single message whose contract names exceed 2048 bytes."""
    d = SessionDictionary()
    total = 0
    n = 0
    try:
        for i in range(10000):
            d.session_id(f"SomeReasonablyLongFieldName{i:04d}")   # 31 bytes
            n += 1
    except Exception as e:
        print(f"\n  a single contract can intern only {n} distinct names "
              f"(~31 bytes each) before: {type(e).__name__}")
    assert n < 100


def test_channel_unusable_after_error():
    srv = MockServer(behaviour="garbage")
    try:
        ch = Channel(srv.uri)
        with pytest.raises(Exception):
            ch.call(action="urn:Demo/Echo", body=lambda w: None)
        # Is the channel still "open"? Does a second call do anything sane?
        print(f"\n  after error: _connection is None? {ch._connection is None}")
        with pytest.raises(Exception) as e2:
            ch.call(action="urn:Demo/Echo", body=lambda w: None)
        print(f"  second call raised {type(e2.value).__name__}: {e2.value}")
        ch.close()
    finally:
        srv.close()


def test_timeout_leaves_channel_open():
    srv = MockServer(behaviour="silent")
    try:
        ch = Channel(srv.uri, timeout=0.5)
        with pytest.raises(Exception):
            ch.call(action="urn:Demo/Echo", body=lambda w: None)
        print(f"\n  after timeout: _connection is None? {ch._connection is None}")
        ch.close()
    finally:
        srv.close()


def test_exception_taxonomy():
    """What must a caller catch?  Show there is no common base."""
    from pynettcp.channel import ChannelError
    from pynettcp.framing import FramingError
    from pynettcp.nbfx import NbfxError
    from pynettcp.nns import NnsError
    bases = {c.__name__: [b.__name__ for b in c.__mro__[1:]]
             for c in (ChannelError, FramingError, NbfxError, NnsError)}
    print("\n  exception hierarchy:")
    for k,v in bases.items():
        print(f"    {k}: {v}")


def test_field_name_not_identifier_round_trip():
    """A contract field whose name is a Python keyword or has odd chars."""
    from pynettcp.codegen.emit import python_identifier
    from dataclasses import dataclass
    print("\n  python_identifier('class') ->", python_identifier("class"))
    print("  python_identifier('Order-Id') ->", python_identifier("Order-Id"))
    print("  python_identifier('_DocumentHash') ->", python_identifier("_DocumentHash"))

    @dataclass
    class T:
        class_: str | None = None
    reg = TypeRegistry(types={"T": __import__("pynettcp.contract", fromlist=["ComplexType"]).ComplexType(
        name="T", namespace="urn:x", fields=(Field(name="class", type="xs:string"),))},
        factories={"T": T})
    try:
        obj = reg.build("T", {"class": "hello"})
        print("  build succeeded:", obj)
    except TypeError as e:
        print("  build FAILED:", e)
