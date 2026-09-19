from __future__ import annotations
import sys, os, threading
sys.path.insert(0, os.path.dirname(__file__))
from mock_server import MockServer
from pynettcp import Channel
from pynettcp.nbfs import SessionCodec
from pynettcp.nbfx import SessionStr
from pynettcp.soap import write_envelope

def correlating_builder():
    state = {}
    def build(payload):
        codec = state.setdefault("codec", SessionCodec())
        rd = state.setdefault("read", SessionCodec())
        events = rd.decode(payload)
        marker = None
        for i, e in enumerate(events):
            if e[0] == "start" and e[2] == "Marker":
                for j in range(i+1, len(events)):
                    if events[j][0] == "text":
                        marker = events[j][1]
                        break
                    if events[j][0] == "end":
                        break
        def body(w):
            w.start_element("", SessionStr("EchoResponse"), SessionStr("urn:Demo"))
            w.start_element("", SessionStr("Marker"), SessionStr("urn:Demo"))
            w.write_string("M:" + str(marker))
            w.end_element()
            w.end_element()
        return codec.encode(lambda w: write_envelope(
            w, action="urn:Demo/EchoResponse", to="net.tcp://x/Demo", body=body))
    return build

def mk_body(tag):
    def body(w):
        w.start_element("", SessionStr("Marker"), SessionStr("urn:Demo"))
        w.write_string(tag)
        w.end_element()
    return body

def test_single_thread_correlation_sanity():
    srv = MockServer(builder_factory=correlating_builder)
    try:
        with Channel(srv.uri) as ch:
            for i in range(5):
                r = ch.call(action="urn:Demo/Echo", body=mk_body(f"t{i}"))
                texts=[e[1] for e in r.body_events if e[0]=="text"]
                print("  ", i, texts)
    finally:
        srv.close()

def test_concurrency_corrupts_stream():
    srv = MockServer(builder_factory=correlating_builder)
    bad=[]; errs=[]
    try:
        with Channel(srv.uri) as ch:
            def worker(tid):
                try:
                    for i in range(30):
                        tag=f"T{tid}I{i}"
                        r = ch.call(action="urn:Demo/Echo", body=mk_body(tag))
                        texts=[e[1] for e in r.body_events if e[0]=="text"]
                        if f"M:{tag}" not in texts:
                            bad.append((tag,texts))
                except Exception as e:
                    errs.append(repr(e))
            ts=[threading.Thread(target=worker,args=(i,)) for i in range(4)]
            for t in ts: t.start()
            for t in ts: t.join(timeout=30)
        print(f"\n  mismatched={len(bad)} client_errors={len(errs)} server_error={srv.error!r}")
        print(f"  sample mismatches: {bad[:4]}")
        print(f"  sample errors: {errs[:3]}")
    finally:
        srv.close()
