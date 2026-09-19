"""A deliberately independent MC-NMF/net.tcp mock server for auditing pynettcp.

It decodes the framing records itself (no pynettcp code in the read path for
framing), so a framing bug in the client shows up here rather than being
cancelled out.  The NBFS/NBFX payload is decoded with pynettcp's own reader,
which is circular for encoding but fine for the transport-level questions this
rig exists to answer.
"""
from __future__ import annotations

import socket
import threading
import time


def read_varint(recv1):
    value = 0
    shift = 0
    while True:
        b = recv1()
        if b == b"":
            raise EOFError("eof in varint")
        byte = b[0]
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value
        shift += 7


def enc_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        s = value & 0x7F
        value >>= 7
        if value:
            out.append(s | 0x80)
        else:
            out.append(s)
            return bytes(out)


class MockServer:
    """Behaviours: 'echo', 'fault', 'framing_fault', 'drip', 'reset',
    'silent', 'end', 'large', 'garbage'."""

    def __init__(self, behaviour="echo", *, reply_builder=None, builder_factory=None, drip_delay=0.0,
                 large_size=300_000, ack_delay=0.0):
        self.behaviour = behaviour
        self.reply_builder = reply_builder
        self.builder_factory = builder_factory
        self.drip_delay = drip_delay
        self.large_size = large_size
        self.ack_delay = ack_delay
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.preamble = {}
        self.requests = []          # raw SizedEnvelope payloads received
        self.error = None
        self.connections = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    @property
    def uri(self):
        return f"net.tcp://127.0.0.1:{self.port}/Demo"

    def _serve(self):
        try:
            while True:
                conn, _ = self.sock.accept()
                self.connections += 1
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        except OSError:
            pass

    def _handle(self, conn):
        try:
            self._session(conn)
        except Exception as exc:              # noqa: BLE001
            self.error = exc
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _session(self, conn):
        f = conn.makefile("rb")
        builder = self.builder_factory() if self.builder_factory else self.reply_builder

        def r1():
            return f.read(1)

        def rexact(n):
            data = f.read(n)
            if len(data) < n:
                raise EOFError("short read")
            return data

        # --- preamble --------------------------------------------------
        while True:
            t = r1()
            if t == b"":
                return
            rt = t[0]
            if rt == 0x00:
                self.preamble["version"] = rexact(2)
            elif rt == 0x01:
                self.preamble["mode"] = rexact(1)[0]
            elif rt == 0x02:
                self.preamble["via"] = rexact(read_varint(r1)).decode()
            elif rt == 0x03:
                self.preamble["encoding"] = rexact(1)[0]
            elif rt == 0x09:
                self.preamble["upgrade"] = rexact(read_varint(r1)).decode()
                # We do not implement NegotiateStream; reject cleanly.
                conn.sendall(bytes([0x08]) + self._string(
                    "http://schemas.microsoft.com/ws/2006/05/framing/faults/UpgradeInvalid"))
                return
            elif rt == 0x0C:
                self.preamble["end"] = True
                break
            else:
                raise AssertionError(f"unexpected preamble record 0x{rt:02X}")

        if self.behaviour == "framing_fault":
            conn.sendall(bytes([0x08]) + self._string(
                "http://schemas.microsoft.com/ws/2006/05/framing/faults/EndpointNotFound"))
            return

        if self.ack_delay:
            time.sleep(self.ack_delay)
        conn.sendall(b"\x0b")               # PreambleAck

        # --- message loop ----------------------------------------------
        while True:
            t = r1()
            if t == b"":
                return
            rt = t[0]
            if rt == 0x07:                   # End
                conn.sendall(b"\x07")
                return
            if rt != 0x06:
                raise AssertionError(f"unexpected record 0x{rt:02X}")
            size = read_varint(r1)
            payload = rexact(size)
            self.requests.append(payload)

            if self.behaviour == "silent":
                time.sleep(30)
                return
            if self.behaviour == "reset":
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                __import__("struct").pack("ii", 1, 0))
                conn.close()
                return
            if self.behaviour == "end":
                conn.sendall(b"\x07")
                return
            if self.behaviour == "garbage":
                conn.sendall(bytes([0x06]) + enc_varint(5) + b"\xff\xff\xff\xff\xff")
                continue

            reply = builder(payload) if builder else b""
            frame = bytes([0x06]) + enc_varint(len(reply)) + reply
            if self.behaviour == "drip":
                for i in range(len(frame)):
                    conn.sendall(frame[i:i + 1])
                    if self.drip_delay:
                        time.sleep(self.drip_delay)
            else:
                conn.sendall(frame)

    @staticmethod
    def _string(value: str) -> bytes:
        data = value.encode()
        return enc_varint(len(data)) + data

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass
