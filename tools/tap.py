"""A TCP relay that logs both directions -- ground truth for the framing layer.

Sits between a stock WCF client and the local demo service, so the exact
MC-NMF record sequence a real ``NetTcpBinding`` client emits can be read off
without a packet capture, without administrator rights, and without going near
any production endpoint.

    python tools/tap.py --listen 8898 --forward 8899 --out capture.json

Each chunk is recorded with its direction and arrival order.  Chunk boundaries
are *not* record boundaries -- TCP may split or coalesce -- so the analyser
concatenates per direction before parsing.
"""

from __future__ import annotations

import argparse
import json
import socket
import threading
from pathlib import Path

CLIENT_TO_SERVER = "c2s"
SERVER_TO_CLIENT = "s2c"


class Tap:
    def __init__(self, listen_port: int, forward_port: int, host: str = "127.0.0.1") -> None:
        self.listen_port = listen_port
        self.forward_port = forward_port
        self.host = host
        self.chunks: list[dict] = []
        self._lock = threading.Lock()

    def _record(self, direction: str, data: bytes) -> None:
        with self._lock:
            self.chunks.append({"direction": direction, "hex": data.hex()})

    def _pump(self, source: socket.socket, sink: socket.socket, direction: str) -> None:
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                self._record(direction, data)
                sink.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (source, sink):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def serve_one(self, timeout: float = 30.0) -> list[dict]:
        """Relay exactly one connection, then return the recorded chunks."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.listen_port))
        listener.listen(1)
        listener.settimeout(timeout)

        try:
            client, _ = listener.accept()
        finally:
            listener.close()

        upstream = socket.create_connection((self.host, self.forward_port), timeout=timeout)

        threads = [
            threading.Thread(target=self._pump, args=(client, upstream, CLIENT_TO_SERVER)),
            threading.Thread(target=self._pump, args=(upstream, client, SERVER_TO_CLIENT)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout)

        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass

        return self.chunks

    def stream(self, direction: str) -> bytes:
        """All bytes seen in one direction, concatenated in arrival order."""
        return b"".join(
            bytes.fromhex(chunk["hex"])
            for chunk in self.chunks
            if chunk["direction"] == direction
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", type=int, default=8898)
    parser.add_argument("--forward", type=int, default=8899)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    tap = Tap(args.listen, args.forward)
    print(f"tap listening on {args.listen}, forwarding to {args.forward}", flush=True)
    tap.serve_one(args.timeout)

    c2s, s2c = tap.stream(CLIENT_TO_SERVER), tap.stream(SERVER_TO_CLIENT)
    print(f"client -> server: {len(c2s)} bytes")
    print(f"server -> client: {len(s2c)} bytes")

    if args.out:
        args.out.write_text(
            json.dumps(
                {"c2s": c2s.hex(), "s2c": s2c.hex(), "chunks": tap.chunks}, indent=2
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
