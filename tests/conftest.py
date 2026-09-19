"""Shared fixtures, including the local demo WCF service.

The rig is compiled and launched on demand and torn down afterwards, so the
live tests need no manual setup -- and, importantly, no external service.
Everything runs against ``net.tcp://localhost`` against code in this repo.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RIG = ROOT / "tests" / "rig"

CSC = (
    Path(os.environ.get("WINDIR", r"C:\Windows"))
    / "Microsoft.NET"
    / "Framework64"
    / "v4.0.30319"
    / "csc.exe"
)

REFERENCES = ["-r:System.ServiceModel.dll", "-r:System.Runtime.Serialization.dll"]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _build(source: str, output: str) -> Path:
    """Compile a rig executable, reusing it if it is already up to date."""
    source_path, output_path = RIG / source, RIG / output
    if output_path.is_file() and output_path.stat().st_mtime >= source_path.stat().st_mtime:
        return output_path

    subprocess.run(
        [str(CSC), "-nologo", "-target:exe", f"-out:{output_path}", *REFERENCES, str(source_path)],
        check=True,
        capture_output=True,
        cwd=RIG,
    )
    return output_path


requires_rig = pytest.mark.skipif(
    not CSC.is_file() or sys.platform != "win32",
    reason="needs the .NET Framework C# compiler to build the demo service",
)


class DemoService:
    """A running instance of the local demo WCF service."""

    def __init__(self, port: int, security: str, process: subprocess.Popen) -> None:
        self.port = port
        self.security = security
        self.process = process

    @property
    def uri(self) -> str:
        return f"net.tcp://localhost:{self.port}/Demo"


def _start(security: str) -> DemoService:
    executable = _build("DemoService.cs", "DemoService.exe")
    port = _free_port()

    process = subprocess.Popen(
        [str(executable), str(port), security],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=RIG,
    )

    # The service prints READY once it is listening, so wait on that rather
    # than sleeping and hoping.
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if not line:
            break
        if line.startswith("READY"):
            return DemoService(port, security, process)
        if line.startswith("FAILED"):
            process.kill()
            pytest.skip(f"demo service could not start: {line.strip()}")

    process.kill()
    pytest.skip("demo service did not report READY within 30s")


def _stop(service: DemoService) -> None:
    service.process.kill()
    service.process.wait(timeout=10)


@pytest.fixture(scope="session")
def demo_service():
    """The demo service with transport security off (framing + encoding only)."""
    service = _start("None")
    try:
        yield service
    finally:
        _stop(service)


@pytest.fixture(scope="session")
def secure_demo_service():
    """The demo service with Windows transport security -- the NetTcpBinding default."""
    service = _start("Transport")
    try:
        yield service
    finally:
        _stop(service)


@pytest.fixture(scope="session")
def local_spn():
    """SPN for a service hosted by this machine.

    The demo service runs as the current user rather than a service account,
    so there is no registered SPN of its own; ``host/<machine>`` is what WCF
    itself falls back to, and it resolves through NTLM on loopback.
    """
    from pynettcp.security import default_spn

    return default_spn("localhost")


requires_security = pytest.mark.skipif(
    __import__("importlib.util", fromlist=["util"]).find_spec("spnego") is None,
    reason="needs pyspnego for Windows authentication",
)
