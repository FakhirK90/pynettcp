""".NET Message Framing Protocol -- [MC-NMF] / [MC-NMFTB].

A ``net.tcp`` connection is a stream of records, each introduced by a one-byte
type.  A full duplex-session exchange, as captured from a stock
``NetTcpBinding`` client against a local demo service::

    client -> 00 01 00                     Version 1.0
              01 02                        Mode = Duplex
              02 1d "net.tcp://host/Path"  Via
              03 08                        KnownEncoding = binary + session
              0c                           PreambleEnd
    server -> 0b                           PreambleAck
    client -> 06 a3 01 <163 bytes>         SizedEnvelope (request)
    server -> 06 94 01 <148 bytes>         SizedEnvelope (reply)
    client -> 06 49 <73 bytes>             SizedEnvelope (second request)
    client -> 07                           End

Note the client does not wait for the ack before sending the first request --
it pipelines the preamble and the message.  We do the same, which saves a
round trip on every connection.

Record boundaries have nothing to do with TCP chunk boundaries, so everything
here reads from a buffered stream rather than calling ``recv`` directly.  That
also leaves room for the security layer: once NegotiateStream is in place it
slots in as the stream, and this module is unchanged.
"""

from __future__ import annotations

import socket
from typing import BinaryIO

from .errors import PyNetTcpError
from .varint import encode_multibyte_int31, read_multibyte_int31

__all__ = [
    "RecordType",
    "NEGOTIATE_UPGRADE",
    "Mode",
    "KnownEncoding",
    "FramingError",
    "FramingFault",
    "UnexpectedRecord",
    "FramingConnection",
    "connect",
    "connect_secure",
]


class RecordType:
    """Record type bytes ([MC-NMF] 2.2). Verified ones are marked."""

    VERSION = 0x00              # verified
    MODE = 0x01                 # verified
    VIA = 0x02                  # verified
    KNOWN_ENCODING = 0x03       # verified
    EXTENSIBLE_ENCODING = 0x04
    UNSIZED_ENVELOPE = 0x05
    SIZED_ENVELOPE = 0x06       # verified
    END = 0x07                  # verified
    FAULT = 0x08
    UPGRADE_REQUEST = 0x09
    UPGRADE_RESPONSE = 0x0A
    PREAMBLE_ACK = 0x0B         # verified
    PREAMBLE_END = 0x0C         # verified


class Mode:
    SINGLETON_UNSIZED = 0x01
    DUPLEX = 0x02               # what NetTcpBinding uses
    SIMPLEX = 0x03
    SINGLETON_SIZED = 0x04


class KnownEncoding:
    """Encoding byte of the KnownEncoding record."""

    SOAP11_UTF8 = 0x00
    SOAP11_UTF16 = 0x01
    SOAP11_UTF16LE = 0x02
    SOAP12_UTF8 = 0x03
    SOAP12_UTF16 = 0x04
    SOAP12_UTF16LE = 0x05
    MTOM = 0x06
    BINARY = 0x07               # application/soap+msbin1
    BINARY_SESSION = 0x08       # application/soap+msbinsession1 -- verified


#: Content type negotiated for a Windows-authenticated upgrade.
NEGOTIATE_UPGRADE = "application/negotiate"

MAJOR_VERSION = 1
MINOR_VERSION = 0


class FramingError(PyNetTcpError):
    """The peer violated the framing protocol, or the connection died."""


class UnexpectedRecord(FramingError):
    def __init__(self, expected: int, actual: int) -> None:
        super().__init__(
            f"expected record 0x{expected:02X}, got 0x{actual:02X}"
        )
        self.expected = expected
        self.actual = actual


class FramingFault(FramingError):
    """A Fault record -- the peer refused before SOAP even started.

    The payload is a bare URI such as
    ``http://schemas.microsoft.com/ws/2006/05/framing/faults/EndpointNotFound``.
    These are worth surfacing distinctly: they mean the address, the encoding
    or the upgrade was rejected, none of which look like a SOAP fault.
    """

    def __init__(self, fault_uri: str) -> None:
        super().__init__(f"framing fault from peer: {fault_uri}")
        self.fault_uri = fault_uri

    @property
    def short(self) -> str:
        """The last path segment, e.g. ``EndpointNotFound``."""
        return self.fault_uri.rsplit("/", 1)[-1]


def _string_record(record: int, value: str) -> bytes:
    encoded = value.encode("utf-8")
    return bytes([record]) + encode_multibyte_int31(len(encoded)) + encoded


class FramingConnection:
    """The [MC-NMF] record layer over an already-connected stream.

    Owns no socket policy beyond timeouts -- construct it with a stream so the
    security layer can wrap the socket transparently later.
    """

    def __init__(
        self,
        stream: BinaryIO,
        via: str,
        *,
        mode: int = Mode.DUPLEX,
        encoding: int = KnownEncoding.BINARY_SESSION,
    ) -> None:
        self.stream = stream
        self.via = via
        self.mode = mode
        self.encoding = encoding
        self._preamble_acked = False
        self._ended = False

    # -- low level --------------------------------------------------------
    def _write(self, data: bytes) -> None:
        self.stream.write(data)
        self.stream.flush()

    def _read_exact(self, count: int) -> bytes:
        data = self.stream.read(count)
        if data is None or len(data) < count:
            got = 0 if data is None else len(data)
            raise FramingError(
                f"connection closed after {got} of {count} expected bytes"
            )
        return data

    def _read_record_type(self) -> int:
        return self._read_exact(1)[0]

    def _read_string(self) -> str:
        length = read_multibyte_int31(self.stream)
        return self._read_exact(length).decode("utf-8")

    def _check(self, actual: int, expected: int) -> None:
        """Raise for an unexpected record, decoding Fault records specially."""
        if actual == expected:
            return
        if actual == RecordType.FAULT:
            raise FramingFault(self._read_string())
        raise UnexpectedRecord(expected, actual)

    # -- preamble ---------------------------------------------------------
    def preamble_bytes(self, *, upgrade: str | None = None) -> bytes:
        """The preamble as a single buffer.

        ``upgrade`` replaces PreambleEnd with an UpgradeRequest, which is how a
        secured connection starts: the token exchange happens next and
        PreambleEnd follows only once the stream is protected.
        """
        parts = [
            bytes([RecordType.VERSION, MAJOR_VERSION, MINOR_VERSION]),
            bytes([RecordType.MODE, self.mode]),
            _string_record(RecordType.VIA, self.via),
            bytes([RecordType.KNOWN_ENCODING, self.encoding]),
        ]
        parts.append(
            _string_record(RecordType.UPGRADE_REQUEST, upgrade)
            if upgrade is not None
            else bytes([RecordType.PREAMBLE_END])
        )
        return b"".join(parts)

    def send_preamble(self, *, upgrade: str | None = None) -> None:
        self._write(self.preamble_bytes(upgrade=upgrade))

    def send_preamble_end(self) -> None:
        """PreambleEnd on its own -- used after a security upgrade."""
        self._write(bytes([RecordType.PREAMBLE_END]))

    def read_upgrade_response(self) -> None:
        self._check(self._read_record_type(), RecordType.UPGRADE_RESPONSE)

    def read_preamble_ack(self) -> None:
        if self._preamble_acked:
            return
        self._check(self._read_record_type(), RecordType.PREAMBLE_ACK)
        self._preamble_acked = True

    # -- messages ---------------------------------------------------------
    def send_envelope(self, payload: bytes) -> None:
        """Send one SizedEnvelope record."""
        if self._ended:
            raise FramingError("cannot send after End")
        self._write(
            bytes([RecordType.SIZED_ENVELOPE])
            + encode_multibyte_int31(len(payload))
            + payload
        )

    def read_envelope(self) -> bytes | None:
        """Read one SizedEnvelope payload, or None if the peer sent End."""
        self.read_preamble_ack()

        record = self._read_record_type()
        if record == RecordType.END:
            self._ended = True
            return None
        self._check(record, RecordType.SIZED_ENVELOPE)

        size = read_multibyte_int31(self.stream)
        return self._read_exact(size)

    def send_end(self) -> None:
        if self._ended:
            return
        self._write(bytes([RecordType.END]))
        self._ended = True

    # -- lifecycle --------------------------------------------------------
    def close(self) -> None:
        try:
            self.send_end()
        except (FramingError, OSError):
            pass
        try:
            self.stream.close()
        except OSError:
            pass

    def __enter__(self) -> "FramingConnection":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


def _open_stream(uri: str, timeout: float) -> BinaryIO:
    host, port, _ = parse_net_tcp_uri(uri)
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock.makefile("rwb")


def connect(
    uri: str,
    *,
    timeout: float = 30.0,
    mode: int = Mode.DUPLEX,
    encoding: int = KnownEncoding.BINARY_SESSION,
) -> FramingConnection:
    """Open an unsecured connection and send the preamble.

    The preamble is written immediately and the ack is collected lazily on the
    first read, so the caller can pipeline its first request behind it exactly
    as WCF does.

    This is ``SecurityMode.None``.  For the ``NetTcpBinding`` default use
    :func:`connect_secure`.
    """
    connection = FramingConnection(
        _open_stream(uri, timeout), uri, mode=mode, encoding=encoding
    )
    connection.send_preamble()
    return connection


def connect_secure(
    uri: str,
    *,
    spn: str | None = None,
    timeout: float = 30.0,
    mode: int = Mode.DUPLEX,
    encoding: int = KnownEncoding.BINARY_SESSION,
    username: str | None = None,
    password: str | None = None,
    encrypt: bool = True,
) -> FramingConnection:
    """Open a Windows-authenticated connection (``SecurityMode.Transport``).

    Follows WCF's own sequence, including its pipelining: the preamble ends
    with an UpgradeRequest and the first SPNEGO token goes out behind it in
    the same write, without waiting for the UpgradeResponse.

        Version, Mode, Via, KnownEncoding, UpgradeRequest + first token
        <- UpgradeResponse, then the token exchange
        PreambleEnd  (now inside an encrypted frame)
        <- PreambleAck
    """
    from .nns import NegotiateStream
    from .security import create_context, default_spn

    host, _, _ = parse_net_tcp_uri(uri)
    target = spn or default_spn(host)

    context = create_context(
        target, username=username, password=password, encrypt=encrypt
    )

    stream = _open_stream(uri, timeout)
    connection = FramingConnection(stream, uri, mode=mode, encoding=encoding)

    first_token = context.step(None)
    if not first_token:
        raise FramingError("security context produced no initial token")

    secured = NegotiateStream(stream, context)

    stream.write(connection.preamble_bytes(upgrade=NEGOTIATE_UPGRADE))
    stream.flush()

    # Wait for the UpgradeResponse before sending the first SPNEGO token, even
    # though a stock WCF client pipelines the two.
    #
    # WCF's ServerSessionPreambleConnectionReader decodes the preamble out of
    # whatever a single socket read returned, and after the upgrade it resumes
    # decoding from that same buffer. If the first token shares a read with the
    # preamble, those bytes are still sitting there and get decoded as the
    # record that should follow: the server lands on byte 2 of
    # `16 01 00 00 7b` and reports
    #
    #     Expected record type 'PreambleEnd', found 'Version'
    #
    # having already logged that it accepted the upgrade -- so it presents as a
    # crypto failure and resets the connection with no diagnostic at all.
    #
    # WCF's own client survives only because its writes happen to land in
    # separate reads. Waiting for the response makes the boundary a fact rather
    # than a race, for one round trip per connection.
    connection.read_upgrade_response()

    secured.send_token(first_token)
    secured.handshake(first_token=first_token)

    # Framing resumes on the secured stream -- PreambleEnd onwards is encrypted.
    connection.stream = secured
    connection.send_preamble_end()
    return connection


def parse_net_tcp_uri(uri: str) -> tuple[str, int, str]:
    """Split ``net.tcp://host:port/path`` into host, port and path."""
    if not uri.startswith("net.tcp://"):
        raise ValueError(f"not a net.tcp URI: {uri!r}")

    remainder = uri[len("net.tcp://"):]
    authority, _, path = remainder.partition("/")

    if authority.startswith("["):  # IPv6 literal
        host, _, port_text = authority.partition("]")
        host = host[1:]
        port_text = port_text.lstrip(":")
    else:
        host, _, port_text = authority.partition(":")

    if not host:
        raise ValueError(f"no host in net.tcp URI: {uri!r}")

    # 808 is the port net.tcp uses when the URI omits one.
    port = int(port_text) if port_text else 808
    return host, port, "/" + path
