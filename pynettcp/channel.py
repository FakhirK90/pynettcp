"""The public entry point: a duplex session channel to a ``net.tcp`` endpoint.

Composes the whole stack -- socket, [MC-NMF] framing, [MC-NBFS] session
dictionary, SOAP 1.2 envelope -- into one object::

    with Channel("net.tcp://localhost:8899/Demo") as channel:
        reply = channel.call(
            action="urn:DemoService/IDemoService/Echo",
            body=lambda w: ...,
        )

The channel is a *session*: one TCP connection, one pair of session
dictionaries, many calls.  Reusing it is not merely an optimisation -- the
dictionary state is what makes later messages small, and with security enabled
it is also what avoids repeating the authentication handshake.
"""

from __future__ import annotations

import threading
import uuid as _uuid
from typing import Callable

from .errors import PyNetTcpError
from .framing import FramingConnection, KnownEncoding, connect, connect_secure
from .nbfs import SessionCodec
from .soap import Envelope, parse_envelope, write_envelope

__all__ = ["Channel", "ChannelError"]

BodyWriter = Callable[[object], None]


class ChannelError(PyNetTcpError):
    """The channel could not complete a call."""


class Channel:
    """A duplex-session channel over ``net.tcp``."""

    def __init__(
        self,
        uri: str,
        *,
        security: str = "none",
        spn: str | None = None,
        username: str | None = None,
        password: str | None = None,
        encrypt: bool = True,
        timeout: float = 30.0,
        max_session_size: int = 2048,
        send_message_id: bool = True,
        send_reply_to: bool = True,
    ) -> None:
        """Open a channel to ``uri``.

        ``security`` is ``"none"`` or ``"transport"``.  Transport is the
        ``NetTcpBinding`` default and means Windows authentication; ``spn``
        overrides the target service principal when the default
        ``host/<hostname>`` is not what the service registered.

        The default here is ``"none"`` rather than matching WCF, because an
        unauthenticated attempt fails immediately and legibly, whereas a
        misconfigured SPN fails as an opaque reset.
        """
        if security not in ("none", "transport"):
            raise ValueError(f"security must be 'none' or 'transport', not {security!r}")

        self.uri = uri
        self.security = security
        self.spn = spn
        self.username = username
        self.password = password
        self.encrypt = encrypt
        self.timeout = timeout
        # WCF's own client sends MessageID and an anonymous ReplyTo on every
        # request, so these default on -- some dispatchers reject a request
        # without them.
        self.send_message_id = send_message_id
        self.send_reply_to = send_reply_to

        self._codec = SessionCodec(max_session_size)
        self._connection: FramingConnection | None = None
        self._max_session_size = max_session_size
        # A net.tcp session is a single ordered request/reply stream with one
        # pair of dictionaries, so two threads interleaving on one Channel do
        # not merely race -- they hand each other the wrong reply, silently.
        # The lock makes a call atomic; it does not make the channel parallel.
        # For throughput, open one Channel per thread.
        self._lock = threading.RLock()

    # -- lifecycle --------------------------------------------------------
    def open(self) -> "Channel":
        if self._connection is not None:
            return self

        if self.security == "transport":
            self._connection = connect_secure(
                self.uri,
                spn=self.spn,
                timeout=self.timeout,
                encoding=KnownEncoding.BINARY_SESSION,
                username=self.username,
                password=self.password,
                encrypt=self.encrypt,
            )
        else:
            self._connection = connect(
                self.uri, timeout=self.timeout, encoding=KnownEncoding.BINARY_SESSION
            )
        return self

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "Channel":
        return self.open()

    def __exit__(self, *exc_info) -> None:
        self.close()

    @property
    def connection(self) -> FramingConnection:
        if self._connection is None:
            raise ChannelError("channel is not open")
        return self._connection

    # -- calls ------------------------------------------------------------
    def call(
        self,
        *,
        action: str,
        body: BodyWriter | None = None,
        headers=(),
        to: str | None = None,
    ) -> Envelope:
        """Send a request and return the parsed reply envelope.

        Atomic with respect to other threads using this same channel.
        """
        with self._lock:
            self.open()
            self.send(action=action, body=body, headers=headers, to=to)
            return self.receive()

    def send(
        self,
        *,
        action: str,
        body: BodyWriter | None = None,
        headers=(),
        to: str | None = None,
    ) -> None:
        payload = self._codec.encode(
            lambda writer: write_envelope(
                writer,
                action=action,
                to=to or self.uri,
                body=body,
                message_id=_uuid.uuid4() if self.send_message_id else None,
                reply_to_anonymous=self.send_reply_to,
                headers=headers,
            )
        )
        self.connection.send_envelope(payload)

    def receive(self) -> Envelope:
        try:
            payload = self.connection.read_envelope()
            if payload is None:
                self.close()
                raise ChannelError("peer ended the session while a reply was expected")
            return parse_envelope(self._codec.decode(payload))
        except ChannelError:
            raise
        except Exception:
            # A failed read leaves the stream at an unknown offset and the two
            # session dictionaries out of step with the peer's. Anything sent
            # afterwards decodes as garbage, so the channel is finished: close
            # it rather than let the next call read from a desynchronised
            # stream. Reopening is the caller's decision.
            self.close()
            raise

    def __del__(self) -> None:  # pragma: no cover - best-effort cleanup
        try:
            self.close()
        except Exception:
            pass
