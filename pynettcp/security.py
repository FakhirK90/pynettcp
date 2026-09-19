"""Windows authentication for ``net.tcp`` -- SPNEGO/Kerberos/NTLM via pyspnego.

``NetTcpBinding`` defaults to ``SecurityMode.Transport`` with a Windows
credential, so most real endpoints need this.  The actual crypto is delegated
to ``pyspnego``, which uses SSPI on Windows and GSSAPI elsewhere; this module
only adapts it to the narrow contract :mod:`pynettcp.nns` expects, and works
out which SPN to ask for.

The SPN is the part that goes wrong in practice
-----------------------------------------------
Kerberos authenticates to a *service principal*, not to a host and port.  If
the SPN is not registered against the account the service runs under, the KDC
cannot issue a ticket and SPNEGO quietly falls back to NTLM -- or fails.  So
this module never guesses silently: pass ``spn=`` explicitly when the default
``host/<hostname>`` is not right, and read :func:`describe_spn_problem` when a
handshake fails.

A WCF endpoint identity is often published as a UPN (``svc@domain.com``) rather
than an SPN.  There is no way to derive one from the other, so a UPN is passed
straight through to the credential layer and Kerberos resolves it -- which is
also why the failure mode is worth explaining rather than papering over.
"""

from __future__ import annotations

import socket

from .nns import SecurityContext

__all__ = [
    "SpnegoContext",
    "default_spn",
    "split_spn",
    "create_context",
    "describe_spn_problem",
]


def default_spn(host: str) -> str:
    """The SPN WCF assumes when an endpoint publishes no identity.

    ``localhost`` is resolved to the real machine name because a Kerberos
    ticket for ``host/localhost`` is meaningless; this keeps loopback testing
    behaving like the remote case.
    """
    if host in ("localhost", "127.0.0.1", "::1"):
        host = socket.gethostname()
    return f"host/{host}"


def split_spn(spn: str) -> tuple[str, str]:
    """Split ``service/host`` into ``(service, host)``.

    A UPN (``svc@domain.com``) has no service part, so it is returned whole as
    the host and pyspnego is left to resolve it.
    """
    service, separator, host = spn.partition("/")
    if not separator:
        return "", spn
    return service, host


class SpnegoContext:
    """Adapts a ``pyspnego`` context to :class:`pynettcp.nns.SecurityContext`."""

    def __init__(self, inner) -> None:
        self._inner = inner

    @property
    def complete(self) -> bool:
        return bool(self._inner.complete)

    def step(self, in_token: bytes | None = None) -> bytes | None:
        return self._inner.step(in_token)

    def wrap(self, data: bytes) -> bytes:
        # encrypt=True matches ProtectionLevel.EncryptAndSign, the
        # NetTcpBinding default. Sign-only would pass encrypt=False.
        return self._inner.wrap(data, encrypt=True).data

    def unwrap(self, data: bytes) -> bytes:
        return self._inner.unwrap(data).data

    @property
    def negotiated_protocol(self) -> str | None:
        """``kerberos`` or ``ntlm`` once known -- useful when diagnosing SPNs."""
        return getattr(self._inner, "negotiated_protocol", None)


def create_context(
    spn: str,
    *,
    username: str | None = None,
    password: str | None = None,
    protocol: str = "negotiate",
    encrypt: bool = True,
) -> SpnegoContext:
    """Build a client security context for ``spn``.

    With no username or password the current Windows login is used through
    SSPI, which is what makes single sign-on work.
    """
    try:
        import spnego
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise RuntimeError(
            "Windows authentication needs pyspnego: pip install 'pynettcp[security]'"
        ) from exc

    service, host = split_spn(spn)

    # These mirror what .NET's NegotiateStream requests. `identify` matters:
    # NegotiateStream defaults to TokenImpersonationLevel.Identification, which
    # sets ISC_REQ_IDENTIFY and so NTLMSSP_NEGOTIATE_IDENTIFY in the negotiate
    # token. Omitting it leaves our flags one bit off WCF's, and the peer drops
    # the connection without a diagnostic.
    context_req = (
        spnego.ContextReq.mutual_auth
        | spnego.ContextReq.replay_detect
        | spnego.ContextReq.sequence_detect
        | spnego.ContextReq.integrity
        | spnego.ContextReq.identify
    )
    if encrypt:
        context_req |= spnego.ContextReq.confidentiality

    inner = spnego.client(
        username=username,
        password=password,
        hostname=host,
        service=service or None,
        protocol=protocol,
        context_req=context_req,
    )
    return SpnegoContext(inner)


def describe_spn_problem(spn: str) -> str:
    """A hint for a failed handshake, aimed at whoever has to fix AD.

    Kerberos failures surface as an opaque reset or a generic SSPI error, and
    the cause is almost always registration rather than code.
    """
    service, host = split_spn(spn)
    if not service:
        return (
            f"{spn!r} looks like a UPN. Kerberos resolves a UPN only if the "
            "account owning it has a matching SPN registered. Check with:\n"
            f"    setspn -L {spn.split('@')[0]}\n"
            "An empty list means no ticket can be issued for this service."
        )
    return (
        f"No Kerberos ticket could be obtained for {spn!r}. Verify the SPN is "
        "registered against the account the service runs under:\n"
        f"    setspn -Q {spn}\n"
        "If it is missing, an administrator can add it with:\n"
        f"    setspn -S {spn} <DOMAIN>\\<service-account>\n"
        "Without it SPNEGO falls back to NTLM, which the service may refuse."
    )
