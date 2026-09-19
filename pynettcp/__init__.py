"""pynettcp -- a native Python client for WCF ``net.tcp://`` services.

No CLR, no pythonnet, no generated C# proxy assembly.  ``net.tcp`` is not a
proprietary black box; it is four published Microsoft Open Specifications
stacked on a plain TCP socket, and this package implements them:

===========  ==========================  ==========================================
Layer        Specification               Module
===========  ==========================  ==========================================
Framing      [MC-NMF], [MC-NMFTB]        ``framing``
Security     [MS-NNS]                    ``nns``, ``security``
Encoding     [MC-NBFX], [MC-NBFS]        ``nbfx``, ``nbfs``, ``dictionary``
Messaging    SOAP 1.2 + WS-Addressing    ``soap``, ``channel``, ``faults``
===========  ==========================  ==========================================

Point the generator at a service and call the result::

    python -m pynettcp.codegen net.tcp://host:8899/Demo/mex -o demo_client.py

Status: complete for the supported schema subset.  Real calls succeed against a
``NetTcpBinding`` service in both security modes, the encoding reproduces real
WCF session messages byte-for-byte, and generated clients drive it end to end.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .channel import Channel, ChannelError
from .errors import PyNetTcpError
from .framing import (
    FramingConnection,
    FramingError,
    FramingFault,
    connect,
    connect_secure,
)
from .nns import NegotiateStream, NnsError
from .nbfs import SessionCodec, SessionDictionary, SessionSizeExceeded
from .nbfx import (
    BinaryXmlReader,
    BinaryXmlWriter,
    DictStr,
    NbfxError,
    SessionStr,
    StaticDictionary,
)
from .contract import ComplexType, ElementSpec, Field, TypeRegistry
from .soap import Envelope, parse_envelope, write_envelope
from .xmltree import events_to_element, events_to_string
from .varint import decode_multibyte_int31, encode_multibyte_int31

__all__ = [
    "__version__",
    # errors
    "PyNetTcpError",
    # channel
    "Channel",
    "ChannelError",
    # framing
    "FramingConnection",
    "FramingError",
    "FramingFault",
    "connect",
    "connect_secure",
    # security
    "NegotiateStream",
    "NnsError",
    # encoding
    "BinaryXmlReader",
    "BinaryXmlWriter",
    "DictStr",
    "SessionStr",
    "StaticDictionary",
    "NbfxError",
    # session
    "SessionCodec",
    "SessionDictionary",
    "SessionSizeExceeded",
    # messaging
    "write_envelope",
    "parse_envelope",
    "Envelope",
    # contracts
    "ElementSpec",
    "Field",
    "ComplexType",
    "TypeRegistry",
    "events_to_element",
    "events_to_string",
    # primitives
    "encode_multibyte_int31",
    "decode_multibyte_int31",
]
