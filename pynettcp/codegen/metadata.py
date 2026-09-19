"""Fetch service metadata, over ``net.tcp`` MEX or plain HTTP.

Two sources, because services publish metadata in two ways:

* **WS-MetadataExchange over net.tcp** -- a ``/mex`` endpoint. Fetched using
  pynettcp itself, which is a useful proof that the transport works: the
  library reads its own service description over the protocol it implements.
* **HTTP ``?wsdl``** -- common where a metadata port is exposed separately.
  ``xsd:import`` / ``wsdl:import`` references are followed.

Both return the same thing: a list of XML roots (``wsdl:definitions`` and
``xs:schema`` elements) for :mod:`pynettcp.codegen.wsdl` to interpret.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
from urllib.request import urlopen

__all__ = ["fetch_metadata", "fetch_mex", "fetch_http_wsdl", "MEX_GET_ACTION"]

MEX_GET_ACTION = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"

MEX_NS = "http://schemas.xmlsoap.org/ws/2004/09/mex"
WSDL_NS = "http://schemas.xmlsoap.org/wsdl/"
XSD_NS = "http://www.w3.org/2001/XMLSchema"


def fetch_metadata(uri: str, **channel_options) -> list[ET.Element]:
    """Fetch metadata from a ``net.tcp://`` MEX endpoint or an HTTP WSDL URL."""
    scheme = urlparse(uri).scheme.lower()
    if scheme == "net.tcp":
        return fetch_mex(uri, **channel_options)
    if scheme in ("http", "https"):
        return fetch_http_wsdl(uri)
    raise ValueError(f"cannot fetch metadata from {uri!r}: unsupported scheme")


def fetch_mex(uri: str, **channel_options) -> list[ET.Element]:
    """Fetch metadata over WS-MetadataExchange on ``net.tcp``.

    A ``/mex`` suffix is added when missing, matching how WCF publishes it.
    """
    from ..channel import Channel
    from ..xmltree import events_to_element

    if not uri.rstrip("/").endswith("/mex"):
        uri = uri.rstrip("/") + "/mex"

    with Channel(uri, **channel_options) as channel:
        reply = channel.call(action=MEX_GET_ACTION)

    if reply.is_fault:
        raise RuntimeError(f"metadata request was refused by {uri}")

    metadata = events_to_element(reply.body_events)
    if metadata is None:
        raise RuntimeError(f"empty metadata response from {uri}")

    roots: list[ET.Element] = []
    for section in metadata.findall(f"{{{MEX_NS}}}MetadataSection"):
        roots.extend(list(section))
    return roots or list(metadata)


def fetch_http_wsdl(url: str, *, seen: set[str] | None = None) -> list[ET.Element]:
    """Fetch a WSDL over HTTP and follow its imports."""
    seen = set() if seen is None else seen
    if url in seen:
        return []
    seen.add(url)

    with urlopen(url) as response:  # noqa: S310 - the URL comes from the caller
        document = ET.fromstring(response.read())

    roots = [document]
    for reference in _import_locations(document):
        roots.extend(fetch_http_wsdl(urljoin(url, reference), seen=seen))
    return roots


def _import_locations(document: ET.Element) -> list[str]:
    """Collect ``wsdl:import/@location`` and ``xs:import|include/@schemaLocation``."""
    locations = []
    for element in document.iter():
        if element.tag == f"{{{WSDL_NS}}}import":
            location = element.get("location")
            if location:
                locations.append(location)
        elif element.tag in (f"{{{XSD_NS}}}import", f"{{{XSD_NS}}}include"):
            location = element.get("schemaLocation")
            if location:
                locations.append(location)
    return locations
