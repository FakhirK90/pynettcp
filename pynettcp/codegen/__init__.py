"""WSDL to Python code generation -- the ``svcutil`` replacement.

Point it at a service's metadata and it emits a typed client module::

    python -m pynettcp.codegen net.tcp://host:8899/Demo/mex -o demo_client.py

Metadata is fetched over ``net.tcp`` MEX using pynettcp itself, or over HTTP
for services that publish ``?wsdl``.  The generated module is plain data --
:class:`~pynettcp.contract.ElementSpec` tables plus dataclasses -- which the
runtime in :mod:`pynettcp.contract` walks.
"""

from __future__ import annotations

from .emit import emit_module
from .metadata import fetch_metadata
from .wsdl import ServiceDescription, parse_metadata

__all__ = ["fetch_metadata", "parse_metadata", "ServiceDescription", "emit_module"]
