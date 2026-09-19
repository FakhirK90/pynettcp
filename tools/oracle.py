"""Ground-truth byte oracle: drives the real .NET binary XML writer.

Development-only (needs pythonnet + .NET Framework).  Used by the differential
tests so that "is our encoder correct?" is answered by WCF itself rather than
by our reading of [MC-NBFX].

An op list is a sequence of tuples in document order::

    ("start", prefix, name)
    ("xmlns", prefix, namespace)
    ("attr",  prefix, name, value)
    ("text",  value)
    ("end",)

The same op list can be replayed into ``pynettcp.nbfx.BinaryXmlWriter``, so the
two outputs are directly comparable byte-for-byte.
"""

from __future__ import annotations

import datetime as _dt
import uuid as _uuid

import clr  # type: ignore  # noqa: F401
import System  # type: ignore
from System.Reflection import BindingFlags  # type: ignore

clr.AddReference("System.ServiceModel")
clr.AddReference("System.Runtime.Serialization")

from System.IO import MemoryStream  # type: ignore  # noqa: E402
from System.Xml import XmlDictionaryWriter  # type: ignore  # noqa: E402

__all__ = ["service_model_dictionary", "encode", "to_bytes"]

_FLAGS = BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public


def service_model_dictionary():
    """The internal WCF static string dictionary (``ServiceModelDictionary.Version1``)."""
    asm = next(
        a
        for a in System.AppDomain.CurrentDomain.GetAssemblies()
        if a.GetName().Name == "System.ServiceModel"
    )
    typ = asm.GetType("System.ServiceModel.ServiceModelDictionary")
    return typ.GetField("Version1", _FLAGS).GetValue(None)


def to_bytes(stream: MemoryStream) -> bytes:
    return bytes(stream.ToArray())


def _xds(value: str):
    """Resolve a DictStr to the .NET XmlDictionaryString it stands for.

    Mirrors how WCF selects the dictionary overload: only strings the caller
    explicitly marks get compressed, and they must exist in the table.
    """
    found, entry = service_model_dictionary().TryLookup(str(value), None)
    if not found:
        raise KeyError(f"{value!r} is not in the WCF static dictionary")
    return entry


def _maybe_dict(value):
    """Pass DictStr through as XmlDictionaryString, everything else as str."""
    from pynettcp.nbfx import DictStr

    return _xds(value) if isinstance(value, DictStr) else value


def _net_value(writer, value: object) -> None:
    """Write a value with the .NET overload matching its Python type."""
    from pynettcp.nbfx import DictStr

    if isinstance(value, DictStr):
        writer.WriteString(_xds(value))
    elif value is None:
        writer.WriteString("")
    elif isinstance(value, bool):
        writer.WriteValue(System.Boolean(value))
    elif isinstance(value, int):
        writer.WriteValue(System.Int32(value)) if -(2**31) <= value < 2**31 else writer.WriteValue(
            System.Int64(value)
        )
    elif isinstance(value, float):
        writer.WriteValue(System.Double(value))
    elif isinstance(value, _dt.datetime):
        writer.WriteValue(
            System.DateTime(value.year, value.month, value.day, value.hour, value.minute, value.second)
        )
    elif isinstance(value, _uuid.UUID):
        writer.WriteValue(System.Guid(str(value)))
    elif isinstance(value, (bytes, bytearray)):
        writer.WriteBase64(bytes(value), 0, len(value))
    else:
        writer.WriteString(str(value))


def encode(ops, *, use_dictionary: bool = True, session=None) -> bytes:
    """Replay ``ops`` through .NET's binary XML writer and return the bytes."""
    stream = MemoryStream()
    if use_dictionary:
        writer = XmlDictionaryWriter.CreateBinaryWriter(
            stream, service_model_dictionary(), session
        )
    else:
        writer = XmlDictionaryWriter.CreateBinaryWriter(stream)

    for op in ops:
        kind = op[0]
        if kind == "start":
            _, prefix, name, namespace = op
            writer.WriteStartElement(prefix, _maybe_dict(name), _maybe_dict(namespace))
        elif kind == "xmlns":
            _, prefix, namespace = op
            writer.WriteXmlnsAttribute(prefix or None, _maybe_dict(namespace))
        elif kind == "attr":
            _, prefix, name, namespace, value = op
            writer.WriteStartAttribute(prefix, _maybe_dict(name), _maybe_dict(namespace))
            _net_value(writer, value)
            writer.WriteEndAttribute()
        elif kind == "text":
            _net_value(writer, op[1])
        elif kind == "end":
            writer.WriteEndElement()
        else:
            raise ValueError(f"unknown op {kind!r}")

    writer.Flush()
    return to_bytes(stream)


if __name__ == "__main__":
    demo = [
        ("start", "", "r", None),
        ("text", "hello"),
        ("end",),
    ]
    print(encode(demo).hex(" "))
