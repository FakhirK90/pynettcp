"""MultiByteInt31 -- the variable-length integer used throughout the stack.

Defined in [MC-NBFX] section 2.1.1 and reused verbatim by [MC-NMF] for record
lengths.  Seven value bits per byte, least-significant group first, high bit
set on every byte except the last.  The value is unsigned and must fit in 31
bits, so the encoding is never longer than five bytes.

    123        -> 7b
    205        -> cd 01
    2147483647 -> ff ff ff ff 07

This lives in its own module because three separate layers need it (framing
record lengths, NBFX string lengths, NBFX dictionary ids) and they must agree
byte-for-byte.
"""

from __future__ import annotations

from typing import BinaryIO

__all__ = ["MAX_MULTIBYTE_INT31", "encode_multibyte_int31", "decode_multibyte_int31", "read_multibyte_int31"]

MAX_MULTIBYTE_INT31 = (1 << 31) - 1


def encode_multibyte_int31(value: int) -> bytes:
    """Encode ``value`` as a MultiByteInt31."""
    if value < 0 or value > MAX_MULTIBYTE_INT31:
        raise ValueError(f"MultiByteInt31 out of range: {value}")

    out = bytearray()
    while True:
        septet = value & 0x7F
        value >>= 7
        if value:
            out.append(septet | 0x80)
        else:
            out.append(septet)
            return bytes(out)


def decode_multibyte_int31(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode a MultiByteInt31 at ``offset``.

    Returns ``(value, next_offset)``.
    """
    value = 0
    shift = 0
    pos = offset

    while True:
        if pos >= len(data):
            raise ValueError("truncated MultiByteInt31")
        if shift > 28:
            raise ValueError("MultiByteInt31 longer than 5 bytes")

        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift

        if not byte & 0x80:
            if value > MAX_MULTIBYTE_INT31:
                raise ValueError(f"MultiByteInt31 overflows 31 bits: {value}")
            return value, pos

        shift += 7


def read_multibyte_int31(stream: BinaryIO) -> int:
    """Read a MultiByteInt31 from a byte stream, consuming exactly its bytes.

    Used by the framing layer, where we cannot look ahead past the record.
    """
    value = 0
    shift = 0

    while True:
        if shift > 28:
            raise ValueError("MultiByteInt31 longer than 5 bytes")

        chunk = stream.read(1)
        if not chunk:
            raise EOFError("stream ended inside a MultiByteInt31")

        byte = chunk[0]
        value |= (byte & 0x7F) << shift

        if not byte & 0x80:
            if value > MAX_MULTIBYTE_INT31:
                raise ValueError(f"MultiByteInt31 overflows 31 bits: {value}")
            return value

        shift += 7
