"""Generate pynettcp/dictionary.py from the live .NET Framework runtime.

Development-only. Requires pythonnet and .NET Framework 4.x; the shipped
library has no CLR dependency at all -- that is the whole point of pynettcp.

The static string table used by WCF's binary encoder lives in the *internal*
type System.ServiceModel.ServiceModelDictionary, static field `Version1`.
Transcribing 487 strings by hand would guarantee a typo that shows up as an
undebuggable mis-parse, so we read them straight out of the assembly.

    python tools/gen_dictionary.py
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import clr  # type: ignore  # noqa: F401
    import System  # type: ignore
    from System.Reflection import BindingFlags  # type: ignore
except ImportError:  # pragma: no cover - dev tool only
    sys.exit("pythonnet is required to regenerate the dictionary: pip install pythonnet")

clr.AddReference("System.ServiceModel")

OUT = Path(__file__).resolve().parent.parent / "pynettcp" / "dictionary.py"

HEADER = '''"""WCF binary-encoder static string dictionary ([MC-NBFS] section 2.2).

GENERATED FILE -- do not edit by hand.
Regenerate with:  python tools/gen_dictionary.py

Source of truth: System.ServiceModel.ServiceModelDictionary.Version1 in
.NET Framework {clr_version}, read via reflection from
{asm_location}

On the wire a dictionary reference is a MultiByteInt31 whose low bit selects
the table:  id & 1 == 0 -> static, index = id >> 1
            id & 1 == 1 -> per-session dynamic, index = id >> 1
"""

from __future__ import annotations

__all__ = ["STATIC_STRINGS", "STATIC_IDS", "static_id", "lookup_static"]

#: Index -> string. Position in this tuple *is* the dictionary index.
STATIC_STRINGS: tuple[str, ...] = (
'''

FOOTER = ''')

#: string -> index, for encoding.
STATIC_IDS: dict[str, int] = {s: i for i, s in enumerate(STATIC_STRINGS)}

assert len(STATIC_IDS) == len(STATIC_STRINGS), "duplicate string in static dictionary"


def static_id(value: str) -> int | None:
    """Return the *wire* id for ``value``, or None if it is not a static string.

    The returned value is already shifted: ``index << 1`` (low bit 0 = static).
    """
    index = STATIC_IDS.get(value)
    return None if index is None else index << 1


def lookup_static(index: int) -> str:
    """Return the string at static-dictionary ``index`` (already un-shifted)."""
    try:
        return STATIC_STRINGS[index]
    except IndexError:
        raise KeyError(f"static dictionary index {index} out of range "
                       f"(table has {len(STATIC_STRINGS)} entries)") from None
'''


def dump() -> list[str]:
    asm = next(
        a for a in System.AppDomain.CurrentDomain.GetAssemblies()
        if a.GetName().Name == "System.ServiceModel"
    )
    typ = asm.GetType("System.ServiceModel.ServiceModelDictionary")
    if typ is None:  # pragma: no cover
        sys.exit("could not find System.ServiceModel.ServiceModelDictionary")

    field = typ.GetField(
        "Version1", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public
    )
    instance = field.GetValue(None)

    strings: list[str] = []
    index = 0
    while True:
        found, entry = instance.TryLookup(index, None)
        if not found:
            break
        strings.append(entry.Value)
        index += 1

    if not strings:  # pragma: no cover
        sys.exit("dictionary came back empty -- reflection path is wrong")
    return strings, asm.Location


def main() -> None:
    strings, location = dump()

    body = "".join(f"    {s!r},\n" for s in strings)
    text = (
        HEADER.format(clr_version=System.Environment.Version, asm_location=location)
        + body
        + FOOTER
    )
    OUT.write_text(text, encoding="utf-8")

    print(f"wrote {OUT} with {len(strings)} entries")
    print(f"  [0]   {strings[0]!r}")
    print(f"  [7]   {strings[7]!r}")
    print(f"  [{len(strings) - 1}] {strings[-1]!r}")


if __name__ == "__main__":
    main()
