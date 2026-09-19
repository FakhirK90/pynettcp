"""Command line entry point: metadata in, typed Python client out.

    python -m pynettcp.codegen net.tcp://host:8899/Demo/mex -o demo_client.py
    python -m pynettcp.codegen http://host:8101/Svc?wsdl -o svc_client.py
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .emit import emit_module
from .metadata import fetch_metadata
from .wsdl import UnsupportedSchema, parse_metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pynettcp.codegen",
        description="Generate a typed Python client from WCF service metadata.",
    )
    parser.add_argument(
        "uri",
        help="net.tcp:// MEX endpoint, or an http(s):// WSDL URL",
    )
    parser.add_argument("-o", "--output", type=Path, help="write to a file (default: stdout)")
    parser.add_argument("--class-name", help="override the generated client class name")
    parser.add_argument(
        "--security",
        choices=("none", "transport"),
        default="none",
        help="security mode for a net.tcp MEX fetch (default: none, as WCF publishes mex)",
    )
    parser.add_argument("--spn", help="service principal name when --security transport")
    args = parser.parse_args(argv)

    channel_options = {}
    if args.uri.lower().startswith("net.tcp://"):
        channel_options["security"] = args.security
        if args.spn:
            channel_options["spn"] = args.spn

    try:
        roots = fetch_metadata(args.uri, **channel_options)
        description = parse_metadata(roots)
    except UnsupportedSchema as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - the CLI should not show a traceback
        print(f"error: could not read metadata from {args.uri}: {exc}", file=sys.stderr)
        return 1

    source = emit_module(
        description,
        source=args.uri,
        output=str(args.output) if args.output else "client.py",
        class_name=args.class_name,
    )

    if args.output:
        args.output.write_text(source, encoding="utf-8")
        print(
            f"wrote {args.output}: {len(description.operations)} operation(s), "
            f"{len(description.types)} type(s)",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(source)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
