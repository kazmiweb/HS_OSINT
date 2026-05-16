"""Command-line interface for HS OSINT."""

from __future__ import annotations

import argparse
import sys

from hs_osint import __version__
from hs_osint.config import load_config
from hs_osint.engine import SearchEngine
from hs_osint.models import SearchContext
from hs_osint.report import render_json, render_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hs-osint",
        description="Safe, extensible OSINT search and analysis tool.",
    )
    parser.add_argument("--version", action="version", version=f"hs-osint {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    search = subparsers.add_parser("search", help="Search configured OSINT providers")
    search.add_argument("query", help="Query, keyword, username, email, domain, IP, URL, or phone")
    search.add_argument("--config", help="Path to JSON/TOML config file")
    search.add_argument(
        "--provider",
        action="append",
        dest="providers",
        help="Provider to run. Can be repeated. Defaults to enabled_providers.",
    )
    search.add_argument("--max-results", type=int, default=10)
    search.add_argument("--timeout", type=float, default=10.0)
    search.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="markdown",
        help="Output format.",
    )
    search.add_argument(
        "--acknowledge-lawful-use",
        action="store_true",
        help="Required for providers that can process personal or breach-exposure data.",
    )
    search.add_argument(
        "--include-raw",
        action="store_true",
        help="Include raw API/local records where providers support it. Secrets are still redacted.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "search":
        config = load_config(args.config)
        engine = SearchEngine(config)
        payload = engine.search(
            args.query,
            SearchContext(
                max_results=args.max_results,
                timeout_seconds=args.timeout,
                lawful_use_acknowledged=args.acknowledge_lawful_use,
                include_raw=args.include_raw,
            ),
            provider_names=args.providers,
        )
        if args.format == "json":
            print(render_json(payload))
        else:
            print(render_markdown(payload))
        return 0

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
