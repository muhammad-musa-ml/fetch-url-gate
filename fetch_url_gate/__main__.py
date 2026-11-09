"""Command line: check one URL, or run the comparison."""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

from .classify import check_url
from .evaluate import evaluate


def _resolve(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None)
    except OSError:
        return []
    return sorted({info[4][0].split("%")[0] for info in infos})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fetch_url_gate")
    sub = parser.add_subparsers(dest="command", required=True)

    check = sub.add_parser("check", help="decide one URL; exit 0 to allow, 1 to deny")
    check.add_argument("url")
    check.add_argument("--resolve", action="store_true", help="also look the name up and judge the addresses")
    check.add_argument("--allow-single-label", action="store_true")

    ev = sub.add_parser("eval", help="run the corpus through the text rule and the gate")
    ev.add_argument("--no-live", action="store_true", help="skip the requests to a local server")
    ev.add_argument("--write", action="store_true", help="write results/summary.md and results/results.csv")
    ev.add_argument("--out", default="results", help="folder for --write (default: results)")

    args = parser.parse_args(argv)
    if args.command == "check":
        verdict = check_url(args.url, resolver=_resolve if args.resolve else None, allow_single_label=args.allow_single_label)
        if verdict.allow:
            print(f"ALLOW {verdict.fetch_url}")
        else:
            print(f"DENY  {verdict.reason}")
        return 0 if verdict.allow else 1
    text = evaluate(live=not args.no_live, out_dir=Path(args.out) if args.write else None)
    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
