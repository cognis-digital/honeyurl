"""HONEYURL command line interface.

Subcommands:
  mint    Mint one or more canary tokens into a registry (JSON).
  scan    Match an access log / JSONL records file against a registry,
          emitting trip events. Non-zero exit when trips are found.

Exit codes:
  0  success, no findings
  1  trips/findings detected (scan) — actionable signal
  2  usage / runtime error
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from typing import Iterable

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    mint_canary,
    match_events,
    load_registry,
    save_registry,
)

SEVERITY_EXIT = {"critical", "high"}


def _print_table(rows: list[list[str]], headers: list[str]) -> None:
    cols = list(zip(*([headers] + rows))) if rows else [[h] for h in headers]
    widths = [max(len(str(c)) for c in col) for col in cols]
    line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    print(line)
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))


def _read_records(path: str) -> list[dict]:
    """Read records as JSONL (one JSON object per line) or plain log lines."""
    records: list[dict] = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.rstrip("\n")
            if not raw.strip():
                continue
            stripped = raw.lstrip()
            if stripped.startswith("{"):
                try:
                    records.append(json.loads(raw))
                    continue
                except json.JSONDecodeError:
                    pass
            records.append({"line": raw})
    return records


def _cmd_mint(args) -> int:
    secret = args.secret or os.environ.get("HONEYURL_SECRET")
    existing: list[dict] = []
    if args.registry and os.path.exists(args.registry):
        reg = load_registry(args.registry)
        secret = secret or reg["secret"]
        existing = reg["canaries"]
    secret = secret or secrets.token_hex(16)

    minted = []
    for _ in range(max(1, args.count)):
        c = mint_canary(
            secret=secret,
            base_url=args.base_url,
            label=args.label,
            kind=args.kind,
            note=args.note,
        )
        minted.append(c)

    all_canaries = existing + [c.to_dict() for c in minted]
    if args.registry:
        save_registry(args.registry, secret, all_canaries)

    if args.format == "json":
        print(json.dumps({
            "tool": TOOL_NAME,
            "action": "mint",
            "secret_stored": bool(args.registry),
            "secret": None if args.registry else secret,
            "minted": [c.to_dict() for c in minted],
        }, indent=2))
    else:
        if not args.registry:
            print(f"# secret (store safely): {secret}")
        rows = [[c.label, c.kind, c.url] for c in minted]
        _print_table(rows, ["LABEL", "KIND", "URL"])
    return 0


def _cmd_scan(args) -> int:
    reg = load_registry(args.registry)
    records = _read_records(args.records)
    events = match_events(reg, records)

    findings = [e for e in events if e.severity in SEVERITY_EXIT]

    if args.format == "json":
        print(json.dumps({
            "tool": TOOL_NAME,
            "action": "scan",
            "records": len(records),
            "trips": len(events),
            "findings": len(findings),
            "events": [e.to_dict() for e in events],
        }, indent=2))
    else:
        if not events:
            print(f"No canary trips across {len(records)} record(s).")
        else:
            rows = [[e.severity.upper(), e.label, e.source_ip or "-", e.reason]
                    for e in events]
            _print_table(rows, ["SEVERITY", "LABEL", "SOURCE_IP", "REASON"])
            print(f"\n{len(events)} trip(s), {len(findings)} actionable finding(s).")

    return 1 if findings else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Generate canary URLs/tokens and match trip events (defensive).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table")
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("mint", help="mint canary token(s)")
    m.add_argument("--registry", help="registry JSON file to create/append")
    m.add_argument("--secret", help="HMAC secret (else env HONEYURL_SECRET / random)")
    m.add_argument("--base-url", default="https://canary.example.net/t")
    m.add_argument("--label", default="")
    m.add_argument("--kind", choices=["url", "dns", "doc", "aws-style"], default="url")
    m.add_argument("--note", default="")
    m.add_argument("--count", type=int, default=1)
    m.set_defaults(func=_cmd_mint)

    s = sub.add_parser("scan", help="match access records against registry")
    s.add_argument("--registry", required=True, help="registry JSON from 'mint'")
    s.add_argument("--records", required=True,
                   help="access log (JSONL or plain lines) to scan for trips")
    s.set_defaults(func=_cmd_scan)
    return p


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    args.format = getattr(args, "format", "table")
    try:
        return args.func(args)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
