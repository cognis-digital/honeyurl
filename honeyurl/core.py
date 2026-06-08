"""HONEYURL core engine.

A canary token is a unique identifier that should never be accessed under
normal operation. When it *is* accessed (a "trip"), that is high-signal
evidence of unauthorized access, data exfiltration, or reconnaissance.

This module mints HMAC-signed tokens bound to a registry secret, embeds them
into canary URLs, and matches inbound access records against the registry to
produce tamper-evident trip events. Standard library only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Iterable

TOKEN_BYTES = 9  # -> 18 hex chars, collision-safe for canary use
SIG_LEN = 12     # truncated HMAC hex chars embedded in the token


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sign(secret: str, token_id: str) -> str:
    mac = hmac.new(secret.encode("utf-8"), token_id.encode("utf-8"), hashlib.sha256)
    return mac.hexdigest()[:SIG_LEN]


@dataclass
class Canary:
    """A minted canary token and its embedding URL."""
    token_id: str
    signature: str
    token: str          # token_id + "." + signature  (what appears in the wild)
    url: str
    label: str
    kind: str           # url | dns | doc | aws-style
    created: str = field(default_factory=_now_iso)
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TripEvent:
    """A matched access against a minted canary."""
    token: str
    token_id: str
    label: str
    valid_signature: bool
    severity: str       # critical | high | info
    reason: str
    source_ip: str = ""
    user_agent: str = ""
    seen: str = ""
    raw: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def mint_canary(
    secret: str,
    base_url: str = "https://canary.example.net/t",
    label: str = "",
    kind: str = "url",
    note: str = "",
) -> Canary:
    """Mint a fresh, signed canary token + embedding URL.

    The signature binds the random token_id to the registry secret so an
    attacker cannot forge a 'valid' token without the secret, and so trips
    on guessed/mangled tokens are flagged as tampered.
    """
    if not secret:
        raise ValueError("secret is required to mint a canary")
    token_id = secrets.token_hex(TOKEN_BYTES)
    sig = _sign(secret, token_id)
    token = f"{token_id}.{sig}"
    base = base_url.rstrip("/")
    if kind == "dns":
        # token as a subdomain label; DNS resolution is the trip
        host = base.split("://", 1)[-1].split("/", 1)[0]
        url = f"{token_id}.{sig}.{host}"
    elif kind == "aws-style":
        url = f"{base}/AKIA{token_id[:12].upper()}?sig={sig}"
    else:  # url | doc
        url = f"{base}/{token}"
    return Canary(
        token_id=token_id,
        signature=sig,
        token=token,
        url=url,
        label=label or f"canary-{token_id[:6]}",
        kind=kind,
        note=note,
    )


def verify_token(secret: str, token: str) -> tuple[bool, str]:
    """Return (valid, token_id) for a presented token string.

    Valid means the embedded signature matches an HMAC of the token_id under
    the registry secret. Uses constant-time comparison.
    """
    if not token or "." not in token:
        return (False, token or "")
    token_id, _, sig = token.rpartition(".")
    if not token_id:
        return (False, token)
    expected = _sign(secret, token_id)
    return (hmac.compare_digest(expected, sig), token_id)


def load_registry(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if "secret" not in data or "canaries" not in data:
        raise ValueError("registry missing 'secret' or 'canaries'")
    return data


def save_registry(path: str, secret: str, canaries: Iterable[Canary]) -> dict:
    data = {
        "version": 1,
        "secret": secret,
        "created": _now_iso(),
        "canaries": [c.to_dict() if isinstance(c, Canary) else c for c in canaries],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return data


_TOKEN_RE_CHARS = "0123456789abcdef"


def _extract_token(text: str) -> str:
    """Pull a token_id.sig pair out of an arbitrary access-log line / URL."""
    # Look for the '<hex>.<hex>' shape produced by mint_canary.
    for chunk in _tokenize(text):
        if "." in chunk:
            tid, _, sig = chunk.rpartition(".")
            if (
                len(tid) == TOKEN_BYTES * 2
                and len(sig) == SIG_LEN
                and all(ch in _TOKEN_RE_CHARS for ch in tid)
                and all(ch in _TOKEN_RE_CHARS for ch in sig)
            ):
                return chunk
    return ""


def _tokenize(text: str) -> list[str]:
    out: list[str] = []
    buf = []
    keep = set(_TOKEN_RE_CHARS) | {"."}
    for ch in text.lower():
        if ch in keep:
            buf.append(ch)
        elif buf:
            out.append("".join(buf))
            buf = []
    if buf:
        out.append("".join(buf))
    return out


def match_events(registry: dict, records: Iterable[dict]) -> list[TripEvent]:
    """Match inbound access records against the registry of minted canaries.

    Each record is a dict with at least one of: 'token', 'url', 'line'.
    Optional context: 'source_ip', 'user_agent', 'seen'.

    Returns trip events. A record that contains a token-shaped string is a
    trip; we then classify severity by whether the signature validates and
    whether the token_id is in our registry.
    """
    secret = registry["secret"]
    known = {c["token_id"]: c for c in registry["canaries"]}

    events: list[TripEvent] = []
    for rec in records:
        raw = rec.get("token") or rec.get("url") or rec.get("line") or ""
        token = rec.get("token") or _extract_token(raw)
        if not token:
            continue  # no canary referenced — not a trip
        valid, token_id = verify_token(secret, token)
        canary = known.get(token_id)
        if canary and valid:
            severity = "critical"
            reason = "Authentic canary tripped — token never used in normal ops."
        elif canary and not valid:
            severity = "high"
            reason = "Registered token_id presented with bad signature — tampering."
        elif not canary and valid:
            severity = "high"
            reason = "Validly signed token not in registry — stale or rotated mint."
        else:
            severity = "info"
            reason = "Unknown/forged token shape — guess or scan, not a real canary."
        events.append(
            TripEvent(
                token=token,
                token_id=token_id,
                label=canary["label"] if canary else "(unknown)",
                valid_signature=valid,
                severity=severity,
                reason=reason,
                source_ip=rec.get("source_ip", ""),
                user_agent=rec.get("user_agent", ""),
                seen=rec.get("seen", "") or _now_iso(),
                raw=raw[:300],
            )
        )
    return events
