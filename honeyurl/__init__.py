"""HONEYURL — generate canary URLs/tokens and match trip events.

Defensive / authorized-testing tool. Generates unique, signed canary
tokens you can embed in files, configs, or endpoints, then matches
inbound access records against the minted tokens to detect tripwires.
No attack capability; analysis/detection only.
"""
from .core import (
    Canary,
    TripEvent,
    mint_canary,
    verify_token,
    match_events,
    load_registry,
    save_registry,
)

TOOL_NAME = "honeyurl"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Canary",
    "TripEvent",
    "mint_canary",
    "verify_token",
    "match_events",
    "load_registry",
    "save_registry",
]
